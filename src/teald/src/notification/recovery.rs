// SPDX-License-Identifier: MIT
//! Phase 5: bounded durable notification recovery. All filesystem calls are
//! executed from the notification subsystem, never the audit/decision path.
use super::config::NotificationTransportConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use teal_notify_protocol::NotificationRequest;
use uuid::Uuid;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingNotification {
    pub request: NotificationRequest,
    /// SMTP/transport attempts only; RATE_LIMIT never increments this.
    pub attempts: u32,
    pub first_attempt_ms: Option<u64>,
    pub last_attempt_ms: Option<u64>,
    pub last_error: Option<String>,
    pub delivery_uncertain: bool,
    /// Set only by a deliberate, authorized NOTIFY RETRY operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_initiator_uid: Option<u32>,
}
impl PendingNotification {
    pub fn fresh(request: NotificationRequest) -> Self {
        Self {
            request,
            attempts: 0,
            first_attempt_ms: None,
            last_attempt_ms: None,
            last_error: None,
            delivery_uncertain: false,
            manual_initiator_uid: None,
        }
    }
    pub fn expired(&self, config: &NotificationTransportConfig) -> bool {
        self.expired_at(config, now_ms())
    }

    /// Deterministic boundary predicate for an absolute timestamp in milliseconds.
    /// This permits exact 600_000-ms testing without sleeping ten minutes.
    pub fn expired_at(&self, config: &NotificationTransportConfig, at_ms: u64) -> bool {
        self.attempts >= config.retry_max_attempts
            || self.first_attempt_ms.is_some_and(|first| {
                at_ms.saturating_sub(first) >= config.retry_max_elapsed.as_millis() as u64
            })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndeliveredRecord {
    pub job: PendingNotification,
    pub reason: String,
    pub stored_at_ms: u64,
    /// Prior manual-delivery sessions; old Step 3 records deserialize unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<ManualRetryHistory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualRetryHistory {
    pub previous_job: PendingNotification,
    pub previous_reason: String,
    pub previous_stored_at_ms: u64,
    pub operator_uid: u32,
    pub finished_at_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResolvedNotification {
    pub original: UndeliveredRecord,
    pub resolved_by_uid: u32,
    pub resolved_at_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptedManualRetry {
    pub original: UndeliveredRecord,
    pub completed_job: PendingNotification,
    pub retried_by_uid: u32,
    pub accepted_at_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Snapshot {
    version: u16,
    jobs: Vec<PendingNotification>,
}

/// One filesystem owner serializes quota accounting and atomic writes.
#[derive(Debug)]
pub struct RecoveryStore {
    root: PathBuf,
    max_total_bytes: u64,
    max_undelivered_records: usize,
    gate: Mutex<()>,
}
impl RecoveryStore {
    pub fn open(config: &NotificationTransportConfig) -> io::Result<Arc<Self>> {
        let root = config.recovery_path.clone();
        // Do not follow a symlink in any existing path component.
        ensure_safe_dir(&root)?;
        ensure_safe_dir(&root.join("undelivered"))?;
        ensure_safe_dir(&root.join("emergency"))?;
        ensure_safe_dir(&root.join("manual_inflight"))?;
        ensure_safe_dir(&root.join("manual_sent"))?;
        ensure_safe_dir(&root.join("resolved"))?;
        for private in [
            root.clone(),
            root.join("undelivered"),
            root.join("emergency"),
            root.join("manual_inflight"),
            root.join("manual_sent"),
            root.join("resolved"),
        ] {
            fs::set_permissions(private, fs::Permissions::from_mode(0o700))?;
        }
        let store = Arc::new(Self {
            root,
            max_total_bytes: config.recovery_max_total_bytes,
            max_undelivered_records: config.recovery_max_undelivered_records,
            gate: Mutex::new(()),
        });
        // Interrupted manual retries must NEVER be silently sent at startup.
        // Restore their original UNDELIVERED records for an explicit new decision.
        store.recover_interrupted_manual_retries()?;
        store.recover_completed_resolves()?;
        Ok(store)
    }

    pub fn restore_pending(&self) -> io::Result<Vec<PendingNotification>> {
        let _gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        let path = self.root.join("pending.json");
        let mut jobs = if path.exists() {
            let bytes = read_regular_limited(&path, self.max_total_bytes)?;
            let saved: Snapshot = serde_json::from_slice(&bytes).map_err(invalid_json)?;
            if saved.version != 1 {
                return Err(invalid("unsupported pending snapshot version"));
            }
            saved.jobs
        } else {
            Vec::new()
        };
        let emergency = self.root.join("emergency");
        for entry in fs::read_dir(&emergency)? {
            let entry = entry?;
            if entry.path().extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let bytes = read_regular_limited(&entry.path(), self.max_total_bytes)?;
            let job: PendingNotification = serde_json::from_slice(&bytes).map_err(invalid_json)?;
            jobs.push(job);
        }
        // Keep the first occurrence of an ID to avoid accidental duplicate delivery.
        let mut ids = std::collections::HashSet::new();
        jobs.retain(|j| ids.insert(j.request.notification_id.clone()));
        for job in &jobs {
            job.request.validate().map_err(invalid)?;
        }
        // Do not discard any input until the complete restore set was validated.
        if path.exists() {
            fs::remove_file(&path)?;
        }
        for entry in fs::read_dir(&emergency)? {
            let entry = entry?;
            if entry.path().extension().and_then(|v| v.to_str()) == Some("json") {
                fs::remove_file(entry.path())?;
            }
        }
        sync_dir(&self.root)?;
        sync_dir(&emergency)?;
        Ok(jobs)
    }

    pub fn save_pending(&self, jobs: &[PendingNotification]) -> io::Result<()> {
        let _gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        for job in jobs {
            job.request.validate().map_err(invalid)?;
        }
        let bytes = serde_json::to_vec(&Snapshot {
            version: 1,
            jobs: jobs.to_vec(),
        })
        .map_err(invalid_json)?;
        self.write_limited(&self.root.join("pending.json"), &bytes, true)
    }

    pub fn store_undelivered(&self, job: PendingNotification, reason: String) -> io::Result<()> {
        let _gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        job.request.validate().map_err(invalid)?;
        if let Some(uid) = job.manual_initiator_uid {
            let id = job.request.notification_id.clone();
            return self.finish_manual_retry_failed_locked(&id, uid, job, reason);
        }
        let name = id_filename(&job.request.notification_id);
        let dest = self.root.join("undelivered").join(name);
        if dest.exists()
            || self
                .root
                .join("manual_inflight")
                .join(id_filename(&job.request.notification_id))
                .exists()
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "undelivered or manual-inflight notification ID already saved",
            ));
        }
        if fs::read_dir(self.root.join("undelivered"))?
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().and_then(|v| v.to_str()) == Some("json"))
            .count()
            .saturating_add(
                fs::read_dir(self.root.join("manual_inflight"))?
                    .filter_map(Result::ok)
                    .filter(|e| e.path().extension().and_then(|v| v.to_str()) == Some("json"))
                    .count(),
            )
            >= self.max_undelivered_records
        {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "undelivered record quota reached",
            ));
        }
        let bytes = serde_json::to_vec(&UndeliveredRecord {
            job,
            reason,
            stored_at_ms: now_ms(),
            history: Vec::new(),
        })
        .map_err(invalid_json)?;
        self.write_limited(&dest, &bytes, false)
    }

    pub fn spool_ai(&self, job: &PendingNotification) -> io::Result<()> {
        let _gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        job.request.validate().map_err(invalid)?;
        let dest = self
            .root
            .join("emergency")
            .join(id_filename(&job.request.notification_id));
        if dest.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "emergency notification already saved",
            ));
        }
        let bytes = serde_json::to_vec(job).map_err(invalid_json)?;
        self.write_limited(&dest, &bytes, false)
    }

    pub fn clear_spooled(&self, id: &str) -> io::Result<()> {
        let _gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        let dir = self.root.join("emergency");
        match fs::remove_file(dir.join(id_filename(id))) {
            Ok(()) => sync_dir(&dir),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Look up one undelivered record by its original Notification ID. The
    /// filename is a SHA-256 digest, never a user-controlled path component.
    /// This method does NOT modify state or trigger a retry.
    pub fn get_undelivered(&self, id: &str) -> io::Result<Option<UndeliveredRecord>> {
        validate_id(id)?;
        let _gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        let path = self.root.join("undelivered").join(id_filename(id));
        let bytes = match read_regular_limited(&path, self.max_total_bytes) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let record: UndeliveredRecord = serde_json::from_slice(&bytes).map_err(invalid_json)?;
        if record.job.request.notification_id != id {
            return Err(invalid(
                "undelivered record notification ID does not match filename",
            ));
        }
        record.job.request.validate().map_err(invalid)?;
        Ok(Some(record))
    }

    pub fn list_undelivered(&self) -> io::Result<Vec<UndeliveredRecord>> {
        let _gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        let mut out = Vec::new();
        for entry in fs::read_dir(self.root.join("undelivered"))? {
            let entry = entry?;
            if entry.path().extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let bytes = read_regular_limited(&entry.path(), self.max_total_bytes)?;
            let record: UndeliveredRecord = serde_json::from_slice(&bytes).map_err(invalid_json)?;
            record.job.request.validate().map_err(invalid)?;
            if entry.file_name()
                != std::ffi::OsString::from(id_filename(&record.job.request.notification_id))
            {
                return Err(invalid("undelivered record filename/ID mismatch"));
            }
            out.push(record);
        }
        Ok(out)
    }

    /// Reconcile a retry interrupted by process termination without automatic
    /// network traffic. An existing target wins over a leftover claim marker.
    fn recover_interrupted_manual_retries(&self) -> io::Result<()> {
        let _gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        let dir = self.root.join("manual_inflight");
        let undelivered = self.root.join("undelivered");
        let sent = self.root.join("manual_sent");
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let bytes = read_regular_limited(&entry.path(), self.max_total_bytes)?;
            let original: UndeliveredRecord =
                serde_json::from_slice(&bytes).map_err(invalid_json)?;
            let id = original.job.request.notification_id.clone();
            original.job.request.validate().map_err(invalid)?;
            let name = id_filename(&id);
            if entry.file_name() != std::ffi::OsString::from(name.as_str()) {
                return Err(invalid("manual retry filename/ID mismatch"));
            }
            let target = undelivered.join(&name);
            if target.exists() || sent.join(&name).exists() {
                fs::remove_file(entry.path())?;
            } else {
                fs::rename(entry.path(), &target)?;
                // If room permits, label the interrupted attempt conservatively;
                // otherwise the original record remains safely available.
                let mut recovered = original;
                recovered.job.delivery_uncertain = true;
                recovered.reason = "MANUAL_RETRY_INTERRUPTED".into();
                match serde_json::to_vec(&recovered).map_err(invalid_json) {
                    Ok(bytes) => {
                        if let Err(error) = self.write_limited(&target, &bytes, true) {
                            eprintln!("[TEAL][notify][WARN] interrupted retry metadata update failed id={id:?} error={error}");
                        }
                    }
                    Err(error) => eprintln!("[TEAL][notify][WARN] interrupted retry metadata encoding failed id={id:?} error={error}"),
                }
                eprintln!("[TEAL][notify][AUDIT] interrupted manual retry restored to UNDELIVERED id={id:?}; no automatic retry");
            }
        }
        sync_dir(&dir)?;
        sync_dir(&undelivered)?;
        Ok(())
    }

    fn recover_completed_resolves(&self) -> io::Result<()> {
        let _gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        let dir = self.root.join("resolved");
        let mut changed = false;
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let bytes = read_regular_limited(&entry.path(), self.max_total_bytes)?;
            let resolved: ResolvedNotification =
                serde_json::from_slice(&bytes).map_err(invalid_json)?;
            let id = &resolved.original.job.request.notification_id;
            resolved.original.job.request.validate().map_err(invalid)?;
            let name = id_filename(id);
            if entry.file_name() != std::ffi::OsString::from(name.as_str()) {
                return Err(invalid("resolved archive filename/ID mismatch"));
            }
            let redundant = self.root.join("undelivered").join(name);
            if redundant.exists() {
                // Crash after archive commit but before deletion of original.
                fs::remove_file(&redundant)?;
                changed = true;
                eprintln!("[TEAL][notify][AUDIT] completed interrupted resolve id={id:?}");
            }
        }
        if changed {
            sync_dir(&self.root.join("undelivered"))?;
        }
        Ok(())
    }

    fn read_record_locked(&self, dir: &str, id: &str) -> io::Result<UndeliveredRecord> {
        validate_id(id)?;
        let path = self.root.join(dir).join(id_filename(id));
        let bytes = read_regular_limited(&path, self.max_total_bytes)?;
        let record: UndeliveredRecord = serde_json::from_slice(&bytes).map_err(invalid_json)?;
        if record.job.request.notification_id != id {
            return Err(invalid("notification record ID/filename mismatch"));
        }
        record.job.request.validate().map_err(invalid)?;
        Ok(record)
    }

    /// Atomic claim is the concurrency gate. Never overwrite the original
    /// history and never queue a notification without an explicit operator call.
    pub fn begin_manual_retry(&self, id: &str, uid: u32) -> io::Result<PendingNotification> {
        let _gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        validate_id(id)?;
        let name = id_filename(id);
        let from = self.root.join("undelivered").join(&name);
        let to = self.root.join("manual_inflight").join(&name);
        if to.exists() || self.root.join("manual_sent").join(&name).exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "manual retry already active or completed",
            ));
        }
        let record = self.read_record_locked("undelivered", id)?;
        fs::rename(&from, &to)?;
        sync_dir(&self.root.join("manual_inflight"))?;
        sync_dir(&self.root.join("undelivered"))?;
        let mut job = PendingNotification::fresh(record.job.request);
        job.delivery_uncertain = record.job.delivery_uncertain;
        job.manual_initiator_uid = Some(uid);
        Ok(job)
    }

    pub fn finish_manual_retry_failed(
        &self,
        id: &str,
        uid: u32,
        job: PendingNotification,
        reason: String,
    ) -> io::Result<()> {
        let _gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        self.finish_manual_retry_failed_locked(id, uid, job, reason)
    }

    fn finish_manual_retry_failed_locked(
        &self,
        id: &str,
        uid: u32,
        job: PendingNotification,
        reason: String,
    ) -> io::Result<()> {
        if job.request.notification_id != id || job.manual_initiator_uid != Some(uid) {
            return Err(invalid("retry job ID differs from claimed ID"));
        }
        let original = self.read_record_locked("manual_inflight", id)?;
        let mut history = original.history;
        history.push(ManualRetryHistory {
            previous_job: original.job,
            previous_reason: original.reason,
            previous_stored_at_ms: original.stored_at_ms,
            operator_uid: uid,
            finished_at_ms: now_ms(),
        });
        let updated = UndeliveredRecord {
            job,
            reason,
            stored_at_ms: now_ms(),
            history,
        };
        let name = id_filename(id);
        let dest = self.root.join("undelivered").join(&name);
        if dest.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "retry outcome already committed",
            ));
        }
        let bytes = serde_json::to_vec(&updated).map_err(invalid_json)?;
        if let Err(error) = self.write_limited(&dest, &bytes, false) {
            // Preserve the original UNDELIVERED record even when quota or I/O
            // prevents saving the new attempt history.
            fs::rename(self.root.join("manual_inflight").join(&name), &dest)?;
            sync_dir(&self.root.join("undelivered"))?;
            return Err(error);
        }
        fs::remove_file(self.root.join("manual_inflight").join(&name))?;
        sync_dir(&self.root.join("manual_inflight"))?;
        Ok(())
    }

    /// Keep both the original failed-session record and the successful retry
    /// attempt under manual_sent. This is not a user RESOLVE operation.
    pub fn finish_manual_retry_accepted(
        &self,
        id: &str,
        uid: u32,
        job: PendingNotification,
    ) -> io::Result<()> {
        let _gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        if job.request.notification_id != id || job.manual_initiator_uid != Some(uid) {
            return Err(invalid(
                "retry job ID differs from claimed ID or operator UID",
            ));
        }
        let original = self.read_record_locked("manual_inflight", id)?;
        let archived = AcceptedManualRetry {
            original,
            completed_job: job,
            retried_by_uid: uid,
            accepted_at_ms: now_ms(),
        };
        let name = id_filename(id);
        let dest = self.root.join("manual_sent").join(&name);
        if dest.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "manual sent archive already exists",
            ));
        }
        let bytes = serde_json::to_vec(&archived).map_err(invalid_json)?;
        self.write_limited(&dest, &bytes, false)?;
        fs::remove_file(self.root.join("manual_inflight").join(&name))?;
        sync_dir(&self.root.join("manual_inflight"))?;
        Ok(())
    }

    pub async fn finish_manual_retry_accepted_async(
        self: &Arc<Self>,
        id: String,
        uid: u32,
        job: PendingNotification,
    ) -> io::Result<()> {
        let store = Arc::clone(self);
        tokio::task::spawn_blocking(move || store.finish_manual_retry_accepted(&id, uid, job))
            .await
            .map_err(io::Error::other)?
    }

    pub fn manual_sent_result(&self, id: &str) -> io::Result<Option<AcceptedManualRetry>> {
        validate_id(id)?;
        let _gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        let path = self.root.join("manual_sent").join(id_filename(id));
        let bytes = match read_regular_limited(&path, self.max_total_bytes) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let archived: AcceptedManualRetry = serde_json::from_slice(&bytes).map_err(invalid_json)?;
        if archived.original.job.request.notification_id != id
            || archived.completed_job.request.notification_id != id
        {
            return Err(invalid("archived manual sent notification ID mismatch"));
        }
        Ok(Some(archived))
    }

    /// Processing acknowledgment is an archive operation, not file deletion.
    /// We write the audit-bearing record first, then retire the old one.
    pub fn mark_resolved(&self, id: &str, uid: u32) -> io::Result<()> {
        let _gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        validate_id(id)?;
        let name = id_filename(id);
        if self.root.join("manual_inflight").join(&name).exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "manual retry is active",
            ));
        }
        let original = self.read_record_locked("undelivered", id)?;
        let dest = self.root.join("resolved").join(&name);
        if dest.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "notification already resolved",
            ));
        }
        let bytes = serde_json::to_vec(&ResolvedNotification {
            original,
            resolved_by_uid: uid,
            resolved_at_ms: now_ms(),
        })
        .map_err(invalid_json)?;
        self.write_limited(&dest, &bytes, false)?;
        fs::remove_file(self.root.join("undelivered").join(&name))?;
        sync_dir(&self.root.join("undelivered"))?;
        Ok(())
    }

    fn write_limited(&self, dest: &Path, bytes: &[u8], replacing: bool) -> io::Result<()> {
        let usage = disk_usage(&self.root)?;
        let _ = replacing; // Old file plus temporary file count against the quota.
        if bytes.len() as u64 > self.max_total_bytes.saturating_sub(usage) {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "notification storage quota reached",
            ));
        }
        atomic_write(dest, bytes)
    }

    pub async fn store_undelivered_async(
        self: &Arc<Self>,
        job: PendingNotification,
        reason: String,
    ) -> io::Result<()> {
        let this = Arc::clone(self);
        tokio::task::spawn_blocking(move || this.store_undelivered(job, reason))
            .await
            .map_err(io::Error::other)?
    }
    pub async fn spool_ai_async(self: &Arc<Self>, job: PendingNotification) -> io::Result<()> {
        let this = Arc::clone(self);
        tokio::task::spawn_blocking(move || this.spool_ai(&job))
            .await
            .map_err(io::Error::other)?
    }
    pub async fn clear_spooled_async(self: &Arc<Self>, id: String) -> io::Result<()> {
        let this = Arc::clone(self);
        tokio::task::spawn_blocking(move || this.clear_spooled(&id))
            .await
            .map_err(io::Error::other)?
    }
    pub async fn save_pending_async(
        self: &Arc<Self>,
        jobs: Vec<PendingNotification>,
    ) -> io::Result<()> {
        let this = Arc::clone(self);
        tokio::task::spawn_blocking(move || this.save_pending(&jobs))
            .await
            .map_err(io::Error::other)?
    }
}

fn validate_id(id: &str) -> io::Result<()> {
    if id.is_empty()
        || id.len() > 512
        || id.chars().any(char::is_whitespace)
        || id.chars().any(char::is_control)
    {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid notification ID",
        ))
    } else {
        Ok(())
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn invalid_json(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}
fn id_filename(id: &str) -> String {
    format!("{:x}.json", Sha256::digest(id.as_bytes()))
}

fn ensure_safe_dir(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(invalid("recovery path must be absolute"));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push("/"),
            Component::Normal(x) => {
                current.push(x);
                match fs::symlink_metadata(&current) {
                    Ok(md) if md.file_type().is_symlink() || !md.is_dir() => {
                        return Err(invalid("recovery directory path is not a real directory"))
                    }
                    Ok(_) => {}
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {
                        fs::create_dir(&current)?;
                        fs::set_permissions(&current, fs::Permissions::from_mode(0o700))?;
                    }
                    Err(err) => return Err(err),
                }
            }
            _ => return Err(invalid("recovery path contains unsafe component")),
        }
    }
    Ok(())
}
fn read_regular_limited(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > max {
        return Err(invalid("invalid or oversized notification file"));
    }
    fs::read(path)
}
fn disk_usage(path: &Path) -> io::Result<u64> {
    let mut total: u64 = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let meta = fs::symlink_metadata(entry.path())?;
        if meta.file_type().is_symlink() {
            return Err(invalid("symlink detected in recovery storage"));
        }
        if meta.is_dir() {
            total = total.saturating_add(disk_usage(&entry.path())?);
        } else if meta.is_file() {
            total = total.saturating_add(meta.len());
        } else {
            return Err(invalid("unexpected storage object"));
        }
    }
    Ok(total)
}
fn sync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}
fn atomic_write(dest: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = dest.parent().ok_or_else(|| invalid("missing parent"))?;
    if dest.exists() && fs::symlink_metadata(dest)?.file_type().is_symlink() {
        return Err(invalid("destination symlink"));
    }
    let tmp = parent.join(format!(".{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, dest)?;
        sync_dir(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use teal_notify_protocol::{AiNotification, NotificationPayload, PROTOCOL_VERSION};
    fn job() -> PendingNotification {
        PendingNotification::fresh(NotificationRequest {
            version: PROTOCOL_VERSION,
            notification_id: "SAME-ID-001".into(),
            recipients: vec![],
            payload: NotificationPayload::Ai(AiNotification {
                hostname: "test".into(),
                confidence: 0.98,
                reason: "test".into(),
                related_event_ids: vec!["AUDIT-1".into()],
                program: "/bin/true".into(),
                action: "READ".into(),
                target: "/tmp/example".into(),
            }),
        })
    }
    #[test]
    fn pending_snapshot_restores_id_and_history() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = NotificationTransportConfig::default();
        c.recovery_path = dir.path().join("recovery");
        let store = RecoveryStore::open(&c).unwrap();
        let mut pending = job();
        pending.attempts = 2;
        pending.first_attempt_ms = Some(now_ms());
        store.save_pending(&[pending.clone()]).unwrap();
        let restored = store.restore_pending().unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].request.notification_id, "SAME-ID-001");
        assert_eq!(restored[0].attempts, 2);
        assert!(store.restore_pending().unwrap().is_empty());
    }
    #[test]
    fn undelivered_is_not_restored_or_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = NotificationTransportConfig::default();
        c.recovery_path = dir.path().join("recovery");
        c.recovery_max_undelivered_records = 1;
        let store = RecoveryStore::open(&c).unwrap();
        store
            .store_undelivered(job(), "SMTP_PERMANENT".into())
            .unwrap();
        assert!(store.restore_pending().unwrap().is_empty());
        assert_eq!(store.list_undelivered().unwrap().len(), 1);
        assert_eq!(
            store
                .store_undelivered(job(), "FAIL".into())
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
    }
    #[test]
    fn get_undelivered_finds_only_matching_notification_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = NotificationTransportConfig::default();
        c.recovery_path = dir.path().join("recovery");
        let store = RecoveryStore::open(&c).unwrap();
        store
            .store_undelivered(job(), "SMTP_PERMANENT".into())
            .unwrap();
        assert_eq!(
            store
                .get_undelivered("SAME-ID-001")
                .unwrap()
                .unwrap()
                .reason,
            "SMTP_PERMANENT"
        );
        assert!(store.get_undelivered("MISSING").unwrap().is_none());
        assert_eq!(store.list_undelivered().unwrap().len(), 1);
    }

    #[test]
    fn get_undelivered_rejects_modified_id_and_invalid_input() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = NotificationTransportConfig::default();
        c.recovery_path = dir.path().join("recovery");
        let store = RecoveryStore::open(&c).unwrap();
        store.store_undelivered(job(), "FAILED".into()).unwrap();
        let original_path = c
            .recovery_path
            .join("undelivered")
            .join(id_filename("SAME-ID-001"));
        let mut record: UndeliveredRecord =
            serde_json::from_slice(&fs::read(&original_path).unwrap()).unwrap();
        record.job.request.notification_id = "FORGED-ID".into();
        fs::write(&original_path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert_eq!(
            store.get_undelivered("SAME-ID-001").unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            store.get_undelivered("bad\n-id").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn emergency_spool_is_recoverable() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = NotificationTransportConfig::default();
        c.recovery_path = dir.path().join("recovery");
        let store = RecoveryStore::open(&c).unwrap();
        store.spool_ai(&job()).unwrap();
        assert_eq!(store.restore_pending().unwrap().len(), 1);
    }
    #[test]
    fn manual_retry_is_exclusive_and_preserves_original_after_failure() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = NotificationTransportConfig::default();
        c.recovery_path = dir.path().join("recovery");
        let store = RecoveryStore::open(&c).unwrap();
        let mut old = job();
        old.attempts = 5;
        old.delivery_uncertain = true;
        store
            .store_undelivered(old, "RETRY_EXHAUSTED".into())
            .unwrap();
        let mut fresh = store.begin_manual_retry("SAME-ID-001", 1000).unwrap();
        assert_eq!(fresh.request.notification_id, "SAME-ID-001");
        assert_eq!(fresh.manual_initiator_uid, Some(1000));
        assert_eq!(fresh.attempts, 0);
        assert!(fresh.delivery_uncertain);
        assert!(store.begin_manual_retry("SAME-ID-001", 1000).is_err());
        assert!(store.get_undelivered("SAME-ID-001").unwrap().is_none());
        fresh.attempts = 2;
        fresh.last_error = Some("SMTP_TEMPORARY".into());
        store
            .finish_manual_retry_failed("SAME-ID-001", 1000, fresh, "MANUAL_RETRY_EXHAUSTED".into())
            .unwrap();
        let after = store.get_undelivered("SAME-ID-001").unwrap().unwrap();
        assert_eq!(after.job.attempts, 2);
        assert_eq!(after.history.len(), 1);
        assert_eq!(after.history[0].previous_job.attempts, 5);
        assert_eq!(after.history[0].operator_uid, 1000);
        assert_eq!(after.reason, "MANUAL_RETRY_EXHAUSTED");
        assert!(store.begin_manual_retry("SAME-ID-001", 1000).is_ok());
    }

    #[test]
    fn accepted_manual_retry_is_archived_not_resolved_and_not_retried_at_start() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = NotificationTransportConfig::default();
        c.recovery_path = dir.path().join("recovery");
        let store = RecoveryStore::open(&c).unwrap();
        store.store_undelivered(job(), "SMTP_TEMP".into()).unwrap();
        let mut sending = store.begin_manual_retry("SAME-ID-001", 1000).unwrap();
        sending.attempts = 1;
        store
            .finish_manual_retry_accepted("SAME-ID-001", 1000, sending)
            .unwrap();
        assert!(store.list_undelivered().unwrap().is_empty());
        let file = store
            .root
            .join("manual_sent")
            .join(id_filename("SAME-ID-001"));
        let sent: AcceptedManualRetry = serde_json::from_slice(&fs::read(file).unwrap()).unwrap();
        assert_eq!(sent.original.job.request.notification_id, "SAME-ID-001");
        assert_eq!(sent.retried_by_uid, 1000);
        drop(store);
        let restarted = RecoveryStore::open(&c).unwrap();
        assert!(restarted.list_undelivered().unwrap().is_empty());
        assert!(restarted.restore_pending().unwrap().is_empty());
    }

    #[test]
    fn resolve_is_idempotency_safe_and_retains_original() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = NotificationTransportConfig::default();
        c.recovery_path = dir.path().join("recovery");
        let store = RecoveryStore::open(&c).unwrap();
        store.store_undelivered(job(), "PERMANENT".into()).unwrap();
        store.mark_resolved("SAME-ID-001", 1000).unwrap();
        assert!(store.get_undelivered("SAME-ID-001").unwrap().is_none());
        assert!(store.mark_resolved("SAME-ID-001", 1000).is_err());
        assert!(store.begin_manual_retry("SAME-ID-001", 1000).is_err());
        let file = store.root.join("resolved").join(id_filename("SAME-ID-001"));
        let archived: ResolvedNotification =
            serde_json::from_slice(&fs::read(file).unwrap()).unwrap();
        assert_eq!(archived.original.reason, "PERMANENT");
        assert_eq!(archived.resolved_by_uid, 1000);
    }

    #[test]
    fn interrupted_retry_never_resends_automatically() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = NotificationTransportConfig::default();
        c.recovery_path = dir.path().join("recovery");
        let store = RecoveryStore::open(&c).unwrap();
        store
            .store_undelivered(job(), "SMTP_TIMEOUT".into())
            .unwrap();
        store.begin_manual_retry("SAME-ID-001", 1000).unwrap();
        drop(store);
        let restored = RecoveryStore::open(&c).unwrap();
        let recovered = restored.get_undelivered("SAME-ID-001").unwrap().unwrap();
        assert!(recovered.job.delivery_uncertain);
        assert_eq!(recovered.reason, "MANUAL_RETRY_INTERRUPTED");
        assert!(restored.restore_pending().unwrap().is_empty());
    }
}
