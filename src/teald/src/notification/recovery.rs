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
        for private in [
            root.clone(),
            root.join("undelivered"),
            root.join("emergency"),
        ] {
            fs::set_permissions(private, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Arc::new(Self {
            root,
            max_total_bytes: config.recovery_max_total_bytes,
            max_undelivered_records: config.recovery_max_undelivered_records,
            gate: Mutex::new(()),
        }))
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
        let name = id_filename(&job.request.notification_id);
        let dest = self.root.join("undelivered").join(name);
        if dest.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "undelivered notification ID already saved",
            ));
        }
        if fs::read_dir(self.root.join("undelivered"))?
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().and_then(|v| v.to_str()) == Some("json"))
            .count()
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
            out.push(record);
        }
        Ok(out)
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
    fn emergency_spool_is_recoverable() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = NotificationTransportConfig::default();
        c.recovery_path = dir.path().join("recovery");
        let store = RecoveryStore::open(&c).unwrap();
        store.spool_ai(&job()).unwrap();
        assert_eq!(store.restore_pending().unwrap().len(), 1);
    }
}
