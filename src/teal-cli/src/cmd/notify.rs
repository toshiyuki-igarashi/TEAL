// SPDX-License-Identifier: MIT
/*
 * TEAL CLI (teal-cli)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

//! Management of undelivered notifications via teald's admin socket.
//! Never reads /var/lib/teal/notifications directly; teald owns authorization.

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::send_command;

const MAX_PAGE_SIZE: usize = 100;
const MAX_NOTIFICATION_ID_BYTES: usize = 512;

fn list_command(offset: usize, limit: usize) -> Result<String> {
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        bail!("--limit must be between 1 and {MAX_PAGE_SIZE}");
    }
    Ok(format!("NOTIFY LIST {offset} {limit}"))
}

fn show_command(id: &str) -> Result<String> {
    if id.is_empty()
        || id.len() > MAX_NOTIFICATION_ID_BYTES
        || id.chars().any(|ch| ch.is_control() || ch.is_whitespace())
    {
        bail!("notification ID must be a single non-empty token of at most 512 bytes");
    }
    Ok(format!("NOTIFY SHOW {id}"))
}

/// teald returns one JSON object on success and "ERR ..." on failure.
/// Do not accidentally convert an authorization/storage error into exit status 0.
fn parse_reply(reply: &str) -> Result<Value> {
    let trimmed = reply.trim();
    if trimmed.starts_with("ERR ") || trimmed == "ERR" {
        bail!("teald: {trimmed}");
    }
    let parsed: Value = serde_json::from_str(trimmed)
        .context("teald returned an invalid notification-management JSON response")?;
    if parsed.get("status").and_then(Value::as_str) != Some("ok") {
        bail!("teald returned an unexpected notification-management status");
    }
    Ok(parsed)
}

fn field_str<'a>(record: &'a Value, name: &str) -> Result<&'a str> {
    record
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {name}"))
}

fn field_u64(record: &Value, name: &str) -> Result<u64> {
    record
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {name}"))
}

// Prevent untrusted text from writing terminal escape/control sequences.
fn printable(input: &str) -> String {
    input.chars().flat_map(char::escape_default).collect()
}

fn render_list(response: &Value, raw_json: bool) -> Result<String> {
    let records = response
        .get("records")
        .and_then(Value::as_array)
        .context("missing notification records array")?;
    let total = field_u64(response, "total")?;
    let offset = field_u64(response, "offset")?;
    let limit = field_u64(response, "limit")?;
    let has_more = response
        .get("has_more")
        .and_then(Value::as_bool)
        .context("missing has_more flag")?;

    // Validate all rows before printing anything, including --json output.
    for record in records {
        field_str(record, "notification_id")?;
        field_str(record, "kind")?;
        field_str(record, "reason")?;
        field_u64(record, "attempts")?;
        field_u64(record, "stored_at_ms")?;
        record
            .get("delivery_uncertain")
            .and_then(Value::as_bool)
            .context("missing delivery_uncertain flag")?;
    }

    if raw_json {
        return Ok(serde_json::to_string_pretty(response)? + "\n");
    }

    let mut out = format!(
        "Undelivered notifications: total={total}, offset={offset}, limit={limit}, has_more={has_more}\n"
    );
    if records.is_empty() {
        out.push_str("No undelivered notifications on this page.\n");
        return Ok(out);
    }
    out.push_str(
        "NOTIFICATION ID                KIND  ATTEMPTS  UNCERTAIN  STORED (Unix ms)  REASON\n",
    );
    for record in records {
        let id = printable(field_str(record, "notification_id")?);
        let kind = printable(field_str(record, "kind")?);
        let attempts = field_u64(record, "attempts")?;
        let uncertain = record["delivery_uncertain"].as_bool().unwrap_or(false);
        let stored = field_u64(record, "stored_at_ms")?;
        let reason = printable(field_str(record, "reason")?);
        out.push_str(&format!(
            "{id:<30} {kind:<5} {attempts:>8}  {uncertain:<9}  {stored:<17} {reason}\n"
        ));
    }
    if has_more {
        out.push_str(&format!(
            "More records available; use --offset {}\n",
            offset.saturating_add(records.len() as u64)
        ));
    }
    Ok(out)
}

fn render_show(response: &Value, requested_id: &str, raw_json: bool) -> Result<String> {
    let record = response
        .get("record")
        .context("missing undelivered notification record")?;
    let returned_id = record
        .pointer("/job/request/notification_id")
        .and_then(Value::as_str)
        .context("missing record notification ID")?;
    if returned_id != requested_id {
        bail!("teald returned a record with an unexpected notification ID");
    }
    // The default view displays the full record (including delivery history and
    // original payload), while --json preserves the outer status/envelope.
    let to_print = if raw_json { response } else { record };
    Ok(serde_json::to_string_pretty(to_print)? + "\n")
}

pub fn list(offset: usize, limit: usize, raw_json: bool) -> Result<()> {
    let command = list_command(offset, limit)?;
    let response = parse_reply(&send_command(&command, false)?)?;
    print!("{}", render_list(&response, raw_json)?);
    Ok(())
}

pub fn show(id: &str, raw_json: bool) -> Result<()> {
    let command = show_command(id)?;
    let response = parse_reply(&send_command(&command, false)?)?;
    print!("{}", render_show(&response, id, raw_json)?);
    Ok(())
}

fn mutation_command(op: &str, id: &str, confirmed: bool) -> Result<String> {
    if !confirmed {
        bail!("notify {op} changes delivery state; pass --yes to confirm");
    }
    let read_command = show_command(id)?;
    let token = read_command.strip_prefix("NOTIFY SHOW ").unwrap();
    Ok(format!("NOTIFY {} {}", op.to_uppercase(), token))
}

fn render_mutation_reply(reply: &str, id: &str, op: &str, raw_json: bool) -> Result<String> {
    let trimmed = reply.trim();
    if trimmed.starts_with("ERR ") || trimmed == "ERR" {
        bail!("teald: {trimmed}");
    }
    let parsed: Value =
        serde_json::from_str(trimmed).context("invalid NOTIFY mutation response")?;
    if field_str(&parsed, "notification_id")? != id || field_str(&parsed, "operation")? != op {
        bail!("teald returned an unexpected mutation response");
    }
    let status = field_str(&parsed, "status")?;
    if status != "ok" && !(op == "retry" && status == "undelivered") {
        bail!("teald returned an unexpected NOTIFY mutation status");
    }
    let output = if raw_json {
        serde_json::to_string_pretty(&parsed)? + "\n"
    } else if op == "resolve" {
        format!("Notification {id} archived as resolved.\n")
    } else {
        let attempts = field_u64(&parsed, "attempts")?;
        let reason = printable(field_str(&parsed, "reason")?);
        let uncertain = parsed
            .get("delivery_uncertain")
            .and_then(Value::as_bool)
            .context("missing delivery_uncertain")?;
        format!(
            "Notification {id}: {reason} (attempts={attempts}, delivery_uncertain={uncertain})\n"
        )
    };
    if status == "undelivered" {
        bail!("{output}Manual retry exhausted; the notification remains UNDELIVERED");
    }
    Ok(output)
}

pub fn retry(id: &str, confirmed: bool, raw_json: bool) -> Result<()> {
    let command = mutation_command("retry", id, confirmed)?;
    let response = send_command(&command, false)?;
    print!(
        "{}",
        render_mutation_reply(&response, id, "retry", raw_json)?
    );
    Ok(())
}

pub fn resolve(id: &str, confirmed: bool, raw_json: bool) -> Result<()> {
    let command = mutation_command("resolve", id, confirmed)?;
    let response = send_command(&command, false)?;
    print!(
        "{}",
        render_mutation_reply(&response, id, "resolve", raw_json)?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn emits_server_compatible_commands() {
        assert_eq!(list_command(0, 50).unwrap(), "NOTIFY LIST 0 50");
        assert_eq!(list_command(50, 100).unwrap(), "NOTIFY LIST 50 100");
        assert_eq!(show_command("N-AI-001").unwrap(), "NOTIFY SHOW N-AI-001");
    }

    #[test]
    fn invalid_limits_and_unsafe_ids_fail_before_socket_access() {
        assert!(list_command(0, 0).is_err());
        assert!(list_command(0, 101).is_err());
        assert!(show_command("").is_err());
        assert!(show_command("N-1\nNOTIFY LIST").is_err());
        assert!(show_command("N 1").is_err());
        assert!(show_command(&"x".repeat(513)).is_err());
    }

    #[test]
    fn returns_errors_for_server_denial_and_bad_json() {
        assert!(parse_reply("ERR NOTIFY not permitted for this UID\n").is_err());
        assert!(
            parse_reply("ERR NOTIFY MPA is enabled but this command has no approval flow\n")
                .is_err()
        );
        assert!(parse_reply("not-json\n").is_err());
        assert!(parse_reply("{\"status\":\"error\"}\n").is_err());
        assert!(parse_reply("").is_err());
    }

    #[test]
    fn list_renders_pagination_and_supports_json() {
        let response = parse_reply(
            &json!({
                "status":"ok", "total":2, "offset":0, "limit":1, "has_more":true,
                "records":[{
                    "notification_id":"N-AI-001", "kind":"ai", "attempts":5,
                    "delivery_uncertain":true, "stored_at_ms":600000,
                    "reason":"RETRY_EXHAUSTED"
                }]
            })
            .to_string(),
        )
        .unwrap();
        let rendered = render_list(&response, false).unwrap();
        assert!(rendered.contains("N-AI-001"));
        assert!(rendered.contains("--offset 1"));
        assert!(rendered.contains("RETRY_EXHAUSTED"));
        assert_eq!(
            render_list(&response, true)
                .unwrap()
                .contains("\"records\""),
            true
        );
    }

    #[test]
    fn show_validates_returned_id_and_prints_original_record() {
        let response = parse_reply(
            &json!({
                "status": "ok",
                "record": {"job": {"request": {
                    "notification_id": "N-AI-001",
                    "payload": {"kind":"ai"}
                }}, "reason":"SMTP_TRANSPORT"}
            })
            .to_string(),
        )
        .unwrap();
        let rendered = render_show(&response, "N-AI-001", false).unwrap();
        assert!(rendered.contains("SMTP_TRANSPORT"));
        assert!(rendered.contains("\"payload\""));
        assert!(!rendered.contains("\"status\""));
        assert!(render_show(&response, "OTHER", true).is_err());
        assert!(render_show(&response, "N-AI-001", true)
            .unwrap()
            .contains("\"status\""));
    }

    #[test]
    fn terminal_control_chars_are_escaped_in_list() {
        assert_eq!(printable("warning\u{1b}[31m"), "warning\\u{1b}[31m");
    }
}

#[cfg(test)]
mod mutation_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn mutation_requires_explicit_confirmation() {
        assert!(mutation_command("retry", "N-1", false).is_err());
        assert!(mutation_command("resolve", "N-1", false).is_err());
        assert_eq!(
            mutation_command("retry", "N-1", true).unwrap(),
            "NOTIFY RETRY N-1"
        );
        assert_eq!(
            mutation_command("resolve", "N-1", true).unwrap(),
            "NOTIFY RESOLVE N-1"
        );
        assert!(mutation_command("retry", "N-1\nFLUSH", true).is_err());
    }
    #[test]
    fn mutation_checks_reply_id_and_operation() {
        let reply = json!({"status":"ok", "operation":"retry", "notification_id":"N-1",
            "attempts":1,"reason":"ACCEPTED_BY_SMTP","delivery_uncertain":false})
        .to_string();
        assert!(render_mutation_reply(&reply, "N-1", "retry", false)
            .unwrap()
            .contains("ACCEPTED_BY_SMTP"));
        assert!(render_mutation_reply(&reply, "N-2", "retry", false).is_err());
        assert!(render_mutation_reply(&reply, "N-1", "resolve", false).is_err());
        let failure = json!({"status":"undelivered", "operation":"retry", "notification_id":"N-1",
            "attempts":5,"reason":"MANUAL_RETRY_EXHAUSTED","delivery_uncertain":true})
        .to_string();
        assert!(render_mutation_reply(&failure, "N-1", "retry", false).is_err());
    }
}
