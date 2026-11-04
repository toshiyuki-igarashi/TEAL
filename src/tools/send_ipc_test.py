#!/usr/bin/env python3
"""Send one Phase 1 notification through the systemd-managed Unix socket.

This sends REAL SMTP mail through teal-mailer. Only use a test address.
Use `sudo` if teal-mailer.socket has SocketMode=0600 and root ownership.
"""
import argparse
import json
import socket
import struct
import uuid

SOCKET = "/run/teal/teal-notify.sock"  # teal_common::TEAL_NOTIFY_SOCKET_PATH
MAX_FRAME = 64 * 1024


def recv_all(sock: socket.socket, n: int) -> bytes:
    chunks = []
    while n:
        chunk = sock.recv(n)
        if not chunk:
            raise EOFError("teal-mailer closed before sending a complete response")
        chunks.append(chunk)
        n -= len(chunk)
    return b"".join(chunks)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipient", required=True, help="test mailbox (real SMTP delivery)")
    parser.add_argument("--kind", choices=["deny", "ai"], default="deny")
    parser.add_argument("--socket", default=SOCKET)
    args = parser.parse_args()

    payload = (
        {
            "hostname": "phase1-test-host",
            "uid": 0,
            "pid": None,
            "program": "/usr/bin/true",
            "action": "EXEC",
            "rule_id": "phase1-test-rule",
            "policy_epoch": 1,
            "target_parent": "/usr/bin",
            "target_samples": ["/usr/bin/true"],
            "count": 1,
            "first_seen": "2026-11-04T00:00:00Z",
            "last_seen": "2026-11-04T00:00:00Z",
            "representative_event_id": "PHASE1-TEST-EVENT",
            "early_flush": False,
        }
        if args.kind == "deny"
        else {
            "hostname": "phase1-test-host",
            "confidence": 0.99,
            "reason": "Phase 1 IPC / SMTP integration test only",
            "related_event_ids": ["PHASE1-TEST-EVENT"],
            "program": "/usr/bin/true",
            "action": "EXEC",
            "target": "/usr/bin/true",
        }
    )
    request = {
        "version": 1,
        "notification_id": f"PHASE1-{uuid.uuid4()}",
        "recipients": [args.recipient],
        "payload": {"kind": args.kind, "data": payload},
    }
    body = json.dumps(request, ensure_ascii=False).encode("utf-8")
    if not body or len(body) > MAX_FRAME:
        raise ValueError("test request exceeds IPC maximum")

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(55)
        conn.connect(args.socket)
        conn.sendall(struct.pack(">I", len(body)) + body)
        size = struct.unpack(">I", recv_all(conn, 4))[0]
        if not 0 < size <= MAX_FRAME:
            raise ValueError("invalid response length")
        response = json.loads(recv_all(conn, size))
        print(json.dumps(response, indent=2, ensure_ascii=False))
        if response.get("status") != "AcceptedBySmtp":
            raise SystemExit(1)


if __name__ == "__main__":
    main()
