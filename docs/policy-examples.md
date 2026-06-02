# TEAL Policy Examples

This document explains the example policy files included in this repository.

The examples are intended for Alpha / PoC evaluation. They are designed to show how TEAL policies are structured, how policy fragments are grouped, how roles are assigned, and how management operations such as START / STOP are controlled.

They are not production hardening profiles. Review every rule before using them on a real system.

> [!IMPORTANT]
> **Configuration Identity Notice:** 
> The example configurations provided below are pre-configured specifically for the environment of **`uid: 1000` / `user: toshiyuki`**. Please modify these identity mappings, UIDs, and username fields to match your specific target deployment system environment and organizational control requirements before initiating enforcement.

## Directory layout

Example policy files are stored under:

```text
examples/
├── bundle.json
├── management.json
├── roles/
│   └── roles.json
└── policies/
    ├── 00-base.json
    ├── 01-ubuntu.json
    └── 02-ubuntu.json
```

Each file has a different responsibility:

| File               | Purpose                                                                    |
| ------------------ | -------------------------------------------------------------------------- |
| `bundle.json`      | Defines which policy fragments are included in a policy bundle             |
| `roles.json`       | Defines TEAL roles and assigns them to users or groups                     |
| `management.json`  | Defines who can start or stop TEAL enforcement and whether MPA is required |
| `00-base.json`     | Minimal base policy, including protection for `/etc/shadow`                |
| `01-ubuntu.json`   | xubuntu baseline / noise-control policy to reduce log storms               |
| `02-ubuntu.json`   | Allow rules for reviewed xubuntu behavior surfaced by the baseline policy  |

## Policy bundle: `bundle.json`

`bundle.json` defines the set of policy files that should be loaded together.

It is intentionally small. Its purpose is to make policy composition explicit and reviewable.

Example:

```json
{
  "schema_version": "1.0",
  "name": "-poc",
  "policy_files": [
    "00-base.json",
    "01-.json",
    "02-.json"
  ]
}
```

### Fields

| Field            | Required | Meaning                                                   |
| ---------------- | -------- | --------------------------------------------------------- |
| `schema_version` | yes      | Bundle schema version. Currently `"1.0"`                  |
| `name`           | no       | Human-readable bundle name                                |
| `policy_files`   | yes      | Ordered list of policy JSON files included in this bundle |

`policy_files` should contain policy file names such as `00-base.json`, not arbitrary paths.

Recommended ordering:

```text
00-base.json
01-ubuntu.json
02-ubuntu.json
local-site-rules.json
```

The order should be chosen so that broad base behavior is defined first, followed by OS baseline rules and local site-specific rules.

## Role assignments: `roles/roles.json`

`roles/roles.json` defines TEAL roles and maps users or groups to those roles.

Regular policy rules can refer to roles in two places:

```json
"subject": {
  "roles": ["admin"]
}
```

and:

```json
"required_roles": ["security_officer"]
```

This allows policy rules to express intent such as:

* an `admin` may initiate a sensitive operation
* a `security_officer` must approve it
* unknown users should receive no roles or be denied

Example:

```json
{
  "schema_version": "1.0",
  "roles": [
    {
      "name": "admin",
      "description": "System administrator role",
      "tags": ["operations"],
      "permissions": ["policy:initiate"]
    },
    {
      "name": "security_officer",
      "description": "Approver role for sensitive operations",
      "tags": ["security"],
      "permissions": ["approval:grant"]
    }
  ],
  "assignments": [
    {
      "user": "alice",
      "roles": ["admin"]
    },
    {
      "uid": 1001,
      "roles": ["security_officer"]
    }
  ],
  "group_assignments": [
    {
      "group": "sudo",
      "roles": ["admin"]
    }
  ],
  "defaults": {
    "roles_for_unknown_user": [],
    "deny_if_role_unknown": true
  }
}
```

### Fields

| Field               | Required | Meaning                                          |
| ------------------- | -------- | ------------------------------------------------ |
| `schema_version`    | yes      | Roles schema version. Currently `"1.0"`          |
| `roles`             | yes      | Role definitions                                 |
| `assignments`       | yes      | User or UID based role assignments               |
| `group_assignments` | yes      | Group or GID based role assignments              |
| `defaults`          | yes      | Behavior for users without explicit role mapping |

### Role definitions

Each role requires a `name`.

Optional fields include:

| Field         | Meaning                                                         |
| ------------- | --------------------------------------------------------------- |
| `description` | Human-readable role description                                 |
| `tags`        | Optional labels for classification                              |
| `permissions` | Optional permission labels used by tooling or future extensions |

### User assignments

A user assignment must specify `roles` and either `uid` or `user`.

Examples:

```json
{
  "uid": 1000,
  "roles": ["admin"]
}
```

```json
{
  "user": "alice",
  "roles": ["security_officer"]
}
```

### Group assignments

A group assignment must specify `roles` and either `gid` or `group`.

Examples:

```json
{
  "gid": 27,
  "roles": ["admin"]
}
```

```json
{
  "group": "sudo",
  "roles": ["admin"]
}
```

### Defaults

`defaults` controls how TEAL behaves when a user has no known role mapping.

Recommended conservative default:

```json
{
  "roles_for_unknown_user": [],
  "deny_if_role_unknown": true
}
```

This avoids accidentally granting broad access to unknown users.

## Management policy: `management.json`

`management.json` controls TEAL management operations.

This is separate from ordinary access policies. It is used for actions that affect the TEAL security boundary itself, such as starting or stopping enforcement.

Example:

```json
{
  "roles": [
    {
      "name": "teal_operator",
      "uids": [1000],
      "description": "Users allowed to initiate TEAL management actions"
    },
    {
      "name": "teal_security",
      "uids": [1001, 1002],
      "description": "Users allowed to approve TEAL management actions"
    }
  ],
  "controls": {
    "start": {
      "description": "Start TEAL enforcement",
      "initiator_roles": ["teal_operator"],
      "mpa": {
        "enabled": true,
        "threshold": 1,
        "approver_roles": ["teal_security"],
        "timeout_minutes": 30
      }
    },
    "stop": {
      "description": "Stop TEAL enforcement",
      "initiator_roles": ["teal_operator"],
      "mpa": {
        "enabled": true,
        "threshold": 2,
        "approver_roles": ["teal_security"],
        "timeout_minutes": 10
      }
    }
  }
}
```

### Top-level fields

| Field      | Required | Meaning                                           |
| ---------- | -------- | ------------------------------------------------- |
| `roles`    | yes      | Management-specific roles mapped directly to UIDs |
| `controls` | yes      | Management controls such as `start` and `stop`    |

### Management roles

Management roles are intentionally simple.

Each role requires:

| Field  | Meaning                           |
| ------ | --------------------------------- |
| `name` | Management role name              |
| `uids` | List of UIDs assigned to the role |

Optional:

| Field         | Meaning                    |
| ------------- | -------------------------- |
| `description` | Human-readable explanation |

Management roles are separate from `roles/roles.json`. This keeps TEAL control-plane authorization independent from ordinary data-plane access policy.

### Controls

The current management schema requires both:

```text
start
stop
```

Each control defines:

| Field             | Required | Meaning                                         |
| ----------------- | -------- | ----------------------------------------------- |
| `description`     | no       | Human-readable explanation                      |
| `initiator_roles` | yes      | Roles allowed to initiate the management action |
| `mpa`             | yes      | MPA requirement for the action                  |

### MPA behavior

`mpa.enabled` controls whether multi-party approval is required.

If MPA is disabled:

```json
"mpa": {
  "enabled": false
}
```

If MPA is enabled, the following fields are required:

```json
"mpa": {
  "enabled": true,
  "threshold": 2,
  "approver_roles": ["teal_security"],
  "timeout_minutes": 10
}
```

| Field             | Meaning                            |
| ----------------- | ---------------------------------- |
| `threshold`       | Number of approvals required       |
| `approver_roles`  | Roles that may approve the action  |
| `timeout_minutes` | Time limit for completing approval |

In general, `stop` should require at least as much scrutiny as `start`, because stopping enforcement changes the active security boundary.

## Regular policy files

Regular policy files use schema version `1.3`.

A minimal policy file has:

```json
{
  "version": "1.3",
  "ttl_minutes": 60,
  "sweep_minutes": 5,
  "rules": []
}
```

Optional top-level fields include:

```json
{
  "default_effect": "allow",
  "default_reason": "No matching rule.",
  "pre_approval_defaults": {
    "ttl_sec_default": 600,
    "ttl_sec_max": 900
  }
}
```

### Rule basics

A standard rule generally binds:

```text
subject + object + action -> effect
```

Example:

```json
{
  "id": "protect-etc-shadow",
  "subject": {
    "roles": ["admin"]
  },
  "object": {
    "path": "/etc/shadow"
  },
  "action": {
    "ops": ["read"]
  },
  "effect": "need_approval",
  "required_roles": ["security_officer"],
  "threshold": 1,
  "reason": "Reading /etc/shadow requires explicit approval."
}
```

Supported effects:

| Effect          | Meaning                               |
| --------------- | ------------------------------------- |
| `allow`         | Allow the operation                   |
| `deny`          | Deny the operation                    |
| `need_approval` | Route the operation through approval  |
| `audit_only`    | Record the operation without blocking |

When `effect` is `need_approval`, the rule must also define:

```json
{
  "required_roles": ["security_officer"],
  "threshold": 1
}
```

## Example: `00-base.json`

`00-base.json` is the minimal base policy.

It demonstrates how to protect a critical file such as `/etc/shadow`.

Typical purpose:

* define a small protected resource
* require explicit approval before access
* demonstrate `need_approval`
* demonstrate `required_roles` and `threshold`
* provide a simple first test for AUDIT and ENFORCE behavior

Example scenario:

```text
A process attempts to read /etc/shadow
        ↓
TEAL LSM hook captures the access
        ↓
teald evaluates the policy
        ↓
approval is required
        ↓
access is allowed or denied according to MPA result
```

Use this file first when verifying that the basic TEAL approval path works.

## Example: `01-ubuntu.json`

`01-ubuntu.json` is an xubuntu baseline / noise-control policy.

A normal xubuntu system generates many file, process, and IPC-related events during boot and normal operation. Without baseline rules, the system may produce excessive logs or approval candidates that are not security-relevant.

Typical purpose:

* reduce log storm during normal xubuntu startup
* suppress low-value high-frequency events
* define trusted system process behavior
* demonstrate `audit_level`
* demonstrate Fast Path caching with `ttl_sec`
* demonstrate process-level ticket profiles such as `silent_io` and `inherit`

This file should not be understood as a complete security boundary by itself. Its primary role is operational: to keep the PoC usable by reducing unnecessary noise from routine system behavior.

Use this file when evaluating TEAL on an xubuntu host or VM and you want a stable baseline before adding stricter protection rules.

## Example: `02-ubuntu.json`

`02-ubuntu.json` complements `01-ubuntu.json`.

Where `01-ubuntu.json` reduces noise and identifies baseline xubuntu behavior, `02-ubuntu.json` demonstrates reviewed allow rules for resources or operations that become visible after applying the baseline policy.

Typical purpose:

* allow known-good accesses observed during AUDIT mode
* demonstrate how to convert observed behavior into explicit policy rules
* show how `teal-logview` generated drafts can be reviewed and converted into policy entries
* provide examples of controlled allow rules with Fast Path caching

A typical workflow is:

```text
1. Start from 00-base.json.
2. Add 01-ubuntu.json to reduce startup/runtime noise.
3. Observe remaining policy-relevant events.
4. Review logs with teal-logview.
5. Convert reviewed events into 02-ubuntu.json allow rules.
6. Move selected high-risk rules to need_approval where appropriate.
```

## Subject-only rules

Some high-frequency system behavior is better described by subject context rather than by object path.

A `subject_only` rule skips object path matching.

This is useful for trusted processes that generate many temporary files, pipes, sockets, or nameless IPC objects.

Example:

```json
{
  "rule_type": "subject_only",
  "id": "trusted-build-tool-silent-io",
  "subject": {
    "origin_program": "/usr/bin/make"
  },
  "action": {
    "ops": ["read", "write"]
  },
  "effect": "allow",
  "audit_level": "silent",
  "ttl_sec": 3600,
  "ticket_profile": {
    "silent_io": true,
    "inherit": true
  },
  "reason": "Allow trusted build process tree to avoid high-volume temporary I/O logging."
}
```

Use this carefully.

Subject-only rules are powerful because they reduce overhead and log volume, but they should be limited to well-understood trusted processes.

## Fast Path and audit behavior

Rules can control Fast Path caching and audit behavior.

Important fields include:

```json
{
  "audit_level": "standard",
  "ttl_sec": 600,
  "max_uses": 1
}
```

General guidance:

| Field                   | Meaning                                               |
| ----------------------- | ----------------------------------------------------- |
| `ttl_sec: 0`            | Do not cache; evaluate through Slow Path              |
| `ttl_sec > 0`           | Allow Fast Path caching for the specified duration    |
| `max_uses`              | Maximum number of times the ticket can be used        |
| `audit_level: standard` | Normal audit behavior                                 |
| `audit_level: silent`   | Reduce log volume for high-frequency trusted behavior |
| `audit_level: strict`   | Prefer stronger audit behavior                        |

Use short TTLs for sensitive resources and longer TTLs only for well-understood, trusted, repetitive workloads.

## Pre-approval rules

A rule may support pre-approval:

```json
{
  "pre_approval": {
    "enabled": true
  }
}
```

Pre-approval is intended for cases where an operation should be approved before execution and then consumed later through a Fast Path ticket.

When pre-approval is enabled, the rule must use `effect: need_approval`.

The subject should also be specific enough to avoid ambiguous tickets. In practice, include at least a UID, user, or role, together with `origin_program`.

Example:

```json
{
  "id": "preapprove-maintenance-tool",
  "subject": {
    "uid": 1000,
    "origin_program": "/usr/bin/example-tool"
  },
  "object": {
    "path": "/var/lib/example/maintenance.dat"
  },
  "action": {
    "ops": ["read"]
  },
  "effect": "need_approval",
  "required_roles": ["security_officer"],
  "threshold": 1,
  "pre_approval": {
    "enabled": true
  },
  "reason": "Pre-approve a planned maintenance read."
}
```

Use pre-approval for planned maintenance tasks, backup operations, or other actions where human approval can happen before execution.

## Suggested PoC evaluation workflow

For a fresh PoC environment:

```text
1. Build and boot the TEAL-enabled kernel.
2. Start teald.
3. Prepare roles/roles.json.
4. Prepare management.json.
5. Prepare bundle.json.
6. Start with 00-base.json.
7. Confirm that /etc/shadow access is intercepted.
8. Add 01-ubuntu.json if normal system activity creates excessive logs.
9. Review logs with teal-logview.
10. Convert reviewed events into 02-ubuntu.json allow rules.
11. Move selected high-risk rules to need_approval.
12. Test AUDIT mode first.
13. Test ENFORCE mode only after reviewing the policy.
```

## Safety notes

These examples are not production hardening profiles.

Before applying them to a real system:

* review every `allow` rule
* keep `subject_only` rules narrow
* avoid broad rules for shells or interpreters
* use short TTLs for sensitive operations
* prefer `need_approval` for security boundary changes
* test in AUDIT mode before ENFORCE mode
* keep `management.json` stricter than ordinary access policy
* avoid assigning management roles to broad UID sets
* keep `deny_if_role_unknown: true` unless there is a clear reason not to

The examples are meant to explain TEAL policy mechanics, not to provide a complete secure xubuntu policy.

