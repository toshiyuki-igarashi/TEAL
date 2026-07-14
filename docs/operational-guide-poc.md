# TEAL Operational Guide (PoC Edition)

This guide provides the minimum operational and verification procedures for **TEAL (Trusted Execution & Authorization Layer)**. Unlike traditional security mechanisms that focus on perimeter defense, TEAL introduces **Post-compromise Execution Governance**, demonstrating how the OS kernel can re-gate access to selected critical resources and enforce human-in-the-loop authorization even after user-space privilege escalation.

---

## 1. Introduction & Objectives

The primary objective of this Proof of Concept (PoC) release is to validate the core architectural ideas of TEAL and gather feedback from the systems programming and security engineering communities. 

### Target Audience
* **Security Engineers:** Evaluating post-exploitation mitigation, runtime integrity, and decentralized multi-party administrative governance.
* **Kernel Developers:** Interested in Linux Security Modules (LSM), Rust-in-the-kernel alternative paradigms, and kernel-space execution control.

### Scope of PoC
This document bypasses enterprise-grade identity federation configurations to focus strictly on a localized, deterministic verification workflow using native Linux UIDs mapped to custom administrative cryptographic roles.

#### Current PoC Coverage

The current PoC is primarily intended to demonstrate:

- file-open based read/write gating via LSM hooks
- exec gating via LSM hooks
- basic socket_connect interception
- teald-based policy decisions
- basic MPA / approval workflow
- Fast Path ticket cache and audit logging

The current PoC should not be interpreted as complete coverage for all destructive namespace operations. Operations such as unlink, rename, create, chmod, and chown require inode-level LSM hooks and are treated as planned or expanding coverage.

---

## 2. Environment Verification & Policy Structure

Before using this guide, **the TEAL kernel module, user-space daemon (`teald`), and management CLI utilities must be fully compiled and installed on your host system.** If you have not yet compiled the custom kernel or configured the baseline systemd units, please follow the comprehensive step-by-step documentation in the build deployment framework guide:

👉 **[TEAL System Build & Compilation Guide (build-teal-system.md)](./build-teal-system.md)**

Once you have successfully executed the system build setup and confirmed that the authorization daemon layer is fully running (`systemctl enable --now teald`), return here to begin live runtime policy deployment.

### 2.1 Configuration & Policy Directory Structure

TEAL processes access rules using a structured, multi-layered directory design initialized at `/etc/teal.d/`. Except for individual dynamic policy files inside the sub-directories, **all core file and directory names are strictly fixed**.

```text
/etc/teal.d/
├── bundle.json          # FIXED: Top-level entrypoint mapping active policy targets [schema v1.0]
├── management.json      # FIXED: Management Governance Policy (Governs teal-cli start/stop & MPA)
├── policies/            # FIXED: Target storage directory for granular policy rules
│   └── 00-base.json     # DYNAMIC: Arbitrary policy file specified inside bundle.json array [schema v1.3]
└── roles/               # FIXED: Target storage directory for system user roles mapping
    └── roles.json       # FIXED: Standard role assignments registry file [schema v1.0]

```

### Configuration Component Definitions

* **`bundle.json` (Fixed Name):** The foundational configuration loader validation profile. It specifies the schema version tracking metadata along with an array list of target JSON files stored within the `policies/` directory that must be dynamically interpreted and locked into the engine state.
* **`management.json` (Fixed Name):** **The Management Governance Policy.** This crucial file controls the execution authorization for administrative commands (`teal-cli start` and `teal-cli stop`). It explicitly defines which system UIDs map to administrative management roles, who can initiate state changes, and what Multi-Party Authorization (MPA) thresholds (e.g., specific approver roles and quorum size) are required to execute them.
* **`policies/` Directory:** Holds your granular runtime interception domain logic. Files here use arbitrary string names matching the schema constraints (e.g., `00-base.json`), specified by their direct names within the `bundle.json` targets tracking array.
* **`roles/roles.json` (Fixed Path & Name):** Defines administrative Subject-to-Role mappings, system assignment constraints, default roles for unmapped system entities, and fallback enforcement modes.

### 2.2 Administrator Identity Setup (Keygen & Registration)

Before switching the TEAL engine into enforcement mode, you must establish a cryptographic identity. All critical commands (including `start`, `stop`, and `approve`) require a BLS digital signature.

Before running `teal-cli`, verify that the `teald` daemon is running:

```bash
sudo systemctl status teald --no-pager
```

Optionally, follow the daemon logs in a separate terminal while performing the PoC workflow:

```bash
journalctl -u teald -f
```

1. **Generate your BLS key pair:**
```bash
   teal-cli keygen

```

*This generates a private key (`~/.teal/id_bls`) with strict `0600` permissions and a corresponding public key.*

2. **Register your identity with the daemon:**
```bash
teal-cli register

```


*This commands the daemon to register your public key, granting you the authority to issue engine control and approval commands.*

Once registered, you can confidently proceed to activate the enforcement barrier.


---

## 3. Core Breakthrough Demo Scenario: Protecting `/etc/shadow` Against Root Access

To experience the core value of TEAL—stopping root-level malicious actions until an explicit human authorization is granted—follow this step-by-step demonstration using the formal JSON structure and administrative governance rules.

### Step 1: Verification of Formatted Base Policy (`policies/00-base.json`)

Verify that your dynamic policy target file successfully conforms to the strict `policy_v1_3.schema.json` format initialized during the build phase. It specifies that any subject attempting to interact with `/etc/shadow` will be forced into a `need_approval` lock requiring 1 authorization ticket from a `security_officer` role:

```bash
cat /etc/teal.d/policies/00-base.json

```

### Step 2: Engage TEAL Engine Protection

Since `teald` is already running via systemd, instruct `teal-cli` to start active kernel-space interception based on the loaded configuration matrix:

```bash
sudo teal-cli start

```

### Step 3: Simulate the Attack (Root Exploitation)

Open a **secondary terminal** window. Switch to the root user (or use `sudo`) and attempt to read the protected file:

```bash
sudo cat /etc/shadow

```
Observed Behavior:
The command does not complete immediately. In the PoC configuration, the intercepted process is held by the kernel-side TEAL path until a decision is returned by `teald` or the request is denied/expired according to the configured policy.

Under the hood, the OS kernel has intercepted the file-open/read path via the TEAL LSM hook. Instead of immediately returning `EPERM` or allowing the read, TEAL holds the calling process in a kernel-side wait state until `teald` returns an allow/deny decision, or until the request is denied or expired according to the configured policy.

 **Note:** This PoC guide demonstrates the normal ENFORCE approval path. Fail-Safe behavior on daemon loss, strict cache invalidation, and full network lockdown are architecture-level behaviors and may depend on the current build configuration and implementation stage.

### Step 4: Human-in-the-Loop Authorization

Return to your **primary terminal**. Check the pending authorization queue using the standard tracking list matrix:

```bash
teal-cli list

```

*Output Example:*

```text
ID: 237 | PID: 87 | Target: /etc/shadow | Status: false | Reason: NEED APPROVAL by rule=rule-protect-shadow-file | MPA: 0/1 | Roles: {"security_officer"}

```

Approve the pending operation using the matched tracking ID token:

```bash
teal-cli approve 237

```

**Result:** The moment the command is entered, the frozen `cat` process in the secondary terminal instantly wakes up, executes successfully, and displays the contents of `/etc/shadow`.

---

### Step 5: Post-Compromise Resilience (Testing `teal-cli stop`)

Imagine an attacker has gained full root access and attempts to completely disable TEAL enforcement using standard administrative pathways:

```bash
sudo teal-cli stop

```

**Observed Behavior:** The command blocks and enters an asynchronous hold phase rather than stopping the daemon. Because `management.json` mandates Multi-Party Authorization for the `stop` command, the system forces a peer-review sequence. An administrator cannot turn off TEAL unilaterally without approval from a user belonging to the `security_officer` role (UID 1000).

---

## 4. Policy Configuration Reference (`00-base.json`)

TEAL uses a declarative JSON format inside `/etc/teal.d/policies/` to map out runtime access governance rules.

### Core Policy Parameters and System Types

| Parameter | Type | Allowed Values | Description |
| --- | --- | --- | --- |
| `version` | String | `"1.4"` (or compatible) | The policy format schema version. |
| `system_type` | String | `"server"`, `"workstation"` | Classifies the environment to enforce context-aware login route boundaries. See details below. |
| `default_effect` | String | `"allow"`, `"deny"`, `"need_approval"`, `"audit_only"` | Fallback enforcement action if no rule matches. |

### Key JSON Rule Attributes and Pragmatic Optimizations

| Parameter | Type | Allowed Values | Description |
| --- | --- | --- | --- |
| `rule_type` | String | `"standard"`, `"subject_only"` | Rule evaluation mode. `"subject_only"` skips target path lookup matching entirely. |
| `effect` | String | `"allow"`, `"deny"`, `"need_approval"`, `"audit_only"` | Action enforcement effect. |
| `ticket_profile.inherit` | Boolean | `true`, `false` | When set to `true`, authorization context propagates to child processes. Crucial for heavy workflows (e.g., `make -j`). |
| `ticket_profile.silent_io` | Boolean | `true`, `false` | When `true`, suppresses redundant I/O logging for temporary/nameless files to maximize performance. |

---

### Deep Dive: Login Context Enforcement by `system_type`

To prevent privilege escalation and block stealthy lateral movement, TEAL strictly inspects the structural origin of each login session (the `login_context` block inside the subject profile). 

This behavioral gating is dynamically controlled at the schema level by two critical boolean constraints inside the policy rules:
* `require_interactive_tty: true` — Ensures the process is strictly attached to an active, interactive terminal plane, entirely neutralizing legacy detached or headless execution vectors (e.g., hidden backdoors, unauthorized web-consoles).
* `bind_registered_session: true` — Binds process execution authorization directly to a verified, cryptographically registered session token authenticated during the primary entry point handshake.

When a controlled administrative or critical operation is triggered, the engine evaluates these criteria based on the active `system_type`:

1. **`server` Mode**
   Restricts administrative operations strictly to head-end or secured command-line environments. Authorized sessions must satisfy:
   * **Physical Console**: Direct physical tty access on the machine.
   * **OpenSSH Session**: Remote connections via OpenSSH Server where `auth_method` evaluates to trusted paths (`publickey`, `fido2`, etc.), enforcing `require_interactive_tty` and `bind_registered_session` to drop background injection attempts.

2. **`workstation` Mode**
   Enables a flexible local workstation layout designed for administrators managing systems with a graphical interface. Authorized sessions include:
   * **Physical Console** & **OpenSSH Session** (Evaluated under the same strict terminal/session binding as server mode).
   * **X11 / Wayland Virtual Terminals**: Interactive GUI terminal emulators spawning within a legitimately authorized desktop environment session.

> ⚠️ **Security Warning (Strict Rejection)**
> Any operation triggered from unmapped or unauthorized login channels (e.g., telnet sessions, automated legacy background tasks, or nested unverified pseudo-terminals) will be **strictly rejected** by default, as they fail to fulfill the mandatory `require_interactive_tty` or session-binding checks.
> 
> *Future Roadmaps:* This sub-attributes layout within the `login_context` schema is explicitly designed for high extensibility. Upcoming releases will natively expand the `auth_method` enum and integrate deeper validation pathways.

---

## 5. Optional: Policy Logical Verification (Alloy-based)

TEAL supports formal logical verification of your JSON policies using the Alloy Analyzer to detect rule conflicts, dead rules, or missing constraints before deploying them into enforcement mode.

### Prerequisites & Toolchain Setup
To use the verification command (`teal-cli verify`), you must have the Alloy toolchain component compiled and configured in your environment.

Please refer to the detailed toolchain construction steps in [System Build Guide](./build-teal-system.md#alloy-toolchain-installation) to download Alloy v6.2.0, generate the required JAR files, and export the `TEAL_ALLOY_JAR` path.

### Execution Example
Once the toolchain setup is verified, you can run the logical verification against your sample policy:

```bash
teal-cli verify examples/policies/00-base.json --goal examples/policies/goals.yaml
```

### Technical Caveats on Alloy-Based Policy Verification

While `teal-cli verify` provides mathematically rigorous logical verification via the Alloy Analyzer, users and security architects must be aware of the following boundary limitations inherent in the current Alpha/PoC translation implementation:

1. **Bounded Path Abstraction (Glob/Prefix Limitation):**
   Alloy operates as a bounded model checker based on a finite set of relational atoms. Dynamic string evaluations—such as `prefix:` and `glob:` matching used in the runtime `teald` daemon—are abstracted into static, explicit file/path objects during the Teal-IR translation phase. 
   Consequently, the SAT solver can only discover logical flaws and counter-examples involving **known paths** specified inside the target policy or goals. It cannot dynamically synthesize or evaluate an infinite combinations of arbitrary wildcard string manipulations.

2. **First-Match Ordering Semantics (Rule Shadowing):**
   The TEAL runtime daemon enforces policies based on a sequential, top-down execution order where the first matching rule dictates the decision (`Allow` / `Deny` / `Need_Approval`). 
   In the current PoC translation layer, if policies are generated as a flat collection of logical relations rather than a strict ordered sequence (`util/ordering`), complex "shadowing rules" (e.g., a loose Allow rule placed below a strict Deny rule) might lead to semantic discrepancies between the mathematical proof and the actual kernel enforcement.

**Recommendation for Architects:**
Formal verification via Alloy should be leveraged to detect **structural rule conflicts, unreachable configurations, and role-graph violations**, rather than relying on it as an absolute guarantee against runtime string-injection evasions.

---

## 6. Generating Policy Drafts from Audit Logs

TEAL can use audit logs to generate candidate policy rules. This is useful during PoC tuning because administrators can observe real system behavior first, then convert repeated or denied patterns into reviewable policy drafts.

A pragmatic workflow for creating policy rules is as follows:

1. Collect audit logs.
2. Generate candidate rules with `teal-logview profile`.
3. Review and minimize generated rules manually.
4. Run schema validation and dry-run checks.
5. Apply the reviewed rules through the normal MPA-protected policy update workflow.

Generated policies are drafts only. They must be reviewed, minimized, validated, and approved before being installed under `/etc/teal.d/policies/`.

```bash
# Generate allow-rule candidates from recent denied or unmanaged events
teal-logview profile --since 1h --target allow-draft --deny-only > policy-draft.json

# Generate anti-storm / silent_io candidates from frequent noisy events
teal-logview profile --since 1h --target anti-storm --threshold 1000 --optimize > anti-storm-draft.json

# Optimize / merge redundant rules in a generated draft
teal-logview optimize policy-draft.json --annotate-reason > policy-draft.optimized.json
```

For production use, generated rules should be treated as starting points for policy authoring, not as automatically trusted allow rules.

---

## 7. Appendix: Known Limitations (Alpha Version)

In alignment with technical transparency expected in open-source security projects, we outline the strict boundary limits of the current Alpha prototype:

1. **Kernel-Space Exploits:** TEAL currently runs as a code logic layer inside the active kernel. If an attacker leverages an exploit that grants arbitrary kernel write execution (e.g., physical memory manipulation or neutralizing LSM hooks), they can bypass TEAL's user-space verification loop. TEAL protects against *Privilege Abuse* (root misbehavior), not structural kernel destruction.
2. **Network Interception:** The network control plane (**TEAL-NET**) is planned for a future release; the current network system call interventions are not fully enforced in this PoC.

---

## 8. Troubleshooting Guide

If you encounter initialization barriers, use these diagnostic procedures to recover the environment:

### Issue 1: Kernel Compilation Version Mismatches

* **Symptom:** `make rustavailable` states toolchain components are missing or wrong version.
* **Solution:** Re-verify that your active pinned system configuration points exactly to Rust 1.74.1 and LLVM 17 compiler binaries. Do not attempt to upgrade or use different default Ubuntu packages.

### Issue 2: Service Verification Logging Diagnostics

To track the background operation logs generated via the user-space interface engine, run the tracking utilities:

```bash
# Check raw systemd operation logs
sudo systemctl status teald --no-pager
journalctl -u teald -f

# Read unified TEAL framework state transaction logs
teal-logview tail

```

