# TEAL Operational Guide (PoC Edition)

This guide provides the minimum operational and verification procedures for **TEAL (Trusted Execution & Authorization Layer)**. Unlike traditional security mechanisms that focus on perimeter defense, TEAL introduces **Post-compromise Execution Governance**, demonstrating how the OS kernel can physically protect critical resources and enforce human-in-the-loop authorization even after root privileges have been entirely compromised.

---

## 1. Introduction & Objectives

The primary objective of this Proof of Concept (PoC) release is to validate the core architectural ideas of TEAL and gather feedback from the systems programming and security engineering communities. 

### Target Audience
* **Security Engineers:** Evaluating post-exploitation mitigation, runtime integrity, and decentralized multi-party administrative governance.
* **Kernel Developers:** Interested in Linux Security Modules (LSM), Rust-in-the-kernel alternative paradigms, and kernel-space execution control.

### Scope of PoC
This document bypasses enterprise-grade identity federation configurations to focus strictly on a localized, deterministic verification workflow using native Linux UIDs mapped to custom administrative cryptographic roles.

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

**Observed Behavior:** The command does not execute immediately, and the terminal completely freezes/hangs.

Under the hood, the OS kernel has intercepted the read system call via the TEAL LSM hook. Instead of returning `EPERM` or allowing the read, TEAL has transitioned the calling process into a `TASK_INTERRUPTIBLE` sleep state inside the kernel scheduler, waiting indefinitely for an external authorization ticket.

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

### Key JSON Rule Attributes and Pragmatic Optimizations

| Parameter | Type | Allowed Values | Description |
| --- | --- | --- | --- |
| `rule_type` | String | `"standard"`, `"subject_only"` | Rule evaluation mode. `"subject_only"` skips target path lookup matching entirely. |
| `effect` | String | `"allow"`, `"deny"`, `"need_approval"`, `"audit_only"` | Action enforcement effect. |
| `ticket_profile.inherit` | Boolean | `true`, `false` | When set to `true`, authorization context propagates to child processes. Crucial for heavy workflows (e.g., `make -j`). |
| `ticket_profile.silent_io` | Boolean | `true`, `false` | When `true`, suppresses redundant I/O logging for temporary/nameless files to maximize performance. |

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

---

## 6. Appendix: Known Limitations (Alpha Version)

In alignment with technical transparency expected in open-source security projects, we outline the strict boundary limits of the current Alpha prototype:

1. **Kernel-Space Exploits:** TEAL currently runs as a code logic layer inside the active kernel. If an attacker leverages an exploit that grants arbitrary kernel write execution (e.g., physical memory manipulation or neutralizing LSM hooks), they can bypass TEAL's user-space verification loop. TEAL protects against *Privilege Abuse* (root misbehavior), not structural kernel destruction.
2. **Network Interception:** The network control plane (**TEAL-NET**) is planned for a future release; the current network system call interventions are not fully enforced in this PoC.

---

## 7. Troubleshooting Guide

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

```

