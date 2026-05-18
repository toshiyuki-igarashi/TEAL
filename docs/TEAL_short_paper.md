# TEAL: Human-Gated Zero-Trust Execution Architecture

**— Post-Compromise Governance via Linux Execution Control: A Model for Structurally Breaking the Attack Chain —**

## Part 1: Overview and Background

### 1. Introduction: Why Do We Need Human-Gated Execution Now?

The primary focus of the Alpha implementation presented in this paper is execution control over the `file` and `exec` subsystems. Network outbound control (TEAL-NET) is treated as a future roadmap extension built upon the same underlying architecture.

#### 1.1 Evolution of the Attack Chain and the Vulnerability of "Internal Execution"

Targeted attacks and ransomware observed between 2025 and 2026 have progressed beyond exploiting a single bug; they now execute a highly stealthy sequence of steps: "Infiltration → Exfiltration/Read → Outbound Transmission → Destruction." In modern computing environments, it is physically impossible to eliminate all vulnerabilities across tens of millions of lines of code. We must operate under the assumption of "Assume Breach." Consequently, we face a critical question: how can we forcefully terminate post-exploitation activities not through mere detection, but directly at the enforcement points of `read`, `exec`, and `send`? In particular, the reality that post-infiltration `read()` and `send()` operations remain virtually unrestricted is driving an exponential surge in data exfiltration.

#### 1.2 Structural Risks of Root Privileges

The security mechanisms of Linux have made significant strides through the implementation of Capabilities, Namespaces, and mandatory access control (MAC) based on the Linux Security Module (LSM) framework. However, a successful privilege escalation still grants attackers extensive operational freedom within the compromised trust domain. The fundamental issue here is not merely the existence of "privileges," but rather that **a sequence of highly critical actions is concentrated within a single (compromised) execution context**. Once privileged execution rights are usurped, restricting subsequent data aggregation or destructive behavior in real-time is extremely difficult under existing architectural structures.

#### 1.3 Exponential Surge in Data Exfiltration Attacks

Recent ransomware strains have standardized a two-stage attack strategy: "exfiltrate data before encryption." The process spanning from file read operations to outbound transmission to Command and Control (C2) servers is highly optimized to evade existing EDR and log monitoring systems. Consequently, by the time an anomaly is detected, sensitive data has already been leaked externally.

#### 1.4 Objectives to Be Addressed

This whitepaper proposes an architectural model to structurally break the attack chain through the following approaches:

1. **Sensitive Data Read Operations (`read`)**: Establish a synchronous "STOP Barrier" that prevents unauthorized file reading without explicit human-in-the-loop authorization.
2. **Network Transmission (`send`)**: Implement the future network plane (TEAL-NET) to govern and intercept unapproved outbound traffic directly at the kernel level.
3. **Neutralizing Independent Root Privilege Abuse**: Enforce absolute denial of access to critical system resources unless the operation satisfies explicit Multi-Party Authorization (MPA) thresholds.
4. **Structural Disruption**: Insert strict, kernel-level enforcement points at the pivotal stages of the attack chain (`read`, `exec`, and `send`).

#### 1.5 Scope and Implementation Stage

The TEAL framework presented in this paper currently encompasses an Alpha-stage prototype alongside a comprehensive architectural proposal built upon it. Core orchestration mechanisms—including LSM hooks, the `teald` daemon, policy evaluation logic, basic Multi-Party Authorization (MPA) / approval flows, the Fast Path ticket cache, audit logging, and performance benchmarks—have been fully implemented and verified within this active Alpha codebase.

**Protected Resources:**
TEAL defines critical assets that remain inaccessible via a compromised root privilege alone. Anticipated target resources include:

* **System Secrets:** `/etc/shadow`, kernel modules, vital system binaries, and TEAL policy/configuration file-planes.
* **Authentication & Cryptographic Material:** SSH private keys, backup decryption keys, and production TLS certificates.
* **Application Infrastructure:** Database dumps, Kubernetes Secrets, production environment variables (`.env`), and master customer data directories.

**Threat Model:**
TEAL assumes an adversary capable of achieving local privilege escalation (from unprivileged user to root), reading sensitive files from compromised processes, executing unauthorized binaries, establishing arbitrary outbound network connections, and performing destructive actions. Conversely, attacks utilizing arbitrary kernel code execution, forced disabling of LSM hooks, boot chain alteration, or physical node access are classified as out-of-scope for the current Alpha implementation. These advanced vectors will be systematically addressed through roadmap extensions, including hardware-backed integrations such as TPM state binding and independent hardware watchdogs.

Meanwhile, advanced integrations—including TPM state binding, FIDO2 authentication, Threshold BLS signatures, the comprehensive implementation of TEAL-NET, a Wasm-based policy engine, and automated policy synthesis—are categorized as future roadmap items designated for further architectural hardening.

| Component / Layer | Scope in Alpha Prototype |
| --- | --- |
| `file` / `exec` LSM hooks | Fully Implemented & Evaluated |
| `teald` / policy decision logic | Fully Implemented & Evaluated |
| MPA / approval workflow | Core Mechanics Implemented |
| Fast Path ticket cache | Implemented & Performance Benchmarked |
| Audit logging | Baseline Implementation Verified |
| TEAL-NET | Planned Roadmap Item |
| TPM / Measured Boot | Planned Roadmap Item |
| FIDO2 / Threshold BLS | Planned Roadmap Item |
| Wasm policy engine | Planned Roadmap Item |

It is critical to note that Human-Gated Execution is not designed to naively demand manual human approval for every consecutive `read`, `exec`, or `write` system call. During nominal operations, the architecture issues short-lived authorization tickets for validated subject-object-operation tuples, processing them with near-zero overhead via the in-kernel Fast Path mechanism. Active human-in-the-loop intervention is strictly restricted to vectors explicitly designated as high-risk, such as anomalous access to protected resources, alterations to privilege boundaries, runtime policy synchronization, or destructive system actions.

### 2. Threat Model and the Reality of the Attack Chain

#### 2.1 Attack Structure Mapping to MITRE ATT&CK

While a standard attack lifecycle spans from Initial Access all the way to Impact, the most critical junctions reside in the final three steps: **Collection ➔ Exfiltration ➔ Impact**. TEAL focuses its architectural enforcement explicitly on severing this "Actions on Objectives" phase.

#### 2.2 Positioning as a Post-LPE Mitigation: A CVE Case Study

As demonstrated by recent Linux Local Privilege Escalation (LPE) exploits, vulnerabilities that allow transitions from unprivileged user access to elevated privileges continue to emerge invariably. CVE-2026-31431 ("Copy Fail") serves as a prime example. The core thesis of TEAL is not to preemptively block this class of LPE vulnerabilities themselves. Rather, its objective is to establish a secondary gating architecture within the OS execution control layer, intercepting the subsequent, high-impact actions an adversary attempts post-LPE—such as reading sensitive files, tampering with system configurations, establishing outbound data transmissions, or executing destructive operations.

#### 2.3 Limitations of Contemporary Tooling

* **EDR (Endpoint Detection and Response)**: While highly proficient in threat detection and post-incident response, EDR possesses inherent structural limitations when tasked with synchronously intercepting and halting `read` or `send` primitives initiated by a compromised process directly at the critical point of OS execution.
* **SASE / IAM**: Though effective for perimeter enforcement, identity governance, and macro-level access authorization, these frameworks are completely decoupled from internal operating system mechanics. They do not provide a mechanism to intercept or govern intra-OS process activity at the kernel enforcement point to dictate which resources an active process can read or which system actions it can execute.

### 3. Limitations of Conventional Security Mechanisms

#### 3.1 Limitations of Detection-Centric Security

Since Endpoint Detection and Response (EDR) relies heavily on dynamic behavioral detection, its architecture inherently tends to generate reactive alerts *after* a system compromise or damage has already occurred. Furthermore, when dealing with a process that has already achieved local privilege escalation, there remains a severe structural risk that the adversary will entirely evade or neutralize the monitoring mechanism itself.

#### 3.2 Architectural Constraints of eBPF (LSM-BPF)

TEAL demands a tightly integrated architecture capable of handling long-duration synchronous process suspension, managing state for pending approvals, maintaining a ticket cache, and enforcing fail-safe control logic as a unified system. For these reasons, the current prototype bypasses eBPF/LSM-BPF in favor of a Loadable Kernel Module (LKM)-based LSM implementation.

The primary objective is to suspend a process while preserving the exact pre-execution context captured by the kernel, and then resume it within that identical context post-approval. This mechanism inherently minimizes the window for race conditions where the evaluated target could be substituted prior to execution (Time-of-Check to Time-of-Use: TOCTOU vulnerabilities). This design choice does not negate the immense utility of eBPF; rather, it represents an architectural decision dictated by the unique prerequisites of Human-Gated Execution.

While the Alpha implementation adopts an LKM approach to maximize verifiability and ease of validation, production deployment strategies and future upstream kernel discussions will actively consider integration as a built-in LSM, compatibility with existing LSM stacking configurations, and minimizing the overall LSM hook footprint.

