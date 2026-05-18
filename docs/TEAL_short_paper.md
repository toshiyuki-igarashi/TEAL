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

