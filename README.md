# TEAL: Trusted Execution & Authorization Layer

TEAL is an experimental kernel-level security architecture designed for multi-party authorization and post-compromise access control.
It consists of a Linux Security Module (LSM) implemented in C and a user-space policy engine built with Rust.

## Project Status

TEAL is currently an Alpha / PoC implementation.

Implemented and evaluated:
- file-open based read/write gating via LSM hooks
- exec gating via LSM hooks
- basic connect gating prototype via LSM hooks
- teald policy decision daemon
- basic MPA / approval flow
- Fast Path ticket cache
- audit logging
- policy draft generation via `teal-logview`
- initial performance evaluation

Planned / expanding:
- full TEAL-NET outbound policy framework
- additional inode/path-level LSM hooks for destructive or namespace-changing operations, such as unlink, rename, create, chmod, and chown
- policy draft generation support for newly added operation types
- TPM / Measured Boot integration
- FIDO2 / Threshold BLS approvals
- Wasm policy engine

## Why TEAL?

TEAL is not an EDR, SIEM, or static MAC policy system.
It is a post-compromise execution governance layer.

TEAL introduces a human-gated execution barrier at the kernel level, designed to disrupt post-compromise attack chains by re-gating sensitive read, exec, write, and policy-changing actions at the OS execution point.

## Architecture

The project is structured to bridge the gap between kernel-level enforcement and modern, safe user-space logic:

- **kernel/**: LSM implementation for Linux kernel 6.8+.
- **src/teald**: The main daemon managing security policies (Rust/Tokio).
- **src/teal_policy_engine**: The core authorization logic.
- **alloy-cli**: Alloy-based helper for policy validation.

## Security Model

TEAL is designed to reduce the impact of post-compromise activity by re-gating sensitive actions at the OS execution point.
The current Alpha focuses mainly on file-open and exec gating. Additional destructive or namespace-changing operations are being expanded.

TEAL is intended to protect:
- sensitive file reads, such as credentials, secrets, database dumps, and policy files
- sensitive executions, including administrative tools and privileged maintenance operations
- destructive or namespace-changing file operations, currently being expanded beyond the initial file-open based coverage
- policy-changing actions that alter the TEAL security boundary

TEAL does not currently claim to protect against:
- arbitrary kernel code execution
- LSM hook tampering after a successful kernel exploit
- boot-chain compromise
- physical attacks
- network exfiltration control via TEAL-NET, which is still a roadmap item

For the detailed threat model and design rationale, see [TEAL_short_paper](./docs/TEAL_short_paper.md).

## Quick Start

TEAL currently requires a Linux kernel built with the TEAL LSM enabled. There is not yet a one-command installer, out-of-tree module package, or DKMS package.

For the full setup procedure, see:

- [build-teal-system](./docs/build-teal-system.md)

After completing the build guide, the basic PoC workflow is:

```bash
sudo systemctl start teald
teal-logview tail
teal-cli keygen
teal-cli register
teal-cli list
```

For operational examples, AUDIT / ENFORCE mode usage, approvals, and log inspection, see:

- [operational-guide-poc](./docs/operational-guide-poc.md)

## Policy Examples

Example policies are available under:

- `examples/policies/`

For policy syntax, rule semantics, approval behavior, and common patterns, see:

- [policy-examples](./docs/policy-examples.md)


## Performance

Initial performance evaluation suggests that TEAL can keep overhead low when Fast Path tickets, ticket inheritance, and `silent_io` are applied appropriately.

Kernel build workload:

| Mode | Run 1 (real) | Run 2 (real) | Notes |
| --- | ---: | ---: | --- |
| Baseline | 48m12s | 48m17s | TEAL disabled |
| Enforce Mode | 53m05s | 48m18s | Near-baseline result observed in the second run under Fast Path conditions |
| Audit Mode | 61m36s | 63m32s | Higher overhead due to audit log I/O |

Microbenchmark results also showed near-baseline median latency for Enforce Mode under the evaluated Fast Path workload.

The results should be interpreted as an initial indication of Fast Path viability, not as a general performance guarantee.
These are early Alpha results. Additional evaluation across hardware, workloads, policy complexity, and long-running systems is still needed.

See [performance_evaluation](./docs/performance_evaluation.md) for details.

## Limitations

TEAL is currently an Alpha / PoC implementation.
The goal of the current implementation is to validate the core mechanism: LSM hooks, user-space policy decision, approval flow, audit logging, and kernel Fast Path tickets.

Current limitations include:

- TEAL does not prevent arbitrary kernel code execution.
- If an attacker gains the ability to modify kernel memory or disable LSM hooks, the current Alpha implementation may be bypassed.
- TPM / Measured Boot integration is not yet implemented.
- TEAL-NET outbound control is planned but not yet fully implemented.
- FIDO2 / Threshold BLS approval is planned but not yet fully implemented.
- Some fields, such as multi-call binary hash and policy epoch, may still be provisional in the Alpha implementation.
- Formal methods are currently used as design and policy validation aids, not as a complete mathematical proof of the entire system.

For a detailed discussion of scope, threat model, and future work, see `docs/TEAL_short_paper.md`.


## Licensing

- Kernel-space components under `kernel/` are licensed under GPL-2.0-only.
- User-space Rust components under `src/` are dual-licensed under MIT OR GPL-2.0-only, unless otherwise noted.
- See `LICENSES/` for the full license texts.

## Patent Notice

A patent application related to TEAL has been filed by the inventor.

Use, modification, and distribution of this TEAL implementation are granted under the patent license described in `PATENTS.md`.

For non-Linux ports or separate commercial licensing, please contact the maintainer.
