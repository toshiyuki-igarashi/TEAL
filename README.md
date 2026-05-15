# TEAL: Trusted Execution & Authorization Layer

TEAL is an experimental kernel-level security architecture designed for multi-party authorization and post-compromise access control.
It consists of a Linux Security Module (LSM) implemented in C and a user-space policy engine built with Rust.

## Project Status

TEAL is currently an Alpha / PoC implementation.

Implemented and evaluated:
- file / exec LSM hooks
- teald policy decision daemon
- basic MPA / approval flow
- Fast Path ticket cache
- audit logging
- initial performance evaluation

Roadmap:
- TEAL-NET outbound control
- TPM / Measured Boot integration
- FIDO2 / Threshold BLS approval
- Wasm policy engine
- automated policy generation

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

TEAL is intended to protect:
- sensitive file reads, such as credentials, secrets, database dumps, and policy files
- sensitive executions, including administrative tools and privileged maintenance operations
- destructive file operations, such as write, unlink, rename, and truncate
- policy-changing actions that alter the TEAL security boundary

TEAL does not currently claim to protect against:
- arbitrary kernel code execution
- LSM hook tampering after a successful kernel exploit
- boot-chain compromise
- physical attacks
- network exfiltration control via TEAL-NET, which is still a roadmap item

For the detailed threat model and design rationale, see `docs/TEAL_short_paper.md`.

## Quick Start

TEAL currently requires building a Linux kernel with the TEAL LSM enabled.
There is not yet a one-command installer or DKMS package.

For now, the recommended path is:

1. Prepare an Ubuntu 24.04 LTS environment.
2. Build Linux 6.8.x with Rust support and the TEAL LSM enabled.
3. Build the TEAL user-space tools with Cargo.
4. Install and start `teald`.
5. Load a sample policy and verify audit/enforce behavior.

See `docs/build-teal-system.md` for the full build procedure.

## Build from Source

Detailed build instructions are available in:

- `docs/build-teal-system.md`

The current Alpha build has been verified with:

- Ubuntu 24.04 LTS
- Linux 6.8.x
- LLVM 17
- Rust 1.74.1, matching the Linux kernel Rust toolchain requirements

TEAL is currently developed outside the upstream Linux kernel tree, but it is built as an in-tree LSM.
The current Alpha build requires copying the TEAL LSM sources into a Linux kernel source tree, registering them with Kconfig/Kbuild, and rebuilding the kernel.
Out-of-tree module builds and DKMS packaging are not yet supported.

## Usage

Start the TEAL daemon:

```bash
sudo systemctl start teald
```

Check logs:

```bash
teal-logview tail
```

Use the CLI to inspect pending requests or approvals:

```bash
teal-cli list
teal-cli approve <REQUEST_ID>
teal-cli deny <REQUEST_ID>
```

TEAL supports both AUDIT and ENFORCE modes.
In AUDIT mode, TEAL records policy-relevant events without blocking them.
In ENFORCE mode, TEAL applies policy decisions and may block sensitive operations unless they are covered by an approved Fast Path ticket.


## Policy Example

Example policy rule requiring approval for reading `/etc/shadow`:

```json
{
  "version": "1.3",
  "default_effect": "allow",
  "ttl_minutes": 10,
  "sweep_minutes": 1,
  "rules": [
    {
      "id": "protect-etc-shadow",
      "subject": {
        "roles": ["admin"]
      },
      "object": {
        "path": "exact:/etc/shadow"
      },
      "action": {
        "ops": ["read"]
      },
      "effect": "need_approval",
      "required_roles": ["security_admin"],
      "threshold": 1,
      "reason": "Reading /etc/shadow requires explicit approval."
    }
  ]
}
```

More examples are available under `examples/policies/`.

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

See `docs/TEAL-performance-evaluation.md` for details.

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
