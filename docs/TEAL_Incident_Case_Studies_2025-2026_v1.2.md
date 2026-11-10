# Post-Compromise Execution Control: Case Studies of Recent Cyber Incidents

## Implications for TEAL (Trusted Execution & Authorization Layer)

**Technical case-study report | Version 1.2 | 8 November 2026**  
**Review period:** 7 November 2025–7 November 2026  
**Scope:** Incident evidence, plausible attack paths, TEAL applicability, and practical validation scenarios

> **Important interpretation rule.** This report distinguishes **reported facts**, **technical inferences**, and **hypothetical TEAL defenses**. It does not claim that TEAL was installed at any affected organization or that the proposed controls would certainly have stopped the actual attacks. For incidents involving Windows products or appliances, the defense discussion expressly assumes an **equivalent Linux-based implementation** with comparable management capabilities. The actual products' architectures are not silently replaced by Linux in the factual incident descriptions.

## Executive summary

Recent attacks highlight three materially different forms of post-compromise activity:

1. **Untrusted operating-system execution:** the adversary executes additional commands, modifies files, or runs malicious code after gaining a foothold. TEAL's file/execute policy engine and basic multi-party authorization (MPA) can potentially intervene at these execution points.
2. **Misuse of legitimate administrative authority:** the adversary reaches a management plane and invokes genuine capabilities—such as virtual-machine deletion, endpoint wipe, or software distribution. TEAL can help when the dangerous operation is performed by a dedicated, infrequently invoked Linux executable; an already-running management daemon or remote API usually requires additional controls at the operation boundary.
3. **Misuse of business transactions:** the adversary issues instructions that are technically legitimate from the operating system's perspective, such as a bank transfer. The final gate must usually be the application's independent business-authorization layer, not a generic file/exec policy.

**Principal finding:** the optimal enforcement point depends on **how management software is used**. An occasional destructive utility is a strong candidate for TEAL-enforced `EXEC` plus MPA. A scheduled maintenance utility can additionally be restricted by identity, time window, and trusted launch context. For a continuously running management service, startup authorization is insufficient: the actual destructive operation must be separately authorized. This distinction is especially important in the Beget and Stryker incidents.

**Planned login-provenance baseline:** the next TEAL revision is assumed to implement a kernel-protected, authentication-bound session origin without trusting user environment variables. This is a committed design requirement, not a feature already shown to work in Alpha (sections 6.4–6.5).

**Kernel-boundary extension:** section 8 distinguishes the Alpha kernel trust assumption from proposed verified/measured boot, TPM-backed remote evidence, independent watchdog monitoring, externally enforced quarantine, and trusted recovery. These are planned complementary measures, not proven defenses against arbitrary kernel compromise.

**Evidence confidence:** detailed command-level observations exist for Ivanti exploitation and the Trivy/LiteLLM supply-chain campaign; Beget, Arkéa, and Stryker provide comparatively strong evidence about *what was done*, but incomplete public evidence about *how the initial trust boundary was crossed*.

## 1. Method and technical boundary

### 1.1 Evidence labels

- **Confirmed/reported:** stated in a victim's official notice, regulatory advisory, vendor incident analysis, or directly attributed investigative reporting. The source and its limitations are cited.
- **Inferred:** a technically plausible attack mechanism that could explain an observed result. This is not an attribution or a confirmed exploit path.
- **Hypothetical control:** a security design for a Linux implementation of the affected workflow, not a claim about the victim's configuration.

Sources were checked against publicly available material as of 7 November 2026. Incidents and recovery estimates may be updated by the organizations concerned after this date.

### 1.2 TEAL capabilities versus extensions

The project documents describe a Linux LSM-based architecture combining kernel-side interception, `teald` policy evaluation, authorization decisions, short-lived tickets, and audit logging. The TEAL short paper characterizes the **Alpha implementation** as validating core file/exec interception, basic MPA/approval flow, Fast Path caching, and auditing. It identifies **TEAL-NET, TPM/measured boot, and cryptographic authorization improvements** as further work. [T1–T3]

This report therefore uses the following conventions:

| Control | Status in this analysis | Important limitation |
|---|---|---|
| File/exec interception and policy checks | Alpha core capability | Precise `WRITE`, `UNLINK`, `RENAME`, and special-device coverage must be validated for the tested kernel/build. |
| Basic MPA and short-lived authorization tickets | Alpha core capability | Strong isolation of approvers, ticket scope, and resistance to compromised process reuse still require validation. |
| Trusted login origin and time-window policy | Design/development direction | Reliable authenticated session provenance and an enforced time matcher are prerequisites. |
| TEAL-NET egress restrictions | Planned/extended capability | A `connect()` gate alone does not semantically authorize all data sent over established sockets. |
| Management-API or transaction-level authorization | External integration or new capability | Requires explicit cooperation from the API/transaction executor. |
| Tamper-proof trust root against kernel compromise | Outside present Alpha guarantee | A kernel exploit or control-plane compromise may bypass a local LSM. |

A permitted **process identity** is not proof that every action taken by that process is permitted. Conversely, even root privileges do not inherently justify access to protected resources; this is the central design goal of TEAL. [T1, T2]

## 2. Case study A — Beget: management-plane access followed by destructive activity

**Organization:** Beget, a Russian hosting and cloud provider  
**Incident:** 2 November 2026  
**Primary sources:** Beget incident notice and its official incident updates [R1, R2]

### 2.1 What is publicly reported

Beget described an attack against its infrastructure during the night of 1–2 November. Its published timeline estimates that attackers gained access to management servers at approximately **02:00 MSK**; at **02:30**, attackers launched software intended to delete server data; at **02:40**, unauthorized access was detected; and by **02:55**, servers had been disconnected from the network as a containment measure. Beget's official channel also described access to the management control plane and the subsequent running of scripts intended to zero out data. Restoration across affected services continued in stages. [R1, R2]

The sequence demonstrates an important operational failure mode: a compromised management plane can affect many underlying customer workloads without requiring a separate successful exploit against every customer VM.

### 2.2 What is not established

Public information does **not** identify the initial vulnerability, whether credentials were stolen, the exact privilege-escalation mechanism, the management system's implementation language, or whether data destruction used direct filesystem calls, raw block-device access, or a cloud management API. Those mechanisms must remain alternatives, not asserted facts.

### 2.3 Plausible technical branches (hypotheses)

| Hypothesis | Destructive execution point | TEAL implication |
|---|---|---|
| A. An attacker launches a separate wiping executable or script | `execve` and subsequent protected file/device operations | A policy on a rare destructive executable can require MPA before launch. |
| B. An attacker modifies or deletes mounted storage from a Linux process | Protected file open, write, unlink, rename, or block-device access | Object/operation controls may stop it, subject to exact hook coverage. |
| C. An attacker invokes a privileged storage/VM-management API | Management RPC/API and downstream service actions | A Linux LSM on the caller alone may not recognize a semantic “delete VM” transaction. |

### 2.4 Counterfactual Linux management-plane design

Assume that routine administration and destructive operations are separated:

```text
Unprivileged monitoring service (always running)
        |
        +--> read-only status and inventory (ordinary allow)
        |
        +--> request destructive maintenance
                        |
                        v
          /usr/local/sbin/vm-destroy (rare EXEC)
                        |
                 TEAL policy check
                        |
              independent MPA approval
                        |
        narrow, short-lived authorization ticket
                        |
                 authorized deletion
```

Under this design, an attacker obtaining an administrative shell cannot run `vm-destroy` without authorization. **However**, this holds only if alternative deletion paths (direct storage access, shell utilities, privileged daemons, management APIs, backup deletion) are inaccessible or equivalently gated. A single blanket exception for a privileged management process could invalidate the protection.

To constrain mass deletion, a stronger design would bind approval to a specific target set, operation type, maintenance window, and expiration, and check destructive **operations** rather than merely the start of a process. A proposed sliding-window threshold would count already-approved destructive actions and reject or escalate a new action **before it commits**; after-the-fact alerts do not protect previously deleted data.

### 2.5 Defense assessment

**Strong potential fit:** infrequently invoked standalone wipe/delete tools and protected local filesystem operations.  
**Conditional fit:** a storage daemon that launches bounded worker processes for each deletion.  
**Insufficient without integration:** a persistent cloud controller issuing legitimate delete-volume API requests.  
**Additional safeguard:** isolated immutable backups in a separate administrative trust domain; TEAL is not a substitute for recoverability.

## 3. Case study B — Crédit Mutuel Arkéa: fraudulent transfers through a third-party platform

**Organization:** Crédit Mutuel Arkéa, France  
**Disclosure:** 4 November 2026  
**Primary sources:** the bank's initial and follow-up notices [R3, R4]; Reuters reporting [R5]

### 3.1 What is publicly reported

The bank reported a cyberattack enabling fraudulent transactions. Its follow-up statement says attackers **used an account belonging to Crédit Mutuel Arkéa** to move money to other banking institutions, potentially followed by cryptocurrency conversion. It expressly stated that the attackers did **not** enter through Fortuneo, but reached Arkéa through **a service provider's platform**. Customer assets were reportedly unaffected, although some transfers were delayed. Reuters subsequently reported that about **EUR 100 million** had been stolen, while final recovery/loss figures were still being assessed. [R3–R5]

### 3.2 Unknown initial compromise

The provider has not been publicly identified. The following questions remain open: Was the provider host compromised? Was an API key or service account stolen? Was a third-party application's authorization logic bypassed? Was a previously approved payment workflow misused? Were two separate authorization domains involved? **No public evidence presented here resolves those questions.**

Therefore it is incorrect to conclude that TEAL would have been irrelevant at the supplier. It might have stopped credential-file access, malicious exec, or unauthorized service connections **if** those activities occurred on an appropriately protected Linux host. It is equally incorrect to claim that ordinary TEAL file/exec enforcement would necessarily stop the final fraudulent transfer.

### 3.3 Two independent opportunities to break the chain

**First boundary: the provider environment.** In a Linux counterfactual, protect the provider's signing credentials, service-account material, deployment paths, and unusual executables; limit access to the bank's endpoints to authorized software. A stolen API token already present in memory, a compromised trusted service, or a flaw entirely inside an application could still escape such OS-level checks.

**Second boundary: the bank's transaction executor.** Apply business authorization *to the transfer itself*, including source account, beneficiary, amount, currency, transfer ID, approved purpose, time window, and aggregate limits. A permission to connect to a payment network must not imply an unrestricted permission to move money.

### 3.4 Ordinary business controls may have been sufficient—if not bypassable

A conventional tiered approval policy is relevant:

- Routine, low-risk payments may proceed under delegated operational limits.
- Higher-value or unusual payments should require elevated financial authorization.
- Exceptional transfers may require independent approval by multiple authorized officers or directors, with separation of duties.
- Repeated transfers below the individual approval threshold must be constrained by **aggregate limits** and beneficiary/risk checks.

A threshold is only meaningful if the system **enforcing the transfer** independently verifies approvals, ensures that approvers are distinct from the requester, and cryptographically or transactionally binds the approval to the **exact** payment instruction. Reusing a previously approved credential for a materially different transfer must not be possible. Always-on real-time payments also require carefully designed automated policy lanes; asking directors to approve every ordinary transfer is not operationally realistic.

**Counterfactual conclusion:** independently enforced, non-bypassable business authorization could have prevented unauthorized high-risk transfers, even if the provider was compromised. The public record does not disclose whether Arkéa lacked such controls, whether exceptions existed, or whether an attacker bypassed controls that were already present.

### 3.5 Implication for TEAL scope

This incident is **not simply “outside TEAL.”** The provider's compromise could have included Linux-level activity relevant to TEAL, but the definitive transfer authorization boundary lies at the business transaction layer. Integrating a TEAL-like MPA service into transaction execution is a possible system architecture, **not a demonstrated capability of TEAL Alpha**.

## 4. Case study C — Stryker: legitimate endpoint-management capabilities used destructively

**Organization:** Stryker Corporation, United States  
**Incident:** 11 March 2026  
**Primary sources:** Stryker's 12 and 16 March statements, CISA's 18 March guidance [R6–R8]

Stryker said an attacker used **Microsoft Intune**, a legitimate mobile/endpoint management system, to wipe its internal virtual infrastructure, rendering laptops, mobile devices, and virtual servers inoperable. It stated that no ransomware or malware was detected/deployed in the affected environment. CISA specifically advised organizations to harden endpoint management systems and adopt appropriate administrative safeguards. The initial entry route and precise privilege acquisition were not established in those notices. [R6–R8]

For evaluation, replace Intune with an **equivalent Linux-based endpoint-management service**. The critical design variable is *how the wipe functionality is invoked*.

### 4.1 Management usage pattern I — rare executable

```text
maintenance administrator -> /opt/manage/bin/fleet-wipe -> remote endpoints
                                 ^
                      TEAL EXEC + MPA gate
```

If `fleet-wipe` is started only for exceptional operations, a policy denying `EXEC` without independent approval is a simple and potentially high-value defense. The executor must still be limited to an approved host list or job manifest. If an attacker can perform the same wipe via a separate daemon, shell, or API, gating only this binary is not sufficient.

### 4.2 Pattern II — scheduled maintenance

An occasional inspection or maintenance executable can be allowed only under a dedicated UID, authenticated job origin, an expected time window, a verified executable identity, and a narrow permitted action set. Destructive operations should remain exceptional even within a permitted maintenance window. Merely matching UID/time is weak if a compromised administrator can impersonate the job or wait until the permitted time.

### 4.3 Pattern III — permanently running daemon

```text
web console/API -> endpoint-manager daemon (already running)
                      |
                      +--> status/telemetry (allowed)
                      +--> fleet wipe (requires separate operation gate)
```

An `EXEC` check at daemon startup does not stop a later authenticated API request. Options include moving wipes into a separately launched privileged helper (then enforce `EXEC` + argument/job authorization) or embedding a separate, independently enforced MPA decision at the API's wipe transaction. This is the key distinction between **program execution approval** and **administrative action approval**.

## 5. Other incidents with substantial technical evidence

### 5.1 Ivanti EPMM — pre-authentication code injection (January–March 2026)

Telekom Security documented exploitation of CVE-2026-1281 and CVE-2026-1340 against Ivanti Endpoint Manager Mobile appliances. Attacker-controlled web inputs reached server-side Bash evaluation, enabling unauthenticated code execution; responders observed command execution, attempts to install JSP web shells, and post-exploitation persistence activity. [R9]

**Linux counterfactual:** if a compromised web-service identity attempts unexpected `EXEC` (shell, downloader, privilege utility), TEAL may deny it; filesystem rules may prevent web-shell installation. Such protection is weaker when the service legitimately invokes arbitrary commands or broadly inherits permissive execution tickets. An exploit that entirely modifies the state of an already running trusted process also may not trigger a new `execve`.

**Testable hypothesis:** a compromise of the HTTP entry point succeeds, but an unauthorized child shell or web-shell write is stopped before persistence is established.

### 5.2 Trivy — trusted CI/CD distribution channels poisoned (March 2026)

Aqua Security reported that attackers initially obtained privileged credentials from GitHub Actions automation, later retained access after incomplete rotation, and on 19 March published malicious Trivy artifacts and redirected **76 of 77** `trivy-action` version tags plus seven `setup-trivy` tags. The legitimate tag names now resolved to attacker-controlled code, exposing downstream CI/CD jobs to credential theft. [R10, R11]

**TEAL relevance:** strict secret-file access controls, constrained process execution, and restricted outbound destinations can limit some payload effects, but the compromised scanner runs as an otherwise trusted tool in a CI environment. Strong countermeasures also include full-commit-SHA pinning, artifact provenance, short-lived tokens, and isolation of release credentials. Do not treat program identity or a previously approved CI job as a universal trust grant.

### 5.3 LiteLLM — downstream Python package compromise (March 2026)

JFrog reconstructed a sequence in which LiteLLM's CI used a compromised Trivy version, exposing CI credentials later used to publish malicious PyPI releases `litellm` **1.82.7 and 1.82.8**. The malicious package contained payloads in `proxy_server.py` and a `.pth` file that could execute Python code during interpreter startup. The payload sought cloud/SSH/Kubernetes credentials and attempted exfiltration and persistence. [R12]

**TEAL relevance:** the executable may still be a perfectly legitimate Python interpreter. Interpreters, import hooks, and in-process malicious logic cannot be reliably classified using executable path alone. Filesystem access restrictions and egress protection can help; already-loaded environment secrets and actions through an authorized process remain residual risks. Avoid broad ticket inheritance to untrusted packages or subprocesses.

### 5.4 Fortinet FortiCloud SSO — administrative authentication bypass (January 2026)

Fortinet documented exploitation of **CVE-2026-24858** in FortiCloud SSO, allowing an attacker with qualifying FortiCloud access to log into vulnerable devices registered to other customers when the feature was enabled. Observed follow-on activity included downloading device configurations and creating local administrative accounts for persistence. [R13, R14]

**Linux counterfactual:** even after a management login succeeds, creation of a new privileged account, changes to security configuration, or export of sensitive device configuration could require separate authorization. In an appliance implemented with a persistent management process, this generally requires action-aware checks, not only a one-time `EXEC` check.

### 5.5 GMO Onamae.com Desktop Cloud — management-server pivot to customer VMs (Japan, 2026)

GMO officially disclosed unauthorized programs in some customer environments. In its 2 November press briefing, as reported by ITmedia, GMO described an initial intrusion into a customer remote-desktop VPS on **5 August**, compromise of an administrative account and entry into a management server by **17 August**, and malware deployment to as many as **26,739 potentially affected customer VMs** during **20 September–14 October**. The exact initial exploit remained undisclosed. [R15, R16]

**Linux counterfactual:** customer-side executable and secret access could be restricted, and management-server software deployment could be gated through a dedicated update helper or approval of signed packages and target scope. The use of a privileged, already running distribution service would require API/transaction-level enforcement. The maximum potentially affected VM count must not be treated as the number confirmed compromised.

## 6. A general TEAL control model for administrative software

The repeated design lesson from Beget, Stryker, and GMO is that **administrative software should be classified by invocation pattern**, not just by the program's name.

| Deployment pattern | Example | Low-complexity control | Residual problem |
|---|---|---|---|
| Rare, standalone utility | `vm-destroy`, `fleet-wipe` | TEAL `EXEC` with independent MPA, narrow ticket | Alternate tools/APIs; misuse of already-approved executable/arguments |
| Scheduled tool | nightly maintenance or periodic audit | UID + authenticated scheduler identity + verified binary + time window | Attacker waits for allowed window or hijacks scheduled job |
| Long-lived service that spawns helpers | controller -> privileged deletion helper | Allow controller; gate helper's `EXEC` and exact job manifest | Bypass through direct API, privileged sockets, or unprotected helpers |
| Long-lived service with internal operations | daemon directly invokes delete/wipe API | Explicit operation/transaction authorization in service | Local `EXEC` occurs only at startup; OS hooks may not identify transaction |
| External business workflow | bank payment instruction | Independent business authorization and separation of duties | OS-level attributes do not encode beneficiary, amount, or purpose |

### 6.1 Preconditions for meaningful `EXEC`-only protection

An `EXEC` gate is a strong and simple defense **only when all of the following hold**:

1. The hazardous capability is accessible only through the gated program, not through an alternative path.
2. The execution event occurs **before** the damaging action; the program is not already running with the hazardous capability available.
3. Identity and provenance checks use trusted kernel- or authentication-backed context; they do not depend solely on attacker-controlled environment variables.
4. Authorization is scoped to the exact action, target, and validity interval as far as the operating model requires.
5. The authorized program cannot be freely repurposed with unvalidated arguments or replaceable scripts/configuration.
6. Attackers with local administrator privileges cannot simply disable TEAL, tamper with policy or approvals, or write to a broader underlying control interface.

Where these conditions fail, **operation-level controls** become necessary. A sensible implementation often separates harmless monitoring from a privileged, rarely executed helper to create a reliable LSM enforcement point.

### 6.2 Tickets, privilege inheritance, and the confused deputy

An approved daemon, interpreter, or deployment tool is a potential **confused deputy** if it accepts attacker-controlled requests. Short TTLs and object-bound tickets reduce exposure but cannot prove the legitimacy of business intent. The TEAL project documents describe both subject-context and object-bound caching strategies. Broad process-scoped or inherited tickets must not silently authorize every privileged action carried out on behalf of a compromised client. [T1, T2]

Recommended design principles: narrow action/target scope; no unnecessary ticket inheritance; explicit exception handling for destructive operations; revocation through policy epochs; and audit records linking authorization intent to actual operations. A signature or hash check of an approved executable does not alone make malicious inputs harmless.

### 6.3 Sliding-window mass-operation control

For fleets, a proposed policy can count destructive operations per authenticated administrative context, target fleet, and time window. This is a **future control design**, not a claim of a demonstrated TEAL Alpha feature.

```text
Before a destructive operation:
  validate actor and permitted target;
  atomically check (recent committed operations + proposed operation);
  if within policy budget: authorize and account for it;
  otherwise: DENY or request a new, tightly scoped MPA approval.
```

The counting/checking boundary must be synchronized with execution. Several concurrent workers must not all pass a stale counter. A robust design also addresses cancelled operations, retries, idempotency, partial failures, and accounting across multiple controller hosts.

### 6.4 Planned implementation baseline: trusted login provenance

**Committed design requirements for the next TEAL revision (not implemented or validated in TEAL Alpha).** The threat-coverage analysis in this report may assume the following four requirements **only when explicitly labelled as a prospective, post-upgrade assessment**. Implementation feasibility is supported by documented Linux/OpenSSH primitives, but the security guarantees depend on correct integration, kernel integrity, and negative-path testing. The existing TEAL v2.2 specification, sections 6.7 and 10.3, still uses environment variables and process ancestry to *infer* the SSH source; that mechanism must be replaced for authorization purposes. [T1, R17-R22]

1. **Environment-independent provenance.** A trusted SSH authentication/session integration shall associate the real accepted TCP socket peer (`getpeername` or an equivalent kernel-derived peer address) with the authenticated UID, the successful authentication event, and the session instance. The registration operation shall be restricted to a verified authentication lifecycle; `SSH_CLIENT`, `SSH_CONNECTION`, `PAM_RHOST`, login records, and command-line strings may inform audit but shall not independently grant trusted provenance. A minimal, reviewed OpenSSH-side integration or equivalent authenticated component is expected; a generic PAM module reading `PAM_RHOST` alone is insufficient. The recorded source IP represents the immediately connected peer, not necessarily the original workstation behind a bastion, VPN, proxy, or NAT.

2. **Kernel-protected, non-reassignable identity.** The registered login context shall have a unique identifier, boot identifier, authenticated identity, peer endpoint, origin type, establishment state, and provenance assurance level. It shall be held in kernel-managed LSM/task or credential-associated state, with an append-only or equivalently restricted registration lifecycle, no unprivileged or root-initiated arbitrary relabelling, and explicit teardown/revocation rules. Linux immutable audit loginuid illustrates a related mechanism but does not itself protect TEAL's source IP or authentication event. Registration must not accept a claim merely because the caller has UID 0 or the `sshd` executable name. A malicious root user must not be able to forge trust by invoking or injecting into the registrar. This guarantee assumes that the kernel and the protected sshd/TEAL registration path remain trustworthy.

3. **Preservation across process and credential transitions.** TEAL shall propagate provenance across supported `fork`/`clone`, `execve`, `sudo`/`su`, and set-UID/credential transitions without converting a new effective UID into a new authenticated login origin. Linux LSM task and credential hooks provide implementation points. Process creation and credential-sharing cases, parallel sessions under one UID, detached descendants, PID reuse, and session closure must be tested. **Delegation to an independently started service** (for example, `systemd-run`/D-Bus, a pre-existing daemon, CI worker, or container orchestrator) is *not* ordinary parent-child propagation: the receiver retains its own origin unless a separately authorized, narrowly scoped delegation mechanism is introduced. A session identifier does not prove that the current process is uncompromised.

4. **Explicit classification of non-SSH origins.** Supported origins shall include `SSH_AUTHENTICATED`, `LOCAL_CONSOLE`, `SERVICE`, `SCHEDULED`, `CONTAINER` (where attribution is available), `DELEGATED`, and `UNKNOWN`. Web-shell or reverse-shell commands executed inside an exploited service shall not receive a fabricated SSH login context; they retain the service origin or are marked unknown. For high-risk operations, incomplete, unverified, conflicting, or unavailable provenance shall result in `DENY` or a separately justified MPA decision, never implicit authorization based on a guessed source IP. Each category requires an explicit, tested entry-point binding rather than classification by command name alone.

**Policy use.** The intended authorization tuple is `authenticated_subject + origin_type + trusted_session_id + source_peer + program_identity + operation + protected_object + time/policy_epoch`. A short-lived ticket shall be bound to the relevant origin and policy epoch, not only to a UID or executable name; ticket inheritance and Fast Path must not erase an origin restriction. For high-risk administrative operations, this adds an independent condition to `EXEC`/file controls and MPA, but it does not replace them.

### 6.5 Residual trust limits and verification obligations

This implementation is feasible **under a non-compromised kernel and a protected registration boundary**, not a guarantee against arbitrary kernel execution. The enforcement design must also restrict userspace root from tampering with `sshd`, policy files, TEAL device controls, process memory, loaded programs, and the trusted registration path sufficiently to preserve its assumptions. A compromised *authorized* administrator workstation, bastion host, SSH session, or already-authorized process can still produce a valid-looking origin; MPA and action/target scoping remain necessary. For trusted connections through SSH proxies, only the immediate peer is known unless another authenticated provenance assertion is linked end to end.

**Acceptance tests for the next revision:** forged environment/PAM fields; duplicate sessions for one UID; interactive and noninteractive SSH; SSH multiplexing and bastion hops; `sudo`/`su`/set-UID; `fork`/`exec` and background jobs; detached and daemonized processes; `systemd-run` or D-Bus service activation; cron/systemd timers; service-origin RCE; attempts by root to register, replace, or steal another session context; session expiry and PID reuse; policy-epoch and ticket cache changes. For any unresolved case, high-risk actions must fail closed. The results shall distinguish **technical feasibility**, **implemented behavior**, and **measured resistance to a specified attacker capability**. [R17-R22]

## 7. Proposed validation experiments

### Experiment 1 — rare destructive tool (Beget/Stryker model)

**Environment:** isolated Linux VMs and dummy customer-data directories; no real customer data. **Setup:** a standalone `fleet-wipe` or `vm-destroy` executable and a separate ordinary monitoring daemon. **Variants:** unprivileged user, stolen admin UID, approved operation, denied operation, alternate helper, modified script, and expired/replayed ticket.

**Pass criterion:** a destructive action cannot begin without a valid authorization bound to the intended executable and permitted target set; the same protection holds under an administrator-compromise assumption. Report the actual blocked syscall/hook, denied operation count, and any bypasses through alternative paths.

### Experiment 2 — scheduled management

**Environment:** a Linux scheduler launches a maintenance helper within a defined interval. **Variants:** execution during window, outside window, from an interactive shell, using a forged environment value, and with a compromised scheduler or writable job definition.

**Pass criterion:** only an authenticated expected job origin can perform permitted work in the intended interval; destructive out-of-scope operations still require additional authorization.

### Experiment 3 — long-running management daemon

**Environment:** a management API provides status and simulated wipe endpoints. Compare (a) daemon performs the wipe internally, (b) daemon launches a gated helper, and (c) daemon calls a transaction-authorization service.

**Pass criterion:** record exactly which model stops an adversary who can submit a syntactically valid, unauthorized wipe request. This experiment should establish when `EXEC`-only control is insufficient.

### Experiment 4 — compromised trusted runtime (Trivy/LiteLLM model)

**Environment:** isolated CI runner and Python test environment using inert, researcher-authored stand-in payloads. **Variants:** approved interpreter reading secret files, child process inheriting a ticket, and outbound requests to an unapproved destination.

**Pass criterion:** measure which resource operations are denied and document the unavoidable gaps for secrets already available in process memory or requests through previously authorized connections.

### Experiment 5 — fraudulent business transaction (Arkéa model)

**Environment:** simulated ledger and bank-transfer API (no real funds). **Variants:** stolen provider token, authorized routine payment, newly introduced beneficiary, split transfers, replay, modification after approval, and compromised provider host.

**Pass criterion:** bank-side transaction enforcement rejects high-risk or changed instructions without independent authorization. Explicitly record that this requires business-layer enforcement in addition to any OS-side TEAL controls.

### Experiment 6 — trusted SSH login provenance and origin constraints (planned revision)

**Environment:** an isolated Linux host with a trusted SSH authentication-to-TEAL registration path and kernel-protected session context. **Variants:** authenticated admin from an allowed and disallowed peer; forged `SSH_CONNECTION`; two sessions with the same UID; root acquired by a web service; `sudo`/`su`; `systemd-run` delegation; bastion and multiplexed SSH; root attempts to reassign provenance or inherit unrelated tickets.

**Pass criterion:** high-risk management operations are allowed only with a kernel-verifiable matching origin (and MPA when required); forbidden source/identity combinations fail closed; no session-origin laundering occurs across process, credential, or service boundaries. Successful validation must identify the exact hooks and policy checks used. No existing Alpha results should be construed as satisfying this criterion.

## 8. Defense Beyond the Kernel Trust Boundary

### 8.1. Scope and fundamental security assumption

TEAL's central security objective is **post-compromise enforcement against a userspace adversary, including one who has acquired UID 0 (root)**. Its Linux Security Module (LSM) checks, policy decisions, in-kernel ticket state, and audit events nevertheless execute within, or rely upon, the same Linux kernel. Thus, **kernel integrity is an explicit trust assumption**, not something the LSM can independently prove. The Alpha prototype does not claim resistance to arbitrary kernel code execution. [T1–T3]

An attacker able to execute arbitrary code with sufficient kernel privileges may alter or bypass LSM hooks, access protected data through unmediated kernel paths, falsify kernel-generated context, manipulate tickets or process credentials, disable audit collection, and interfere with `teald` or its communication channel. Even a correctly implemented TEAL policy cannot guarantee enforcement after that boundary has been crossed. Conversely, a root account **without** arbitrary kernel execution is not, by itself, equivalent to kernel compromise; maintaining this distinction is essential to TEAL's value proposition.

For this chapter, the proposed defense-in-depth architecture distinguishes four adversary conditions:

| Attacker capability | TEAL role | Independent protection required |
|---|---|---|
| Compromised unprivileged process | Deny out-of-policy `EXEC`, protected file operations, and other mediated actions | Ordinary patching, sandboxing, least privilege |
| Userspace root or privileged management service, kernel still trustworthy | Enforce critical-operation policy and MPA, subject to verified hook coverage and hardening | Signed boot chain, protected TEAL policy and registration interfaces |
| Arbitrary kernel-level execution or equivalent enforcement bypass | **No dependable LSM enforcement guarantee** | Hardware-rooted boot assurance, external monitoring/containment, trusted recovery |
| Firmware, hypervisor, management controller, or physical trust-root compromise | Outside TEAL and potentially outside an ordinary TPM/watchdog deployment | Separately hardened platform/control plane and incident-specific recovery |

The objective beyond the kernel boundary is therefore **risk reduction, externally visible evidence, damage containment, and recoverability**—not a promise that TPM 2.0 or a watchdog makes an arbitrary compromised kernel trustworthy. The protection/detection/recovery distinction is consistent with NIST SP 800-193, whose *primary scope is platform firmware*, not proof of runtime Linux-kernel integrity. [R23, R31]

### 8.2. Hardening the kernel boundary before compromise

The first line of defense remains preventing a userspace-root attacker from reaching arbitrary kernel execution. For a TEAL deployment, the following measures should be treated as prerequisites or strongly recommended host-hardening controls, with availability dependent on the hardware, distribution, and kernel build:

1. **Verified boot and trusted update chain.** UEFI Secure Boot (where supported), appropriately signed boot components and kernels, controlled signing keys, and tested rollback/recovery procedures reduce opportunities to replace the boot chain. Secure Boot verifies approved signatures; it is *not* a runtime exploit detector. Measurements and enforcement must be assessed separately.
2. **Kernel Lockdown and module-loading controls.** Restrict interfaces exposing kernel memory or permitting unauthorized modification; enforce kernel-module signatures and protect module-signing private keys. The actual protection depends on lockdown mode, configuration, trust stores, and whether alternative loading paths exist. A signed module may still be vulnerable or malicious if an attacker controls a trusted signing key. [R24, R25]
3. **Restrict kernel attack surfaces.** Apply timely kernel updates and disable or constrain unneeded privileged interfaces and kernel features, such as unrestricted module loading, dangerous device access, debugging facilities, and unnecessarily exposed privileged subsystems. These measures reduce risk but cannot exclude unknown kernel vulnerabilities.
4. **Protect TEAL's own control plane.** The `teal_module`, `/dev/teal` control operations, `teald` executable, loaded policy/bundle, role definitions, SSH-provenance registrar, authorization keys, and policy-epoch/ticket transitions must not be writable, replaceable, or arbitrarily reconfigured by a compromised userspace administrator. Enforceable checks must remain independent of the identity claims they validate.
5. **Keep MPA approval authority outside the compromised host where feasible.** Independent approvers and signing-key custody reduce the likelihood that one root compromise can both request and approve the destructive action. They do not help if a kernel-compromised host can simply bypass the LSM gate.

These controls must be verified with the *actual kernel configuration and boot state*, rather than assumed from product names or package installation. For example, permissive module-signature checking is materially different from enforced signature verification. [R24]

### 8.3. TPM 2.0, measured boot, and remote attestation

A TPM 2.0 can anchor measurements in Platform Configuration Registers (PCRs) and produce a cryptographic **Quote** using an attestation key. In a measured-boot design, trusted firmware and subsequent boot components extend measurements into PCRs. An independent verifier can challenge the platform with a fresh nonce, verify the Quote signature and platform identity, compare the PCR evidence with an approved policy, and validate the associated event log against the signed PCR state. This establishes evidence about **measured events and their integrity**, under the assumed measurement chain; it does not establish that every subsequent memory operation was benign. [R27]

A proposed TEAL attestation flow is shown below. Open-source projects such as Keylime illustrate how an independent registrar/verifier can consume TPM Quotes and IMA evidence; this report does not assume Keylime is already integrated with TEAL. [R30]


```text
Hardware / firmware root of measurement
              |
              v
UEFI / boot components / kernel and approved boot policy
              |
              v
TPM PCR measurements + measurement/event log
              |
       [TEAL-host attestation agent]
              |  signed Quote(nonce, selected PCRs) + event evidence
              v
      Independent remote verifier
              |
      approved / untrusted / unavailable
              |
              v
External admission or quarantine controller
```

**Design requirements for meaningful attestation:**

- Provision and authenticate the TPM attestation identity; verify freshness with verifier-generated nonces and reject replay or unverifiable event logs.
- Define exactly which firmware, boot-loader, kernel, initramfs, boot parameters, and TEAL-related artifacts are covered by measurements. **TEAL presence or policy integrity must not be inferred from a PCR that does not actually include the relevant artifact.**
- Manage an approved measurement baseline, signed maintenance changes, kernel/firmware update transitions, and rollback policies. A normal upgrade can alter PCRs without being an attack.
- Keep the verifier's keys, decisions, and logs outside the measured host. Treat missing evidence, invalid Quotes, and timeout as **not attested**, not automatically as a proven compromise.
- Where feasible, condition network admission or access to critical remote services on a recent successful attestation and a short authorization lease, rather than on a one-time check at startup.

**Important limit:** a machine may boot a legitimate kernel, produce an approved Quote, and then suffer a runtime kernel exploit while its boot PCRs continue to match the approved baseline. Nor does periodic re-quoting of unchanged boot PCRs by itself discover an attacker who has modified kernel memory. A TPM protects its own signing operation and measurement registers; it is not a general-purpose live scanner of kernel RAM. [R27]

TPM **sealing** can additionally bind access to particular secrets to selected PCR values, reducing the ability to use those secrets when the platform starts in an unauthorized measured state. However, once an operating system successfully unseals a secret and stores plaintext or key material in memory, later kernel compromise may expose it. For higher-value keys, keep sensitive cryptographic operations in an external HSM or in hardware that avoids exporting plaintext keys into a compromised host, where supported and appropriately integrated. [R29]

### 8.4. Runtime file-integrity controls: IMA/EVM and their limits

Linux Integrity Measurement Architecture (IMA) supports *measurement*, *appraisal*, and *audit* policies. Measurement can produce an event log and extend integrity values into a TPM PCR; **measurement alone does not deny execution**. Appraisal can reject access to files that fail a configured hash or signature policy, provided the policy is actually enforced. EVM can protect security-relevant extended metadata used in integrity decisions. [R26]

In a hardened TEAL installation, a carefully scoped IMA appraisal policy could protect the executables and policy artifacts underlying trusted SSH provenance, `teald`, and critical administrative helpers. IMA measurements could also help a separate verifier evaluate changes to selected runtime-loaded files and configuration. That requires the file set, load order, appraisal mode, policy signature enforcement, and update procedure to be specified and tested. It must not be assumed that every relevant file is automatically covered.

IMA and TPM evidence should be interpreted narrowly:

- They improve the ability to prevent or notice **measured or appraised file changes**; they do not automatically prove that a permitted process's *runtime memory* is intact.
- A kernel attacker can potentially change execution flow without altering the measured executable file. Once kernel integrity is lost, a malicious kernel may also suppress future measurements or lie through other local interfaces; a TPM-signed history does not prove the absence of omitted future events.
- Remote verification must validate event-log consistency with the relevant PCRs, while recognizing that successful verification establishes a **measurement history under stated assumptions**, not comprehensive runtime integrity.
- IMA cannot replace TEAL's action-aware policy. A perfectly signed administration tool may still be used to perform an unauthorized operation.

Independent runtime-memory monitoring (for example, appropriately isolated hypervisor- or hardware-assisted inspection) can be considered as separate research, but is **not** part of the present TEAL Alpha guarantee. Such monitors also have coverage, performance, and trust-boundary limitations. [R26, R27]

### 8.5. Watchdogs, external monitoring, and containment

A conventional Linux **hardware watchdog timer** principally detects a liveness failure: when a local process or watchdog driver stops supplying keepalive signals, the hardware may reset the machine after a configured timeout. This can improve availability and recovery from hangs, including some attacks that crash or disable essential components. It does **not** detect arbitrary kernel compromise. A capable kernel attacker might continue supplying keepalives or disable the mechanism when hardware/driver configuration permits. Driver behavior and `nowayout` support vary by platform. [R28]

To be meaningful against threats to the kernel, the monitoring and **response authority** should be placed as far as practicable *outside the suspect kernel*. An external verifier or management controller can observe independent signals such as missing attestation evidence, missed application-level checks, loss of service, unexpected management-plane activity, or alerts received through an independent channel. Nevertheless, a malicious kernel that continues to behave plausibly may evade these checks. A watchdog heartbeat is evidence of some liveness, **not evidence of trustworthiness**.

A practical distinction is:

| Mechanism | What it can establish or cause | What it cannot guarantee |
|---|---|---|
| In-host watchdog daemon + hardware timer | Reset after missed local keepalives | Detect a silent or cooperating kernel attacker |
| Remote heartbeat/service probes | Detect specified connectivity or service failures | Prove kernel memory integrity |
| TPM Quote + approved event evidence | Authenticate specified measurements and their freshness | Detect unmeasured runtime code execution |
| External network switch / independent gateway | Block the host's network traffic despite compromised local firewall rules | Stop all local disk corruption already underway |
| Independently managed recovery controller | Reset, boot rescue media, and gate production re-admission | Recover stolen data or automatically remove all persistent firmware compromise |

**Response-plane separation is essential.** The suspect host must not be able to remove its own quarantine rule, rewrite the remote verifier's verdict, change management-controller credentials, or approve its own restoration to production. Management controllers and switches must themselves be hardened, access-controlled, monitored, and updated. A BMC that accepts commands from the compromised host without independent authentication is not a sufficient isolation boundary.

Operationally, distinguish three outcomes: **healthy** (evidence meets the stated policy), **untrusted** (evidence conflicts with policy), and **unknown/unavailable** (evidence cannot be obtained). Unknown is not proof of intrusion, but high-risk privileges should not be granted solely because the evidence is missing. The appropriate quarantine or service-degradation policy should be set in advance to balance containment against availability.

### 8.6. Proposed defense-in-depth architecture and incident response

The following *future* architecture separates local enforcement, evidence verification, and consequential response. It is a proposal—not a description of the current Alpha implementation:

```text
 TRUST DOMAIN A: Protected Linux host
  +-----------------------------------------------------+
  | Signed / measured boot -> Linux kernel -> TEAL LSM  |
  |          |                |           |             |
  |        TPM 2.0       IMA appraisal  teald / MPA      |
  |          |                |           |             |
  |    TPM Quote + IMA evidence + heartbeat / audit     |
  +--------------------------|--------------------------+
                             | authenticated telemetry
                             v
 TRUST DOMAIN B: Independent verifier / log store
  +-----------------------------------------------------+
  | Nonce/Quote verification; approved measurements;   |
  | timeouts; alert correlation; append-only evidence   |
  +--------------------------|--------------------------+
                             | signed/authorized decision
                             v
 TRUST DOMAIN C: Independent response plane
  +-----------------------------------------------------+
  | Gateway/switch quarantine; service access revocation|
  | BMC or independent watchdog action; rescue boot;   |
  | clean reimage; re-attestation before readmission    |
  +-----------------------------------------------------+
```

The verifier and response plane may be combined in a small deployment **only if their compromise resistance and administrative separation are retained**. Protect against the common-mode failure in which the same single administrator credential controls the TEAL host, verifier, switches, backups, and recovery images. Separate privileges and, for exceptional operations, use independent approval. This directly addresses the *concentration of management authority* highlighted by the case-study discussion, without attributing unverified details to any incident.

A conservative response sequence after a credible alert or failed integrity verification is:

1. **Classify and confirm.** Record the alert time, host identity, last accepted attestation and policy epoch, recent approval/ticket activity, and which sensor or condition failed. Do not infer kernel compromise from a single missing ping.
2. **Contain externally.** Revoke access to sensitive services and apply quarantine at a network gateway or switch **not administered by the suspect host**. Preserve a separately authenticated forensic or recovery path where needed.
3. **Preserve evidence as appropriate.** Retain remote audit/attestation records and, where incident policy permits, obtain forensic images or memory evidence with controlled tooling. The contents of an already compromised kernel's local logs are not authoritative on their own. Live acquisition may alter evidence and expose investigators to malicious code.
4. **Revoke and rotate authority.** Expire affected sessions, tickets and service credentials, review signing keys and SSH/management access, and restrict backup-delete or deployment privileges. Root credentials alone are not the only secrets at risk.
5. **Recover from an independent trust source.** Reinstall or reimage from a verified image; verify relevant firmware and management-controller integrity; reinstall TEAL and its policy; restore data from separately protected, integrity-checked backups. **A simple reboot of an untrusted installation is not equivalent to recovery.**
6. **Re-attest before production access.** Require fresh measured-boot evidence and approved policy state, then run functional and security checks before lifting external isolation. Maintain a recovery audit trail and verify that the original entry route has been addressed.

A hardware watchdog can initiate a reset in some failure states, but whether to reset automatically or pause for evidence collection is an explicit operational choice. Automatic reboots may erase volatile forensic evidence or repeatedly reboot into the same compromised installation. For hosts containing critical data, external **isolation first**, followed by controlled recovery, may be safer than unconditional reboot.

### 8.7. TEAL-specific failure modes and verifiable assurances

The integration must account for `teald` failure independently of arbitrary kernel compromise. The TEAL v2.2 design specifies a **Fail-Safe** behavior in which new Slow Path operations requiring a daemon decision are denied when the daemon becomes unavailable, while still-valid Fast Path tickets may remain usable unless a stricter configuration revokes them. Its watchdog and network-lockdown aspects are *specified or proposed*, not established as deployed Alpha defenses. [T1]

This distinction has operational consequences:

- A lost `teald` heartbeat should trigger local fail-safe rules **while kernel enforcement is still trusted**, and may separately trigger external alarms. It does not establish that the kernel is intact.
- Existing tickets, especially broad process-bound or inherited ones, may permit actions during a daemon outage. A high-assurance profile should define whether to revoke them, what happens to in-flight operations, and how to prevent a stale ticket from surviving a policy transition.
- The protection of `/dev/teal`, policy updates, daemon registration, audit state, and the proposed SSH-provenance registration channel is part of the **pre-kernel-compromise** hardening problem; external attestation should not be described as a substitute for enforcing these controls.
- An external verifier cannot assume that local TEAL audit records are complete after kernel compromise. Sending audit events to an append-only remote sink improves evidence preservation but does not guarantee that all events were produced.
- Restored service access should be granted by the external admission controller only after the host passes the agreed recovery and attestation checks; an attacker-controlled local `ENFORCE` status string is not sufficient.

**Defense claim to use in this report:** *TEAL can enforce critical-action policy against userspace privilege compromise while the kernel and policy-enforcement path remain trustworthy. Verified/measured boot, IMA, TPM-backed evidence, independent monitoring, external quarantine, and trusted recovery can reduce further risk and improve resilience beyond that boundary, but they cannot guarantee detection or prevention of arbitrary runtime kernel compromise.*

### 8.8. Experimental validation and proposed roadmap

The defense-in-depth layer should be tested separately from the existing file/exec benchmarks. The following are **proposed test cases**, not completed TEAL results:

| Test case | Controlled fault / attack simulation | Evidence and pass criterion |
|---|---|---|
| B1 — Unauthorized boot artifact | Boot a non-approved test kernel or modified signed-boot configuration | Secure Boot enforcement or remote admission rejects the unapproved state, as configured; specify which component enforced the decision. |
| B2 — Measured-file tampering | Modify a protected test executable or TEAL-related config in an isolated image | IMA *appraisal* blocks covered access when enforced, or measurement produces a verifier-visible deviation where configured; report coverage gaps. |
| B3 — Quote replay / wrong platform | Replay an old Quote or use mismatched attestation identity | Verifier rejects the stale nonce, wrong key, inconsistent PCR/event-log evidence. |
| B4 — `teald` failure | Stop/kill only the policy daemon; retain a trusted test kernel | Document exact Slow Path denial, retained/revoked Fast Path tickets, and external notification; inspect recovery transitions. |
| B5 — Silent kernel-compromise model | Under authorized lab conditions, emulate a compromised host that continues to send heartbeats while bypassing **local** enforcement | Demonstrate that heartbeat-only detection is insufficient; report only detections produced by genuinely independent measurements or probes. Do not claim comprehensive kernel-compromise detection. |
| B6 — External quarantine | Simulate integrity failure or loss of acceptable evidence | Independent switch/gateway blocks designated outbound and management access even if the local firewall continues to allow it. |
| B7 — Trustworthy recovery | Reboot an untrusted test image, then replace it with a known-good image | Reboot alone does not re-establish authorization; verified reimage plus fresh attestation is required before re-admission. |
| B8 — Control-plane compromise | Give a test administrator root on the protected host but not control of verifier/switch or approval keys | The host cannot change the external policy, erase remote evidence, lift quarantine, or authorize its own return. |

**Implementation sequencing:** (i) document and validate the root-versus-kernel threat boundary; (ii) harden verified boot, kernel-module loading, and TEAL's local control plane; (iii) build a TPM-backed remote-attestation proof of concept with explicit measurement scope; (iv) integrate independently managed quarantine and carefully configured watchdog behavior; (v) exercise clean recovery, key rotation, and re-admission; and (vi) assess stronger runtime-integrity instrumentation only if the remaining threat model justifies its complexity.

The proposed protections are complementary, not interchangeable. In particular, **successful boot attestation must never be reported as proof that an actively running kernel is uncompromised**. The final research output should report *enforced operations, measured coverage, verification freshness, independent response capability, and residual trust assumptions* as distinct findings. [R23–R31, T1–T3]

## 9. Conclusions

1. **Beget and Stryker provide strong examples of management-operation risk.** A Linux redesign that exposes destructive functionality only through dedicated, infrequently executed helpers is well suited to TEAL `EXEC` control and MPA. The real incidents do not establish that such helpers existed.
2. **The invocation model is decisive.** Rare or scheduled utilities can often be governed with comparatively simple execution policies. A permanently running controller that performs its own dangerous work requires a check closer to the actual operation.
3. **Crédit Mutuel Arkéa crosses two trust boundaries.** TEAL could conceivably help in a compromised third-party Linux environment, but the final protection for funds must be a bank-enforced approval policy for precise, non-replayable transactions. The underlying provider intrusion remains publicly unexplained.
4. **Ivanti demonstrates an especially concrete post-exploitation `EXEC`/file-control scenario.** Trivy and LiteLLM demonstrate the converse: malware may run inside trusted deployment tools or interpreters, making the exact resource and network privileges more important than the program's name.
5. **Trusted login provenance is a committed next-revision design, not an Alpha result.** Kernel-derived SSH peer information, authenticated session registration, kernel-protected identity, inheritance rules, and non-SSH origin classification are explicit implementation requirements. Their security value depends on verified registration and fail-closed policies; a trusted origin does not prove an uncompromised session.
6. **Avoid overclaiming.** These are control-mapping hypotheses and laboratory test plans, not retroactive proof that TEAL would have stopped any named victim's actual incident. TEAL Alpha does not presently establish full protection against kernel compromise, all management APIs, or business-level transactions.
7. **Kernel compromise is a separate trust domain.** TEAL requires an intact kernel to enforce LSM decisions. The proposed TPM, integrity, external-monitoring, quarantine, and recovery mechanisms improve resilience and evidence quality but cannot guarantee detection of stealthy runtime kernel takeover (section 8).

**Overall thesis:** apply the least complex dependable gate at the last reliably enforceable point before damage. For a seldom-used destructive program, that may be `EXEC` plus MPA; for a persistent controller, it is the destructive management operation; for a bank, it is the specific transfer transaction.

---

## References: public incident sources

**[R1]** Beget. *Security / cyberattack recovery notice*, incident of 2 November 2026, timeline updated 5 November 2026. https://beget.com/en/security (The site is dynamic; its incident notice may subsequently be replaced by routine security content.)

**[R2]** Beget Official. *Incident updates regarding compromise of the management control plane and deletion scripts*, November 2026. https://t.me/s/beget_official/573

**[R3]** Crédit Mutuel Arkéa. *Crédit Mutuel Arkéa announces it has been the target of a cyberattack*, 4 November 2026. https://www.actusnews.com/fr/credit-mutuel-arkea/cp/2026/11/04/credit-mutuel-arkea-announces-it-has-been-the-target-of-a-cyberattack

**[R4]** Crédit Mutuel Arkéa. *Additional Information Following the Cyberattack on Crédit Mutuel Arkéa*, 4 November 2026. https://www.actusnews.com/fr/credit-mutuel-arkea/cp/2026/11/04/additional-information-following-the-cyberattack-on-credit-mutuel-arkea

**[R5]** Reuters. *French bank Credit Mutuel Arkea says €100 million missing after cyberattack*, 5 November 2026. https://www.reuters.com/legal/government/french-bank-credit-mutuel-arkea-says-100-million-missing-after-cyberattack-2026-11-05/

**[R6]** Stryker. *Customer Updates: Stryker Network Disruption*, 12 March 2026. https://www.stryker.com/cn/en/about/news/a-message-to-our-customers-03-2026.html

**[R7]** Stryker. *Cyber incident response certification letter*, 16 March 2026 (hosted copy). https://www.nwcemss.org/assets/1/news/2026-03-16_Stryker_Customer_Certification_Letter.pdf

**[R8]** U.S. CISA. *CISA Urges Endpoint Management System Hardening After Cyberattack Against US Organization*, 18 March 2026. https://content.govdelivery.com/accounts/USDHSCISA/bulletins/40ef439

**[R9]** Telekom Security. *Mass exploitation of CVE-2026-1281 and CVE-2026-1340 in Ivanti EPMM*, 3 March 2026. https://github.security.telekom.com/2026/03/ivanti-CVE-2026-1281-exploitation.html

**[R10]** Aqua Security. *Trivy supply chain attack: ongoing investigation and continued remediation*, updated 1 April 2026. https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/

**[R11]** Aqua Security / GitHub Security Advisory. *Trivy ecosystem supply chain temporarily compromised*, GHSA-69fq-xp46-6x23, 21 March 2026 (subsequently updated). https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23

**[R12]** JFrog Security Research. *Popular litellm Python package is the latest victim of TeamPCP's ongoing supply chain attack*, 24 March 2026. https://research.jfrog.com/post/litellm-compromised-teampcp/

**[R13]** Fortinet. *Analysis of Single Sign-On Abuse on FortiOS*, January 2026. https://www.fortinet.com/blog/psirt-blogs/analysis-of-sso-abuse-on-fortios

**[R14]** Fortinet PSIRT. *Administrative FortiCloud SSO authentication bypass*, FG-IR-26-060 / CVE-2026-24858, 27 January 2026. https://fortiguard.fortinet.com/psirt/FG-IR-26-060

**[R15]** GMO Internet. *Notice regarding unauthorized access to Onamae.com Desktop Cloud*, 21 October 2026. https://internet.gmo/news/article/246

**[R16]** @IT / ITmedia. *GMO press-conference analysis and disclosed intrusion timeline*, 3 November 2026 (Japanese). https://atmarkit.itmedia.co.jp/ait/articles/2611/03/news014.html

**[R17]** Linux manual pages. *getpeername(2): get name of connected peer socket*. https://man7.org/linux/man-pages/man2/getpeername.2.html

**[R18]** Linux-PAM manual pages. *pam_get_item(3): PAM_RHOST and its limitations*. https://man7.org/linux/man-pages/man3/pam_get_item.3.html

**[R19]** The Linux Kernel documentation. *Credentials in Linux*. https://docs.kernel.org/security/credentials.html

**[R20]** The Linux Kernel documentation. *The Linux Kernel API: security_task_alloc, security_prepare_creds and related LSM operations*. https://docs.kernel.org/core-api/kernel-api.html

**[R21]** Linux audit userspace manual. *audit_set_loginuid_immutable(3)*. https://man7.org/linux/man-pages/man3/audit_set_loginuid_immutable.3.html

**[R22]** systemd manual pages. *pam_systemd(8): registration and tracking of sessions*. https://man7.org/linux/man-pages/man8/pam_systemd.8.html

**[R23]** NIST. *Platform Firmware Resiliency Guidelines*, NIST SP 800-193, May 2018. https://csrc.nist.gov/pubs/sp/800/193/final (Protection/detection/recovery principles are primarily scoped to platform firmware.)

**[R24]** The Linux Kernel documentation. *Kernel module signing facility*. https://docs.kernel.org/admin-guide/module-signing.html

**[R25]** Linux manual pages. *kernel_lockdown(7): kernel image access prevention feature*. https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html

**[R26]** Linux Integrity documentation project. *IMA and EVM Concepts*. https://github.com/linux-integrity/ima-doc/blob/main/ima-concepts.rst (Distinguishes measurement, appraisal, and audit.)

**[R27]** IETF. *RFC 9683: Remote Integrity Verification of Network Devices Containing Trusted Platform Modules*, 2024. https://www.rfc-editor.org/rfc/rfc9683.html (TPM PCR, Quote, nonce, and event-log verification; architectural concepts also apply to appropriately equipped Linux hosts.)

**[R28]** The Linux Kernel documentation. *The Linux Watchdog driver API*. https://docs.kernel.org/watchdog/watchdog-api.html (Device behavior varies by hardware and driver.)

**[R29]** The Linux Kernel documentation. *Trusted and Encrypted Keys*. https://docs.kernel.org/security/keys/trusted-encrypted.html (TPM-bound keys and limitations of keys exposed to a compromised kernel.)

**[R30]** Keylime project. *Overview of Keylime*. https://keylime-docs.readthedocs.io/en/latest/design/overview.html (Example implementation pattern for remote TPM/IMA attestation; not a TEAL dependency.)

**[R31]** The Linux Kernel documentation. *The Linux Kernel threat model*. https://www.kernel.org/doc/html/latest/process/threat-model.html

## References: TEAL project documents

**[T1]** *TEAL System Implementation Architecture Specification, v2.2* (`TEALシステム実装構成仕様書_2_2.md`), 20 April 2026. Project-supplied architecture document; see sections on LSM flow, ticket binding, audit, and fail-safe behavior.

**[T2]** *Kernel-MPA / TEAL / TEAL-NET: Comprehensive Defensive Architecture* (`Kernel-MPA_TEAL_TEAL-NETによる総合防御アーキテクチャ.md`). Project-supplied design paper; see execution-stop barriers, MPA, control-plane isolation, and cloud/backup use cases. Its aspirational design should not be confused with implementation evidence.

**[T3]** *TEAL: Human-Gated Zero-Trust Execution Architecture* (`TEAL_short_paper.md`). Project-supplied short paper; see Alpha scope, LSM interception, Fast Path, future work, and limits.

**[T4]** *TEAL Performance Evaluation Report v2.0* (`TEAL_パフォーマンス評価報告書.md`). Project-supplied benchmark report; results apply only to the documented tested workload and policy configuration, not to any incident described here.
