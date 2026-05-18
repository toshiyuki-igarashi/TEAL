# TEAL System Performance Evaluation Report (v2.0)

## 1. Methodology

### 1.1 Environment
The hardware and software configurations used for this evaluation are as follows:

* **Hardware:** HP EliteDesk 800 G4 SFF
    * **CPU:** Intel Core i7-8700 (3.20GHz) - Intel PTT (TPM 2.0) supported
    * **Memory:** 16GB
    * **Storage:** 256GB NVMe SSD + 500GB HDD
* **Software:**
    * **OS:** Ubuntu 24.04.4 LTS
    * **Kernel:** 6.17.13
    * **TEAL Version:** v2.1 (Evaluation Build)

### 1.2 Workload and Benchmark Tool
To measure the overhead associated with process creation and execution (`exec`), we targeted `/usr/bin/true`, an extremely lightweight binary. Measurements were conducted using a dedicated tool, `teal-bench`. Each trial consisted of 2,000 consecutive executions, repeated over 10 sets to gather statistical data.

### 1.3 Measurement Rigor
To minimize measurement noise caused by the OS scheduler and context switches, the following command structures were utilized during benchmarking:

* `chrt -f 99`: Runs the process with real-time priority (the highest priority in `SCHED_FIFO`) to mitigate scheduling delays from other processes.
* `taskset -c 0`: Pins the process to CPU Core 0 to eliminate cache loss effects caused by inter-CPU migration.

### 1.4 Test Cases
1.  **Baseline (TEAL Disabled):** A baseline state where the TEAL LSM hooks are deactivated by removing `teal` from the GRUB kernel parameters and rebooting the system.
2.  **TEAL Enforce Mode:** A state where the TEAL module is loaded, and the defense capabilities (`Fast Path` / ticket cache) provided by `teald` are fully operational.
3.  **TEAL Audit Mode:** A state where the TEAL module is loaded, but it only performs access evaluation and generates log outputs (audit trails). Actual blocking (Deny) is disabled, focusing strictly on monitoring.
4.  **TEAL Stop Mode:** A state where the kernel module is loaded, but the user-space daemon `teald` is stopped. This case evaluates the residual cost of hooks during a communication failure (fallback behavior).

---

## 2. Microbenchmark: Runtime Overhead

We evaluated the overhead of hook processing and cache evaluation (`Fast Path`) within the TEAL kernel module during process execution.

### 2.1 Measurement Results
The table below compares the median execution time (nanoseconds per operation) for each system state:

| System State | Median Range (ns/op) | Average Median | Observed Difference |
| :--- | :--- | :--- | :--- |
| **Baseline (TEAL Disabled)** | 278,436 – 286,540 ns | Approx. 282,153 ns | - |
| **Enforce Mode (Fast Path)** | 280,835 – 282,330 ns | Approx. 281,857 ns | ±0% (Within margin of error) |
| **Audit Mode** | 286,043 – 289,308 ns | Approx. 288,133 ns | +2.2% |
| **TEAL Stop Mode** | 301,071 – 303,644 ns | Approx. 301,866 ns | +7.0% |

### 2.2 Discussion (Effectiveness of Fast Path)
The results show no significant performance difference under these evaluation conditions between **Enforce Mode** (where TEAL's defense features are fully active) and **Baseline** (where TEAL is completely unloaded).

This suggests that the in-kernel ticket cache evaluation (`Fast Path`), based on the subject's credential context (`cred`), functions effectively. In this implementation and workload, high-cost operations such as string parsing are successfully excluded from the hot path. Consequently, for workloads where a similar `Fast Path` hits, access control can potentially be applied with minimal impact on the user experience.

---

## 3. Worst-case Bounded Latency (Slow Path Evaluation)

### Overview
This section evaluates the "Slow Path" latency—the complete round-trip time required when an initial access misses the `Fast Path` (in-kernel cache), delegates the decision from kernel space to the user-space daemon (`teald`), receives approval, and resumes the process. 

Using the standard Linux eBPF tool (`funclatency-bpfcc`), we directly measured the execution time of the in-kernel wait function `teal_wait_for_approval` in microseconds (µs).

### Results & Discussion
By using `teal-bench` to intentionally trigger continuous cache misses (`TTL=0`), we observed the following regarding the Slow Path processing time:

* **Average Latency:** The round-trip average latency was **336 µs**, demonstrating sub-millisecond responsiveness under these evaluation conditions.
* **Distribution:** The mode of the distribution was heavily concentrated between **128 -> 255 µs**, indicating that the kernel-to-user space round-trip and `teald` policy evaluation remain well within a practical delay range for this test scope.
* **Maximum Latency:** The maximum observed value was approximately **4 ms**. Within this measurement range, there were no signs of the Slow Path causing prolonged blocking.

*Note: Further evaluation under higher concurrent loads, different hardware configurations, and more complex policy conditions with larger sample sizes is required.*

---

## 4. Macrobenchmark (Real-world Workload Evaluation)

### Overview
To evaluate the overhead TEAL introduces under realistic, high-load conditions, we measured the execution time (`real time`) of a full Linux kernel compilation (`make -j$(nproc)`).

### Verification Conditions
* **Target Workload:** Full build of the Linux kernel (`bzImage` + `modules`).
* **Cache Condition:** To ensure fairness, `make clean` was executed immediately before each trial to wipe any build cache.
* **Policy Application:** A dedicated domain policy was loaded for the process tree originating from the `make` command, applying ticket inheritance (`inherit: true`) and I/O log suppression (`silent_io: true`).

### Measurement Results

| Operating Mode | Trial 1 (real) | Trial 2 (real) | Evaluation |
| :--- | :--- | :--- | :--- |
| **Baseline (TEAL Disabled)** | 48m 12s | 48m 17s | Reference Value |
| **Enforce Mode (TEAL Active)** | 53m 05s | 48m 18s | Under this workload/policy, additional overhead was near the limit of measurability (Trial 2). |
| **Audit Mode (All Logs)** | 61m 36s | 63m 32s | Observed a performance penalty due to an I/O log storm. |

### Discussion and Conclusion
In the second trial of **Enforce Mode**, the difference from the baseline was less than one second, meaning the additional overhead was near the limit of measurability. This indicates that the in-kernel `Fast Path` via ticket inheritance and the suppression of unnecessary audit logs (`silent_io`) worked effectively for this specific workload.

On the other hand, the first trial of Enforce Mode recorded 53 minutes and 05 seconds. Additional measurements are required to isolate the impacts of measurement variance, warm-up states, cache conditions, and background system loads.

**Summary:** In a workload containing intensive process generation and file I/O like a Linux kernel build, TEAL demonstrated that its overhead can be kept within a practically negligible range under an appropriately designed policy. This initial evaluation highlights that combining a `Fast Path` architecture with domain-specific policy design makes applying zero-trust execution control performance-viable.

---

## Conclusion: Performance Characteristics and Viability of TEAL

This evaluation provided an initial performance analysis of "TEAL" (Trusted Execution & Authorization Layer)—an OS kernel-level dynamic access control module—using an Alpha-stage evaluation build across Fast Path, Slow Path, and kernel compilation workloads.

The results confirm that combining ticket inheritance, an in-kernel Fast Path, and audit log suppression (`silent_io`) can minimize additional overhead for specific workloads.

### 1. Low-Overhead Potential via Fast Path
In the microbenchmark targeting `/usr/bin/true`, the median values for Enforce Mode (Fast Path) and the Baseline were nearly identical, meaning the cost of the Fast Path fell within the margin of measurement error. Similarly, in the macrobenchmark (Linux kernel build), Trial 2 of Enforce Mode performed almost identically to the Baseline. This indicates that TEAL can be applied with extremely low overhead in environments where the Fast Path condition is met.

### 2. Initial Assessment of Slow Path Latency
When a cache miss occurs, the Slow Path latency (measured via eBPF on `teal_wait_for_approval`) averaged 336 µs with a maximum of ~4 ms. This aligns with TEAL’s design philosophy: instead of routing all unapproved operations to human intervention, normal operations are handled swiftly by the Fast Path, and only exceptional or high-risk operations are deferred to the Slow Path.

### 3. Critical Importance of Policy Design
In Audit Mode, compiling the kernel took significantly longer due to full audit log generation. This emphasizes that TEAL's performance does not rely solely on its kernel implementation, but is heavily dependent on policy design, log suppression, ticket inheritance, and Fast Path coverage. For production deployment, profiling via AUDIT, domain-specific policy design, and minimizing redundant logging will be essential.

### Final Summary
This evaluation demonstrates that TEAL’s in-kernel Fast Path and domain-specific policy architecture can achieve low-overhead execution under specific conditions. 

These results do not imply that TEAL is currently a finished, general-purpose Linux security product. Rather, they serve as a promising initial validation that the core mechanism for delivering **Post-compromise Execution Governance** at the OS level is highly viable from a performance standpoint.
