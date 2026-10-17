## Installation & Development

This guide intentionally pins the build environment instead of supporting arbitrary kernel/Rust/bindgen combinations.
It has been verified with Ubuntu 24.04 LTS, Linux 6.8.12, LLVM/Clang 17, rustc 1.74.1, and bindgen-cli 0.65.1 installed via cargo.
Before building the kernel, run the following command from the top-level Linux kernel source tree.
The `O=../kernel_build_v6.8` option points to the external kernel build output directory.

```bash
cd ~/linux-6.8.12/
make LLVM=-17 O=../kernel_build_v6.8 rustavailable
```

If `make rustavailable` fails, treat the environment as unsupported for this quick install guide. Do not continue by mixing arbitrary Rust or bindgen versions; use the verified environment or prepare a separate build adaptation.

## Quick Install

TEAL is implemented as an experimental Linux Security Module (LSM) integrated into a custom Linux kernel build. This document describes a source-tree build for development and evaluation, not an out-of-tree DKMS installation.

### 1 Prerequisites

* OS: Ubuntu 24.04 LTS
* Kernel source: Linux 6.8.12
* Rust: version required by `scripts/min-tool-version.sh rustc` for the selected kernel
* LLVM/Clang: LLVM 17 / Clang 17
* SSH Server: OpenSSH Server (strongly recommended for remote administration, testing, and system recovery)
* Required packages:
  `build-essential`, `bc`, `bison`, `flex`, `libssl-dev`, `libelf-dev`, `dwarves`, `clang-17`, `llvm-17`, `lld-17`, `rustup`, `curl`, `wget`, `git`, `openssh-server`

### 2 Installation

First, install the necessary build tools (excluding Rust):

```bash
sudo apt update
sudo apt install -y \
  build-essential bc bison flex libssl-dev libelf-dev dwarves \
  clang-17 llvm-17 lld-17 curl wget git
```

Next, install rustup via the official installer to manage the Rust toolchain. When prompted, choose "1) Proceed with installation (default)".

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
rustup install stable
rustup default stable
cargo install bindgen-cli --version 0.65.1 --locked
```

Clone the repository:

```bash
cd ~
git clone https://github.com/toshiyuki-igarashi/TEAL.git
```

Download the Linux kernel source and copy the TEAL LSM components into the tree:

```bash
cd ~
# Download and extract Linux v6.8.12 source
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.8.12.tar.xz
tar -xf linux-6.8.12.tar.xz

# Copy TEAL modules to the kernel tree
cp -r ~/TEAL/kernel/security/teal ~/linux-6.8.12/security/
cp -r ~/TEAL/kernel/include/linux ~/linux-6.8.12/include/

cd ~/linux-6.8.12/
```

Register TEAL with the kernel build system (Kbuild):

* Edit and append to **`security/Kconfig`**:
  `source "security/teal/Kconfig"`
* Edit and append to the LSM list in **`security/Makefile`**:
  `obj-$(CONFIG_SECURITY_TEAL) += teal/`

Force the Rust version to `1.74.1` for **both the source and external build directories**. The C compiler will use **LLVM 17** to match the Rust backend.

```bash
# Verify and pin the required Rust version (1.74.1)
cd ~/linux-6.8.12
rustup override set $(scripts/min-tool-version.sh rustc)
rustup component add rust-src

# Set the version for the external build directory
mkdir ../kernel_build_v6.8
cd ../kernel_build_v6.8
rustup override set 1.74.1
```

Enable Rust and TEAL support via the configuration script:

```bash
cd ~/linux-6.8.12

# Generate default configuration
make LLVM=-17 O=../kernel_build_v6.8 defconfig

# Enable Rust and TEAL
./scripts/config --file ../kernel_build_v6.8/.config --enable CONFIG_RUST
./scripts/config --file ../kernel_build_v6.8/.config --enable CONFIG_SECURITY_TEAL
make LLVM=-17 O=../kernel_build_v6.8 olddefconfig
```

Enable TEAL in the LSM Initialization List

Check the generated kernel configuration and make sure that `teal` is included in `CONFIG_LSM`:

```bash
grep '^CONFIG_LSM=' ../kernel_build_v6.8/.config
```

The value should include `teal` exactly once, for example:

```text
CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor,bpf,teal"
```

If `teal` is missing, edit `../kernel_build_v6.8/.config` manually and append `teal` to the comma-separated list. Do not add it more than once.

Launch the menu configuration tool from the source directory to configure additional required kernel options:

```bash
cd ~/linux-6.8.12
make LLVM=-17 O=../kernel_build_v6.8 menuconfig
```

#### Enabling Required Security Options

Within the `menuconfig` interface (you can press the `/` key to search for specific items):

1. Select **`Security options`**.
2. Verify that **`Enable different security models`** (or direct `CONFIG_SECURITY` related entries) is enabled.
3. Locate **`Security hooks for pathname based access control`** (which corresponds to `CONFIG_SECURITY_PATH`) and enable it by ensuring it is marked as `[*]` or `<*>`.

### Optional: Enable Lock Debugging (Development Only)

When building a kernel for TEAL development and debugging, enable lock dependency checking to detect potential deadlocks, incorrect lock ordering, and other locking issues.

In `make menuconfig`:

1. Select **`Kernel hacking`**.
2. Select **`Lock Debugging (spinlocks, mutexes, etc...)`**.
3. Enable **`Lock debugging: prove locking correctness`** (`CONFIG_PROVE_LOCKING`) by setting it to `[*]`.

This option requires `CONFIG_DEBUG_KERNEL=y` and `CONFIG_LOCK_DEBUGGING_SUPPORT=y`. Enabling `CONFIG_PROVE_LOCKING` also enables related lock debugging features, including `LOCKDEP`, `DEBUG_SPINLOCK`, and `DEBUG_MUTEXES`.

**Note:** This option is recommended only for development and debugging builds, as it introduces runtime overhead. For production use and performance benchmarking, leave `CONFIG_PROVE_LOCKING` disabled (`n`).

Save your changes and exit the interface. When executing the build, ensure that you accept the default values for any unconfigured option prompts.

```bash
# Final build using LLVM 17
LIBCLANG_PATH=/usr/lib/llvm-17/lib make LLVM=-17 O=../kernel_build_v6.8 -j$(nproc)
```

#### Install Kernel and Modules

Install the compiled kernel and modules, then update the GRUB bootloader.

```bash
# Install modules
# Using LLVM=17 ensures consistency with the build environment
sudo make LLVM=-17 O=../kernel_build_v6.8 modules_install

# Install kernel
sudo make LLVM=-17 O=../kernel_build_v6.8 install

# Update GRUB to recognize the new kernel
sudo update-grub
```

#### Build and Install the `teald` Daemon

```bash
cd ~/TEAL/src

sudo apt update
sudo apt install pkg-config libtss2-dev  libpam0g-dev

rustup update
cargo build --release

# Deploy binaries with correct ownership (root) and permissions (755)
sudo install -o root -g root -m 0755 target/release/libpam_teal.so /lib/x86_64-linux-gnu/security/pam_teal.so
sudo install -o root -g root -m 0755 target/release/teald /usr/local/sbin/
sudo install -o root -g root -m 0755 target/release/teal-cli /usr/local/bin/
sudo install -o root -g root -m 0755 target/release/teal-logview /usr/local/bin/
sudo install -o root -g root -m 0755 target/release/teal-bench /usr/local/bin/
```

#### Initialize Configuration Directory & Skeleton Files

Before starting the daemon, the required configuration paths and fixed skeleton files must exist to prevent the core parser from failing on startup.

> **NOTICE:** The following configuration files deploy a pragmatic reference scenario where the root user (`admin`) can control execution states, but engine termination (`stop`) mandates Multi-Party Authorization (MPA) from a Security Officer. **Please adjust these logic structure values according to your specific target deployment system environment and organizational controls.** All generated skeletons strictly conform to TEAL v1.0 and v1.4 strict validation schemas.

```bash
# Create the structural hierarchy
sudo mkdir -p /etc/teal.d/policies
sudo mkdir -p /var/log/teal
sudo mkdir -p /var/lib/teal/epochs

# 1. Deploy Management Policy (Enforces teal-cli start/stop & MPA conditions)
sudo tee /etc/teal.d/management.json >/dev/null <<'EOF'
{
  "roles": [
    {
      "name": "admin",
      "uids": [0],
      "description": "System Root Administrator"
    },
    {
      "name": "security_officer",
      "uids": [1000],
      "description": "Designated Operational Security Approver"
    }
  ],
  "controls": {
    "start": {
      "description": "Initiate TEAL core execution engine",
      "initiator_roles": ["admin"],
      "mpa": {
        "enabled": false
      }
    },
    "stop": {
      "description": "Terminate TEAL core execution engine protection loop",
      "initiator_roles": ["admin"],
      "mpa": {
        "enabled": true,
        "threshold": 1,
        "approver_roles": ["security_officer"],
        "timeout_minutes": 30
      }
    }
  }
}
EOF

# 2. Deploy Bundle Entrypoint Loader (Conforms to bundle_v1_0.schema.json)
sudo tee /etc/teal.d/bundle.json >/dev/null <<'EOF'
{
  "schema_version": "1.0",
  "name": "PoC Baseline Bundle",
  "policy_files": [
    "00-base.json"
  ]
}
EOF

# 3. Initialize Roles Map Definition (Conforms to roles_v1_0.schema.json)
sudo tee /etc/teal.d/roles.json >/dev/null <<'EOF'
{
  "schema_version": "1.0",
  "roles": [
    {
      "name": "user",
      "description": "Normal user."
    },
    {
      "name": "admin",
      "description": "Normal operator who can request privileged actions."
    },
    {
      "name": "security_officer",
      "description": "Can approve requests (general approver)."
    }
  ],
  "assignments": [
    { "uid":    0, "roles": [ "admin", "user" ] },
    { "uid": 1000, "roles": [ "security_officer", "user" ] }
  ],
  "group_assignments": [],
  "defaults": {
    "roles_for_unknown_user": [ "user" ],
    "deny_if_role_unknown": false
  }
}
EOF

# 4. Deploy Base Policy Rule Example (Conforms to policy_v1_3.schema.json)
sudo tee /etc/teal.d/policies/00-base.json >/dev/null <<'EOF'
{
  "version": "1.4",
  "system_type": "workstation",
  "default_effect": "allow",
  "default_reason": "No matching rule; default allow.",
  "ttl_minutes": 10,
  "sweep_minutes": 5,
  "pre_approval_defaults": { 
    "ttl_sec_default": 600, 
    "ttl_sec_max": 900 
  },
  "rules": [
    {
      "id": "protect-etc-shadow",
      "subject": {
        "roles": ["admin"]
      },
      "object": {
        "path": "/etc/shadow"
      },
      "action": {
        "ops": ["READ"]
      },
      "effect": "need_approval",
      "mpa": {
        "threshold": 1,
        "approver_roles": ["security_officer"]
      },
      "reason": "Reading /etc/shadow requires explicit approval."
    }
  ]
}
EOF

# 5. Enable TEAL PAM Module for System-Wide Session Tracking
# This hooks TEAL into sshd, login, and sudo
# Ensure we don't append it multiple times

# --- A. common-session (セッション管理) の設定 ---
if ! grep -q "pam_teal.so" /etc/pam.d/common-session; then
  echo "session optional pam_teal.so" | sudo tee -a /etc/pam.d/common-session >/dev/null
  echo "TEAL PAM module enabled in /etc/pam.d/common-session"
else
  echo "TEAL PAM module already configured in /etc/pam.d/common-session"
fi

# --- B. common-auth (認証管理) の設定 ---
# 独立した if 文に分けることで、common-session だけが設定済みの既存環境でも確実に追記されます
if ! grep -q "pam_teal.so" /etc/pam.d/common-auth; then
  echo "auth optional pam_teal.so" | sudo tee -a /etc/pam.d/common-auth >/dev/null
  echo "TEAL PAM module enabled in /etc/pam.d/common-auth"
else
  echo "TEAL PAM module already configured in /etc/pam.d/common-auth"
fi
```

##### Configuration & Policy Directory Structure

TEAL processes rules using a structured, multi-layered directory design. Except for individual dynamic policy files inside the sub-directories, **all core file and directory names are strictly fixed**.

```text
/etc/teal.d/
├── bundle.json          # FIXED: Top-level entrypoint mapping active policy targets [schema v1.0]
├── management.json      # FIXED: Management Governance Policy (Governs teal-cli start/stop & MPA)
├── policies/            # FIXED: Target storage directory for granular policy rules
│   └── 00-base.json     # DYNAMIC: Arbitrary policy file specified inside bundle.json array [schema v1.4]
└── roles.json           # FIXED: Standard role assignments registry file [schema v1.0]
```

##### Configuration Component Definitions

* **`bundle.json` (Fixed Name):** The foundational configuration loader validation profile. It specifies the schema version tracking metadata along with an array list of target JSON files stored within the `policies/` directory that must be dynamically interpreted and locked into the engine state.
* **`management.json` (Fixed Name):** **The Management Governance Policy.** This crucial file controls the execution authorization for administrative commands (`teal-cli start` and `teal-cli stop`). It explicitly defines which system UIDs map to administrative management roles, who can initiate state changes, and what Multi-Party Authorization (MPA) thresholds (e.g., specific approver roles and quorum size) are required to execute them.
* **`policies/` Directory:** Holds your granular runtime interception domain logic. Files here use arbitrary string names matching the schema constraints (e.g., `00-base.json`), specified by their direct names within the `bundle.json` targets tracking array.
* **`roles.json` (Fixed Path & Name):** Defines administrative Subject-to-Role mappings, system assignment constraints, default roles for unmapped system entities, and fallback enforcement modes.

#### Create a systemd Service for `teald`

Create a systemd unit file for the `teald` authorization daemon:

```bash
sudo tee /etc/systemd/system/teald.service >/dev/null <<'EOF'
[Unit]
Description=TEAL authorization daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/teald
Restart=always
Nice=-20
RestartSec=2
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now teald
```

#### Kernel Switch & Boot Preparation

Before starting the daemon, you must boot into the newly compiled TEAL kernel.

**1. Secure Boot Considerations**
If your system has UEFI Secure Boot enabled, you must either sign the newly compiled kernel and modules with your Machine Owner Key (MOK) or temporarily disable Secure Boot in the BIOS/UEFI settings for this PoC.

**2. GRUB Configuration (`/etc/default/grub`)**
To ensure TEAL operates without interference from other default LSMs (like AppArmor) and to ensure you can easily boot back into your original stock kernel if needed, update your GRUB configuration. *(An example configuration is provided at `examples/grub` in the repository).*

Modify `/etc/default/grub` to include:

```text
# Display the boot menu for easy fallback
GRUB_TIMEOUT_STYLE=menu
GRUB_TIMEOUT=5

# Isolate TEAL as the only active LSM
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=teal"
```

After editing, apply the changes:

```bash
sudo update-grub
```

**3. Advanced Example Policies (Log Storm Prevention)**
For production-like high-load environments, refer to `examples/01-bundle.json` and `examples/02-bundle.json`. These examples demonstrate how to correctly configure `silent_io` and inheritance settings to avoid audit log storms.

**4. Reboot the System**
Reboot and select the newly compiled TEAL kernel from the GRUB menu.

```bash
sudo reboot
```

### 3 Starting the Daemon

Launch `teald`, which serves as the core authorization engine:

```bash
sudo systemctl start teald
```

Check that the daemon is running:

```bash
sudo systemctl status teald --no-pager
```

View the systemd journal if needed:

```bash
journalctl -u teald -f
```

Verify TEAL operation via logs:

```bash
teal-logview tail
```

#### Optional: Build Alloy-based Policy Verifier

```bash
cd ~/TEAL/src/alloy-cli
wget https://github.com/AlloyTools/org.alloytools.alloy/releases/download/v6.2.0/org.alloytools.alloy.dist.jar -O alloy.jar

# Compile using the downloaded alloy.jar
javac -cp alloy.jar AlloyCli.java

# Create the executable wrapper JAR
jar cvfm alloy-cli.jar manifest.txt AlloyCli*.class

# Set up local library and copy files
mkdir -p $HOME/.local/lib/teal
cp alloy-cli.jar alloy.jar $HOME/.local/lib/teal/

# Persist the environment variable
if ! grep -q "TEAL_ALLOY_JAR" ~/.bashrc; then
  echo 'export TEAL_ALLOY_JAR="$HOME/.local/lib/teal/alloy-cli.jar"' >> ~/.bashrc
  source ~/.bashrc
fi
```

---

### Appendix: Advanced Configuration & Troubleshooting

#### A. Kernel Pinning (Preventing Overwrites)

To prevent the OS package manager (`apt`) from automatically overriding your default boot entry with a standard distribution kernel update, configure GRUB to remember your last kernel choice:

```text
# In /etc/default/grub
GRUB_DEFAULT=saved
GRUB_SAVEDEFAULT=true
```

*(Run `sudo update-grub` after modifying).*

#### B. Log Rotation

In Audit mode, TEAL may generate a significant volume of logs. To prevent disk space exhaustion, configure `logrotate` for the TEAL log directory.
Create a file at `/etc/logrotate.d/teal`:

```text
/var/log/teal/*.jsonl {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
```

#### C. Kernel Signing with Machine Owner Key (MOK)

If you need to sign the kernel in an Ubuntu/Xubuntu environment due to UEFI Secure Boot, follow the procedures below.

**Step 1: Generate and Import the MOK**

```bash
# 1. Create the private key (MOK.priv) and PEM certificate (MOK.pem) in one step
openssl req -new -x509 -newkey rsa:2048 -keyout MOK.priv -out MOK.pem -nodes -days 3650 -subj "/CN=TEAL Verification Key/"

# 2. Generate DER format (MOK.der) from PEM to import into mokutil
openssl x509 -in MOK.pem -outform DER -out MOK.der

# 3. Sign the kernel (using PEM)
sudo sbsign --key MOK.priv --cert MOK.pem /boot/vmlinuz-6.8.12 --output /boot/vmlinuz-6.8.12

# 4. Schedule the key for enrollment in UEFI (using DER)
sudo mokutil --import MOK.der
```

When executing `mokutil`, you will be prompted for passwords in two distinct stages.

* **Stage 1: `[sudo] password for <user>:**`

* **What to enter:** Your standard Ubuntu (Xubuntu) **login password**.

* **Reason:** Required to execute the command with administrator (root) privileges.

* **Stage 2: `input password:` and `Confirm password:**`

* **What to enter:** A **new, temporary password** of your choosing.

* **Reason:** This one-time password is used to verify your identity on the "MOK manager" (blue screen) that appears right after rebooting, before the OS boots. You must enter it twice.

> **Crucial Warning for the MOK Password (Stage 2)**
> The UEFI screen (blue screen) after reboot frequently defaults to a "US (English) layout". If you use symbols like `@` or `_` assuming a JIS (Japanese) layout, you may be unable to type them correctly, resulting in authentication failure.
> **Recommendation:** To prevent lockout, set a password using **"only numbers (e.g., 12345678)" or "only simple lowercase letters"**. This password is a throwaway used merely to enroll the key into the firmware, so high cryptographic strength is unnecessary here.

**Step 2: Reboot and Enroll the Key in UEFI**

Upon restarting the PC, before the OS (GRUB) boots, a blue screen titled **"Perform MOK management"** will appear.

1. Select **`Enroll MOK`**. *(Note: Do not select `Continue boot`, or the menu will disappear).*
2. Select **`View key 0`** to inspect the key details if desired, then select **`Continue`** to proceed.
3. When prompted with **`Enroll the key(s)?`**, select **`Yes`**.
4. When **`Password:`** appears, enter the **temporary password** you created in Stage 2, and press Enter.
   *(Note: As you type, the screen will remain completely blank without `*` characters, but your keystrokes are being registered).*
5. Finally, select **`Reboot`**.

#### D. Installing Ollama on Ubuntu Linux for TEAL

This guide describes how to install Ollama, download a local language model, and verify its operation for TEAL's AI-based anomaly detection experiments.

**1. System Requirements**

- Ubuntu 24.04 or another supported Linux distribution
- x86-64 processor
- RAM: 8 GB recommended for TEAL development and CPU-only inference experiments with `qwen3:1.7b`.
- Actual memory requirements depend on the model, context length, and runtime configuration.
- A dedicated GPU is optional; CPU-only inference is supported.
- Internet connection for installation and model downloads

TEAL's initial experiments use `qwen3:1.7b`, a relatively small language model suitable for testing on machines without a dedicated GPU.

**2. Install Ollama**

Download the official installation script:

```bash
curl -fsSL https://ollama.com/install.sh -o ollama-install.sh
```

Review the script if required, then execute it:

```bash
sh ollama-install.sh
```

Alternatively, install Ollama directly:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

The installation normally configures Ollama as a systemd service.

Verify the installation:

```bash
ollama --version
```

**3. Start and Verify the Ollama Service**

Start Ollama:

```bash
sudo systemctl start ollama
```

Enable automatic startup:

```bash
sudo systemctl enable ollama
```

Check the service status:

```bash
systemctl status ollama
```

Verify that the HTTP API is available:

```bash
curl http://127.0.0.1:11434/api/tags
```

A successful response contains a JSON object with a `models` array.

By default, the local Ollama API is accessible at:

```
http://127.0.0.1:11434
```

**4. Download the Language Model**

Download the model used for TEAL's initial experiments:

```bash
ollama pull qwen3:1.7b
```

Verify that the model has been downloaded:

```bash
ollama list
```

Run the model interactively:

```bash
ollama run qwen3:1.7b
```

Enter a simple question to verify that the model responds.

Type `/bye` to exit the interactive session.

**5. Test the Ollama HTTP API**

TEAL communicates with Ollama using the `/api/chat` endpoint.

Execute the following command:

```bash
curl http://127.0.0.1:11434/api/chat \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen3:1.7b",
    "stream": false,
    "think": false,
    "format": "json",
    "messages": [
      {
        "role": "system",
        "content": "You are a Linux security analyst. Return JSON only."
      },
      {
        "role": "user",
        "content": "Analyze this event: root renamed /data/test.txt to /data/test.enc. Return a JSON object with an anomalies array."
      }
    ],
    "options": {
      "num_ctx": 4096,
      "num_predict": 256
    }
  }'
```

The API should return a JSON response containing the model's generated message in `message.content`.

The response also includes performance information, such as:

- `prompt_eval_count`: Number of input tokens
- `eval_count`: Number of generated tokens
- `prompt_eval_duration`: Input processing time
- `eval_duration`: Output generation time
- `total_duration`: Total processing time

Timing values are expressed in nanoseconds.

**Note:** This example is intended only to verify basic communication with the Ollama HTTP API.

TEAL's Ollama adapter uses JSON Schema-based structured outputs to validate anomaly reports, including severity, confidence scores, and evidence event IDs. The actual request format is defined in `teald/src/ai/adapters/ollama.rs`.

**6. Monitor Model Execution**

Display loaded models:

```bash
ollama ps
```

This command shows the model name, memory usage, processing device, and context size.

Check system memory:

```bash
free -h
```

Monitor CPU and memory usage:

```bash
top
```

For detailed Ollama service logs:

```bash
sudo journalctl -u ollama -f
```

To display recent logs:

```bash
sudo journalctl -u ollama -n 100 --no-pager
```

**7. Run TEAL's Ollama Integration Tests**

After installing Ollama and downloading `qwen3:1.7b`, navigate to the TEAL source directory:

```bash
cd ~/TEAL/src
```

Execute the basic integration test:

```bash
cargo test -p teald test_ollama_integration -- --ignored --nocapture
```

Execute the mass file-rename anomaly detection test:

```bash
cargo test -p teald test_ollama_mass_rename -- --ignored --nocapture
```

These tests verify communication between the TEAL AI analysis engine and the local Ollama server.

The tests are marked `#[ignore]` because they require a running Ollama service and a downloaded model.

**8. Notes on CPU-Only Execution**

Ollama can run without dedicated GPU hardware.

However, CPU-only inference may be relatively slow, especially when analyzing large audit-event batches.

During initial TEAL experiments on a CPU-only laptop with approximately 8 GB of RAM, `qwen3:1.7b` successfully analyzed 20 file-rename events using JSON Schema-based structured outputs.

The analysis required approximately 134 seconds, including about 87 seconds for prompt processing and 41 seconds for response generation.

These figures are preliminary measurements from a development laptop, not representative performance benchmarks. Further performance evaluation will be conducted on a dedicated test machine.

For larger experiments, a faster CPU or supported GPU is recommended.

TEAL's anomaly detection logic can be developed and tested independently of inference performance using `MockAdapter`.

##### Version Recording for Reproducible Experiments

Before running performance or accuracy benchmarks, record the installed Ollama version and model information:

```bash
ollama --version
ollama list
ollama show qwen3:1.7b
```

Record these details together with the TEAL Git commit, CPU configuration, available RAM, context length, and generation options.

For reproducible experiments, avoid upgrading Ollama or replacing the model during a benchmark series.

**9. Updating Ollama**

To update Ollama, rerun the official installation script:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Verify the installed version:

```bash
ollama --version
```

**10. References**

- [Ollama Official Website](https://ollama.com/)
- [Ollama Linux Installation Guide](https://docs.ollama.com/linux)
- [Ollama Chat API Documentation](https://docs.ollama.com/api/chat)

---

**Note:** Ollama is used as an optional AI analysis provider in TEAL. AI-generated anomaly assessments are advisory and do not directly authorize or deny Linux system operations.

#### E. Troubleshooting

If TEAL fails to start or the system becomes unstable, follow these steps:

1. **Daemon Initialization Failure:**
   Check the `teald` logs using `sudo journalctl -u teald -f`. TEAL enforces strict JSON schema validation. A single syntax error or missing bracket in `/etc/teal.d/` will cause the daemon to refuse startup for safety reasons.
2. **Boot Loops or Kernel Panics:**
   Hard reboot the machine, hold `Shift` or `Esc` to access the GRUB menu, and select your original stock Ubuntu kernel (e.g., 6.8.0-xx-generic) to recover the system.
3. **Module Loading Issues:**
   Run `dmesg | grep -i teal` to check for kernel-level initialization errors, LSM registration failures, or Fast Path cache allocation issues.
