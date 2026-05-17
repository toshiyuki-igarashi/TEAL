## Installation & Development

This guide intentionally pins the build environment instead of supporting arbitrary kernel/Rust/bindgen combinations.
It has been verified with Ubuntu 24.04 LTS, Linux 6.8.12, LLVM/Clang 17, rustc 1.74.1, and the distribution-provided `rust-bindgen`.
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
* Required packages:
  `build-essential`, `bc`, `bison`, `flex`, `libssl-dev`, `libelf-dev`, `dwarves`, `clang-17`, `llvm-17`, `lld-17`, `rustup`, `curl`, `wget`, `git`

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
```

Clone the repository:

```bash
cd ~
git clone https://github.com/toshiyuki/TEAL.git

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
````

The value should include `teal` exactly once, for example:

```text
CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor,bpf,teal"
```

If `teal` is missing, edit `../kernel_build_v6.8/.config` manually and append `teal` to the comma-separated list. Do not add it more than once.

```bash
# Final build using LLVM 17
make LLVM=-17 O=../kernel_build_v6.8 -j$(nproc)

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
cd ~/TEAL/
cargo build --release

# Deploy binaries with correct ownership (root) and permissions (755)
sudo install -o root -g root -m 0755 target/release/teald /usr/local/sbin/
sudo install -o root -g root -m 0755 target/release/teal-cli /usr/local/bin/
sudo install -o root -g root -m 0755 target/release/teal-logview /usr/local/bin/
sudo install -o root -g root -m 0755 target/release/teal-bench /usr/local/bin/

```

#### Initialize Configuration Directory & Skeleton Files

Before starting the daemon, the required configuration paths and fixed skeleton files must exist to prevent the core parser from failing on startup.

> **NOTICE:** The following configuration files deploy a pragmatic reference scenario where the root user (`admin`) can control execution states, but engine termination (`stop`) mandates Multi-Party Authorization (MPA) from a Security Officer. **Please adjust these logic structure values according to your specific target deployment system environment and organizational controls.** All generated skeletons strictly conform to TEAL v1.0 and v1.3 strict validation schemas.

```bash
# Create the structural hierarchy
sudo mkdir -p /etc/teal.d/policies
sudo mkdir -p /etc/teal.d/roles

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
sudo tee /etc/teal.d/roles/roles.json >/dev/null <<'EOF'
{
  "schema_version": "1.0",
  "roles": [
    {
      "name": "default_user_role",
      "description": "Baseline unprivileged execution domain",
      "tags": ["standard"],
      "permissions": ["generic_read"]
    }
  ],
  "assignments": [],
  "group_assignments": [],
  "defaults": {
    "roles_for_unknown_user": [
      "default_user_role"
    ],
    "deny_if_role_unknown": false
  }
}
EOF

# 4. Deploy Base Policy Rule Example (Conforms to policy_v1_3.schema.json)
sudo tee /etc/teal.d/policies/00-base.json >/dev/null <<'EOF'
{
  "version": "1.3",
  "ttl_minutes": 60,
  "sweep_minutes": 10,
  "rules": [
    {
      "id": "rule-protect-shadow-file",
      "rule_type": "standard",
      "subject": {},
      "object": {
        "path": "/etc/shadow"
      },
      "action": {
        "ops": ["file_read"]
      },
      "effect": "need_approval",
      "required_roles": [
        "security_officer"
      ],
      "threshold": 1,
      "ticket_profile": {
        "silent_io": true,
        "inherit": true
      }
    }
  ]
}
EOF

```

##### Configuration & Policy Directory Structure

TEAL processes rules using a structured, multi-layered directory design. Except for individual dynamic policy files inside the sub-directories, **all core file and directory names are strictly fixed**.

```text
/etc/teal.d/
├── bundle.json          # FIXED: Top-level entrypoint mapping active policy targets [schema v1.0]
├── management.json      # FIXED: Management Governance Policy (Governs teal-cli start/stop & MPA)
├── policies/            # FIXED: Target storage directory for granular policy rules
│   └── 00-base.json     # DYNAMIC: Arbitrary policy file specified inside bundle.json array [schema v1.3]
└── roles/               # FIXED: Target storage directory for system user roles mapping
    └── roles.json       # FIXED: Standard role assignments registry file [schema v1.0]

```

##### Configuration Component Definitions

* **`bundle.json` (Fixed Name):** The foundational configuration loader validation profile. It specifies the schema version tracking metadata along with an array list of target JSON files stored within the `policies/` directory that must be dynamically interpreted and locked into the engine state.
* **`management.json` (Fixed Name):** **The Management Governance Policy.** This crucial file controls the execution authorization for administrative commands (`teal-cli start` and `teal-cli stop`). It explicitly defines which system UIDs map to administrative management roles, who can initiate state changes, and what Multi-Party Authorization (MPA) thresholds (e.g., specific approver roles and quorum size) are required to execute them.
* **`policies/` Directory:** Holds your granular runtime interception domain logic. Files here use arbitrary string names matching the schema constraints (e.g., `00-base.json`), specified by their direct names within the `bundle.json` targets tracking array.
* **`roles/roles.json` (Fixed Path & Name):** Defines administrative Subject-to-Role mappings, system assignment constraints, default roles for unmapped system entities, and fallback enforcement modes.

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
RestartSec=2
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now teald

```

### 3 Starting the Daemon

Launch `teald`, which serves as the core authorization engine:

```bash
sudo systemctl start teald
````

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
