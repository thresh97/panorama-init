# Panorama Virtual VM Initial Provisioning CLI

A Python CLI tool designed to idempotently bootstrap and provision a Palo Alto Networks Panorama Virtual Machine.

Due to the nature of Panorama deployments (long boot times, multiple management server restarts when applying licenses/certificates), traditional automation tools can sometimes struggle or falsely report failures. This script tracks its progress locally in a JSON state file. If a network timeout occurs or the Panorama web server restarts mid-flight, you can safely re-run the exact same command, and the script will pick up exactly where it left off.

## Why This Was Built (The Bootstrapping Dilemma)

When deploying Palo Alto Networks software firewalls (VM-Series and Cloud NGFW) at scale, it's common practice to bootstrap them directly to a Panorama management server. However, this creates a strict dependency: Panorama *must* exist and be fully operational *prior* to the firewalls being provisioned.

Attempting to deploy the Panorama VM and the software firewalls simultaneously in a single Infrastructure-as-Code (IaC) pipeline (like Terraform or CloudFormation) creates race conditions that are nearly impossible to resolve natively. The firewalls will boot up, attempt to connect to Panorama, and fail because Panorama is still initializing, rebooting to apply its license, or missing necessary routing/cloud plugins.

This script does the heavy lifting required to solve this problem, enabling a robust, serialized deployment strategy:

1. **Deploy Panorama VM:** Spin up the base Panorama virtual appliance via your IaC tool of choice.
2. **Provision Panorama (This Script):** Run this tool to handle the messy, reboot-heavy phases — applying licenses, fetching device certificates, generating VM auth keys, and installing required plugins (like SD-WAN or Cloud Services).
3. **Configure Panorama Base Policy:** Push the foundational Device Groups (DG) and Template Stacks to the now-ready Panorama (via Terraform, Ansible, or PAN-OS Python).
4. **Deploy Software Firewalls:** Finally, deploy the VM-Series or Cloud NGFW instances. They will successfully bootstrap, connect to Panorama, and pull down their assigned configurations without issue.

### Why Python and not Ansible?
While it would probably be best to handle this multi-step, stateful process natively within Ansible, this script was built as a "quick and dirty" alternative. It serves as a lightweight, stand-alone tool that is arguably much easier to read, run, and debug in isolation than a more complex and fully integrated Ansible playbook configuration.

### Why raw XML API instead of `pan-os-python`?
Similarly, utilizing the official `pan-os-python` SDK would normally be the most appropriate and robust way to interact with PAN-OS programmatically. However, this script relies strictly on raw Python `urllib` XML API calls. This was a deliberate design choice: `pan-os-python` occasionally auto-wraps XML payloads in ways that PAN-OS rejects for very specific, low-level operational commands (like setting a serial number or downloading specific plugin versions). Using raw XML gives us the explicit, character-for-character control required for these early bootstrapping tasks without requiring external dependencies.

---

## Features

- **SSH Bootstrapping:** Connects via SSH (key-based or password fallback via ENV) to disable CLI pagination, verify system readiness, set an initial API password, and perform the initial config commit.
- **Idempotent State Tracking:** Generates a `panorama-<ip>-state.json` file to track the success of every step. Automatically discovers existing state files in the current directory on re-runs.
- **Licensing & Certificates:** Sets the Panorama serial number, configures the CSP API Key, and fetches a Device Certificate via OTP using the XML API.
- **Dynamic Updates:** Downloads and installs the latest Content and Anti-Virus definitions. Skips download if already at latest version.
- **Plugin Management:** Checks existing installed plugins and sequentially downloads and installs a comma-separated list of required Panorama plugins. Skips plugins already present.
- **VM Auth Key Generation:** Generates a VM Auth Key with a configurable lifetime (default 1 year) for bootstrapping managed firewalls.
- **PAN-OS Upgrade:** Downloads, installs, and waits through reboots to upgrade Panorama to a specified version or the latest in the current major.minor family.
- **Live Idempotency Checks:** Before sending any potentially disruptive command (serial number set, commit, content/AV download), the script first queries the device's live state and skips the step if it is already complete — even without a state file.

---

## Firewall Licensing: Two Approaches

This is the most important architectural decision before running this script. How you intend to license your VM-Series or Cloud NGFW firewalls determines which flags to use.

### Approach A: Software Firewall Licensing via Panorama (recommended for scale)

The `sw_fw_license` plugin turns Panorama into a centralized license manager. Firewalls receive their licenses automatically from Panorama's pool when they first connect, with no per-device authcodes required.

**What you need on Panorama:**
- The `sw_fw_license` plugin installed (via `--plugins`)
- The CSP API Key configured (via `--csp-api-key`) so Panorama can communicate with the PAN licensing cloud
- A VM Auth Key generated (via `--vm-auth-key`) for firewall-to-Panorama registration

**What the firewall bootstrap needs:**
- Panorama IP and VM Auth Key — that's it. Licensing is handled automatically upon connection.

```bash
python3 panorama_init.py \
  --serial-number 000000000000 \
  --otp abcdef123456 \
  --csp-api-key 0123456789abcdef... \
  --plugins sw_fw_license-1.2.0,sd_wan-3.3.3-h2,ztp-3.0.1 \
  --vm-auth-key \
  192.168.1.100
```

### Approach B: Traditional Per-Device Authcodes

The traditional model. Each firewall is licensed individually using an authcode pushed from Panorama (or applied directly). The VM Auth Key is still used for registration, but licenses are not pooled — each device consumes its own activation code.

**What you need on Panorama:**
- VM Auth Key generated (via `--vm-auth-key`) for firewall-to-Panorama registration
- Authcodes pushed to Device Groups after firewalls connect (done outside this script)
- The `sw_fw_license` plugin is **not** used

**What the firewall bootstrap needs:**
- Panorama IP and VM Auth Key. Authcodes are applied after the firewall registers.

```bash
python3 panorama_init.py \
  --serial-number 000000000000 \
  --otp abcdef123456 \
  --vm-auth-key \
  192.168.1.100
```

### Summary

| | Approach A (sw_fw_license) | Approach B (Authcodes) |
|---|---|---|
| `--vm-auth-key` | Required (firewall registration) | Required (firewall registration) |
| `--csp-api-key` | Required (license pool auth) | Optional (cert fetch only) |
| `sw_fw_license` plugin | Required | Not used |
| Per-firewall authcodes | Not needed | Required |

The VM Auth Key is used in both approaches — it is the credential that allows a firewall to register with Panorama during bootstrap. The two approaches differ only in how the firewall's *license* is activated once it's connected.

---

## Prerequisites & Setup

- **Panorama Version:** Initially built and tested with Panorama 11.2.8.
- **Python Environment:** Python 3.7+ and `paramiko`.

It is recommended to run this within a Python Virtual Environment.

```bash
python3 -m venv venv
source venv/bin/activate
pip install paramiko
```

---

## Usage

### Authentication

SSH key-based authentication is used by default (`~/.ssh/id_rsa`). To fall back to password authentication, set the environment variable:

```bash
export PANORAMA_PASSWORD='YourSecretPassword123!'
```

### Command Line Arguments

| Argument | Default | Description |
|---|---|---|
| `ip` | *(required)* | IP address of the Panorama VM. Optional if `--state-file` is provided (IP is read from state). |
| `--hostname` | `Panorama-Management` | Hostname to configure on the Panorama VM. |
| `--username` | `admin` | SSH/API username. |
| `--ssh-key` | `~/.ssh/id_rsa` | Path to SSH private key file. |
| `--state-file` | `./panorama-<ip>-state.json` | Path to state tracking JSON file. If omitted, the current directory is scanned for an existing matching state file. |
| `--serial-number` | — | Serial number to apply to Panorama via XML API. |
| `--otp` | — | One-Time Password for fetching the device certificate. Skipped automatically if certificate is already valid. |
| `--csp-api-key` | — | Customer Support Portal API Key. Required for Software Firewall Licensing (Approach A). |
| `--upgrade-content` | `false` | Check, download, and install the latest Content (App-ID) update. Skips if already at latest. |
| `--upgrade-av` | `false` | Check, download, and install the latest Anti-Virus update. Skips if already at latest. |
| `--upgrade-panos` | — | Upgrade PAN-OS to a specific version (e.g. `11.2.8`) or `latest` for the newest in the current major.minor family. Triggers a full reboot. |
| `--plugins` | — | Comma-separated list of plugins to install (e.g. `sw_fw_license-1.2.0,sd_wan-3.3.3-h2`). Skips any already installed. |
| `--vm-auth-key` | — | Generate a VM Auth Key for firewall bootstrapping. Optionally accepts a lifetime in hours (default: `8760` = 1 year). Omitting the flag skips key generation entirely. |
| `--debug` | `false` | Enable verbose logging, including full XML requests and responses. |

### Example Invocations

**Full provisioning — Software Firewall Licensing (Approach A):**
```bash
python3 panorama_init.py \
  --debug \
  --username panadmin \
  --hostname My-Panorama \
  --serial-number 000710029871 \
  --otp abcdef123456 \
  --csp-api-key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --upgrade-content \
  --upgrade-av \
  --plugins sw_fw_license-1.2.0,sd_wan-3.3.3-h2,ztp-3.0.1,azure-5.2.3,aws-5.4.3 \
  --vm-auth-key \
  192.168.1.100
```

**Full provisioning — Traditional authcodes (Approach B):**
```bash
python3 panorama_init.py \
  --username panadmin \
  --serial-number 000710029871 \
  --otp abcdef123456 \
  --upgrade-content \
  --upgrade-av \
  --plugins sd_wan-3.3.3-h2,ztp-3.0.1 \
  --vm-auth-key \
  192.168.1.100
```

**Resume from an explicit state file (IP inferred from state):**
```bash
python3 panorama_init.py --state-file panorama-192.168.1.100-state.json
```

**PAN-OS upgrade only:**
```bash
python3 panorama_init.py --state-file panorama-192.168.1.100-state.json --upgrade-panos 11.2.8
```

**Add plugins to an already-provisioned Panorama:**
```bash
python3 panorama_init.py \
  --state-file panorama-192.168.1.100-state.json \
  --plugins sw_fw_license-1.2.0
```

**Generate a new VM Auth Key with a custom lifetime:**
```bash
python3 panorama_init.py \
  --state-file panorama-192.168.1.100-state.json \
  --vm-auth-key 4380
```

---

## State File & Idempotency

Every completed step is recorded in a local JSON state file (`panorama-<ip>-state.json` by default). This means:

- **Safe to re-run:** If the script is interrupted at any point, re-running the same command resumes exactly where it left off.
- **State file discovery:** If `--state-file` is not specified and the default file doesn't exist, the script scans the current directory for any `panorama-*-state.json` files. If exactly one is found with a matching IP, it is used automatically (with a warning). If multiple are found, you are prompted to choose one or start fresh.
- **IP recovery:** The IP address is stored in the state file on the first run. When using `--state-file` without an explicit IP argument, the IP is read from state.

The state file records: IP address, hostname, API password, serial number, content version, AV version, plugin list, VM Auth Key, and the completion status of each provisioning step.

---

## Planned / Future Functionality

- **Active/Passive High Availability (HA):** Automated configuration of A/P HA peering between two provisioned Panorama nodes.
- **Deployment Mode Configuration:** Ability to dynamically set or toggle the Panorama deployment mode between `panorama` mode (management + logging), `management-only` mode, and `log-collector` mode.
- **Log Collector Setup:** Automated initialization of logging disks, creation of Collector Groups, and assignment of the local Log Collector when running in `panorama` mode.

---

## Disclaimer

**Lab & Demo Use Only:** This script is provided as-is for educational, lab, and demonstration purposes. It is not officially supported by Palo Alto Networks. Please review the code and test thoroughly in a non-production environment before utilizing it in any production capacity. The authors assume no responsibility for any misconfigurations or disruptions caused by the use of this tool.

---

## License (MIT)

MIT License — Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
