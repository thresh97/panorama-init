# Panorama Virtual VM Initial Provisioning CLI 🚀

A Python CLI tool designed to idempotently bootstrap and provision a Palo Alto Networks Panorama Virtual Machine.

Due to the nature of Panorama deployments (long boot times, multiple management server restarts when applying licenses/certificates), traditional automation tools can sometimes struggle or falsely report failures. This script tracks its progress locally in a JSON state file. If a network timeout occurs or the Panorama web server restarts mid-flight, you can safely re-run the exact same command, and the script will pick up exactly where it left off.

## Why This Was Built (The Bootstrapping Dilemma)

When deploying Palo Alto Networks software firewalls (VM-Series and Cloud NGFW) at scale, it's common practice to bootstrap them directly to a Panorama management server. However, this creates a strict dependency: Panorama *must* exist and be fully operational *prior* to the firewalls being provisioned.

Attempting to deploy the Panorama VM and the software firewalls simultaneously in a single Infrastructure-as-Code (IaC) pipeline (like Terraform or CloudFormation) creates race conditions that are nearly impossible to resolve natively. The firewalls will boot up, attempt to connect to Panorama, and fail because Panorama is still initializing, rebooting to apply its license, or missing necessary routing/cloud plugins.

This script does the heavy lifting required to solve this problem, enabling a robust, serialized deployment strategy:

1. **Deploy Panorama VM:** Spin up the base Panorama virtual appliance via your IaC tool of choice.
2. **Provision Panorama (This Script):** Run this tool to handle the messy, reboot-heavy phases—applying licenses, fetching device certificates, generating VM auth keys, and installing required plugins (like SD-WAN or Cloud Services).
3. **Configure Panorama Base Policy:** Push the foundational Device Groups (DG) and Template Stacks to the now-ready Panorama (via Terraform, Ansible, or PAN-OS Python).
4. **Deploy Software Firewalls:** Finally, deploy the VM-Series or Cloud NGFW instances. They will successfully bootstrap, connect to Panorama, and pull down their assigned configurations without issue.

### Why Python and not Ansible?
While it would probably be best to handle this multi-step, stateful process natively within Ansible, this script was built as a "quick and dirty" alternative. It serves as a lightweight, stand-alone tool that is arguably much easier to read, run, and debug in isolation than a more complex and fully integrated Ansible playbook configuration.

### Why raw XML API instead of `pan-os-python`?
Similarly, utilizing the official `pan-os-python` SDK would normally be the most appropriate and robust way to interact with PAN-OS programmatically. However, this script relies strictly on raw Python `urllib` XML API calls. This was a deliberate design choice: `pan-os-python` occasionally auto-wraps XML payloads in ways that PAN-OS rejects for very specific, low-level operational commands (like setting a serial number or downloading specific plugin versions). Using raw XML gives us the explicit, character-for-character control required for these early bootstrapping tasks without requiring external dependencies.

## Features

* **SSH Bootstrapping:** Connects via SSH (key-based or password fallback via ENV) to disable CLI pagination, verify system readiness, set an initial API password, and perform the initial config commit.
* **Idempotent State Tracking:** Automatically generates a `panorama-<ip>-state.json` file to track the success of every step.
* **Licensing & Certificates:** Sets the Panorama serial number, configures the CSP API Key, and fetches a Device Certificate via OTP using the XML API.
* **Dynamic Updates:** Downloads and installs the latest Content and Anti-Virus definitions.
* **Plugin Management:** Checks existing plugins and sequentially downloads and installs a comma-separated list of required Panorama plugins.
* **VM Auth Key Generation:** Automatically generates a VM Auth Key with a configurable lifetime (default 1 year) for bootstrapping managed firewalls.

## Planned / Future Functionality

* **Active/Passive High Availability (HA):** Automated configuration of A/P HA peering between two provisioned Panorama nodes.
* **Deployment Mode Configuration:** Ability to dynamically set or toggle the Panorama deployment mode between standard `panorama` mode (management + logging), `management-only` mode, and `log-collector` mode.
* **Log Collector Setup (Panorama Mode):** Automated initialization of logging disks, creation of Collector Groups, and assignment of the local Log Collector when running in the default `panorama` mode.

## Prerequisites & Setup

* **Panorama Version:** Initially built and tested with Panorama 11.2.8.
* **Python Environment:** This script requires Python 3.7+ and relies on `paramiko`.

It is highly recommended to run this within a Python Virtual Environment (`venv`).

### 1. Create and Activate the Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
<<<<<<< HEAD
=======
```

### 2. Install Dependencies
```bash
pip install paramiko
```

## Usage

You can provide the Panorama password securely via an environment variable if you are not using SSH keys:
```bash
export PANORAMA_PASSWORD='YourSecretPassword123!'
```

### Example Invocation

```bash
python3 panorama_provision.py \
  --debug \
  --username panadmin \
  --serial-number 000000000000 \
  --otp abcdef123456 \
  --vm-auth-key \
  --csp-api-key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --plugins sd_wan-3.3.3-h2,ztp-3.0.1,azure-5.2.3,aws-5.4.3,sw_fw_license-1.2.0 \
  192.168.1.100
```

### Command Line Arguments

* `ip`: (Required) The IP address of the Panorama VM.
* `--username`: The SSH/API username (default: `admin`).
* `--ssh-key`: Path to your SSH private key file (default: `~/.ssh/id_rsa`).
* `--serial-number`: Serial number to apply to Panorama.
* `--otp`: One-Time Password for fetching the device certificate.
* `--csp-api-key`: Customer Support Portal API Key for licensing.
* `--upgrade-content`: Flag to download and install the latest Content update.
* `--upgrade-av`: Flag to download and install the latest Anti-Virus update.
* `--plugins`: Comma-separated list of plugins to download and install.
* `--vm-auth-key`: Generates a VM auth key. Optionally accepts a lifetime in hours (default: `8760`).
* `--state-file`: Custom path for the state tracking JSON file.
* `--debug`: Enables verbose logging, printing exact XML requests and responses.

## Disclaimer

**Lab & Demo Use Only:** This script is provided as-is for educational, lab, and demonstration purposes. It is not officially supported by Palo Alto Networks. Please review the code and test thoroughly in a non-production environment before utilizing it in any production capacity. The authors assume no responsibility for any misconfigurations or disruptions caused by the use of this tool.

## License (MIT)

MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
>>>>>>> 201713e (updated README.md)
