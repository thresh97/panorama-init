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
