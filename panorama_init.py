#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Panorama Virtual VM Initial Provisioning CLI 🚀

A Python CLI tool to idempotently bootstrap and provision a Palo Alto Networks
Panorama Virtual Machine.

Features:
  - Connects via SSH (Key-based by default, falls back to password from ENV).
  - Tracks progress in a JSON state file for idempotency.
  - Waits for system readiness (Panorama can take a while to boot).
  - Performs initial configuration (e.g., setting hostname, committing).
  - Configures an API password, applies a serial number, and fetches a device certificate via XML API.
  - Configures the CSP Licensing API key.
  - Upgrades Content and Anti-Virus definitions to the latest versions.
  - Downloads and installs specified Panorama plugins.
  - Generates and tracks a VM Auth Key for bootstrapping managed devices.

Prerequisites:
  - Python 3.7+
  - Required package: `paramiko`
    (install with: pip install paramiko)

Usage Examples:

# Basic usage (defaults to admin, ~/.ssh/id_rsa, and generates an 8760-hr auth key)
python panorama_provision.py 192.168.1.100

# Specify custom username, SSH key, serial number, and OTP
python panorama_provision.py 10.0.0.50 --username pantech --ssh-key ~/.ssh/custom_key --serial-number 000710008449 --otp 123456

# Set CSP API Key, upgrade content and AV after bootstrapping
python panorama_provision.py 10.0.0.50 --csp-api-key 043062840... --upgrade-content --upgrade-av

# Install specific plugins and override the default VM auth key lifetime
python panorama_provision.py 10.0.0.50 --plugins vm_series-3.0.0,aws-5.4.3 --vm-auth-key 4380

# Enable verbose XML debugging
python panorama_provision.py 10.0.0.50 --upgrade-content --debug
"""

import argparse
import json
import logging
import os
import sys
import time
import secrets
import string
import ssl
import re
import urllib.request
import urllib.parse
import urllib.error
import xml.etree.ElementTree as ET
from pathlib import Path

import paramiko

# --- Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOGGER = logging.getLogger(__name__)

# Reduce paramiko logging noise
logging.getLogger("paramiko").setLevel(logging.WARNING)


# --- State Management ---
def load_state(state_file_path: Path) -> dict:
    """Loads the deployment state from a file."""
    if not state_file_path.is_file():
        LOGGER.info(f"State file {state_file_path} not found. Starting fresh.")
        return {}
    with state_file_path.open("r") as f:
        return json.load(f)


def save_state(state_file_path: Path, state: dict):
    """Saves the deployment state to a file."""
    with state_file_path.open("w") as f:
        json.dump(state, f, indent=2)
    LOGGER.debug(f"State saved to {state_file_path}")


# --- API Helpers ---
def _send_op_command(ip, api_key, ctx, cmd_xml, timeout=60):
    """Sends a synchronous OP command and returns the raw response body."""
    LOGGER.debug(f"XML Request: {cmd_xml}")
    op_data = urllib.parse.urlencode({'type': 'op', 'key': api_key, 'cmd': cmd_xml}).encode('utf-8')
    req = urllib.request.Request(f"https://{ip}/api/", data=op_data)
    try:
        res = urllib.request.urlopen(req, context=ctx, timeout=timeout)
        response_body = res.read().decode('utf-8', errors='ignore')
        LOGGER.debug(f"XML Response: {response_body}")
        return response_body
    except urllib.error.HTTPError as e:
        # Catch HTTP 400 Bad Request and print the raw XML error reason so it doesn't get swallowed
        error_body = e.read().decode('utf-8', errors='ignore')
        LOGGER.debug(f"HTTP Error {e.code} Response: {error_body}")
        raise RuntimeError(f"HTTP {e.code} {e.reason}: {error_body}")


def _send_op_job_command(ip, api_key, ctx, cmd_xml, timeout=30):
    """Sends an asynchronous OP command, extracts, and returns the Job ID."""
    raw_res = _send_op_command(ip, api_key, ctx, cmd_xml, timeout)
    try:
        response_xml = ET.fromstring(raw_res)
        
        # Check for error status
        if response_xml.get('status') == 'error':
            msg = response_xml.findtext(".//msg/line", default=raw_res)
            raise RuntimeError(f"API Error: {msg}")
        
        job_id_elem = response_xml.find(".//job")
        if job_id_elem is None or not job_id_elem.text:
            msg = response_xml.findtext(".//msg/line", default="")
            LOGGER.info(f"No job returned by system (might be already installed/up-to-date). Msg: {msg}")
            return None
            
        return job_id_elem.text
    except ET.ParseError:
        raise RuntimeError(f"Invalid XML response: {raw_res}")


def poll_panorama_job(ip, api_key, ctx, job_id, job_name, timeout_mins=20):
    """Polls a Panorama Job ID until completion or failure."""
    if not job_id:
        LOGGER.info(f"✅ {job_name} skipped (likely already downloaded/installed).")
        return True
        
    LOGGER.info(f"Job {job_id} enqueued for {job_name}. Polling status...")
    max_attempts = timeout_mins * 4  # 15s intervals
    for attempt in range(max_attempts):
        time.sleep(15)
        try:
            job_cmd = f"<show><jobs><id>{job_id}</id></jobs></show>"
            job_raw = _send_op_command(ip, api_key, ctx, job_cmd, timeout=10)
            
            try:
                root = ET.fromstring(job_raw)
                
                # Check for structured XML first (Newer PAN-OS versions)
                job_node = root.find('.//job')
                if job_node is not None:
                    status = job_node.findtext('status', default='')
                    res_val = job_node.findtext('result', default='')
                    if status == 'FIN' and res_val == 'OK':
                        LOGGER.info(f"✅ Job {job_id} ({job_name}) completed successfully!")
                        return True
                    elif status == 'FIN' and res_val == 'FAIL':
                        # Check for benign failure: Already downloaded
                        if "Image exists already" in job_raw:
                            LOGGER.info(f"✅ Job {job_id} ({job_name}) skipped: Image exists already.")
                            return True
                        LOGGER.error(f"Job {job_id} ({job_name}) failed. Raw output:\n{job_raw}")
                        raise RuntimeError(f"Job {job_id} failed.")
                    else:
                        LOGGER.info(f"Job {job_id} ({job_name}) processing (status: {status})... (Attempt {attempt+1}/{max_attempts})")
                        continue
                
                # Fallback to plaintext table parsing (Older PAN-OS versions)
                result_text = root.findtext('.//result', default=job_raw)
            except ET.ParseError:
                result_text = job_raw
            
            # Replace non-breaking spaces with standard spaces
            if result_text:
                result_text = result_text.replace('\xa0', ' ')
            else:
                result_text = ""
            
            if re.search(r'FIN\s+OK', result_text):
                LOGGER.info(f"✅ Job {job_id} ({job_name}) completed successfully!")
                return True
            elif re.search(r'FIN\s+FAIL', result_text):
                # Check for benign failure: Already downloaded
                if "Image exists already" in job_raw:
                    LOGGER.info(f"✅ Job {job_id} ({job_name}) skipped: Image exists already.")
                    return True
                LOGGER.error(f"Job {job_id} ({job_name}) failed. Raw output:\n{result_text}")
                raise RuntimeError(f"Job {job_id} failed.")
            else:
                LOGGER.info(f"Job {job_id} ({job_name}) processing... (Attempt {attempt+1}/{max_attempts})")
        except RuntimeError:
            raise
        except Exception as e:
            LOGGER.debug(f"Connection error while polling (expected if mgmtsrvr restarting): {e}")
            
    raise RuntimeError(f"Timed out waiting for job {job_id} ({job_name}).")


# --- SSH Interaction Class ---
class PanoramaSSHClient:
    """A wrapper for Paramiko to handle interactive shell sessions with Panorama."""

    def __init__(self, ip: str, username: str, ssh_key_path: Path, password: str = None):
        self.ip = ip
        self.username = username
        self.ssh_key_path = ssh_key_path
        self.password = password
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.shell = None

    def connect(self, max_retries=15, delay=30):
        """Connects to Panorama, opens a shell, and disables the pager."""
        for attempt in range(max_retries):
            try:
                LOGGER.info(f"Attempting SSH connection to {self.ip} (Attempt {attempt + 1}/{max_retries})...")
                
                # Attempt Key-based auth first if key file exists
                if self.ssh_key_path and self.ssh_key_path.is_file():
                    LOGGER.debug(f"Trying key-based auth using {self.ssh_key_path}")
                    try:
                        self.client.connect(
                            hostname=self.ip,
                            username=self.username,
                            key_filename=str(self.ssh_key_path),
                            timeout=15
                        )
                    except paramiko.ssh_exception.AuthenticationException:
                        if self.password:
                            LOGGER.debug("Key auth failed, falling back to password auth.")
                            self.client.connect(
                                hostname=self.ip,
                                username=self.username,
                                password=self.password,
                                timeout=15
                            )
                        else:
                            raise
                elif self.password:
                    LOGGER.debug("No SSH key found. Trying password auth from ENV.")
                    self.client.connect(
                        hostname=self.ip,
                        username=self.username,
                        password=self.password,
                        timeout=15
                    )
                else:
                    raise ValueError(f"No valid SSH key found at {self.ssh_key_path} and PANORAMA_PASSWORD env var is not set.")

                LOGGER.info("✅ SSH connection successful.")
                LOGGER.info("Opening interactive shell...")
                self.shell = self.client.invoke_shell()
                
                # Wait for standard prompt (handles both user and config mode prompts)
                self.wait_for_prompt(timeout=90)

                LOGGER.info("Disabling CLI pager for this session...")
                self.send_command("set cli pager off")
                
                LOGGER.info("✅ Interactive shell is ready.")
                return

            except Exception as e:
                LOGGER.warning(f"SSH connection failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(delay)
                else:
                    raise TimeoutError(f"Could not establish SSH connection to {self.ip} after {max_retries} attempts.")

    def close(self):
        """Closes the SSH connection."""
        if self.shell:
            self.shell.close()
        self.client.close()
        LOGGER.info("SSH client closed.")

    def wait_for_prompt(self, prompt_chars=['>', '#'], timeout=60):
        """Waits for one of the possible command prompts to appear."""
        output = ""
        start_time = time.time()
        self.shell.settimeout(timeout)

        while True:
            if time.time() - start_time > timeout:
                LOGGER.error(f"Timeout waiting for prompt. Received:\n{output}")
                raise TimeoutError("Timeout waiting for command prompt.")

            if self.shell.recv_ready():
                output += self.shell.recv(4096).decode('utf-8', errors='ignore')
            
            # Check if any of our expected prompt characters are in the tail of the output
            lines = output.split('\n')
            last_line = lines[-1] if lines else ""
            
            prompt_found = any(p in last_line for p in prompt_chars)

            if prompt_found:
                time.sleep(0.5) # Wait slightly to ensure output flush
                if not self.shell.recv_ready():
                    return output
            
            time.sleep(0.2)
    
    def send_command(self, command, prompt_chars=['>', '#'], timeout=120):
        """Sends a command and returns the output once a prompt reappears."""
        self.shell.send(command + '\n')
        full_output = self.wait_for_prompt(prompt_chars, timeout)
        
        # Clean up output (remove the echoed command and the trailing prompt)
        lines = full_output.splitlines()
        if len(lines) > 1:
            return '\n'.join(lines[1:-1]).strip()
        return full_output.strip()


# --- Provisioning Logic ---
def provision_panorama(ip: str, username: str, ssh_key: Path, password: str, state_file: Path, 
                       serial_number: str = None, otp: str = None, csp_api_key: str = None,
                       upgrade_content: bool = False, upgrade_av: bool = False, plugins: str = None,
                       vm_auth_key_hours: int = 8760):
    """Executes the idempotent provisioning sequence on Panorama."""
    state = load_state(state_file)
    ssh = PanoramaSSHClient(ip, username, ssh_key, password)
    
    try:
        # Step 1: Connect
        ssh.connect()

        # Step 2: Check System Readiness
        # Panorama can take 15-20 minutes to fully initialize services on first boot.
        if not state.get("system_ready"):
            LOGGER.info("Checking if Panorama system is ready...")
            ready = False
            for attempt in range(60):  # Wait up to ~30 mins (60 * 30s)
                output = ssh.send_command("show system info")
                if "sw-version:" in output.lower() or "hostname:" in output.lower():
                    LOGGER.info("✅ Panorama system is fully ready!")
                    state["system_ready"] = True
                    save_state(state_file, state)
                    ready = True
                    break
                else:
                    LOGGER.info(f"System not ready yet. Retrying in 30 seconds... (Attempt {attempt+1}/60)")
                    time.sleep(30)
            
            if not ready:
                raise TimeoutError("Panorama system did not become ready in time.")
        else:
            LOGGER.info("⏭️  Skipping system readiness check (already complete).")

        # Step 3: Enter Configuration Mode
        if not state.get("initial_commit_done"):
            LOGGER.info("Entering configuration mode...")
            ssh.send_command("configure", prompt_chars=['#'])

            # Step 3.1: Set Admin Password for API Access
            if not state.get("admin_password_set"):
                LOGGER.info(f"Setting password for user '{username}' to enable XML API access...")
                
                # If no password was provided via ENV, generate a secure one
                api_password = password
                if not api_password:
                    alphabet = string.ascii_letters + string.digits
                    api_password = ''.join(secrets.choice(alphabet) for _ in range(16))
                    LOGGER.info(f"Generated new secure password for '{username}': {api_password}")

                # Send the password command
                ssh.shell.send(f"set mgt-config users {username} password\n")
                
                # Handle the interactive prompts
                ssh.wait_for_prompt(prompt_chars=['Enter password'])
                ssh.shell.send(api_password + '\n')
                
                ssh.wait_for_prompt(prompt_chars=['Confirm password'])
                ssh.shell.send(api_password + '\n')
                
                ssh.wait_for_prompt(prompt_chars=['#'])
                
                state["admin_password_set"] = True
                state["api_password"] = api_password  # Store the password in state for future API calls
                save_state(state_file, state)
                LOGGER.info("✅ Admin password configured in candidate config.")
            else:
                LOGGER.info("⏭️  Skipping admin password configuration (already complete).")

            # Example Provisioning Step A: Set Hostname
            if not state.get("hostname_set"):
                target_hostname = "Panorama-Management"
                LOGGER.info(f"Setting hostname to '{target_hostname}'...")
                ssh.send_command(f"set deviceconfig system hostname {target_hostname}", prompt_chars=['#'])
                
                state["hostname_set"] = True
                save_state(state_file, state)
                LOGGER.info("✅ Hostname configured.")
            else:
                LOGGER.info("⏭️  Skipping hostname configuration (already complete).")

            # Step 4: Commit Configuration
            if not state.get("initial_commit_done"):
                LOGGER.info("Committing initial configuration... (This may take a few minutes)")
                # Commits can take a while on Panorama, bump timeout
                commit_output = ssh.send_command("commit", prompt_chars=['#'], timeout=600)
                
                if "Configuration committed successfully" in commit_output or "success" in commit_output.lower():
                    LOGGER.info("✅ Initial commit successful.")
                    state["initial_commit_done"] = True
                    save_state(state_file, state)
                else:
                    LOGGER.error(f"Commit may have failed. Output:\n{commit_output}")
                    raise RuntimeError("Commit process did not return expected success message.")

            # Exit config mode
            ssh.send_command("exit", prompt_chars=['>'])
        else:
            LOGGER.info("⏭️  Skipping initial configuration and commit (already complete).")

    finally:
        # We can safely close the SSH session before interacting with the API
        ssh.close()

    # --- XML API Interactions ---
    
    # Generate API key once if we need to do any XML API actions
    api_key = None
    if serial_number or otp or csp_api_key or upgrade_content or upgrade_av or plugins or vm_auth_key_hours is not None:
        api_password = state.get("api_password") or password
        if not api_password:
            raise ValueError("Cannot connect to API. No password provided in ENV or generated in state file.")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        LOGGER.info("Generating API Key for XML API...")
        keygen_data = urllib.parse.urlencode({
            'type': 'keygen',
            'user': username,
            'password': api_password
        }).encode('utf-8')
        
        try:
            req = urllib.request.Request(f"https://{ip}/api/", data=keygen_data)
            res = urllib.request.urlopen(req, context=ctx, timeout=15)
            root = ET.fromstring(res.read())
            api_key = root.find(".//key").text
            if not api_key:
                raise ValueError("Failed to extract API key from response.")
        except Exception as e:
            raise RuntimeError(f"API Keygen failed: {e}")

    # Step 5: Execute Serial Number setting via XML API
    if serial_number:
        if not state.get("serial_number_set"):
            LOGGER.info(f"Setting Panorama serial number to '{serial_number}' via XML API...")
            
            command_sent = False
            for attempt in range(10):
                try:
                    # Send exactly what the user requested, without pan-os-python auto-wrapping
                    cmd_xml = f"<set><serial-number>{serial_number}</serial-number></set>"
                    LOGGER.info(f"Sending API command (Attempt {attempt+1}/10)...")
                    
                    _send_op_command(ip, api_key, ctx, cmd_xml, timeout=15)
                    command_sent = True
                    LOGGER.info("API command accepted. Panorama management server is likely restarting...")
                    break
                except RuntimeError as e:
                    # _send_op_command wraps the HTTP error in a RuntimeError, catch that
                    LOGGER.warning(f"API command failed: {e}. Retrying in 15 seconds...")
                    time.sleep(15)
                except Exception as e:
                    # If the connection drops during the call, the web server likely restarted successfully
                    error_str = str(e).lower()
                    expected_disconnects = [
                        "connection reset", 
                        "remotedisconnected", 
                        "eof occurred", 
                        "timed out", 
                        "remote end closed connection",
                        "connection refused"
                    ]
                    if any(msg in error_str for msg in expected_disconnects):
                        LOGGER.warning(f"Connection dropped during API call (expected behavior as web server reboots): {e}")
                        command_sent = True
                        break

                    LOGGER.warning(f"API command failed: {e}. Retrying in 15 seconds...")
                    time.sleep(15)
            
            if not command_sent:
                raise RuntimeError("Failed to set serial number via XML API after multiple attempts.")
            
            # Now wait for the web server to come back up and verify the serial number
            LOGGER.info("Waiting for Panorama web server to come back up and verifying serial number...")
            serial_verified = False
            for attempt in range(24):  # Wait up to 6 minutes (24 * 15s)
                time.sleep(15)
                try:
                    sysinfo_raw = _send_op_command(ip, api_key, ctx, "<show><system><info/></system></show>", timeout=10)
                    
                    # PAN-OS sometimes returns plain text wrapped in a <result> tag for this command
                    if f"<serial>{serial_number}</serial>" in sysinfo_raw or f"serial: {serial_number}" in sysinfo_raw:
                        LOGGER.info(f"✅ Serial number '{serial_number}' successfully verified!")
                        serial_verified = True
                        break
                    
                    match = re.search(r'(?:<serial>|serial:\s*)([^<\r\n]+)', sysinfo_raw)
                    current_serial = match.group(1).strip() if match else "unknown"

                    if current_serial and current_serial != "unknown":
                        LOGGER.info(f"Web server is up, but serial is currently '{current_serial}'. Waiting...")
                except Exception as e:
                    LOGGER.debug(f"Web server still unreachable (Attempt {attempt+1}/24)...")

            if not serial_verified:
                raise RuntimeError("Panorama web server did not return the expected serial number after restarting.")
            
            state["serial_number_set"] = True
            state["serial_number"] = serial_number
            save_state(state_file, state)
        else:
            LOGGER.info("⏭️  Skipping serial number configuration (already complete).")

    # Step 6: Fetch Device Certificate via XML API
    if otp:
        if not state.get("certificate_fetched"):
            LOGGER.info("Checking current device certificate status...")
            cert_already_valid = False
            
            for attempt in range(3): # Short retry in case mgmtsrvr is just settling
                try:
                    sysinfo_raw = _send_op_command(ip, api_key, ctx, "<show><system><info/></system></show>", timeout=10)
                    
                    if "device-certificate-status: Valid" in sysinfo_raw or "<device-certificate-status>Valid</device-certificate-status>" in sysinfo_raw:
                        LOGGER.info("✅ Device certificate is already 'Valid'. Skipping OTP fetch.")
                        cert_already_valid = True
                        state["certificate_fetched"] = True
                        save_state(state_file, state)
                    break # Success checking status, exit loop
                except Exception as e:
                    LOGGER.debug(f"Pre-check connection error: {e}. Retrying...")
                    time.sleep(5)

            if not cert_already_valid:
                LOGGER.info(f"Fetching device certificate using OTP via XML API...")
                
                # 1. Dispatch the Fetch Job
                try:
                    cmd_xml = f"<request><certificate><fetch><otp>{otp}</otp></fetch></certificate></request>"
                    job_id = _send_op_job_command(ip, api_key, ctx, cmd_xml, timeout=15)
                    if not job_id:
                        raise RuntimeError("Certificate fetch initiated, but no job ID was returned.")
                    LOGGER.info(f"Certificate fetch job enqueued with ID: {job_id}. Monitoring progress...")
                except Exception as e:
                    raise RuntimeError(f"Failed to enqueue device certificate fetch job: {e}")
                
                # 2. Poll the Job Status and System Info
                cert_valid = False
                for attempt in range(30):  # Wait up to 7.5 minutes (30 * 15s)
                    time.sleep(15)
                    try:
                        # Best validation: Check if system info reports the cert is valid
                        sysinfo_raw = _send_op_command(ip, api_key, ctx, "<show><system><info/></system></show>", timeout=10)
                        
                        if "device-certificate-status: Valid" in sysinfo_raw or "<device-certificate-status>Valid</device-certificate-status>" in sysinfo_raw:
                            LOGGER.info("✅ Device certificate fetched and successfully verified!")
                            cert_valid = True
                            break

                        # If not valid yet, check job status to fail fast if OTP was rejected
                        job_cmd = f"<show><jobs><id>{job_id}</id></jobs></show>"
                        job_raw = _send_op_command(ip, api_key, ctx, job_cmd, timeout=10)
                        
                        # Parse XML to check structured FIN FAIL or fallback to plaintext extraction
                        try:
                            root = ET.fromstring(job_raw)
                            job_node = root.find('.//job')
                            if job_node is not None:
                                status = job_node.findtext('status', default='')
                                res_val = job_node.findtext('result', default='')
                                if status == 'FIN' and res_val == 'FAIL':
                                    LOGGER.error(f"Certificate fetch job {job_id} failed. Raw output:\n{job_raw}")
                                    raise RuntimeError("Device certificate fetch failed (invalid OTP or network error).")
                                
                            result_text = root.findtext('.//result', default=job_raw)
                        except ET.ParseError:
                            result_text = job_raw
                            
                        if result_text:
                            result_text = result_text.replace('\xa0', ' ')
                        else:
                            result_text = ""
                        
                        if re.search(r'FIN\s+FAIL', result_text):
                            LOGGER.error(f"Certificate fetch job {job_id} failed. Raw output:\n{result_text}")
                            raise RuntimeError("Device certificate fetch failed (invalid OTP or network error).")
                        
                        LOGGER.info(f"Job {job_id} processing, cert not yet valid... (Attempt {attempt+1}/30)")
                    except RuntimeError:
                        raise # Re-raise the FIN FAIL runtime error immediately
                    except Exception as e:
                        # The web server sometimes restarts after a certificate is applied, similar to the serial number
                        LOGGER.debug(f"Connection error while polling (expected if mgmtsrvr is restarting): {e}")

                if not cert_valid:
                    raise RuntimeError(f"Timed out waiting for device certificate to become 'Valid'.")
                
                state["certificate_fetched"] = True
                save_state(state_file, state)
        else:
            LOGGER.info("⏭️  Skipping device certificate fetch (already complete).")

    # Step 7: Configure CSP API Key
    if csp_api_key:
        if not state.get("csp_api_key_set"):
            LOGGER.info("Setting CSP Licensing API Key via XML API...")
            try:
                cmd_xml = f"<request><license><api-key><set><key>{csp_api_key}</key></set></api-key></license></request>"
                raw_response = _send_op_command(ip, api_key, ctx, cmd_xml, timeout=30)
                
                if 'status="error"' in raw_response.lower() and 'same as old' in raw_response.lower():
                    LOGGER.info("✅ CSP API key is already set to the provided value.")
                elif 'status="error"' in raw_response.lower():
                    raise RuntimeError(f"Failed to set CSP API key. Raw response: {raw_response}")
                else:
                    LOGGER.info("✅ CSP API key applied successfully.")
                    
                state["csp_api_key_set"] = True
                save_state(state_file, state)
            except Exception as e:
                LOGGER.error(f"Failed to configure CSP API key: {e}")
                raise
        else:
            LOGGER.info("⏭️  Skipping CSP API Key configuration (already complete).")

    # Step 8: Content Upgrade via XML API
    if upgrade_content:
        if not state.get("content_upgraded"):
            LOGGER.info("Starting Content Upgrade process...")
            try:
                LOGGER.info("1/3 Checking for latest content updates...")
                check_cmd = "<request><content><upgrade><check/></upgrade></content></request>"
                _send_op_command(ip, api_key, ctx, check_cmd, timeout=60)
                
                LOGGER.info("2/3 Downloading latest content update...")
                dl_cmd = "<request><content><upgrade><download><latest/></download></upgrade></content></request>"
                dl_job_id = _send_op_job_command(ip, api_key, ctx, dl_cmd, timeout=30)
                poll_panorama_job(ip, api_key, ctx, dl_job_id, "Content Download")
                
                LOGGER.info("3/3 Installing latest content update...")
                inst_cmd = "<request><content><upgrade><install><version>latest</version></install></upgrade></content></request>"
                inst_job_id = _send_op_job_command(ip, api_key, ctx, inst_cmd, timeout=30)
                poll_panorama_job(ip, api_key, ctx, inst_job_id, "Content Install")
                
                state["content_upgraded"] = True
                save_state(state_file, state)
            except Exception as e:
                LOGGER.error(f"Content upgrade failed: {e}")
                raise
        else:
            LOGGER.info("⏭️  Skipping Content upgrade (already complete).")

    # Step 9: Anti-Virus Upgrade via XML API
    if upgrade_av:
        if not state.get("av_upgraded"):
            LOGGER.info("Starting Anti-Virus Upgrade process...")
            try:
                LOGGER.info("1/3 Checking for latest Anti-Virus updates...")
                check_cmd = "<request><anti-virus><upgrade><check/></upgrade></anti-virus></request>"
                _send_op_command(ip, api_key, ctx, check_cmd, timeout=60)
                
                LOGGER.info("2/3 Downloading latest Anti-Virus update...")
                dl_cmd = "<request><anti-virus><upgrade><download><latest/></download></upgrade></anti-virus></request>"
                dl_job_id = _send_op_job_command(ip, api_key, ctx, dl_cmd, timeout=30)
                poll_panorama_job(ip, api_key, ctx, dl_job_id, "Anti-Virus Download")
                
                LOGGER.info("3/3 Installing latest Anti-Virus update...")
                inst_cmd = "<request><anti-virus><upgrade><install><version>latest</version></install></upgrade></anti-virus></request>"
                inst_job_id = _send_op_job_command(ip, api_key, ctx, inst_cmd, timeout=30)
                poll_panorama_job(ip, api_key, ctx, inst_job_id, "Anti-Virus Install")
                
                state["av_upgraded"] = True
                save_state(state_file, state)
            except Exception as e:
                LOGGER.error(f"Anti-Virus upgrade failed: {e}")
                raise
        else:
            LOGGER.info("⏭️  Skipping Anti-Virus upgrade (already complete).")

    # Step 10: Plugin Installation via XML API
    if plugins:
        plugin_list = [p.strip() for p in plugins.split(",") if p.strip()]
        
        LOGGER.info("Checking currently installed plugins on the device...")
        installed_cmd = "<show><plugins><installed/></plugins></show>"
        
        installed_raw = ""
        for attempt in range(6):
            try:
                installed_raw = _send_op_command(ip, api_key, ctx, installed_cmd, timeout=30)
                break
            except Exception as e:
                LOGGER.debug(f"Connection error while checking installed plugins: {e}. Retrying...")
                time.sleep(10)
        
        installed_plugins_state = state.get("plugins_installed", [])
        plugins_to_install = []
        
        for p in plugin_list:
            if p in installed_raw:
                LOGGER.info(f"✅ Plugin '{p}' is already installed on the device. Skipping.")
                if p not in installed_plugins_state:
                    installed_plugins_state.append(p)
            elif p in installed_plugins_state:
                LOGGER.info(f"✅ Plugin '{p}' is marked as installed in state file. Skipping.")
            else:
                plugins_to_install.append(p)
                
        state["plugins_installed"] = installed_plugins_state
        save_state(state_file, state)
        
        if plugins_to_install:
            LOGGER.info(f"Starting Plugin Installation process for: {', '.join(plugins_to_install)}")
            try:
                LOGGER.info("Checking for available plugins...")
                check_cmd = "<request><plugins><check/></plugins></request>"
                _send_op_command(ip, api_key, ctx, check_cmd, timeout=60)
                
                for plugin in plugins_to_install:
                    LOGGER.info(f"Downloading plugin '{plugin}'...")
                    dl_cmd = f"<request><plugins><download><file>{plugin}</file></download></plugins></request>"
                    dl_job_id = _send_op_job_command(ip, api_key, ctx, dl_cmd, timeout=30)
                    poll_panorama_job(ip, api_key, ctx, dl_job_id, f"Plugin Download ({plugin})")
                    
                    LOGGER.info(f"Installing plugin '{plugin}'...")
                    inst_cmd = f"<request><plugins><install>{plugin}</install></plugins></request>"
                    inst_job_id = _send_op_job_command(ip, api_key, ctx, inst_cmd, timeout=30)
                    poll_panorama_job(ip, api_key, ctx, inst_job_id, f"Plugin Install ({plugin})")
                    
                    # Validation step
                    LOGGER.info(f"Validating installation of '{plugin}'...")
                    verified = False
                    for val_attempt in range(12):  # Wait up to 3 minutes
                        time.sleep(15)
                        try:
                            validate_raw = _send_op_command(ip, api_key, ctx, installed_cmd, timeout=15)
                            if plugin in validate_raw:
                                LOGGER.info(f"✅ Verified '{plugin}' appears in installed plugins list.")
                                verified = True
                                break
                            else:
                                LOGGER.info(f"Plugin '{plugin}' not yet in installed list. Waiting... (Attempt {val_attempt+1}/12)")
                        except Exception as e:
                            LOGGER.debug(f"Web server unreachable during validation (likely restarting): {e}")
                    
                    if not verified:
                        LOGGER.warning(f"Plugin '{plugin}' installed via job, but could not be verified in 'show plugins installed'.")
                    
                    installed_plugins_state.append(plugin)
                    state["plugins_installed"] = installed_plugins_state
                    save_state(state_file, state)
                    
            except Exception as e:
                LOGGER.error(f"Plugin installation failed: {e}")
                raise
        else:
            LOGGER.info("⏭️  Skipping Plugin installation (all requested plugins already installed).")

    # Step 11: Generate VM Auth Key
    if vm_auth_key_hours is not None:
        if not state.get("vm_auth_key"):
            LOGGER.info(f"Generating VM Auth Key with lifetime {vm_auth_key_hours} hours...")
            try:
                cmd_xml = f"<request><bootstrap><vm-auth-key><generate><lifetime>{vm_auth_key_hours}</lifetime></generate></vm-auth-key></bootstrap></request>"
                raw_response = _send_op_command(ip, api_key, ctx, cmd_xml, timeout=30)
                
                # Parse the response XML to extract the text
                try:
                    root = ET.fromstring(raw_response)
                    result_text = root.findtext(".//result", default=raw_response)
                except ET.ParseError:
                    result_text = raw_response
                
                # Expected format: "VM auth key 891933040429594 generated. Expires at: 2027/03/30 13:03:21"
                match = re.search(r"VM auth key\s+(\S+)\s+generated\.\s+Expires at:\s+(.*)", result_text)
                if match:
                    auth_key = match.group(1).strip()
                    expiry = match.group(2).strip()
                    LOGGER.info(f"✅ VM Auth Key generated: {auth_key} (Expires: {expiry})")
                    
                    state["vm_auth_key"] = auth_key
                    state["vm_auth_key_expiry"] = expiry
                    save_state(state_file, state)
                else:
                    LOGGER.warning(f"Could not parse VM Auth Key from response: {result_text}")
                    raise RuntimeError("Failed to parse VM Auth Key from response.")
                    
            except Exception as e:
                LOGGER.error(f"Failed to generate VM Auth Key: {e}")
                raise
        else:
            auth_key = state.get("vm_auth_key")
            expiry = state.get("vm_auth_key_expiry")
            LOGGER.info(f"⏭️  Skipping VM Auth Key generation (already generated: {auth_key}, Expires: {expiry}).")

    LOGGER.info(f"🎉 Provisioning of Panorama at {ip} is complete!")


def main():
    parser = argparse.ArgumentParser(
        description="Idempotent Initial Provisioning for Virtual Panorama VMs",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Positional argument for IP
    parser.add_argument(
        "ip", 
        help="The IP address of the Panorama VM to connect to."
    )
    
    # Optional arguments
    parser.add_argument(
        "--username", 
        default="admin", 
        help="The SSH username (default: admin)."
    )
    parser.add_argument(
        "--ssh-key", 
        default="~/.ssh/id_rsa", 
        metavar="PATH", 
        help="Path to your SSH private key file (default: ~/.ssh/id_rsa)."
    )
    parser.add_argument(
        "--state-file", 
        default=None, 
        metavar="PATH", 
        help="Path to save the state JSON file. Defaults to './panorama-<ip>-state.json'."
    )
    parser.add_argument(
        "--serial-number",
        default=None,
        help="Serial number to apply to the Panorama VM via the XML API."
    )
    parser.add_argument(
        "--otp",
        default=None,
        help="One-Time Password (OTP) for fetching the device certificate."
    )
    parser.add_argument(
        "--csp-api-key",
        default=None,
        help="Customer Support Portal (CSP) API Key for licensing."
    )
    parser.add_argument(
        "--upgrade-content",
        action="store_true",
        help="Check, download, and install the latest Content update."
    )
    parser.add_argument(
        "--upgrade-av",
        action="store_true",
        help="Check, download, and install the latest Anti-Virus update."
    )
    parser.add_argument(
        "--plugins",
        default=None,
        help="Comma-separated list of plugins to download and install (e.g. vm_series-2.1.6,aws-3.0.0)."
    )
    parser.add_argument(
        "--vm-auth-key",
        dest="vm_auth_key_hours",
        type=int,
        nargs='?',
        const=8760,
        default=8760,
        help="Generate a VM auth key with the specified lifetime in hours (default: 8760)."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug logging (including XML requests/responses)."
    )

    args = parser.parse_args()

    if args.debug:
        LOGGER.setLevel(logging.DEBUG)

    # Read password from environment variable
    panorama_password = os.environ.get("PANORAMA_PASSWORD")

    # Resolve paths
    ssh_key_path = Path(args.ssh_key).expanduser().resolve()
    
    if args.state_file:
        state_file_path = Path(args.state_file).expanduser().resolve()
    else:
        state_file_path = Path(f"panorama-{args.ip}-state.json").resolve()

    try:
        provision_panorama(
            ip=args.ip,
            username=args.username,
            ssh_key=ssh_key_path,
            password=panorama_password,
            state_file=state_file_path,
            serial_number=args.serial_number,
            otp=args.otp,
            csp_api_key=args.csp_api_key,
            upgrade_content=args.upgrade_content,
            upgrade_av=args.upgrade_av,
            plugins=args.plugins,
            vm_auth_key_hours=args.vm_auth_key_hours
        )
    except Exception as e:
        LOGGER.error(f"Provisioning failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
