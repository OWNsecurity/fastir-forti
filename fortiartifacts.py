#!/usr/bin/env python3
"""
FortiArtifacts

Lightweight Python utility that automates the collection of live-response artifacts from Fortinet devices using SSH wrapper method and YAML-based command definitions to specify useful artifacts.

Process:
- Loads all YAML files from artifacts/<type>/*.yaml related to asset type
- Connects via SSH and checks the connection.
- Executes the commands to collect artifacts and saves the output into the specified folder

Usage:
    python fortiartifacts.py --ip IP --type DEVICE_TYPE

Optional :
    --zip : create ZIP output
    --port : specific SSH port

Example :
    python fortiartifacts.py --ip 192.168.100.45 --type fortigate --zip

Requirements:
    pip install paramiko pyyaml

"""

import argparse
import getpass
import glob
import os
import sys
import time
import logging
from typing import List, Dict
import logging
import zipfile
from datetime import datetime
import hashlib

try:
    import paramiko
except Exception as e:
    print("Module 'paramiko' not found. Install it using: pip install paramiko")
    raise

try:
    import yaml
except Exception as e:
    print("Module 'PyYAML' not found. Install it using: pip install pyyaml")
    raise

# -----------------------------
# --- Logging configuration ---
LOG_DIR = "outputs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "collector_logs.txt")
HASH_CSV_PATH = os.path.join(LOG_DIR, "hashs.txt")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8"),
        logging.StreamHandler()  # also log to console
    ]
)

logger = logging.getLogger("fortiartifacts")


def parse_args():
    p = argparse.ArgumentParser(description="Collects command outputs from Fortinet devices via SSH")
    p.add_argument("--ip", required=True, help="Fortinet device IP address")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--type", required=True, choices=["fortigate", "fortiweb"], help="Device type (e.g., fortigate, fortiweb)")
    p.add_argument("--timeout", type=int, default=10, help="SSH connection timeout in seconds (default: 10)")
    p.add_argument("--zip", action="store_true", help="Create a ZIP archive based on the the outputs/ folder after collection")
    return p.parse_args()


def prompt_credentials():

    username = input("Enter forti SSH username: ").strip()
    password = getpass.getpass("Enter forti SSH password: ")
    return username, password


def discover_artifact_files(device_type: str) -> List[str]:
    base = os.path.join("artifacts", device_type)
    pattern1 = os.path.join(base, "*.yml")
    pattern2 = os.path.join(base, "*.yaml")
    files = glob.glob(pattern1) + glob.glob(pattern2)
    files.sort()
    return files


def load_yaml_file(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data or {}


def validate_artifact_structure(data: Dict, path: str):
    required = ["version", "output_file", "description", "command"]
    for r in required:
        if r not in data:
            raise ValueError(f"YAML file {path} is missing required key: {r}")


def ensure_parent_dir(path: str):
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)


def ssh_connect(ip: str, port: int, username: str, password: str, timeout: int = 10) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=ip, port=port, username=username, password=password, timeout=timeout, allow_agent=False, look_for_keys=False,)
        return client
    except Exception as e:
        raise


def run_command(ssh_client: paramiko.SSHClient, command: str, timeout: int = 30) -> Dict[str, str]:
    stdin, stdout, stderr = ssh_client.exec_command(command, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    exit_status = stdout.channel.recv_exit_status()
    return {"stdout": out, "stderr": err, "exit_status": exit_status}


def write_output_file(path: str, content: str, metadata: Dict = None):
    full_path = os.path.join("outputs", path.lstrip("/"))
    ensure_parent_dir(full_path)
    with open(full_path, "w", encoding="utf-8") as f:
        f.write(content)
    return full_path

# -----------------------------
# --- Archive (ZIP) generation ---
# Creates a ZIP archive of the ./outputs/ folder. The ZIP file is placed in the project root as:
# Output example: ./output_<type>_<timestamp>.zip
def create_output_zip(device_type: str):

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_name = f"output_{device_type}_{timestamp}.zip"
    zip_path = os.path.join(os.getcwd(), zip_name)

    logger.info(f"Creating ZIP archive: {zip_path}")

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk("outputs"):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, "outputs")
                zipf.write(full_path, os.path.join("outputs", rel_path))

    logger.info(f"Archive successfully created: {zip_path}")
    return zip_path

def compute_sha256(file_path: str) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def append_hash_record(relative_output_path: str, sha256_hex: str):
    header_needed = not os.path.exists(HASH_CSV_PATH)
    with open(HASH_CSV_PATH, "a", encoding="utf-8", newline="") as f:
        if header_needed:
            f.write("filename,hash\n")
        f.write(f"{relative_output_path},{sha256_hex}\n")

def main():
    args = parse_args()
    ip = args.ip
    device_type = args.type

    username, password = prompt_credentials()

    logger.info("------------------------------------")
    logger.info(f"Searching artifacts for type '{device_type}'...")
    artifact_files = discover_artifact_files(device_type)

    if not artifact_files:
        logger.warning(f"No YAML files found in artifacts/{device_type}. Please check artifacts folder, files are missing.")
        sys.exit(2)

    logger.info(f"YAML files found: {len(artifact_files)}")

    logger.info("------------------------------------")

    logger.info(f"Testing SSH connection to {ip} ...")
    try:
        ssh = ssh_connect(ip=ip, port=args.port, username=username, password=password, timeout=args.timeout)
        logger.info("SSH connection successful")
    except Exception as e:
        logger.error(f"SSH connection failed: {e}")
        sys.exit(3)

    logger.info("------------------------------------")

    try:
        failed_commands = []
        for yaml_file in artifact_files:
            try:
                data = load_yaml_file(yaml_file)
                validate_artifact_structure(data, yaml_file)
            except Exception as e:
                logger.error(f"Error reading/validating {yaml_file}: {e}")
                failed_commands.append(yaml_file)
                continue

            command = data["command"]
            output_file = data["output_file"]
            description = data.get("description", "")

            logger.info(f"Executing command: {command}")
            try:
                res = run_command(ssh, command)
            except Exception as e:
                logger.error(f"Failed to execute command '{command}': {e}")
                failed_commands.append(command)
                continue

            header = []
            header.append(f"# Command: {command}")
            header.append(f"# Artifact source file: {yaml_file}")
            header.append(f"# Description: {description}")
            header.append(f"# Collected at: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
            header.append(f"# Exit status: {res.get('exit_status')}")
            header.append("")
            body = res.get("stdout", "")
            if res.get("stderr"):
                body += "\n\n# STDERR:\n" + res.get("stderr")

            full_content = "\n".join(header) + "\n" + body

            try:
                written_full_path = write_output_file(output_file, full_content, metadata={
                    "collected_at": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    "source_ip": ip,
                    "description": description,
                    "command": command
                })
                logger.info(f"- Output saved to {output_file}")
                sha256_hex = compute_sha256(written_full_path)
                append_hash_record(output_file, sha256_hex)
                logger.info(f"- SHA256 recorded for {output_file}: {sha256_hex})")
            except Exception as e:
                logger.error(f"- Unable to write file {output_file}: {e}")

    finally:
        try:
            ssh.close()
        except Exception:
            pass

    logger.info("------------------------------------")

    if len(failed_commands) != 0:
        logger.error(f"{len(failed_commands)} commands failed during collection: {', '.join(failed_commands)}")
    else:
        logger.info("Alls artifacts were collected!")

    if args.zip:
        try:
            create_output_zip(device_type)
        except Exception as e:
            logger.error(f"Failed to create ZIP archive: {e}")

    logger.info("Collection completed.")


if __name__ == '__main__':
    main()