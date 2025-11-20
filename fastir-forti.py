#!/usr/bin/env python3
"""
FastIR-Forti

Lightweight Python utility that automates the collection of live-response artifacts from Fortinet devices using SSH wrapper method and YAML-based command definitions to specify useful artifacts.

Process:
- Loads all YAML files from artifacts/<type>/*.yaml related to asset type
- Connects via SSH and checks the connection.
- Executes the commands to collect artifacts and saves the output into the specified folder

Usage:
    python fastir-forti.py --ip IP --type DEVICE_TYPE

Optional :
    --zip : create ZIP output
    --port : specific SSH port

Example :
    python fastir-forti.py --ip 192.168.100.45 --type fortigate --zip

Requirements:
    pip install paramiko pyyaml

"""

import argparse
import csv
import getpass
import hashlib
import logging
import sys
import time
import zipfile
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, Generator, List, Optional, Tuple

try:
    import paramiko
except ImportError as e:
    print(f"Module 'paramiko' not found: {e}")
    print("Install it using: pip install paramiko")
    sys.exit(1)

try:
    import yaml
except ImportError as e:
    print(f"Module 'PyYAML' not found: {e}")
    print("Install it using: pip install pyyaml")
    sys.exit(1)

# -----------------------------
# --- Constants ---
DEFAULT_SSH_PORT = 22
DEFAULT_SSH_TIMEOUT = 10
DEFAULT_COMMAND_TIMEOUT = 30
CHUNK_SIZE = 1024 * 1024  # 1MB for file hash computation

# -----------------------------
# --- Logging configuration ---
LOG_DIR = Path("outputs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "collector_logs.txt"
HASH_CSV_PATH = LOG_DIR / "hashes.txt"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8"),
        logging.StreamHandler(),  # also log to console
    ],
)

logger = logging.getLogger("fastir-forti")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed command-line arguments containing ip, port, type, timeout, and zip options.
    """
    p = argparse.ArgumentParser(
        description="Collects command outputs from Fortinet devices via SSH"
    )
    p.add_argument(
        "--ip",
        required=True,
        help="Fortinet device IP address",
    )
    p.add_argument(
        "--port",
        type=int,
        default=DEFAULT_SSH_PORT,
        help=f"SSH port (default: {DEFAULT_SSH_PORT})",
    )
    p.add_argument(
        "--type",
        required=True,
        choices=["fortigate", "fortiweb", "fortiadc"],
        help="Device type (e.g., fortigate, fortiweb, fortiadc)",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_SSH_TIMEOUT,
        help=f"SSH connection timeout in seconds (default: {DEFAULT_SSH_TIMEOUT})",
    )
    p.add_argument(
        "--zip",
        action="store_true",
        help="Create a ZIP archive based on the the outputs/ folder after collection",
    )
    return p.parse_args()


def prompt_credentials() -> Tuple[str, str]:
    """Prompt user for SSH credentials interactively.

    Returns:
        Tuple[str, str]: Username and password for SSH authentication.
    """
    username = input("Enter forti SSH username: ").strip()
    password = getpass.getpass("Enter forti SSH password: ")
    return username, password


def discover_artifact_files(device_type: str) -> List[Path]:
    """Discover YAML artifact definition files for a specific device type.

    Args:
        device_type: Type of Fortinet device (fortigate, fortiweb, fortiadc).

    Returns:
        List[Path]: Sorted list of Path objects pointing to YAML artifact files.
    """
    base = Path("artifacts") / device_type
    files = list(base.glob("*.yml")) + list(base.glob("*.yaml"))
    return sorted(files)


def load_yaml_file(path: Path) -> Dict:
    """Load and parse a YAML artifact definition file.

    Args:
        path: Path to the YAML file to load.

    Returns:
        Dict: Parsed YAML data as a dictionary, or empty dict if file is empty.
    """
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data or {}


def validate_artifact_structure(data: Dict, path: str) -> None:
    """Validate that artifact YAML contains all required fields.

    Args:
        data: Parsed YAML data dictionary to validate.
        path: Path to YAML file (for error messages).

    Raises:
        ValueError: If any required field is missing from the artifact definition.
    """
    required = ["version", "output_file", "description", "command"]
    for r in required:
        if r not in data:
            raise ValueError(f"YAML file {path} is missing required key: {r}")


def ensure_parent_dir(path: Path) -> None:
    """Ensure parent directory exists for a given file path.

    Args:
        path: File path whose parent directory should be created.
    """
    path.parent.mkdir(parents=True, exist_ok=True)


@contextmanager
def ssh_connection(
    ip: str, port: int, username: str, password: str, timeout: int = DEFAULT_SSH_TIMEOUT
) -> Generator[paramiko.SSHClient, None, None]:
    """Context manager for SSH connections with automatic cleanup.

    Args:
        ip: IP address of the Fortinet device.
        port: SSH port number.
        username: SSH username.
        password: SSH password.
        timeout: Connection timeout in seconds (default: DEFAULT_SSH_TIMEOUT).

    Yields:
        paramiko.SSHClient: Connected SSH client instance.

    Raises:
        Exception: If SSH connection fails.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec B507
    try:
        client.connect(
            hostname=ip,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        yield client
    finally:
        client.close()


def run_command(
    ssh_client: paramiko.SSHClient, command: str, timeout: int = DEFAULT_COMMAND_TIMEOUT
) -> Dict[str, str]:
    """Execute a command on the SSH connection and return results.

    Args:
        ssh_client: Connected SSH client instance.
        command: Command string to execute on remote device.
        timeout: Command execution timeout in seconds (default: DEFAULT_COMMAND_TIMEOUT).

    Returns:
        Dict: Dictionary containing stdout, stderr, and exit_status keys.
    """
    stdin, stdout, stderr = ssh_client.exec_command(command, timeout=timeout)  # nosec B601
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    exit_status = stdout.channel.recv_exit_status()
    return {"stdout": out, "stderr": err, "exit_status": exit_status}


def write_output_file(path: str, content: str, metadata: Optional[Dict] = None) -> Path:
    """Write artifact content to output file with proper directory structure.

    Args:
        path: Relative path within outputs/ directory.
        content: Content to write to the file.
        metadata: Optional metadata dict (currently unused, reserved for future use).

    Returns:
        Path: Absolute Path object to the written file.
    """
    full_path = Path("outputs") / path.lstrip("/")
    ensure_parent_dir(full_path)
    full_path.write_text(content, encoding="utf-8")
    return full_path


def create_output_zip(device_type: str) -> Path:
    """Create a ZIP archive of all collected artifacts.

    Creates a timestamped ZIP file in the current directory containing
    all files from the outputs/ folder.

    Args:
        device_type: Type of device (used in ZIP filename).

    Returns:
        Path: Path to the created ZIP archive.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_name = f"output_{device_type}_{timestamp}.zip"
    zip_path = Path.cwd() / zip_name

    logger.info(f"Creating ZIP archive: {zip_path}")

    outputs_dir = Path("outputs")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for file_path in outputs_dir.rglob("*"):
            if file_path.is_file():
                arcname = Path("outputs") / file_path.relative_to(outputs_dir)
                zipf.write(file_path, arcname)

    logger.info(f"Archive successfully created: {zip_path}")
    return zip_path


def compute_sha256(file_path: Path) -> str:
    """Compute SHA256 hash of a file using chunked reading.

    Args:
        file_path: Path to the file to hash.

    Returns:
        str: Hexadecimal SHA256 hash of the file.
    """
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def append_hash_record(relative_output_path: str, sha256_hex: str) -> None:
    """Append hash record to CSV file using csv module for proper formatting.

    Args:
        relative_output_path: Relative path to the output file.
        sha256_hex: SHA256 hash in hexadecimal format.
    """
    header_needed = not HASH_CSV_PATH.exists()
    with HASH_CSV_PATH.open("a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if header_needed:
            writer.writerow(["filename", "hash"])
        writer.writerow([relative_output_path, sha256_hex])


def main() -> None:
    """Main entry point for FastIR-Forti artifact collection.

    Orchestrates the complete artifact collection workflow:
    1. Parse command-line arguments
    2. Prompt for SSH credentials
    3. Discover artifact definition files
    4. Connect to device via SSH
    5. Execute commands and collect outputs
    6. Compute and record file hashes
    7. Optionally create ZIP archive
    """
    args = parse_args()
    ip = args.ip
    device_type = args.type

    username, password = prompt_credentials()

    logger.info("------------------------------------")
    logger.info(f"Searching artifacts for type '{device_type}'...")
    artifact_files = discover_artifact_files(device_type)

    if not artifact_files:
        logger.warning(
            f"No YAML files found in artifacts/{device_type}. Please check artifacts folder, files are missing."
        )
        sys.exit(2)

    logger.info(f"YAML files found: {len(artifact_files)}")

    logger.info("------------------------------------")

    logger.info(f"Testing SSH connection to {ip}:{args.port} ...")
    failed_commands = []
    try:
        with ssh_connection(
            ip=ip,
            port=args.port,
            username=username,
            password=password,
            timeout=args.timeout,
        ) as ssh:
            logger.info("SSH connection successful")
            logger.info("------------------------------------")
            for yaml_file in artifact_files:
                try:
                    data = load_yaml_file(yaml_file)
                    validate_artifact_structure(data, yaml_file)
                except Exception as e:
                    logger.error(f"Error reading/validating {yaml_file}: {e}")
                    failed_commands.append(str(yaml_file))
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
                header.append(
                    f"# Collected at: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}"
                )
                header.append(f"# Exit status: {res.get('exit_status')}")
                header.append("")
                body = res.get("stdout", "")
                if res.get("stderr"):
                    body += "\n\n# STDERR:\n" + res.get("stderr")

                full_content = "\n".join(header) + "\n" + body

                try:
                    written_full_path = write_output_file(
                        output_file,
                        full_content,
                        metadata={
                            "collected_at": time.strftime(
                                "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                            ),
                            "source_ip": ip,
                            "description": description,
                            "command": command,
                        },
                    )
                    logger.info(f"- Output saved to {output_file}")
                    sha256_hex = compute_sha256(written_full_path)
                    append_hash_record(output_file, sha256_hex)
                    logger.info(f"- SHA256 recorded for {output_file}: {sha256_hex})")
                except Exception as e:
                    logger.error(f"- Unable to write file {output_file}: {e}")
    except Exception as e:
        logger.error(f"SSH connection failed: {e}")
        sys.exit(3)

    logger.info("------------------------------------")

    if failed_commands:
        logger.error(
            f"{len(failed_commands)} command(s) failed during collection: {', '.join(failed_commands)}"
        )
    else:
        logger.info("All artifacts were collected!")

    if args.zip:
        try:
            create_output_zip(device_type)
        except Exception as e:
            logger.error(f"Failed to create ZIP archive: {e}")

    logger.info("Collection completed.")


if __name__ == "__main__":
    main()
