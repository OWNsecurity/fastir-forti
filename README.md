
# 🛡️ FastIR-Forti

---

## 🎯 Goals

FastIR-Forti is a lightweight Python utility that automates the collection of live-response artifacts from Fortinet devices (For now : FortiGate, FortiWeb and FortiADC) using SSH wrapper method and YAML-based command definitions to specify useful artifacts.

It is intended for incident responders who need to automate the execution of diagnostic commands and systematically collect their outputs from Fortinet systems.

## 📋 Features

- 🔍 Collects artifacts (command outputs) from Fortinet devices via SSH
- 🧩 YAML-based artifact definitions for modularity and reuse
- 💾 Saves collected outputs under the outputs/ directory
- 📦 Optionally creates a ZIP archive of all collected data

## 🧰 Requirements

- SSH enable on Fortinet appliance, SSH credentials (username/password)
- Python 3.8+
- Python libs :
  - paramiko (SSH client)
  - PyYAML

Install dependencies with:
```
pip install -r requirements.txt
```

## 🚀 Usage

```
python fastir-forti.py --ip <DEVICE_IP> --type <DEVICE_TYPE>
```

Arguments :
- --ip (mandatory) : Fortinet IP appliance, example: `192.168.100.45`
- --type (mandatory) : Fortinet device type : `fortigate`, `fortiweb`, `fortiadc`
- --timeout (optionnal): specify timeout for ssh connection (default: 10s)
- --port (optionnal): specific SSH port (default: 22)
- --zip (optionnal) : Generate an output ZIP at the end containing output (`output_DEVICETYPE_TIMESTAMP.zip`)

#### Example

```
python fastir-forti.py --ip 192.168.100.45 --type fortigate --zip
```

FastIR-Forti collects artifacts defined in `artifacts/fortigate` on `192.168.100.45` fortigate appliance and creates an output ZIP archive at the end of the execution to simplify transfer to the investigation server.

#### Architecture

```
📁 fastir-forti/
├── fastir-forti.py
├── artifacts/
│   ├── fortigate/
│   │   ├── system_interface.yaml
│   │   ├── system_status.yaml
│   │   └── ...
│   └── fortiweb/
│       └── system_status.yaml
├── outputs/
|   ├── collector_logs.txt
│   ├── fortigate/
│   │   ├── system_interface.txt
│   │   ├── system_status.txt
│   └── └── ...
└── output_fortigate_20251005_213736.zip
```


## 🧩 YAML Artifact Definition

Each YAML file defines one command to collect.

Example:
```
version: 1.0
output_file: fortigate/system/interfaces.txt
description: Get interface information
command: get system interface
```

FastIR-Forti will parse the YAML, extract command line and executes it on the appliance via SSH.

version: Artifact version (for internal tracking)

output_file: Path (under outputs/) where the result will be stored

description: Human-readable summary of the command

command: CLI command executed on the Fortinet device

## 🧾 Example Output

```
root@proxmox-server ~/fastir-forti # python3 fastir-forti.py --ip 192.168.100.45 --type fortigate --zip
Enter forti SSH username: admin
Enter forti SSH password:
2025-10-05 21:30:49,912 INFO: ------------------------------------
2025-10-05 21:30:49,912 INFO: Searching artifacts for type 'fortigate'...
2025-10-05 21:30:49,912 INFO: YAML files found: 12
2025-10-05 21:30:49,912 INFO: ------------------------------------
2025-10-05 21:30:49,912 INFO: Testing SSH connection to 192.168.100.45:22 ...
2025-10-05 21:30:49,915 INFO: Connected (version 2.0, client DEw6V)
2025-10-05 21:30:51,155 INFO: Authentication (password) successful!
2025-10-05 21:30:51,155 INFO: SSH connection successful
2025-10-05 21:30:51,155 INFO: ------------------------------------
2025-10-05 21:30:51,156 INFO: Executing command: diagnose sys print-conserve-info
2025-10-05 21:30:51,341 INFO: - Output saved to fortigate/conserve_mode_info.txt
2025-10-05 21:30:51,342 INFO: Executing command: diagnose sys filesystem hash
2025-10-05 21:30:54,467 INFO: - Output saved to fortigate/filesystem_hash.txt
2025-10-05 21:30:54,467 INFO: Executing command: diagnose sys filesystem tree /
2025-10-05 21:30:56,646 INFO: - Output saved to fortigate/filesystem_tree.txt
2025-10-05 21:30:56,647 INFO: Executing command: show system interface
2025-10-05 21:30:56,702 INFO: - Output saved to fortigate/interfaces.txt
2025-10-05 21:30:56,703 INFO: Executing command: diagnose sys filesystem open-files /
2025-10-05 21:30:56,852 INFO: - Output saved to fortigate/open_files.txt
2025-10-05 21:30:56,852 INFO: Executing command: diagnose sys saml
2025-10-05 21:30:56,867 INFO: - Output saved to fortigate/saml_diagnostics.txt
2025-10-05 21:30:56,867 INFO: Executing command: diagnose sys tcpsock
2025-10-05 21:30:56,934 INFO: - Output saved to fortigate/tcpsock.txt
2025-10-05 21:30:56,934 INFO: Executing command: get system status
2025-10-05 21:30:57,019 INFO: - Output saved to fortigate/system_status.txt
2025-10-05 21:30:57,019 INFO: Executing command: diagnose hardware deviceinfo disk
2025-10-05 21:30:57,131 INFO: - Output saved to fortigate/system_deviceinfo_disk.txt
2025-10-05 21:30:57,132 INFO: Executing command: diagnose log show event 0
2025-10-05 21:30:57,192 INFO: - Output saved to fortigate/system_events_0.txt
2025-10-05 21:30:57,193 INFO: Executing command: diagnose ip address list
2025-10-05 21:30:57,250 INFO: - Output saved to fortigate/ip_address_list.txt
2025-10-05 21:30:57,251 INFO: Executing command: get vpn ssl settings
2025-10-05 21:30:57,310 INFO: - Output saved to fortigate/vpn_ssl_configuration.txt
2025-10-05 21:30:57,310 INFO: ------------------------------------
2025-10-05 21:30:57,310 INFO: Alls artifacts were collected!
2025-10-05 21:30:57,310 INFO: Creating ZIP archive: /root/fastir-forti/output_fortigate_20251005_213057.zip
2025-10-05 21:30:57,406 INFO: Archive successfully created: /root/fastir-forti/output_fortigate_20251005_213057.zip
2025-10-05 21:30:57,406 INFO: Collection completed.
```
