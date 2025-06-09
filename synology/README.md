# Synology Integration for Wazuh

## Overview
This directory contains decoders, rules, and demo logs for integrating Synology NAS security events into Wazuh SIEM. Synology offers network-attached storage solutions with built-in security features and monitoring capabilities.

## Directory Structure
- `decoders/`: Contains XML decoder files for parsing Synology logs
- `rules/`: Contains XML rule files for alerting on Synology events
- `Demo logs/`: Sample log files for testing decoders and rules

## Demo Logs
The `Demo logs/` directory contains sample logs that simulate real Synology alerts:

### synology_logs.log
Basic Synology security logs including:
- Connection and authentication events
- File access and modifications
- SSH login attempts
- WinFileService activities

### synology_apt_attacks.log
Advanced APT (Advanced Persistent Threat) simulation logs including:

- **Suspicious User Activity**: Unauthorized backdoor account accessing sensitive shared folders (executive_files, financial_data, strategic_plans)
- **Data Exfiltration Preparation**: Suspicious file operations on financial and strategic documents
- **APT28 (Fancy Bear)**: SSH brute-force attempts from known APT28 IP ranges
- **APT41**: Suspicious outbound connections to known APT41 command and control infrastructure
- **APT29 (Cozy Bear)**: Malicious executable detected in backup directory attributed to Russian SVR
- **NOBELIUM**: TEARDROP loader detection in system backup scripts
- **HAFNIUM**: Scanning patterns targeting management ports matching known HAFNIUM tactics

Each log entry includes realistic details such as:
- Timestamps
- User accounts
- IP addresses
- Accessed resources
- File paths
- Malware names
- Threat actor attributions
- Attack patterns

## Usage
1. Deploy the decoders to your Wazuh installation
2. Deploy the corresponding rules
3. Configure Synology to forward logs to Wazuh
4. Test using the provided demo logs

## Log Format
Synology logs follow several formats depending on the event type:

1. **Connection events**:
   ```
   timestamp hostname Connection: User [username] from [ip] accessed shared folder [folder_name]
   ```

2. **WinFileService events**:
   ```
   timestamp hostname WinFileService Event: EVENT_TYPE, Path: PATH, File/Folder: FILENAME, User: USER, IP: IP_ADDRESS
   ```

3. **SSH events**:
   ```
   timestamp hostname sshd[pid]: from=user@ip user=username
   ```

4. **System events**:
   ```
   timestamp hostname service_name: message
   ```

The decoders in this directory are designed to parse these formats and extract relevant fields for rule matching.

## Installation

### Prerequisites

- Wazuh Server v4.x or higher
- Synology NAS with DSM 6.x or higher
- Properly configured syslog forwarding from Synology

### Decoder and Rule Installation

1. Copy the decoder file to your Wazuh installation:
   ```bash
   cp decoders/synology_decoders.xml /var/ossec/etc/decoders/
   ```

2. Copy the rule file to your Wazuh installation:
   ```bash
   cp rules/synology_rules.xml /var/ossec/etc/rules/
   ```

3. Restart Wazuh Manager:
   ```bash
   systemctl restart wazuh-manager
   ```

## Configuration

### Synology Log Forwarding Setup

To forward Synology logs to Wazuh, follow these steps:

1. Log in to Synology DSM
2. Go to Control Panel > Log Center > Log Settings
3. Enable "Send logs to a syslog server"
4. Enter your Wazuh server IP address
5. Select the appropriate protocol (UDP or TCP) and port
6. Choose the log types to forward (System, Connections, File Transfer, etc.)
7. Click Apply

### Wazuh Configuration

Add the following to your `ossec.conf` to properly receive Synology logs:

```xml
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/synology.log</location>
  </localfile>
</ossec_config>
```

## Rules Details

| Rule ID | Level | Description |
|---------|-------|-------------|
| 130000  | 3     | Base rule for Synology connection logs |
| 130001  | 7     | Base rule for Synology file events |
| 130002  | 11    | File deletion detected |
| 130003  | 10    | File rename detected |
| 130004  | 10    | File write detected |
| 130005  | 7     | File read detected |
| 130006  | 12    | File permission change detected |
| 130010  | 3     | Synology system event detected |
| 130011  | 7     | Synology authentication event detected |
| 130012  | 10    | Failed authentication attempt |
| 130013  | 12    | Multiple authentication failures (possible brute force) |
| 130020  | 12    | Unauthorized access attempt |

## Field Mapping

The decoders extract various fields from Synology logs, including:

- `user_conn`: User accessing a connection
- `host_conn`: Host/IP address making the connection
- `event_sharedfolder`: Shared folder being accessed
- `event`: Type of file operation (read, write, delete, rename, permission)
- `path`: Path to the file or folder
- `file`: File or folder name
- `username`: Username performing the action
- `ip`: IP address of the user
- `srcip`: Source IP for authentication events
- `user`: Username for authentication events

## Use Cases

- Monitor file operations on shared folders
- Track user access to NAS resources
- Detect unauthorized access attempts
- Identify potential data exfiltration through excessive file deletions
- Monitor authentication failures and brute force attempts
- Track system events and status changes on Synology devices

Made with ❤️ by SaruMan
