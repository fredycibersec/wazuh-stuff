# Synology Integration for Wazuh

## Overview

This integration enables Wazuh to monitor Synology NAS devices by collecting and analyzing logs from Synology DiskStation Manager (DSM). It provides visibility into file operations, access to shared folders, authentication events, and system events on Synology devices.

## Files Included

- **Decoders**: `decoders/synology_decoders.xml`
- **Rules**: `rules/synology_rules.xml`

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
