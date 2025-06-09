# Microsoft Defender Integration for Wazuh

## Overview
This directory contains decoders, rules, and demo logs for integrating Microsoft Defender security events into Wazuh SIEM. Microsoft Defender provides endpoint protection against malware, viruses, and other threats.

## Directory Structure
- `decoders/`: Contains XML decoder files for parsing Microsoft Defender logs
- `rules/`: Contains XML rule files for alerting on Microsoft Defender events
- `Demo logs/`: Sample log files for testing decoders and rules

## Demo Logs
The `Demo logs/` directory contains sample logs that simulate real Microsoft Defender alerts:

### windows_defender.log
Basic Microsoft Defender alerts including:
- Malware detection events
- Trojan detection and remediation
- Status change notifications
- Configuration change events

### windows_defender_apt.log
Advanced APT (Advanced Persistent Threat) detection logs including:

- **SUNBURST Backdoor (NOBELIUM)**: Critical detection of SolarWinds supply chain compromise components
- **Cobalt Strike Beacon (APT41)**: Backdoor with C2 communication patterns from Chinese state actors
- **APT29 DropBox**: Spearphishing attachment targeting HR personnel
- **HAFNIUM WebShell**: Exchange server web shell deployed by Chinese state-sponsored group
- **Lazarus RAT**: Remote Access Trojan attributed to North Korean threat actors

Each log entry includes enriched data such as:
- Severity and categorization
- File paths and affected systems
- Detection methods and origins
- Actions taken (quarantined, blocked, etc.)
- MITRE ATT&CK technique references
- Threat actor attribution
- Threat intelligence confidence scores

## Usage
1. Deploy the decoders to your Wazuh installation
2. Deploy the corresponding rules
3. Configure Windows systems to forward Microsoft Defender events to Wazuh
4. Test using the provided demo logs

## Log Format
Microsoft Defender logs follow this general format:

```
Microsoft-Windows-Windows Defender/Operational: Log(EVENT_ID)
Windows Defender: HOSTNAME: DOMAIN: HOSTNAME Windows Defender has detected malware
Name: MALWARE_NAME
ID: DETECTION_ID
Severity: SEVERITY_LEVEL
Category: CATEGORY
Path: FILE_PATH
...
```

The decoders in this directory are designed to parse these formats and extract relevant fields for rule matching.

## Installation

### Prerequisites

- Wazuh Server v4.x or higher
- Windows agents with Microsoft Defender enabled
- Proper Windows event collection configured

### Decoder and Rule Installation

1. Copy the decoder file to your Wazuh installation:
   ```bash
   cp decoders/ms_defender_decoders.xml /var/ossec/etc/decoders/
   ```

2. Copy the rule file to your Wazuh installation:
   ```bash
   cp rules/ms_defender_rules.xml /var/ossec/etc/rules/
   ```

3. Restart Wazuh Manager:
   ```bash
   systemctl restart wazuh-manager
   ```

## Configuration

### Agent Configuration

Ensure your Windows agents are configured to collect Microsoft Defender events. Add the following to your agent's `ossec.conf`:

```xml
<ossec_config>
  <localfile>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

## Rules Details

| Rule ID | Level | Description |
|---------|-------|-------------|
| 83000   | 0     | Base rule for Windows Defender events |
| 83001   | 12    | Windows Defender detected potentially unwanted software |
| 83002   | 7     | Windows Defender took action to protect machine |
| 83003   | 12    | Windows Defender alert |
| 83004   | 3     | Windows Defender status changed |
| 83005   | 7     | Windows Defender status changed to non-compliant |
| 83006   | 8     | Windows Defender scanning feature disabled |
| 83007   | 9     | Windows Defender antivirus service stopped |
| 83008   | 8     | Windows Defender antivirus protection disabled |
| 83009   | 3     | Windows Defender antivirus protection enabled |

## Field Mapping

The decoders extract various fields from Windows Defender events:

- `id`: Event ID
- `win.eventdata.name`: Malware/threat name
- `win.eventdata.severity`: Threat severity level
- `win.eventdata.category`: Threat category
- `win.eventdata.path`: Path to the affected file
- `win.eventdata.detectionOrigin`: Origin of detection
- `win.eventdata.detectionType`: Type of detection
- `win.eventdata.detectionSource`: Source of detection
- `win.eventdata.user`: User affected
- `win.eventdata.processName`: Process involved
- `win.eventdata.action`: Action taken
- `win.eventdata.actionStatus`: Status of action
- `win.eventdata.oldStatus`/`win.eventdata.newStatus`: Status change details
- `win.eventdata.featureType`: Feature type changed
- `win.eventdata.oldValue`/`win.eventdata.newValue`: Feature value change details

## Use Cases

- Detect malware and potentially unwanted software on Windows endpoints
- Monitor Microsoft Defender status changes
- Alert when protection features are disabled
- Track remediation actions taken by Microsoft Defender
- Ensure continuous antivirus protection across your environment

Made with ❤️ by SaruMan
