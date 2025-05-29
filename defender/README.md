# Microsoft Defender Integration for Wazuh

## Overview

This integration enables Wazuh to monitor and alert on Microsoft Defender events, providing visibility into antivirus detections, status changes, and protection actions on Windows systems.

## Files Included

- **Decoders**: `decoders/ms_defender_decoders.xml`
- **Rules**: `rules/ms_defender_rules.xml`

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
