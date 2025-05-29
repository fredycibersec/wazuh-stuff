# Kaspersky Integration for Wazuh

## Overview

This integration allows Wazuh to collect, analyze, and alert on security events from Kaspersky Endpoint Security and Kaspersky Security Center. The integration provides comprehensive visibility into threats detected by Kaspersky products, including viruses, suspicious activities, attacks, and system status events.

## Files Included

- **Decoders**: `decoders/kaspersky_decoders.xml`
- **Rules**: `rules/kaspersky_rules.xml`

## Installation

### Prerequisites

- Wazuh Server v4.x or higher
- Kaspersky Endpoint Security or Kaspersky Security Center
- Properly configured syslog forwarding from Kaspersky

### Decoder and Rule Installation

1. Copy the decoder file to your Wazuh installation:
   ```bash
   cp decoders/kaspersky_decoders.xml /var/ossec/etc/decoders/
   ```

2. Copy the rule file to your Wazuh installation:
   ```bash
   cp rules/kaspersky_rules.xml /var/ossec/etc/rules/
   ```

3. Restart Wazuh Manager:
   ```bash
   systemctl restart wazuh-manager
   ```

## Configuration

### Kaspersky Log Forwarding Setup

To forward Kaspersky logs to Wazuh, configure Kaspersky Security Center to send events in CEF format:

1. In Kaspersky Security Center, navigate to Settings > External Event Services
2. Add a new Syslog service pointing to your Wazuh server
3. Configure the format as CEF (Common Event Format)
4. Select the event types you want to forward

### Wazuh Configuration

Add the following to your `ossec.conf` to properly receive Kaspersky events:

```xml
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/kaspersky.log</location>
  </localfile>
</ossec_config>
```
Or configure the syslog TCP/UDP port in your allowed sourceIP's.

## Rules Details

| Rule ID | Level | Description |
|---------|-------|-------------|
| 120090  | 0     | Base rule for Kaspersky events |
| 120092  | 3     | Generic attack detection |
| 120093  | 3     | Generic object detection |
| 120095  | 12    | Attack detected |
| 120096  | 12    | Virus found |
| 120097  | 12    | Malicious object blocked/quarantined/deleted |
| 120098  | 8     | License expiration warning |
| 120099  | 12    | Suspicious object found |
| 120100  | 10    | Intrusion detected |
| 120101  | 10    | Object infected |
| 120102  | 8     | Suspicious activity detected |

## Field Mapping

The decoders extract numerous fields from Kaspersky CEF-formatted events, including:

- `dhost`: Destination hostname
- `dstip`: Destination IP
- `srcip`: Source IP
- `dstport`: Destination port
- `duser`: Username
- `data.Kaspersky.description`: Event description
- `data.Kaspersky.action`: Action taken
- Various other CEF fields (cs1-cs10, cn1, etc.) that contain specific Kaspersky event details that you can personalize in the ruleset.

## Use Cases

- Monitor for malware and virus detections across your environment
- Track suspicious activities on endpoints
- Detect potential intrusions and attacks
- Monitor Kaspersky license status
- Create comprehensive security reports including endpoint protection status
- Correlate Kaspersky events with other security information for better threat hunting

Made with ❤️ by SaruMan
