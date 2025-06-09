# Kaspersky Integration for Wazuh

## Overview
This directory contains decoders, rules, and demo logs for integrating Kaspersky security events into Wazuh SIEM. Kaspersky offers advanced threat protection and endpoint security solutions for enterprises.

## Directory Structure
- `decoders/`: Contains XML decoder files for parsing Kaspersky logs
- `rules/`: Contains XML rule files for alerting on Kaspersky events
- `Demo logs/`: Sample log files for testing decoders and rules

## Demo Logs
The `Demo logs/` directory contains sample logs that simulate real Kaspersky alerts:

### kaspersky_security.log
Basic Kaspersky security alerts including:
- Virus detection events
- Network attack blocking
- Application control events
- Suspicious activity monitoring

### kaspersky_apt_threats.log
Advanced APT (Advanced Persistent Threat) detection logs including:

- **TURLA/SNAKE**: Memory implant detected in Exchange server processes, attributed to Russian state actors
- **DRAGONFLY/ENERGETIC BEAR**: Data exfiltration attempt from R&D workstation, Russian APT group targeting energy sector
- **APT41 POISONPLUG**: Supply chain compromise via backdoored library in Jenkins build server
- **LAZARUS**: DCSync attack for credential theft, attributed to North Korean actors
- **WIZARD SPIDER/RYUK**: Credential harvesting tools detected, financially motivated threat actor
- **FIN7**: Fileless malware utilizing Windows PowerShell, targeting finance department

Each log entry includes enriched data such as:
- Detailed APT group attribution
- MITRE ATT&CK technique references
- Threat scores and risk levels
- Detection methods
- Process information
- Action taken (blocked, quarantined)
- Timestamps of detection

## Usage
1. Deploy the decoders to your Wazuh installation
2. Deploy the corresponding rules
3. Configure Kaspersky to forward logs to Wazuh
4. Test using the provided demo logs

## Log Format
Kaspersky logs follow the Common Event Format (CEF):

```
CEF:0|KasperskyLab|SecurityCenter|VERSION|EVENT_TYPE|EVENT_NAME|SEVERITY|key1=value1 key2=value2...
```

The decoders in this directory are designed to parse these formats and extract relevant fields for rule matching.

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
