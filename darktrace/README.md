# Darktrace Integration for Wazuh

## Overview
This directory contains decoders, rules, and demo logs for integrating Darktrace security alerts into Wazuh SIEM. Darktrace is an AI-based cyber defense platform that detects and responds to emerging threats using machine learning.

## Directory Structure
- `decoders/`: Contains XML decoder files for parsing Darktrace logs
- `rules/`: Contains XML rule files for alerting on Darktrace events
- `Demo logs/`: Sample log files for testing decoders and rules

## Demo Logs
The `Demo logs/` directory contains sample logs that simulate real Darktrace alerts:

### darktrace_alert.log
Basic Darktrace alerts including:
- Suspicious connection detection
- Lateral movement alerts
- Configuration audit events
- Model breach notifications

### darktrace_apt_activity.log
Advanced APT (Advanced Persistent Threat) detection logs including:
- **APT28 (Fancy Bear)**: Command and Control communication detection
- **NOBELIUM**: Data exfiltration to known malicious infrastructure
- **STONE PANDA**: Unusual admin credential use and lateral movement
- **VENOMOUS BEAR (Turla)**: Suspicious RDP connection chains
- **EMBER BEAR**: Data staging activity for potential exfiltration

Each log entry includes enriched data such as:
- MITRE ATT&CK technique references
- Threat actor attribution
- Attack phase identification
- Confidence scores
- Affected systems and data

## Usage
1. Deploy the decoders to your Wazuh installation
2. Deploy the corresponding rules
3. Configure Darktrace to forward logs to Wazuh
4. Test using the provided demo logs

## Log Format
Darktrace logs follow several formats depending on the event type:

1. **Alert events**:
   ```
   timestamp hostname darktrace {JSON alert data}
   ```

2. **Audit events**:
   ```
   timestamp hostname darktrace_audit {JSON audit data}
   ```

3. **Model breach events**:
   ```
   timestamp hostname model-breach {JSON model data}
   ```

The decoders in this directory are designed to parse these formats and extract relevant fields for rule matching.


## Installation

### Prerequisites

- Wazuh Server v4.x or higher
- Darktrace Enterprise Immune System
- Access to Darktrace API or log forwarding capability

### Decoder and Rule Installation

1. Copy the decoder file to your Wazuh installation:
   ```bash
   cp decoders/darktrace_decoders.xml /var/ossec/etc/decoders/
   ```

2. Copy the rule file to your Wazuh installation:
   ```bash
   cp rules/darktrace_rules.xml /var/ossec/etc/rules/
   ```

3. Restart Wazuh Manager:
   ```bash
   systemctl restart wazuh-manager
   ```

## Configuration

### Darktrace Integration Setup

There are two main methods to integrate Darktrace with Wazuh:

#### Method 1: API Integration

Configure a script to pull events from the Darktrace API and forward them to Wazuh:

1. Create a dedicated API key in Darktrace
2. Set up a scheduled task to query the Darktrace API
3. Format the output as JSON and send to Wazuh

#### Method 2: Syslog Forwarding

Configure Darktrace to forward events via syslog:

1. In Darktrace, navigate to System Config > Integration > Syslog
2. Configure the Wazuh server as a syslog destination (p.e. port 514 UDP/TCP).
3. Select JSON as the output format
4. Choose which event types to forward (alerts, model breaches, audit logs)

### Wazuh Configuration

Add the following to your `ossec.conf` to properly receive Darktrace events:

```xml
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/darktrace.log</location>
  </localfile>
</ossec_config>
```


## Rules Details

| Rule ID | Level | Description |
|---------|-------|-------------|
| 119000  | 12    | Base rule for Darktrace alerts |
| 119001  | 12    | Base rule for Darktrace model breaches |
| 119002  | 12    | Base rule for Darktrace audit events |
| 119010  | 14    | Critical/High severity Darktrace alert |
| 119011  | 10    | Medium severity Darktrace alert |
| 119012  | 7     | Low severity Darktrace alert |
| 119020  | 14    | Critical model breach (score 90-100) |
| 119021  | 12    | High model breach (score 70-89) |
| 119022  | 10    | Medium model breach (score 40-69) |
| 119023  | 7     | Low model breach (score 10-39) |

## Field Mapping

The decoders use the JSON decoder plugin to extract fields from Darktrace events, including:

- `alert.description`: Description of the alert
- `alert.severity`: Severity level of the alert
- `breach.score`: Numerical score of the model breach
- `breach.model`: Model that triggered the breach
- Various other fields like device information, timestamps, and event details

## Use Cases

- Monitor for unusual network behavior detected by Darktrace
- Correlate Darktrace alerts with other security events in Wazuh
- Create automated response actions based on Darktrace detections
- Generate comprehensive reports of security incidents across platforms
- Maintain compliance with security frameworks using Darktrace's advanced detection capabilities

Made with ❤️ by SaruMan
