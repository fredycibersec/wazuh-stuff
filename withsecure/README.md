# WithSecure Integration for Wazuh

## Overview
This directory contains decoders, rules, and demo logs for integrating WithSecure (formerly F-Secure) security events into Wazuh SIEM. WithSecure offers enterprise-grade endpoint protection and advanced threat detection solutions.

## Files Included

- **Decoders**: `Contains XML decoder files for parsing WithSecure logs`
- **Rules**: `Contains XML rule files for alerting on WithSecure events`
- **Scripts**:
  - `scripts/withsecure_logs.py`: Main script for collecting logs from WithSecure API
  - `scripts/generate_test_event.py`: Script for generating test events
- **Demo logs**: `Sample log files for testing decoders and rules`

## Demo Logs
The `Demo logs/` directory contains sample logs that simulate real WithSecure alerts:

### withsecure_events.log
Basic WithSecure security alerts including:
- Malware detection and blocking
- Ransomware prevention events
- Suspicious behavior monitoring
- Application control logs

### withsecure_apt_detections.log
Advanced APT (Advanced Persistent Threat) detection logs including:

- **SANDWORM**: Targeted email attachment with ELECTRUM payload, attributed to Russian state actors targeting industrial systems
- **GALLIUM**: Webshell detected in IIS web application, Chinese state actor targeting telecommunications
- **APT10/MENUPASS**: Credential dumping attempt using PlugX variant, attributed to Chinese threat actors
- **KIMSUKY**: Command & Control communication to malicious domain from developer workstation, North Korean actor
- **HAFNIUM**: Data exfiltration attempt from database server using China Chopper webshell
- **CARBON SPIDER**: DARKSIDE ransomware deployment attempt through PowerShell, financially motivated threat group

Each log entry includes enriched data such as:
- Actions taken (blocked, quarantined)
- Alert types and severity
- Device and organization information
- Process details and file paths
- Malware identification
- MITRE ATT&CK technique references
- Attack stage information
- Threat actor attribution
- Campaign identification
- Confidence scores

## Usage
1. Deploy the decoders to your Wazuh installation
2. Deploy the corresponding rules
3. Configure WithSecure to forward logs to Wazuh
4. Test using the provided demo logs

## Log Format
WithSecure logs follow this general format:

```
timestamp hostname withsecure-collector[process_id]: key="value" key="value"...
```

The decoders in this directory are designed to parse these formats and extract relevant fields for rule matching.

## Installation

### Decoder and Rule Installation

1. Copy the decoder file to your Wazuh installation:
   ```bash
   cp decoders/withsecure_decoders.xml /var/ossec/etc/decoders/
   ```

2. Copy the rule file to your Wazuh installation:
   ```bash
   cp rules/withsecure_rules.xml /var/ossec/etc/rules/
   ```

3. Restart Wazuh Manager:
   ```bash
   systemctl restart wazuh-manager
   ```

### API Integration Setup

1. Install required Python libraries:
   ```bash
   pip3 install requests
   ```

2. Copy the integration script:
   ```bash
   cp scripts/withsecure_logs.py /var/ossec/integrations/
   chmod +x /var/ossec/integrations/withsecure_logs.py
   ```

3. Configure environment variables for the API:
   ```bash
   export WITHSECURE_AUTH="your-base64-encoded-credentials"
   export WITHSECURE_ORG_ID="your-organization-id"
   ```

## Rules Details

| Rule ID | Level | Description |
|---------|-------|-------------|
| 110100  | 3     | Base rule for WithSecure events |
| 110101  | 15    | High severity events |
| 110102  | 8     | Medium severity events |
| 110103  | 13    | Blocked events |
| 110104  | 8     | Harmful webpage blocks |
| 110110  | 12    | Malware detection |
| 110111  | 10    | Suspicious execution |
| 110140  | 10    | High frequency of similar events |
| 110150  | 8     | DeepGuard protection events |
| 110190  | 5     | Generic events catch-all |

## Field Mapping
The decoders extract the following fields from WithSecure events:

- `ws.action`: Action taken by WithSecure
- `ws.alertType`: Type of alert
- `ws.device_name`: Name of the affected device
- `ws.engine`: WithSecure engine information
- `ws.event_id`: Event transaction ID
- `ws.organization_name`: Organization name
- `ws.process`: Process involved
- `ws.reason`: Reason for alert
- `ws.description`: Detailed description
- `ws.severity`: Severity level
- `ws.userName`: User affected
- Various other fields including infection details and host information

Made with ❤️ by SaruMan
