# WithSecure Integration for Wazuh

## Overview

This integration allows Wazuh to collect, parse, and alert on security events from WithSecure's endpoint protection platform.

## Files Included

- **Decoders**: `decoders/withsecure_decoders.xml`
- **Rules**: `rules/withsecure_rules.xml`
- **Scripts**:
  - `scripts/withsecure_logs.py`: Main script for collecting logs from WithSecure API
  - `scripts/generate_test_event.py`: Script for generating test events

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

The decoders extract fields from WithSecure events like `ws.action`, `ws.alertType`, `ws.device_name`, etc.

Made with ❤️ by SaruMan
