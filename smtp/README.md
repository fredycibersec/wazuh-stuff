# SMTP Integration for Wazuh Using Office 365

## Overview

This integration enables Wazuh to send email alerts through Microsoft Office 365 SMTP servers. Since Wazuh doesn't natively support authenticated SMTP, this integration uses Postfix as a relay server to handle the authentication with Office 365.

## Files Included

- **Scripts**: `scripts/setup_o365_smtp.sh` - Script to configure Postfix and Wazuh for email alerts

## Installation

### Prerequisites

- Wazuh Server v4.x or higher
- Root access to the Wazuh server
- Microsoft Office 365 account with SMTP authentication enabled
- Outbound access to Office 365 SMTP server (`smtp.office365.com:587`)

### Setup Instructions

1. Make the setup script executable:
   ```bash
   chmod +x scripts/setup_o365_smtp.sh
   ```

2. Run the setup script with your Office 365 email and password:
   ```bash
   sudo ./scripts/setup_o365_smtp.sh youremail@yourdomain.com yourpassword
   ```

3. Edit Wazuh configuration to specify recipient email address:
   ```bash
   sudo nano /var/ossec/etc/ossec.conf
   ```
   
   Find the `<email_to>` tag and update it with your recipient email address.

4. Restart Wazuh manager:
   ```bash
   sudo systemctl restart wazuh-manager
   ```

## Configuration Details

### Postfix Configuration

The setup script configures Postfix with the following settings:

```
relayhost = [smtp.office365.com]:587
mynetworks = 127.0.0.0/8
inet_interfaces = loopback-only
smtp_use_tls = yes
smtp_always_send_ehlo = yes
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_sasl_tls_security_options = noanonymous
smtp_tls_security_level = encrypt
smtp_generic_maps = hash:/etc/postfix/generic
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination
```

### Wazuh Email Configuration

The script adds the following to your Wazuh configuration:

```xml
<global>
  <email_notification>yes</email_notification>
  <email_to>recipient@yourdomain.com</email_to>
  <smtp_server>localhost</smtp_server>
  <email_from>wazuh@hostname</email_from>
  <email_maxperhour>12</email_maxperhour>
  <email_idsname>Wazuh</email_idsname>
</global>
```

## Customizing Email Alerts

You can customize when Wazuh sends email alerts by adding email_alerts sections to your Wazuh configuration:

```xml
<email_alerts>
  <email_to>recipient@yourdomain.com</email_to>
  <level>10</level>
  <group>authentication_failure,authentication_success</group>
  <do_not_delay />
</email_alerts>
```

This example would send immediate email alerts for any authentication-related events with a level of 10 or higher.

## Troubleshooting

1. Test email delivery:
   ```bash
   echo "Test email from Wazuh" | mail -s "Wazuh Test" recipient@yourdomain.com
   ```

2. Check Postfix logs:
   ```bash
   tail -f /var/log/mail.log
   ```

3. Verify Postfix service is running:
   ```bash
   systemctl status postfix
   ```

4. Check Wazuh manager logs:
   ```bash
   tail -f /var/ossec/logs/ossec.log
   ```

## Security Notes

- The Office 365 credentials are stored in `/etc/postfix/sasl_passwd` and `/etc/postfix/sasl_passwd.db`
- These files have restricted permissions (0600) to prevent unauthorized access
- Consider using an App Password or dedicated service account for enhanced security
- Regularly rotate the password used for SMTP authentication

Made with ❤️ by SaruMan
