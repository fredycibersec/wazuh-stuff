#!/bin/bash
# Setup Office 365 SMTP relay for Wazuh email alerts
# This script configures Postfix to relay emails through Office 365
# Usage: ./setup_o365_smtp.sh youremail@yourdomain.com yourpassword

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Check if arguments are provided
if [ $# -ne 2 ]; then
    echo "Usage: $0 youremail@yourdomain.com yourpassword"
    exit 1
fi

EMAIL=$1
PASSWORD=$2

# Install required packages
echo "Installing required packages..."
apt update
apt install -y postfix mailutils libsasl2-2 ca-certificates libsasl2-modules

# Configure Postfix
echo "Configuring Postfix..."
cat > /etc/postfix/main.cf << EOL
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
EOL

# Create SASL password file
echo "Creating SASL password file..."
echo "[smtp.office365.com]:587 $EMAIL:$PASSWORD" > /etc/postfix/sasl_passwd
chown root:root /etc/postfix/sasl_passwd
chmod 0600 /etc/postfix/sasl_passwd
postmap /etc/postfix/sasl_passwd

# Create generic mapping
echo "Creating generic mapping file..."
HOSTNAME=$(hostname)
echo "root@$HOSTNAME $EMAIL" > /etc/postfix/generic
echo "@$HOSTNAME $EMAIL" >> /etc/postfix/generic
postmap /etc/postfix/generic

# Restart Postfix
echo "Restarting Postfix..."
systemctl restart postfix

# Configure Wazuh
echo "Updating Wazuh configuration..."
cat >> /var/ossec/etc/ossec.conf << EOL
<global>
  <email_notification>yes</email_notification>
  <email_to>recipient@yourdomain.com</email_to>
  <smtp_server>localhost</smtp_server>
  <email_from>wazuh@$HOSTNAME</email_from>
  <email_maxperhour>12</email_maxperhour>
  <email_idsname>Wazuh</email_idsname>
</global>
EOL

# Restart Wazuh
echo "Restarting Wazuh Manager..."
systemctl restart wazuh-manager

echo "Office 365 SMTP relay setup complete!"
echo "Don't forget to edit /var/ossec/etc/ossec.conf and update email_to with your recipient email address."

exit 0
