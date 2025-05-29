# Wazuh Agent Installation Scripts

## Overview

This directory contains installation scripts for deploying Wazuh agents on various platforms. These scripts simplify the process of installing, configuring, and registering Wazuh agents with your Wazuh manager.

## Available Scripts

### Windows Installation Script

- **File**: `install_agent_windows.ps1`
- **Description**: PowerShell script for installing Wazuh agents on Windows systems
- **Usage**:
  ```powershell
  .\install_agent_windows.ps1 -WazuhManager "wazuh-manager.yourdomain.com" -WazuhAgentGroup "windows-servers"
  ```

### Linux Installation Script

- **File**: `install_agent_linux.sh`
- **Description**: Bash script for installing Wazuh agents on Linux systems
- **Usage**:
  ```bash
  sudo ./install_agent_linux.sh --manager wazuh-manager.yourdomain.com --group linux-servers
  ```

## Windows Script Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-WazuhManager` | IP or hostname of the Wazuh manager | `wazuh-manager.yourdomain.com` |
| `-WazuhRegistrationServer` | IP or hostname of the registration server | Same as manager |
| `-WazuhAgentGroup` | Agent group to assign | `default` |
| `-WazuhVersion` | Version of Wazuh to install | `4.7.5` |
| `-UseHostnameAsAgentName` | Use system hostname as agent name | `$true` |

## Linux Script Parameters

| Option | Description | Default |
|--------|-------------|---------|
| `-m, --manager` | IP or hostname of the Wazuh manager | `wazuh-manager.yourdomain.com` |
| `-r, --registration` | IP or hostname of the registration server | Same as manager |
| `-g, --group` | Agent group to assign | `default` |
| `-v, --version` | Version of Wazuh to install | `4.7.5` |
| `-n, --name` | Agent name | System hostname |
| `-h, --help` | Show help message | - |

## Usage Examples

### Mass Deployment on Windows

You can use Group Policy (GPO) to deploy the agent on multiple Windows systems:

1. Create a shared folder with the installation script
2. Create a GPO that runs the script with appropriate parameters
3. Link the GPO to your organizational unit (OU)

Example GPO command:
```
PowerShell.exe -ExecutionPolicy Bypass -File "\\server\share\install_agent_windows.ps1" -WazuhManager "192.168.1.10" -WazuhAgentGroup "windows-workstations"
```

### Mass Deployment on Linux

For Linux systems, you can use configuration management tools like Ansible:

```yaml
- name: Download Wazuh agent installation script
  get_url:
    url: https://raw.githubusercontent.com/fredycibersec/wazuh-stuff/main/scripts/install_agent_linux.sh
    dest: /tmp/install_agent_linux.sh
    mode: '0755'

- name: Install Wazuh agent
  command: /tmp/install_agent_linux.sh --manager 192.168.1.10 --group linux-servers
  become: yes
```

Or use SSH to deploy to multiple systems:
```bash
for host in $(cat servers.txt); do
  scp install_agent_linux.sh root@$host:/tmp/
  ssh root@$host "bash /tmp/install_agent_linux.sh --manager 192.168.1.10 --group linux-servers"
done
```

## Troubleshooting

### Windows

- Check Windows Event Viewer for installation errors
- Review `C:\Program Files (x86)\ossec-agent\ossec.log` for agent issues
- Verify connectivity to the Wazuh manager: `Test-NetConnection -ComputerName wazuh-manager.yourdomain.com -Port 1514`

### Linux

- Check installation logs: `less /var/log/wazuh-installation.log`
- Review agent logs: `less /var/ossec/logs/ossec.log`
- Verify connectivity to the Wazuh manager: `telnet wazuh-manager.yourdomain.com 1514`

## Customization

Both scripts can be modified to suit your specific deployment needs. Common customizations include:

- Adding additional configuration settings in `ossec.conf`
- Configuring local rules and decoders
- Setting up specific log collection paths
- Enabling additional modules like CIS benchmarks or vulnerability detection

Made with ❤️ by SaruMan
