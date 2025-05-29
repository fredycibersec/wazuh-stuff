# Wazuh Rulesets Collection

<p align="center">
  <img src="https://github.com/fredycibersec/wazuh-stuff/edit/main/assets/wazuh_logo.png" width="400" alt="Wazuh Logo"/>
</p>

<p align="center">
  <a href="https://github.com/fredycibersec/wazuh-stuff/releases"><img src="https://img.shields.io/github/v/release/fredycibersec/wazuh-stuff?color=blue"></a>
  <a href="https://github.com/fredycibersec/wazuh-stuff/blob/main/LICENSE"><img src="https://img.shields.io/github/license/fredycibersec/wazuh-stuff?color=blue"></a>
  <a href="https://github.com/fredycibersec/wazuh-stuff/stargazers"><img src="https://img.shields.io/github/stars/fredycibersec/wazuh-stuff?color=yellow"></a>
  <a href="https://github.com/fredycibersec/wazuh-stuff/network/members"><img src="https://img.shields.io/github/forks/fredycibersec/wazuh-stuff?color=green"></a>
</p>

## Overview

This repository contains a collection of custom Wazuh rulesets and decoders for various technologies to help security professionals enhance their monitoring capabilities. These rulesets are designed to work with [Wazuh](https://wazuh.com/), an open source security monitoring solution.

## Technologies Included

This repository includes rulesets and decoders for the following technologies:

| Technology | Description | Documentation |
| --- | --- | --- |
| **WithSecure** | Advanced endpoint protection solutions | [WithSecure README](withsecure/README.md) |
| **Microsoft Defender** | Microsoft's built-in antivirus and security solution | [Defender README](defender/README.md) |
| **Darktrace** | Enterprise Immune System for network detection and response | [Darktrace README](darktrace/README.md) |
| **Kaspersky** | Endpoint security and antivirus solutions | [Kaspersky README](kaspersky/README.md) |
| **Synology** | Network-attached storage devices | [Synology README](synology/README.md) |
| **SMTP/Email** | Email server monitoring with Outlook integration | [SMTP README](smtp/README.md) |
| **Installation Scripts** | Deployment scripts for Wazuh agents | [Scripts README](scripts/README.md) |

## Directory Structure

```
wazuh-stuff/
├── withsecure/          # WithSecure integration
│   ├── decoders/        # Decoders for WithSecure logs
│   ├── rules/           # Alert rules for WithSecure events
│   ├── scripts/         # Integration scripts for WithSecure
│   └── docs/            # Documentation for WithSecure integration
├── defender/            # Microsoft Defender integration
│   ├── decoders/        # Decoders for Defender logs
│   ├── rules/           # Alert rules for Defender events
│   └── docs/            # Documentation for Defender integration
├── darktrace/           # Darktrace integration
├── kaspersky/           # Kaspersky integration
├── synology/            # Synology integration
├── smtp/                # SMTP monitoring integration
└── scripts/             # General installation and configuration scripts
```

## Quick Start

### Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/fredycibersec/wazuh-stuff.git
   ```

2. Navigate to the repository:
   ```bash
   cd wazuh-stuff
   ```

3. Choose the technology you want to implement and follow the specific README instructions.

### Basic Installation Example

To install the WithSecure integration:

```bash
# Copy decoders
sudo cp withsecure/decoders/withsecure_decoders.xml /var/ossec/etc/decoders/

# Copy rules
sudo cp withsecure/rules/withsecure_rules.xml /var/ossec/etc/rules/

# Restart Wazuh Manager
sudo systemctl restart wazuh-manager
```

## Contributing

Contributions to improve existing rulesets or add new technologies are welcome! Please follow these steps:

1. Fork the repository
2. Create a new branch for your changes:
   ```bash
   git checkout -b feature/new-technology-integration
   ```
3. Make your changes following the same structure and style
4. Test your changes thoroughly
5. Submit a pull request with a clear description of your changes

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Wazuh Team](https://wazuh.com/) for creating an amazing open source security monitoring solution
- All contributors who have helped improve and expand this collection

Made with ❤️ by SaruMan
