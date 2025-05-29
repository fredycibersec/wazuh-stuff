#!/bin/bash
# Wazuh Agent Installation Script for Linux
# This script downloads and installs the Wazuh agent on Linux systems

# Default values
WAZUH_MANAGER="wazuh-manager.yourdomain.com"
WAZUH_REGISTRATION_SERVER=""
WAZUH_AGENT_GROUP="default"
WAZUH_VERSION="4.12.0"
USE_HOSTNAME=true

# Colors for pretty output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Print usage information
function show_usage {
    echo -e "Usage: $0 [options]"
    echo -e "Options:"
    echo -e "  -m, --manager <address>        Wazuh manager IP or hostname"
    echo -e "  -r, --registration <address>   Registration server IP or hostname"
    echo -e "  -g, --group <group>            Agent group (default: default)"
    echo -e "  -v, --version <version>        Wazuh version (default: 4.7.5)"
    echo -e "  -n, --name <name>              Agent name (default: system hostname)"
    echo -e "  -h, --help                     Show this help message"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -m|--manager)
            WAZUH_MANAGER="$2"
            shift
            shift
            ;;
        -r|--registration)
            WAZUH_REGISTRATION_SERVER="$2"
            shift
            shift
            ;;
        -g|--group)
            WAZUH_AGENT_GROUP="$2"
            shift
            shift
            ;;
        -v|--version)
            WAZUH_VERSION="$2"
            shift
            shift
            ;;
        -n|--name)
            AGENT_NAME="$2"
            USE_HOSTNAME=false
            shift
            shift
            ;;
        -h|--help)
            show_usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_usage
            ;;
    esac
done

# If registration server not specified, use manager
if [ -z "$WAZUH_REGISTRATION_SERVER" ]; then
    WAZUH_REGISTRATION_SERVER="$WAZUH_MANAGER"
fi

# Use hostname as agent name if not specified
if [ "$USE_HOSTNAME" = true ]; then
    AGENT_NAME=$(hostname)
fi

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}This script must be run as root${NC}"
    exit 1
fi

echo -e "${GREEN}Starting Wazuh Agent installation...${NC}"
echo -e "${CYAN}Manager: $WAZUH_MANAGER${NC}"
echo -e "${CYAN}Agent Name: $AGENT_NAME${NC}"

# Detect OS type
echo -e "${YELLOW}Detecting operating system...${NC}"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
elif [ -f /etc/redhat-release ]; then
    OS="rhel"
elif [ -f /etc/debian_version ]; then
    OS="debian"
else
    echo -e "${RED}Unsupported operating system${NC}"
    exit 1
fi

echo -e "${CYAN}Detected: $OS $VERSION${NC}"

# Install Wazuh agent based on OS type
echo -e "${YELLOW}Installing Wazuh Agent...${NC}"
case $OS in
    centos|rhel|fedora|amzn|rocky|almalinux)
        # RPM-based systems
        TMP_DIR=$(mktemp -d)
        PACKAGE_NAME="wazuh-agent-$WAZUH_VERSION-1.x86_64.rpm"
        PACKAGE_URL="https://packages.wazuh.com/$WAZUH_VERSION/yum/$PACKAGE_NAME"
        
        echo -e "${YELLOW}Downloading Wazuh Agent package...${NC}"
        curl -o "$TMP_DIR/$PACKAGE_NAME" "$PACKAGE_URL"
        
        echo -e "${YELLOW}Installing package...${NC}"
        WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" \
        WAZUH_REGISTRATION_SERVER="$WAZUH_REGISTRATION_SERVER" \
        WAZUH_AGENT_GROUP="$WAZUH_AGENT_GROUP" \
        rpm -ivh "$TMP_DIR/$PACKAGE_NAME"
        
        rm -rf "$TMP_DIR"
        ;;
        
    ubuntu|debian)
        # DEB-based systems
        TMP_DIR=$(mktemp -d)
        PACKAGE_NAME="wazuh-agent_$WAZUH_VERSION-1_amd64.deb"
        PACKAGE_URL="https://packages.wazuh.com/$WAZUH_VERSION/apt/pool/main/w/wazuh-agent/$PACKAGE_NAME"
        
        echo -e "${YELLOW}Downloading Wazuh Agent package...${NC}"
        wget -O "$TMP_DIR/$PACKAGE_NAME" "$PACKAGE_URL"
        
        echo -e "${YELLOW}Installing package...${NC}"
        WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" \
        WAZUH_REGISTRATION_SERVER="$WAZUH_REGISTRATION_SERVER" \
        WAZUH_AGENT_GROUP="$WAZUH_AGENT_GROUP" \
        dpkg -i "$TMP_DIR/$PACKAGE_NAME"
        
        rm -rf "$TMP_DIR"
        ;;
        
    *)
        echo -e "${RED}Unsupported operating system: $OS${NC}"
        exit 1
        ;;
esac

# Start the Wazuh agent service
echo -e "${YELLOW}Starting Wazuh Agent service...${NC}"
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

# Check if service is running
if systemctl is-active wazuh-agent > /dev/null; then
    echo -e "${GREEN}Wazuh Agent service started successfully${NC}"
else
    echo -e "${RED}Failed to start Wazuh Agent service${NC}"
    exit 1
fi

echo -e "${GREEN}Wazuh Agent installation completed successfully${NC}"
echo -e "${CYAN}Agent Name: $AGENT_NAME${NC}"
echo -e "${CYAN}Manager: $WAZUH_MANAGER${NC}"

# Display agent status
echo -e "${YELLOW}Agent Status:${NC}"
/var/ossec/bin/agent_control -l

exit 0
