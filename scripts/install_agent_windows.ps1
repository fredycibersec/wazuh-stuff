# Wazuh Agent Installation Script for Windows
# This script downloads and installs the Wazuh agent on Windows systems

# Define parameters
param(
    [string]$WazuhManager = "wazuh-manager.yourdomain.com",
    [string]$WazuhRegistrationServer = "",
    [string]$WazuhAgentGroup = "default",
    [string]$WazuhVersion = "4.12.0",
    [switch]$UseHostnameAsAgentName = $true
)

# Set registration server to manager if not specified
if ($WazuhRegistrationServer -eq "") {
    $WazuhRegistrationServer = $WazuhManager
}

# Define agent name
if ($UseHostnameAsAgentName) {
    $AgentName = [System.Net.Dns]::GetHostName()
} else {
    $AgentName = Read-Host -Prompt "Enter the agent name"
}

Write-Host "Starting Wazuh Agent installation..." -ForegroundColor Green
Write-Host "Manager: $WazuhManager" -ForegroundColor Cyan
Write-Host "Agent Name: $AgentName" -ForegroundColor Cyan

# Create temporary directory
$TempDir = "$env:TEMP\wazuh-install"
if (-not (Test-Path -Path $TempDir)) {
    New-Item -ItemType Directory -Path $TempDir | Out-Null
}

# Download the Wazuh agent installer
$InstallerUrl = "https://packages.wazuh.com/$WazuhVersion/windows/wazuh-agent-$WazuhVersion-1.msi"
$InstallerPath = "$TempDir\wazuh-agent.msi"

Write-Host "Downloading Wazuh Agent installer..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath
} catch {
    Write-Host "Failed to download the installer: $_" -ForegroundColor Red
    exit 1
}

# Install the Wazuh agent
Write-Host "Installing Wazuh Agent..." -ForegroundColor Yellow
$InstallArgs = "/i $InstallerPath /q WAZUH_MANAGER='$WazuhManager' WAZUH_AGENT_NAME='$AgentName' WAZUH_REGISTRATION_SERVER='$WazuhRegistrationServer'"

if ($WazuhAgentGroup -ne "default") {
    $InstallArgs += " WAZUH_AGENT_GROUP='$WazuhAgentGroup'"
}

try {
    Start-Process -FilePath "msiexec.exe" -ArgumentList $InstallArgs -Wait
} catch {
    Write-Host "Failed to install the agent: $_" -ForegroundColor Red
    exit 1
}

# Start the Wazuh agent service
Write-Host "Starting Wazuh Agent service..." -ForegroundColor Yellow
try {
    Start-Service -Name "Wazuh" -ErrorAction Stop
    Write-Host "Wazuh Agent service started successfully" -ForegroundColor Green
} catch {
    Write-Host "Failed to start the Wazuh Agent service: $_" -ForegroundColor Red
    exit 1
}

# Set service to start automatically
try {
    Set-Service -Name "Wazuh" -StartupType Automatic
    Write-Host "Wazuh Agent service set to start automatically" -ForegroundColor Green
} catch {
    Write-Host "Failed to set service startup type: $_" -ForegroundColor Red
}

# Clean up the temporary directory
Remove-Item -Path $TempDir -Recurse -Force

Write-Host "Wazuh Agent installation completed successfully" -ForegroundColor Green
Write-Host "Agent Name: $AgentName" -ForegroundColor Cyan
Write-Host "Manager: $WazuhManager" -ForegroundColor Cyan

# Display agent status
Write-Host "Agent Status:" -ForegroundColor Yellow
& "C:\Program Files (x86)\ossec-agent\ossec-control.exe" status

exit 0
