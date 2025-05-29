#!/usr/bin/env python3
import random
from datetime import datetime, timedelta
import json
import sys

def get_alert_details():
    alerts = {
        "malware": {
            "types": [
                "malware.infection.prevention",
                "malware.suspicious_behavior.detection",
                "malware.trojan.detection",
                "malware.ransomware.prevention",
                "malware.backdoor.detection",
                "malware.exploit.prevention"
            ],
            "severity_weights": [0.1, 0.3, 0.6],  # info, warning, critical
            "reasons": [
                "Known_Malware", 
                "Suspicious_Behavior", 
                "Ransomware_Behavior", 
                "Malicious_Script",
                "Memory_Injection",
                "Process_Hollowing"
            ],
            "engines": ["deepGuard", "realTimeScan", "behaviorAnalysis", "exploitProtection"],
            "processes": [
                "explorer.exe", 
                "svchost.exe", 
                "powershell.exe", 
                "cmd.exe", 
                "rundll32.exe",
                "regsvr32.exe",
                "mshta.exe",
                "wscript.exe",
                "cscript.exe"
            ],
            "files": [
                "invoice_{{random}}.exe",
                "document_{{random}}.pdf.exe",
                "update_{{random}}.msi",
                "crypto_wallet_{{random}}.exe",
                "system_update_{{random}}.zip.exe",
                "urgent_payment_{{random}}.iso"
            ],
            "cves": [
                "CVE-2024-{{random}}",
                "CVE-2023-{{random}}",
                "CVE-2022-{{random}}"
            ],
            "paths": [
                "C:\\Users\\{{user}}\\Downloads\\",
                "C:\\Users\\{{user}}\\AppData\\Local\\Temp\\",
                "C:\\ProgramData\\{{random}}\\",
                "C:\\Windows\\Temp\\",
                "C:\\Users\\{{user}}\\Desktop\\"
            ]
        },
        "web": {
            "types": [
                "online_safety.harmful_page.block",
                "online_safety.phishing_page.block",
                "browsing_protection.harmful_site.block",
                "system.suspicious_connection.block",
                "network.anomaly.detection",
                "data.exfiltration.prevention"
            ],
            "severity_weights": [0.5, 0.3, 0.2],  # info, warning, critical
            "reasons": [
                "BP_Harmful", 
                "Phishing_Site", 
                "Malicious_Content", 
                "Suspicious_Domain",
                "Command_And_Control",
                "Data_Theft_Attempt"
            ],
            "engines": [
                "reputationBasedBrowsing", 
                "browserProtection", 
                "networkControl",
                "trafficAnalysis"
            ],
            "processes": [
                "chrome.exe", 
                "firefox.exe", 
                "msedge.exe", 
                "outlook.exe", 
                "teams.exe",
                "iexplore.exe",
                "thunderbird.exe"
            ],
            "domains": [
                "login-{{random}}.secure-banking.com",
                "crypto-wallet-{{random}}.com",
                "document-{{random}}.share-point.net",
                "tracking-{{random}}.analytics.net",
                "cdn-{{random}}.cloud-storage.net",
                "mail-{{random}}.corporate-mail.com"
            ],
            "ports": [
                "80", "443", "8080", "8443", "21", "22", "23", "25", 
                "445", "3389", "5938", "4444", "1337"
            ]
        }
    }
    return alerts

def get_organization_details():
    return {
        "departments": [
            "IT", "Finance", "HR", "Sales", "Marketing", 
            "Engineering", "Support", "Operations"
        ],
        "locations": [
            "Madrid", "Barcelona", "Valencia", "Seville", 
            "Bilbao", "Malaga", "Zaragoza"
        ],
        "domains": [
            "example.com", "example.local", "example.org", 
            "example.net", "corp.example.com"
        ]
    }

def generate_test_event():
    alerts = get_alert_details()
    org_details = get_organization_details()
    event_category = random.choice(["malware", "web"])
    alert_config = alerts[event_category]

    # Current timestamp with slight randomization
    now = datetime.now()
    random_minutes = random.randint(-30, 0)
    event_time = now + timedelta(minutes=random_minutes)
    
    # Format timestamps
    client_timestamp = event_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    server_timestamp = (event_time + timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    persistence_timestamp = (event_time + timedelta(seconds=9)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    syslog_timestamp = event_time.strftime("%Y %b %d %H:%M:%S")

    # User and organization details
    department = random.choice(org_details["departments"])
    location = random.choice(org_details["locations"])
    domain = random.choice(org_details["domains"])
    username = f"{random.choice(['john.doe', 'jane.smith', 'admin.user', 'support.tech', 'dev.user'])}"

    # Device information
    device_prefixes = ["DESKTOP-", "LAPTOP-", "WS-"]
    device_name = random.choice(device_prefixes) + "".join(random.choices("0123456789ABCDEF", k=8))

    # Severity levels
    severities = ["info", "warning", "critical"]
    
    event = {
        "timestamp": syslog_timestamp,
        "hostname": "wazuh-server",
        "program": "withsecure-collector",
        "action": random.choice(["blocked", "detected", "prevented"]),
        "alertType": random.choice(alert_config["types"]),
        "clientTimestamp": client_timestamp,
        "device_name": device_name,
        "engine": random.choice(alert_config["engines"]),
        "eventTransactionId": f"0000-{random.getrandbits(32):08x}",
        "hostIpAddress": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}/24",
        "id": f"{random.getrandbits(128):032x}_0",
        "organization_name": "Example Organization",
        "department": department,
        "location": location,
        "persistenceTimestamp": persistence_timestamp,
        "process": random.choice(alert_config["processes"]),
        "profileId": str(random.randint(1000000, 9999999)),
        "profileName": "WindowsDefault",
        "reason": random.choice(alert_config["reasons"]),
        "serverTimestamp": server_timestamp,
        "severity": random.choices(severities, weights=alert_config["severity_weights"])[0],
        "throttledCount": "0",
    }

    # Add specific fields based on event category
    if event_category == "malware":
        file_template = random.choice(alert_config["files"])
        event["fileName"] = file_template.replace("{{random}}", str(random.randint(1000, 9999)))
        path_template = random.choice(alert_config["paths"])
        event["filePath"] = path_template.replace("{{user}}", username.split('.')[0])
        event["fileHash"] = f"{random.getrandbits(128):032x}"
        if random.random() < 0.3:  # 30% chance to include CVE
            cve_template = random.choice(alert_config["cves"])
            event["cve"] = cve_template.replace("{{random}}", str(random.randint(1000, 9999)))
    else:
        domain_template = random.choice(alert_config["domains"])
        event["url"] = f"hxxps://{domain_template.replace('{{random}}', str(random.randint(100, 999)))}"
        if random.random() < 0.4:  # 40% chance to include port
            event["port"] = random.choice(alert_config["ports"])

    # Add user information
    event["userName"] = f"{location.upper()}\\{username}"
    event["userPrincipalName"] = f"{username}@{domain}"

    # Format the log entry similar to syslog format
    log_entry = f"{event['timestamp']} {event['hostname']} {event['program']}: " + \
               " ".join([f'{k}="{v}"' for k, v in event.items() 
                       if k not in ['timestamp', 'hostname', 'program']])
    
    return log_entry

if __name__ == "__main__":
    num_events = 1
    if len(sys.argv) > 1:
        try:
            num_events = int(sys.argv[1])
        except ValueError:
            print("Please provide a valid number of events to generate")
            sys.exit(1)

    for _ in range(num_events):
        print(generate_test_event())
