# Wazuh Detection Rules — TAFAT Abderrahim
## Smart Threat Detection with Wazuh and AI — ESI SBA 2025/2026

---

## Files in This Package

| File | Attack |
|------|--------|
| credential_access.xml | Credential Access |
| defense_evasion.xml | Defense Evasion |
| exfiltration.xml | Exfiltration |
| kerberoasting.xml | Kerberoasting |
| malicious_powershell.xml | Malicious Powershell |
| pass_the_hash.xml | Pass The Hash |
| persistence.xml | Persistence |
| privilege_escalation.xml | Privilege Escalation |
| rdp_brute_force.xml | Rdp Brute Force |
| reconnaissance.xml | Reconnaissance |
| reverse_shell.xml | Reverse Shell |
| scheduled_task.xml | Scheduled Task |
| suspicious_download_eicar.xml | Suspicious Download Eicar |
| uac_bypass.xml | Uac Bypass |
| user_enumeration.xml | User Enumeration |
| eicar_detection.yar | YARA — EICAR + PE + PS cradle |

---
---|--------|
| credential_access.xml | Credential Access |
| defense_evasion.xml | Defense Evasion |
| exfiltration.xml | Exfiltration |
| kerberoasting.xml | Kerberoasting |
| malicious_powershell.xml | Malicious Powershell |
| pass_the_hash.xml | Pass The Hash |
| persistence.xml | Persistence |
| privilege_escalation.xml | Privilege Escalation |
| rdp_brute_force.xml | Rdp Brute Force |
| reconnaissance.xml | Reconnaissance |
| reverse_shell.xml | Reverse Shell |
| scheduled_task.xml | Scheduled Task |
| suspicious_download_eicar.xml | Suspicious Download Eicar |
| uac_bypass.xml | Uac Bypass |
| user_enumeration.xml | User Enumeration |
| eicar_detection.yar | YARA — EICAR + PE + PS cradle |

---
---|--------|-------|
| rdp_brute_force.xml | RDP Brute Force (Hydra) | T1110, T1110.001 |
| user_enumeration.xml | User Enumeration (CrackMapExec) | T1087, T1087.001 |
| malicious_powershell.xml | Malicious PowerShell | T1059.001, T1027 |
| suspicious_download_eicar.xml | Suspicious Downloads + EICAR | T1105, T1204.002 |
| privilege_escalation.xml | Privilege Escalation | T1068, T1134 |
| eicar_detection.yar | YARA — EICAR + PE + PS cradle | T1105, T1059.001 |

---

## Deployment Instructions

### 1. Copy XML rules to Wazuh server
```bash
sudo cp *.xml /var/ossec/etc/rules/
sudo chown ossec:ossec /var/ossec/etc/rules/*.xml
```

### 2. Copy YARA rule to agents
```bash
sudo cp eicar_detection.yar /var/ossec/active-response/bin/
```

### 3. Verify rules load without errors
```bash
sudo /var/ossec/bin/wazuh-logtest
```

### 4. Restart Wazuh manager
```bash
sudo systemctl restart wazuh-manager
```

---

## Rule ID Map

| Rule ID | Description | Level |
|---------|-------------|-------|
| 100001 | RDP: Single failed login attempt detected (Event ID 4625) | 3 |
| 100002 | RDP Brute Force: $(win.eventdata.ipAddress) made $(frequency) failed login attempts in $(timeframe) seconds | 12 |
| 100003 | RDP Brute Force SUSTAINED: $(win.eventdata.ipAddress) continues attacking | 15 |
| 100010 | Account Discovery: Login attempt with non-existent username from $(win.eventdata.ipAddress) | 3 |
| 100011 | User Enumeration: $(win.eventdata.ipAddress) is probing multiple non-existent usernames | 11 |
| 100012 | User Enumeration HIGH VOLUME: $(win.eventdata.ipAddress) probed $(frequency) different usernames | 13 |
| 100020 | Malicious PowerShell: encoded command detected | 10 |
| 100021 | Malicious PowerShell: download cradle detected | 12 |
| 100022 | Malicious PowerShell: AMSI bypass attempt detected | 13 |
| 100023 | Malicious PowerShell: Invoke-Expression / IEX detected in script block | 12 |
| 100024 | Malicious PowerShell EVASION: encoded command with hidden window | 14 |
| 100030 | Suspicious File Creation: file written to temp/download path | 8 |
| 100031 | Suspicious Executable Drop: $(win.eventdata.targetFilename) written to temp path | 10 |
| 100032 | Suspicious Download: $(win.eventdata.image) wrote file to $(win.eventdata.targetFilename) | 11 |
| 100033 | YARA Match: EICAR test file detected on $(agent.name) | 13 |
| 100034 | FIM Alert: new file added to monitored path | 10 |
| 100040 | Suspicious Process Chain: $(win.eventdata.parentImage) spawned $(win.eventdata.image) | 8 |
| 100041 | Privilege Request Failed: $(win.eventdata.subjectUserName) attempted privileged operation and was denied | 7 |
| 100042 | Special Privileges Assigned: $(win.eventdata.subjectUserName) received elevated privileges (Event ID 4672) | 5 |
| 100043 | Privilege Escalation DETECTED: suspicious process chain followed by privilege assignment for user $(win.eventdata.subjectUserName) | 13 |
| 100044 | Privilege Escalation CONFIRMED: access denied followed by privilege grant for $(win.eventdata.subjectUserName) | 14 |
| 100045 | Token Impersonation: LogonType 9 detected for $(win.eventdata.targetUserName) | 12 |
| 100050 | Pass the Hash: NTLM network logon with KeyLength=0 from $(win.eventdata.ipAddress) | 10 |
| 100051 | Pass the Hash SPRAY: $(win.eventdata.ipAddress) made $(frequency) hash-based logins in $(timeframe)s | 13 |
| 100052 | Explicit Credential Use via NTLM: possible lateral movement after Pass the Hash | 12 |
| 100053 | Pass the Hash CONFIRMED from Kali attacker 192.168.109.158 | 14 |
| 100055 | LSASS Access: $(win.eventdata.sourceImage) opened handle to lsass.exe | 10 |
| 100056 | Mimikatz DETECTED: $(win.eventdata.sourceImage) is dumping lsass.exe memory | 15 |
| 100057 | LSASS Memory Read with suspicious access mask $(win.eventdata.grantedAccess) | 14 |
| 100058 | LSASS Dump via Tool: $(win.eventdata.image) targeting lsass.exe | 13 |
| 100059 | LSASS Dump File Created: $(win.eventdata.targetFilename) | 14 |
| 100060 | Registry Persistence: value written to autostart key $(win.eventdata.targetObject) by $(win.eventdata.image) | 10 |
| 100061 | Registry Persistence SUSPICIOUS: Run key value points to temp path or script | 13 |
| 100062 | Registry Persistence via Script Engine: $(win.eventdata.image) wrote to Run key | 14 |
| 100063 | Registry Key Created in Autostart Path: $(win.eventdata.targetObject) | 8 |
| 100064 | Winlogon Hijack: $(win.eventdata.targetObject) modified | 14 |
| 100065 | CRITICAL | 14 |
| 100066 | System Event Log Cleared by $(win.eventdata.subjectUserName) | 13 |
| 100067 | Log Clearing Command: wevtutil clear executed by $(win.eventdata.user) | 12 |
| 100068 | PowerShell Log Clearing: Clear-EventLog detected | 12 |
| 100069 | ATTACK + LOG WIPE: attack activity followed by log clearing | 15 |
| 100070 | Scheduled Task Created: $(win.eventdata.taskName) by $(win.eventdata.subjectUserName) | 8 |
| 100071 | Suspicious Scheduled Task: $(win.eventdata.taskName) executes script or temp file | 12 |
| 100072 | Persistent Scheduled Task: $(win.eventdata.taskName) triggers at boot or logon | 13 |
| 100073 | Scheduled Task Creation Command: schtasks /create detected | 10 |
| 100074 | Scheduled Task Modified: $(win.eventdata.taskName) updated by $(win.eventdata.subjectUserName) | 10 |
| 100075 | Reverse Shell Indicator: $(win.eventdata.image) initiated outbound TCP connection to $(win.eventdata.destinationIp):$(win.eventdata.destinationPort) | 12 |
| 100076 | Reverse Shell CONFIRMED: $(win.eventdata.image) connected to Kali attacker 192.168.109.158:$(win.eventdata.destinationPort) | 15 |
| 100077 | Reverse Shell on Known Backdoor Port: $(win.eventdata.image) → $(win.eventdata.destinationIp):$(win.eventdata.destinationPort) | 13 |
| 100078 | Netcat Executed: $(win.eventdata.image) launched | 12 |
| 100079 | C2 Beacon Pattern: $(win.eventdata.image) made $(frequency) outbound connections in $(timeframe)s | 13 |
| 100080 | Recon Command Executed: $(win.eventdata.image) by $(win.eventdata.user) | 3 |
| 100081 | Reconnaissance Pattern: $(win.eventdata.user) ran $(frequency) discovery commands in $(timeframe)s | 10 |
| 100082 | Net Enumeration: $(win.eventdata.commandLine) | 8 |
| 100083 | Privilege Enumeration: whoami with privilege flags executed by $(win.eventdata.user) | 8 |
| 100084 | Sustained Reconnaissance: $(win.eventdata.user) ran $(frequency) discovery commands in $(timeframe)s | 12 |
| 100085 | Kerberos RC4 Ticket Request: $(win.eventdata.serviceName) requested with RC4 encryption by $(win.eventdata.clientAddress) | 8 |
| 100086 | Kerberoasting DETECTED: $(win.eventdata.clientAddress) requested $(frequency) RC4 service tickets in $(timeframe)s | 13 |
| 100087 | Kerberoasting High-Value Target: RC4 ticket requested for sensitive service $(win.eventdata.serviceName) | 10 |
| 100088 | Kerberoasting Tool Detected: $(win.eventdata.image) executed | 14 |
| 100089 | Kerberoasting from Kali: RC4 ticket request from attacker IP 192.168.109.158 | 14 |
| 100090 | Exfiltration Attempt: $(win.eventdata.image) connecting to Kali attacker 192.168.109.158:$(win.eventdata.destinationPort) | 12 |
| 100091 | HTTP POST Exfiltration: PowerShell sending data via POST | 13 |
| 100092 | Certutil Encoding: $(win.eventdata.commandLine) | 10 |
| 100093 | Exfiltration Chain: file access followed by outbound connection | 14 |
| 100094 | Exfiltration on Non-Standard Port: $(win.eventdata.image) → $(win.eventdata.destinationIp):$(win.eventdata.destinationPort) | 11 |
| 100095 | UAC Bypass DETECTED: $(win.eventdata.parentImage) spawned $(win.eventdata.image) | 14 |
| 100096 | UAC Bypass CONFIRMED: auto-elevate spawn followed by privilege assignment for $(win.eventdata.subjectUserName) | 15 |
| 100097 | UAC Bypass Preparation: registry key $(win.eventdata.targetObject) set | 13 |
| 100098 | fodhelper.exe Launched by Script: $(win.eventdata.parentImage) launched fodhelper.exe | 12 |
| 100099 | UAC Bypass FULL CHAIN: registry hijack followed by fodhelper execution | 15 |

---
------|-------------|-------|
| 100001 | RDP: Single failed login attempt detected (Event ID 4625) | 3 |
| 100002 | RDP Brute Force: $(win.eventdata.ipAddress) made $(frequency) failed login attempts in $(timeframe) seconds | 12 |
| 100003 | RDP Brute Force SUSTAINED: $(win.eventdata.ipAddress) continues attacking | 15 |
| 100010 | Account Discovery: Login attempt with non-existent username from $(win.eventdata.ipAddress) | 3 |
| 100011 | User Enumeration: $(win.eventdata.ipAddress) is probing multiple non-existent usernames | 11 |
| 100012 | User Enumeration HIGH VOLUME: $(win.eventdata.ipAddress) probed $(frequency) different usernames | 13 |
| 100020 | Malicious PowerShell: encoded command detected | 10 |
| 100021 | Malicious PowerShell: download cradle detected | 12 |
| 100022 | Malicious PowerShell: AMSI bypass attempt detected | 13 |
| 100023 | Malicious PowerShell: Invoke-Expression / IEX detected in script block | 12 |
| 100024 | Malicious PowerShell EVASION: encoded command with hidden window | 14 |
| 100030 | Suspicious File Creation: file written to temp/download path | 8 |
| 100031 | Suspicious Executable Drop: $(win.eventdata.targetFilename) written to temp path | 10 |
| 100032 | Suspicious Download: $(win.eventdata.image) wrote file to $(win.eventdata.targetFilename) | 11 |
| 100033 | YARA Match: EICAR test file detected on $(agent.name) | 13 |
| 100034 | FIM Alert: new file added to monitored path | 10 |
| 100040 | Suspicious Process Chain: $(win.eventdata.parentImage) spawned $(win.eventdata.image) | 8 |
| 100041 | Privilege Request Failed: $(win.eventdata.subjectUserName) attempted privileged operation and was denied | 7 |
| 100042 | Special Privileges Assigned: $(win.eventdata.subjectUserName) received elevated privileges (Event ID 4672) | 5 |
| 100043 | Privilege Escalation DETECTED: suspicious process chain followed by privilege assignment for user $(win.eventdata.subjectUserName) | 13 |
| 100044 | Privilege Escalation CONFIRMED: access denied followed by privilege grant for $(win.eventdata.subjectUserName) | 14 |
| 100045 | Token Impersonation: LogonType 9 detected for $(win.eventdata.targetUserName) | 12 |
| 100050 | Pass the Hash: NTLM network logon with KeyLength=0 from $(win.eventdata.ipAddress) | 10 |
| 100051 | Pass the Hash SPRAY: $(win.eventdata.ipAddress) made $(frequency) hash-based logins in $(timeframe)s | 13 |
| 100052 | Explicit Credential Use via NTLM: possible lateral movement after Pass the Hash | 12 |
| 100053 | Pass the Hash CONFIRMED from Kali attacker 192.168.109.158 | 14 |
| 100055 | LSASS Access: $(win.eventdata.sourceImage) opened handle to lsass.exe | 10 |
| 100056 | Mimikatz DETECTED: $(win.eventdata.sourceImage) is dumping lsass.exe memory | 15 |
| 100057 | LSASS Memory Read with suspicious access mask $(win.eventdata.grantedAccess) | 14 |
| 100058 | LSASS Dump via Tool: $(win.eventdata.image) targeting lsass.exe | 13 |
| 100059 | LSASS Dump File Created: $(win.eventdata.targetFilename) | 14 |
| 100060 | Registry Persistence: value written to autostart key $(win.eventdata.targetObject) by $(win.eventdata.image) | 10 |
| 100061 | Registry Persistence SUSPICIOUS: Run key value points to temp path or script | 13 |
| 100062 | Registry Persistence via Script Engine: $(win.eventdata.image) wrote to Run key | 14 |
| 100063 | Registry Key Created in Autostart Path: $(win.eventdata.targetObject) | 8 |
| 100064 | Winlogon Hijack: $(win.eventdata.targetObject) modified | 14 |
| 100065 | CRITICAL | 14 |
| 100066 | System Event Log Cleared by $(win.eventdata.subjectUserName) | 13 |
| 100067 | Log Clearing Command: wevtutil clear executed by $(win.eventdata.user) | 12 |
| 100068 | PowerShell Log Clearing: Clear-EventLog detected | 12 |
| 100069 | ATTACK + LOG WIPE: attack activity followed by log clearing | 15 |
| 100070 | Scheduled Task Created: $(win.eventdata.taskName) by $(win.eventdata.subjectUserName) | 8 |
| 100071 | Suspicious Scheduled Task: $(win.eventdata.taskName) executes script or temp file | 12 |
| 100072 | Persistent Scheduled Task: $(win.eventdata.taskName) triggers at boot or logon | 13 |
| 100073 | Scheduled Task Creation Command: schtasks /create detected | 10 |
| 100074 | Scheduled Task Modified: $(win.eventdata.taskName) updated by $(win.eventdata.subjectUserName) | 10 |
| 100075 | Reverse Shell Indicator: $(win.eventdata.image) initiated outbound TCP connection to $(win.eventdata.destinationIp):$(win.eventdata.destinationPort) | 12 |
| 100076 | Reverse Shell CONFIRMED: $(win.eventdata.image) connected to Kali attacker 192.168.109.158:$(win.eventdata.destinationPort) | 15 |
| 100077 | Reverse Shell on Known Backdoor Port: $(win.eventdata.image) → $(win.eventdata.destinationIp):$(win.eventdata.destinationPort) | 13 |
| 100078 | Netcat Executed: $(win.eventdata.image) launched | 12 |
| 100079 | C2 Beacon Pattern: $(win.eventdata.image) made $(frequency) outbound connections in $(timeframe)s | 13 |
| 100080 | Recon Command Executed: $(win.eventdata.image) by $(win.eventdata.user) | 3 |
| 100081 | Reconnaissance Pattern: $(win.eventdata.user) ran $(frequency) discovery commands in $(timeframe)s | 10 |
| 100082 | Net Enumeration: $(win.eventdata.commandLine) | 8 |
| 100083 | Privilege Enumeration: whoami with privilege flags executed by $(win.eventdata.user) | 8 |
| 100084 | Sustained Reconnaissance: $(win.eventdata.user) ran $(frequency) discovery commands in $(timeframe)s | 12 |
| 100085 | Kerberos RC4 Ticket Request: $(win.eventdata.serviceName) requested with RC4 encryption by $(win.eventdata.clientAddress) | 8 |
| 100086 | Kerberoasting DETECTED: $(win.eventdata.clientAddress) requested $(frequency) RC4 service tickets in $(timeframe)s | 13 |
| 100087 | Kerberoasting High-Value Target: RC4 ticket requested for sensitive service $(win.eventdata.serviceName) | 10 |
| 100088 | Kerberoasting Tool Detected: $(win.eventdata.image) executed | 14 |
| 100089 | Kerberoasting from Kali: RC4 ticket request from attacker IP 192.168.109.158 | 14 |
| 100090 | Exfiltration Attempt: $(win.eventdata.image) connecting to Kali attacker 192.168.109.158:$(win.eventdata.destinationPort) | 12 |
| 100091 | HTTP POST Exfiltration: PowerShell sending data via POST | 13 |
| 100092 | Certutil Encoding: $(win.eventdata.commandLine) | 10 |
| 100093 | Exfiltration Chain: file access followed by outbound connection | 14 |
| 100094 | Exfiltration on Non-Standard Port: $(win.eventdata.image) → $(win.eventdata.destinationIp):$(win.eventdata.destinationPort) | 11 |
| 100095 | UAC Bypass DETECTED: $(win.eventdata.parentImage) spawned $(win.eventdata.image) | 14 |
| 100096 | UAC Bypass CONFIRMED: auto-elevate spawn followed by privilege assignment for $(win.eventdata.subjectUserName) | 15 |
| 100097 | UAC Bypass Preparation: registry key $(win.eventdata.targetObject) set | 13 |
| 100098 | fodhelper.exe Launched by Script: $(win.eventdata.parentImage) launched fodhelper.exe | 12 |
| 100099 | UAC Bypass FULL CHAIN: registry hijack followed by fodhelper execution | 15 |

---
------|-------------|-------|
| 100001 | RDP single failed login (base) | 3 |
| 100002 | RDP brute force threshold | 12 |
| 100003 | RDP brute force sustained | 15 |
| 100010 | Unknown username attempt (base) | 3 |
| 100011 | User enumeration pattern | 11 |
| 100012 | User enumeration high volume | 13 |
| 100020 | PowerShell encoded command | 10 |
| 100021 | PowerShell download cradle | 12 |
| 100022 | PowerShell AMSI bypass | 13 |
| 100023 | Script block IEX detection | 12 |
| 100024 | PowerShell full evasion chain | 14 |
| 100030 | File created in temp path | 8 |
| 100031 | Executable dropped to disk | 10 |
| 100032 | File written by suspicious process | 11 |
| 100033 | YARA EICAR match | 13 |
| 100034 | FIM alert on monitored path | 10 |
| 100040 | Suspicious parent-child process | 8 |
| 100041 | Failed privilege request | 7 |
| 100042 | Special privileges assigned (base) | 5 |
| 100043 | Process chain + privilege (chain) | 13 |
| 100044 | Failed then successful escalation | 14 |
| 100045 | Token impersonation logon | 12 |

---

## MITRE ATT&CK Mapping Table

| Rule ID | Tactic | Technique ID | Technique Name |
|---------|--------|-------------|----------------|
| 100002, 100003 | Credential Access | T1110 | Brute Force |
| 100011, 100012 | Discovery | T1087 | Account Discovery |
| 100020–100024 | Execution | T1059.001 | PowerShell |
| 100022 | Defense Evasion | T1562.001 | Disable Security Tools |
| 100031–100033 | Command & Control | T1105 | Ingress Tool Transfer |
| 100043, 100044 | Privilege Escalation | T1068 | Exploitation for Privilege Esc. |
| 100045 | Privilege Escalation | T1134 | Access Token Manipulation |
