# Wazuh Detection Rules — TAFAT Abderrahim
## Smart Threat Detection with Wazuh and AI — ESI SBA 2025/2026

---

## Files in This Package

| File | Attack | MITRE |
|------|--------|-------|
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
