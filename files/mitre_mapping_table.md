# MITRE ATT&CK Mapping Table
## Smart Threat Detection with Wazuh and AI — ESI SBA 2025/2026
### Author: TAFAT Abderrahim — Detection Engineering

---

## Complete Rule-to-MITRE Mapping

| Rule ID | Rule Name | Tactic | Technique ID | Technique Name | Sub-technique | Data Source | Detection Method |
|---------|-----------|--------|-------------|----------------|---------------|-------------|------------------|
| 100001 | RDP single failed login | Credential Access | T1110 | Brute Force | T1110.001 — Password Guessing | Windows Event Logs | Event ID 4625, LogonType 3/10 |
| 100002 | RDP brute force threshold | Credential Access | T1110 | Brute Force | T1110.001 — Password Guessing | Windows Event Logs | Threshold: 5 failures / 30s, same source IP |
| 100003 | RDP brute force sustained | Credential Access | T1110 | Brute Force | T1110.001 — Password Guessing | Windows Event Logs | Threshold: repeated rule 100002 triggers |
| 100010 | Unknown username attempt | Discovery | T1087 | Account Discovery | T1087.001 — Local Account | Windows Event Logs | Event ID 4625, SubStatus 0xC0000064 |
| 100011 | User enumeration pattern | Discovery | T1087 | Account Discovery | T1087.001 — Local Account | Windows Event Logs | different_user field variation, same source IP |
| 100012 | User enumeration high volume | Discovery | T1087 | Account Discovery | T1087.001 — Local Account | Windows Event Logs | 10+ different usernames / 120s |
| 100020 | PowerShell encoded command | Execution | T1059 | Command and Scripting Interpreter | T1059.001 — PowerShell | Sysmon Event ID 1 | CommandLine contains -EncodedCommand / -enc |
| 100021 | PowerShell download cradle | Execution + C2 | T1059 / T1105 | PowerShell / Ingress Tool Transfer | T1059.001 | Sysmon Event ID 1 | CommandLine contains DownloadString/WebClient |
| 100022 | PowerShell AMSI bypass | Defense Evasion | T1562 | Impair Defenses | T1562.001 — Disable Security Tools | Sysmon Event ID 1 | CommandLine contains AmsiUtils/amsiInitFailed |
| 100023 | Script block IEX detection | Execution | T1059 | Command and Scripting Interpreter | T1059.001 — PowerShell | Windows Event ID 4104 | ScriptBlockText contains IEX/Invoke-Expression |
| 100024 | PowerShell full evasion chain | Execution + Evasion | T1059 / T1564 | PowerShell / Hide Artifacts | T1564.003 — Hidden Window | Sysmon Event ID 1 | Encoded command + -WindowStyle Hidden |
| 100030 | File created in temp path | Command & Control | T1105 | Ingress Tool Transfer | — | Sysmon Event ID 11 | TargetFilename in Temp/Downloads/Public |
| 100031 | Executable dropped to disk | Command & Control | T1105 | Ingress Tool Transfer | T1204.002 — Malicious File | Sysmon Event ID 11 | Executable extension in temp path |
| 100032 | File written by suspicious process | Command & Control | T1105 | Ingress Tool Transfer | T1059.001 | Sysmon Event ID 11 | Image = powershell/certutil + temp path |
| 100033 | YARA EICAR match | Command & Control | T1105 | Ingress Tool Transfer | — | YARA Active Response | YARA rule match on EICAR signature |
| 100034 | FIM alert on monitored path | Command & Control | T1105 | Ingress Tool Transfer | — | Wazuh FIM / Syscheck | File added to FIM-monitored directory |
| 100040 | Suspicious parent-child process | Execution | T1059 | Command and Scripting Interpreter | — | Sysmon Event ID 1 | Unexpected parentImage spawning shell/script |
| 100041 | Failed privilege request | Privilege Escalation | T1068 | Exploitation for Privilege Escalation | — | Windows Event ID 4673 | Access denied on privileged operation |
| 100042 | Special privileges assigned | Privilege Escalation | T1068 | Exploitation for Privilege Escalation | — | Windows Event ID 4672 | Special privileges granted at logon |
| 100043 | Process chain + privilege (chain) | Privilege Escalation | T1068 | Exploitation for Privilege Escalation | — | Sysmon + Windows Events | Rule chain: 100040 → 100042, same user, 60s |
| 100044 | Failed then successful escalation | Privilege Escalation | T1068 / T1134 | Privilege Escalation / Token Manipulation | — | Windows Events | Rule chain: 100041 → 100042, same user, 120s |
| 100045 | Token impersonation logon | Privilege Escalation | T1134 | Access Token Manipulation | T1134.001 — Token Impersonation | Windows Event ID 4624 | LogonType 9 detected |

---

## Mapping by Tactic (Summary View)

### Credential Access
| Technique | Attack Scenario | Rules | Tool Used |
|-----------|----------------|-------|-----------|
| T1110 — Brute Force | RDP Brute Force | 100001, 100002, 100003 | Hydra |

### Discovery
| Technique | Attack Scenario | Rules | Tool Used |
|-----------|----------------|-------|-----------|
| T1087 — Account Discovery | User Enumeration | 100010, 100011, 100012 | CrackMapExec |

### Execution
| Technique | Attack Scenario | Rules | Tool Used |
|-----------|----------------|-------|-----------|
| T1059.001 — PowerShell | Malicious PowerShell | 100020, 100021, 100022, 100023, 100024 | PowerShell Empire |

### Defense Evasion
| Technique | Attack Scenario | Rules | Tool Used |
|-----------|----------------|-------|-----------|
| T1562.001 — Disable Security Tools | AMSI Bypass | 100022 | PowerShell |
| T1564.003 — Hidden Window | PowerShell Evasion | 100024 | PowerShell |

### Command and Control / Delivery
| Technique | Attack Scenario | Rules | Tool Used |
|-----------|----------------|-------|-----------|
| T1105 — Ingress Tool Transfer | Suspicious Download + EICAR | 100030, 100031, 100032, 100033, 100034 | PowerShell / Browser |

### Privilege Escalation
| Technique | Attack Scenario | Rules | Tool Used |
|-----------|----------------|-------|-----------|
| T1068 — Exploitation for Privilege Escalation | Privilege Escalation | 100040, 100041, 100042, 100043, 100044 | Metasploit / manual |
| T1134 — Access Token Manipulation | Token Impersonation | 100045 | PowerShell / Metasploit |

---

## Data Sources Summary

| Data Source | Events Captured | Attacks Covered |
|-------------|----------------|-----------------|
| Windows Security Log | Event ID 4625, 4672, 4673, 4624 | RDP, Enumeration, Privilege Escalation |
| Sysmon | Event ID 1, 3, 7, 10, 11, 22 | All 5 attacks |
| Windows PowerShell Log | Event ID 4104 (Script Block) | Malicious PowerShell |
| Wazuh FIM / Syscheck | File creation events | Suspicious Downloads, EICAR |
| YARA Active Response | Signature matching | EICAR test file |
| auditd (Linux) | execve, open, connect, bind | Linux-side escalation attempts |

---

## MITRE Navigator Coverage

The following MITRE ATT&CK techniques are covered by our detection system:

```
TA0006 — Credential Access    → T1110, T1110.001
TA0007 — Discovery            → T1087, T1087.001
TA0002 — Execution            → T1059, T1059.001
TA0005 — Defense Evasion      → T1562.001, T1564.003, T1027
TA0011 — Command and Control  → T1105
TA0004 — Privilege Escalation → T1068, T1134, T1134.001
TA0001 — Initial Access       → (covered via RDP brute force detection)
```

Total unique techniques covered: **10**
Total rules deployed: **22**
