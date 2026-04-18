# Log Forensics Report — Evidence Chain Documentation
## Smart Threat Detection with Wazuh and AI — ESI SBA 2025/2026
### Author: TAFAT Abderrahim — Detection Engineering + Log Forensics

---

> **HOW TO USE THIS TEMPLATE:**
> After each of Yacine's attacks, fill in one section below.
> Go to Wazuh → Discover → filter by timestamp → find the raw log.
> Copy the raw log entry here and fill in every field.
> This document becomes Section 3.6 of Chapter 3.

---

## Attack 1 — RDP Brute Force

### Attack Summary
- **Executed by:** Yacine using Hydra
- **Target:** Windows VM port 3389
- **Date/Time:** [FILL AFTER ATTACK]
- **Attacker IP:** [FILL — Kali VM IP]
- **Target IP:** [FILL — Windows VM IP]

### Step 1 — Raw Log Entry (copy from Wazuh Discover)
```xml
<!-- PASTE THE RAW WINDOWS EVENT XML HERE AFTER THE ATTACK -->
<!-- Go to: Wazuh → Discover → filter: rule.id: 100002 -->
<!-- Click the event → expand → copy full JSON or XML -->

Example structure you will find:
{
  "timestamp": "2025-XX-XXTXX:XX:XX",
  "agent": { "name": "windows-agent" },
  "win": {
    "system": { "eventID": "4625" },
    "eventdata": {
      "targetUserName": "Administrator",
      "ipAddress": "192.168.X.X",
      "logonType": "3",
      "subStatus": "0xC000006A"
    }
  }
}
```

### Step 2 — Wazuh Decoder Output
```
<!-- What decoder parsed this log -->
<!-- Go to: Wazuh → Tools → Logtest → paste the raw log → run -->
Decoder matched : windows_eventchannel
Field extracted : win.system.eventID = 4625
Field extracted : win.eventdata.ipAddress = [attacker IP]
Field extracted : win.eventdata.logonType = 3
```

### Step 3 — Rule That Fired
```
Rule ID    : 100002
Rule Level : 12
Description: RDP Brute Force — X failed logins from same IP in 30s
MITRE Tag  : T1110.001
```

### Step 4 — Alert in Wazuh Dashboard
```
[PASTE SCREENSHOT DESCRIPTION OR ALERT JSON]
Alert timestamp :
Alert level     : 12
Alert description:
Source IP       :
```

### Step 5 — Forensic Evidence Chain
```
Timeline:
  [T+0s]  First failed RDP login from 192.168.X.X → Event 4625 #1
  [T+3s]  Second failed login → Event 4625 #2
  [T+6s]  Third failed login → Event 4625 #3
  [T+9s]  Fourth failed login → Event 4625 #4
  [T+12s] Fifth failed login → Event 4625 #5 → Rule 100002 FIRES
  [T+15s] Wazuh alert generated, level 12

Evidence chain:
  Raw log (Event ID 4625) 
    → Decoded by windows_eventchannel decoder
    → Matched base rule 100001 (level 3)
    → Threshold reached: 5 matches in 30s, same source IP
    → Rule 100002 fires (level 12)
    → Alert visible in OpenSearch dashboard
```

### Step 6 — Did the Rule Fire? (tick one)
- [ ] YES — rule fired as expected
- [ ] NO — rule did not fire (document reason below)
- [ ] PARTIAL — rule fired but with wrong data (document below)

**Notes:** [FILL]

---

## Attack 2 — User Enumeration

### Attack Summary
- **Executed by:** Yacine using CrackMapExec
- **Target:** Windows VM SMB port 445
- **Date/Time:** [FILL AFTER ATTACK]
- **Attacker IP:** [FILL]

### Step 1 — Raw Log Entry
```xml
<!-- PASTE HERE — filter by rule.id: 100011 in Wazuh Discover -->
```

### Step 2 — Wazuh Decoder Output
```
Decoder matched :
Field extracted : win.system.eventID = 4625
Field extracted : win.eventdata.subStatus = 0xC0000064
Field extracted : win.eventdata.targetUserName = [different each time]
Field extracted : win.eventdata.ipAddress =
```

### Step 3 — Rule That Fired
```
Rule ID    : 100011
Rule Level : 11
Description: User Enumeration — multiple different invalid usernames
MITRE Tag  : T1087.001
Key field  : different_user — confirm that usernames varied across events
```

### Step 4 — Alert in Wazuh Dashboard
```
[PASTE ALERT JSON OR SCREENSHOT DESCRIPTION]
```

### Step 5 — Forensic Evidence Chain
```
Timeline:
  [T+0s]  Login attempt: username "admin" → 4625, SubStatus 0xC0000064
  [T+2s]  Login attempt: username "administrator" → 4625
  [T+4s]  Login attempt: username "user1" → 4625
  [T+6s]  Rule 100011 fires — 3 different usernames from same IP

Key forensic indicator:
  SubStatus 0xC0000064 = "user does not exist"
  This distinguishes enumeration (invalid username) from
  brute force (valid username, wrong password = 0xC000006A)
```

### Step 6 — Did the Rule Fire?
- [ ] YES
- [ ] NO
- [ ] PARTIAL

**Notes:** [FILL]

---

## Attack 3 — Malicious PowerShell

### Attack Summary
- **Executed by:** Yacine using encoded PowerShell commands
- **Target:** Windows VM
- **Date/Time:** [FILL]
- **Command used:** [FILL — copy from Yacine's attack documentation]

### Step 1 — Raw Log Entry
```xml
<!-- PASTE HERE — filter by rule.id: 100020 OR 100023 in Wazuh Discover -->
<!-- Event ID 1 (Sysmon process creation) OR 4104 (script block) -->
```

### Step 2 — Wazuh Decoder Output
```
Decoder matched : windows_eventchannel
Field extracted : win.system.eventID = 1 (or 4104)
Field extracted : win.eventdata.image = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Field extracted : win.eventdata.commandLine = [PASTE COMMAND]
```

### Step 3 — Rule That Fired
```
Rule ID    : [100020 / 100021 / 100022 / 100023 / 100024]
Rule Level :
Description:
MITRE Tag  : T1059.001
```

### Step 4 — Alert in Wazuh Dashboard
```
[PASTE]
```

### Step 5 — Forensic Evidence Chain
```
Timeline:
  [T+0s]  powershell.exe launched with -EncodedCommand flag
  [T+0s]  Sysmon Event ID 1 generated (process creation)
  [T+0s]  Wazuh agent reads Sysmon log
  [T+0s]  Rule 100020 fires immediately (no threshold needed)
  [T+1s]  Alert generated, level 10+

  If Event ID 4104 also captured:
  [T+0s]  PowerShell decodes the base64 payload internally
  [T+0s]  Windows Script Block Logging logs the DECODED content
  [T+0s]  Rule 100023 fires on IEX/DownloadString in decoded text
```

### Step 6 — Did the Rule Fire?
- [ ] YES
- [ ] NO
- [ ] PARTIAL

**Notes:** [FILL]

---

## Attack 4 — Suspicious Download / EICAR

### Attack Summary
- **Executed by:** Yacine downloading EICAR test file
- **Target:** Windows VM
- **Date/Time:** [FILL]
- **File dropped to:** [FILL path — e.g. C:\Users\Public\Downloads\eicar.exe]

### Step 1 — Raw Log Entry
```xml
<!-- TWO events to find: -->
<!-- 1. Sysmon Event ID 11 (file creation) → rule 100031/100032 -->
<!-- 2. YARA match alert → rule 100033 -->
<!-- 3. FIM alert from Wazuh Syscheck → rule 100034 -->
```

### Step 2 — Wazuh Decoder Output
```
For Sysmon Event ID 11:
  Decoder matched : windows_eventchannel
  Field extracted : win.system.eventID = 11
  Field extracted : win.eventdata.targetFilename = [path]
  Field extracted : win.eventdata.image = [process that wrote the file]

For FIM:
  Decoder matched : syscheck
  Field extracted : syscheck.path = [file path]
  Field extracted : syscheck.event = added
```

### Step 3 — Rules That Fired
```
Rule ID    : 100031 (executable drop) + 100033 (YARA) + 100034 (FIM)
MITRE Tag  : T1105
Note       : This attack triggers THREE separate rules — document all
```

### Step 4 — Alert in Wazuh Dashboard
```
[PASTE — should see 3 separate alerts for this one attack]
```

### Step 5 — Forensic Evidence Chain
```
Timeline:
  [T+0s]  PowerShell/browser downloads EICAR file to Downloads folder
  [T+0s]  Sysmon Event ID 11 fires (file creation detected)
  [T+0s]  Rule 100031 fires — executable in temp path
  [T+1s]  Wazuh FIM detects new file in monitored directory
  [T+1s]  Rule 100034 fires — FIM alert
  [T+2s]  Wazuh active response triggers YARA scan on new file
  [T+3s]  YARA matches EICAR signature
  [T+3s]  Rule 100033 fires — malware confirmed

Layered detection demonstrated:
  Layer 1 — Process behavior (Sysmon Event ID 11)
  Layer 2 — File integrity monitoring (Wazuh FIM)
  Layer 3 — Signature detection (YARA)
```

### Step 6 — Did the Rule Fire?
- [ ] YES
- [ ] NO
- [ ] PARTIAL

**Notes:** [FILL]

---

## Attack 5 — Privilege Escalation

### Attack Summary
- **Executed by:** Yacine attempting to gain admin rights
- **Target:** Windows VM
- **Date/Time:** [FILL]
- **Method used:** [FILL — e.g. token impersonation / exploit]

### Step 1 — Raw Log Entry
```xml
<!-- THREE events to find in sequence: -->
<!-- 1. Sysmon Event ID 1 — suspicious process spawned (rule 100040) -->
<!-- 2. Event ID 4673 — failed privilege request (rule 100041) -->
<!-- 3. Event ID 4672 — special privileges assigned (rule 100042) -->
<!-- 4. Chain rule fires (rule 100043 or 100044) -->
```

### Step 2 — Wazuh Decoder Output
```
Event 1 (Sysmon ID 1):
  win.eventdata.parentImage = [parent process]
  win.eventdata.image       = [child process]
  win.eventdata.user        = [username]

Event 2 (ID 4673):
  win.eventdata.subjectUserName = [username]
  win.eventdata.objectName      = [privilege requested]

Event 3 (ID 4672):
  win.eventdata.subjectUserName = [same username]
  win.eventdata.privilegeList   = SeDebugPrivilege / SeTcbPrivilege
```

### Step 3 — Rules That Fired
```
Rule ID    : 100040 → 100041 → 100042 → 100043 (chain)
Rule Level : escalates from 8 → 7 → 5 → 13
MITRE Tag  : T1068
Note       : Show the chain — this is your most complex forensic section
```

### Step 4 — Alert in Wazuh Dashboard
```
[PASTE — document all alerts in the chain, in order]
```

### Step 5 — Forensic Evidence Chain
```
Timeline:
  [T+0s]  Suspicious process spawned (unexpected parent-child)
  [T+0s]  Rule 100040 fires — level 8
  [T+5s]  Process attempts privileged operation → Access denied
  [T+5s]  Event ID 4673 generated
  [T+5s]  Rule 100041 fires — level 7
  [T+10s] Escalation succeeds — special privileges assigned
  [T+10s] Event ID 4672 generated
  [T+10s] Rule 100042 fires — level 5
  [T+10s] Rule 100043 fires (chain: 100040+100042, same user, <60s)
  [T+10s] FINAL ALERT — level 13 — Privilege Escalation Detected

This chain is the forensic evidence that a human analyst would
use to reconstruct the attacker's steps from low-privilege
process to elevated access.
```

### Step 6 — Did the Rule Fire?
- [ ] YES — full chain fired
- [ ] PARTIAL — some rules fired but chain did not complete
- [ ] NO

**Notes:** [FILL]

---

## Summary Table (fill after all attacks)

| Attack | Rules Fired | Detected? | False Positives | Notes |
|--------|-------------|-----------|-----------------|-------|
| RDP Brute Force | 100001, 100002 | [ ] | | |
| User Enumeration | 100010, 100011 | [ ] | | |
| Malicious PowerShell | 100020, 100023 | [ ] | | |
| EICAR Download | 100031, 100033, 100034 | [ ] | | |
| Privilege Escalation | 100040→100043 | [ ] | | |

**Detection rate:** [X] / 5 attacks detected = [X]%
