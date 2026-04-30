# 4th Year Project: Smart Threat Detection with Wazuh and AI
## ESI SBA 2025/2026 -  TAFAT Abderrahim

Welcome to the threat detection and logging repository for my 4th-year project. This repository contains all the necessary configurations, detection rules, and documentation needed to set up the environment, run attacks, and perform forensic analysis.

## Repository Structure

For testers, the project is organized into the following directories to make deployment straightforward:

- **`configs/`**: Contains endpoint monitoring configurations.
  - `sysmonconfig.xml`: Windows Sysmon configuration. Deploy on the Windows VM using `sysmon -accepteula -i sysmonconfig.xml`.
  - `audit.rules`: Linux auditd rules. Copy to `/etc/audit/rules.d/` on the Linux VM, then run `augenrules --load`.

- **`rules/wazuh/`**: Custom Wazuh detection rules (XML format) for detecting specific attack techniques:
  - `credential_access.xml`
  - `defense_evasion.xml`
  - `exfiltration.xml`
  - `kerberoasting.xml`
  - `malicious_powershell.xml`
  - `pass_the_hash.xml`
  - `persistence.xml`
  - `privilege_escalation.xml`
  - `rdp_brute_force.xml`
  - `reconnaissance.xml`
  - `reverse_shell.xml`
  - `scheduled_task.xml`
  - `suspicious_download_eicar.xml`
  - `uac_bypass.xml`
  - `user_enumeration.xml`

- **`rules/yara/`**: YARA rules for file-based detection.
  - `eicar_detection.yar`

- **`docs/`**: Documentation and templates for analysis.
  - `README.md` (Original rule documentation and MITRE mapping).
  - `mitre_mapping_table.md`: Complete MITRE mapping table (for Chapter 3 of the thesis).
  - `log_forensics_template.md`: Template to fill in live during/after the attacks (Phase 4).

## Deployment Instructions for Testers

### 1. Endpoint Configuration
**Windows Endpoint:**
```cmd
sysmon.exe -accepteula -i configs\sysmonconfig.xml
```

**Linux Endpoint:**
```bash
sudo cp configs/audit.rules /etc/audit/rules.d/
sudo augenrules --load
sudo systemctl restart auditd
```

### 2. Loading Wazuh Rules
On the Wazuh Manager, copy the XML rules:
```bash
sudo cp rules/wazuh/*.xml /var/ossec/etc/rules/
sudo chown ossec:ossec /var/ossec/etc/rules/*.xml
```

### 3. Loading YARA Rules
On the target agents, copy the YARA rule:
```bash
sudo cp rules/yara/eicar_detection.yar /var/ossec/active-response/bin/
```

### 4. Verification & Restart
Verify the rules map without errors and restart the manager:
```bash
sudo /var/ossec/bin/wazuh-logtest
sudo systemctl restart wazuh-manager
```

## Testing Protocol (Phase 4)
When the tester (Yacine) executes the attacks:
1. Ensure both endpoints are actively shipping logs to Wazuh.
2. Monitor Wazuh dashboards for the triggered alerts based on the custom rules.
3. Open `docs/log_forensics_template.md` and document the forensics live, collecting real log data, timestamps, and screenshots.

---

*Prepared by TAFAT Abderrahim.*
