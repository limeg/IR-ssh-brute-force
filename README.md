# Incident Response: SSH Brute Force Attempt

> 🔒 *Note: Internal IPs/hostnames redacted for security. Attacker IP is public.*

## About This Analysis
This incident demonstrates:
- How to investigate brute-force attacks
- Security control effectiveness validation
- Cloud infrastructure threat patterns
- SOC workflow best practices

## Incident Overview
- **Date**: April 2, 2025
- **Attacker IP**: 46.101.82.74 (DigitalOcean, UK)
- **Target**: Internal server (`[REDACTED_INTERNAL_IP]`)
- **Tactics**: 
  - T1110.001 (Password Guessing)
  - T1021.004 (SSH Brute Force)
- **Severity**: Low

## Key Findings
- 58 failed SSH login attempts for non-existent user `ubuntu`
- 1,000+ rule triggers from single IP
- IP belongs to DigitalOcean (common attack origin)
- No successful compromise

 ## Tools Used
- Wazuh (SIEM alerting)
- Kibana (log analysis)
- MXToolbox (WHOIS lookup)

## Response Actions
1. **Containment**: N/A (no access gained)
2. **Investigation**:
   - Verified invalid user account
   - Analyzed Wazuh/Kibana logs
   - WHOIS lookup ([MXToolbox](https://mxtoolbox.com))
3. **Mitigation**:
   - Recommended IP block at firewall
   - Proposed SSH hardening:
     ``` bash
     Key-based authentication
     Disable password logins
     Implement fail2ban
     ```
   - Alert tuning for high-frequency/low-risk events
4. **Escalation**: Reported to SOC L2 for IOC correlation



## MITRE ATT&CK Mapping
| Technique                                                    | Purpose              |
|--------------------------------------------------------------|----------------------|
| ([T1110.001](https://attack.mitre.org/techniques/T1110/001/))| Credential brute-forcing|
| ([T1021.004](https://attack.mitre.org/techniques/T1021/004/))| SSH-based persistence|

### NIST 800-53 Controls
| Control | How It Applied |
|---|---|
| **AC-7** | Failed logons (39+) triggered investigation |
| **SI-4** | Wazuh detected pattern in real-time |
| **AU-6** | Log review confirmed invalid user |


## Recommendations
- Block IP at firewall: `iptables -A INPUT -s 46.101.82.74 -j DROP`
- Harden SSH (see code snippet above)
- **Report abuse**: abuse@digitalocean.com
- Audit external exposure: `nmap -Pn -p22 [REDACTED_INTERNAL_IP]`

  
## Lessons Learned:
- ✅ Importance of WHOIS data enrichment
- ✅ Need for SSH security best practices
- ✅ Value of alert tuning to reduce noise
- ✅ Confirmed effectiveness of monitoring controls
  
