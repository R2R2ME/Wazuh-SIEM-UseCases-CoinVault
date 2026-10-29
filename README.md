# CoinVault: Wazuh SIEM Use Cases for the Banking Sector

20 custom Wazuh detection use cases for banking-sector threats, each mapped to MITRE ATT&CK and PCI DSS and tested in a lab environment.

The full write-up for each use case (banking scenario, false-positive handling, test steps and alert evidence) is in the [report](CoinVault-Wazuh-Detection-Report.pdf).

## Overview

CoinVault is a SIEM detection engineering project built on Wazuh (rebranded as CoinVault). Rather than relying on Wazuh's default rules as-is, every use case either fills a gap where no default rule existed, or improves on one that did: reducing false positives, adding correlation, or targeting attacker behavior more precisely.

The use cases cover Credential Access, Persistence, Execution, Defense Evasion, Discovery, Lateral Movement, Collection, Exfiltration, Command and Control, and Impact.

## Lab environment

| Component | Role |
|---|---|
| Wazuh manager | SIEM (CoinVault) |
| Windows 10 + Sysmon | Banking employee workstation |
| Ubuntu server | Backend banking infrastructure |
| Suricata | Network intrusion detection |

## Use cases

| # | Use case | MITRE ATT&CK | Rule ID(s) |
|---|---|---|---|
| 1 | SSH brute force detection | T1110.001 | 100010 |
| 2 | New account created and added to Administrators group | T1136.001 | 100011 |
| 3 | Successful login after brute force attempt | T1078 | 100013 |
| 4 | PowerShell executed with encoded command | T1059.001 | 100014 |
| 5 | Registry Run key persistence to a suspicious location | T1547.001 | 100015 |
| 6 | Rapid bulk file staging in customer records directory | T1074.001 | 100020 |
| 7 | Suspicious high-privilege access to LSASS memory | T1003.001 | 100016 |
| 8 | Discovery command followed by outbound SSH connection | T1021.004 | 100026, 100028 |
| 9 | Suricata C2 alert frequency correlation (beaconing) | T1071 | 100030, 100031 |
| 10 | Mass creation of ransomware-style encrypted files | T1486 | 100033, 100034 |
| 11 | Archive creation followed by network activity (exfiltration) | T1560.001 | 100035, 100036 |
| 12 | Cryptomining tool execution | T1496 | 100047 |
| 13 | Regsvr32 LOLBin code execution (Squiblydoo) | T1218.010 | 100050 |
| 14 | Mshta remote script execution | T1218.005 | 100051 |
| 15 | Active Directory domain enumeration | T1087.002 | 100052 |
| 16 | PowerShell execution policy bypass | T1059.001 | 100056 |
| 17 | AMSI bypass attempt | T1562.001 | 100058 |
| 18 | PowerShell reflective assembly loading (fileless execution) | T1620 | 100059 |
| 19 | Process injection targeting a web browser (banking trojan web-inject) | T1055 | 100060 |
| 20 | Windows Credential Manager / Vault enumeration | T1555.004 | 100062 |

Use cases with two rule IDs use a helper rule as a correlation trigger, followed by the detection rule.

## Repository structure

```
rules/coinvault_wazuh_rules.xml       all 20 use cases
decoders/coinvault_decoders.xml       custom Suricata decoder (use case 9)
CoinVault-Wazuh-Detection-Report.pdf  full report
```

## Installation

1. Append `rules/coinvault_wazuh_rules.xml` to `/var/ossec/etc/rules/local_rules.xml`
2. Append `decoders/coinvault_decoders.xml` to `/var/ossec/etc/decoders/local_decoder.xml`
3. Validate and restart:
   ```
   /var/ossec/bin/wazuh-analysisd -t
   systemctl restart wazuh-manager
   ```

Windows use cases require Sysmon on the endpoint. Use cases 9 and 11 require Suricata alerts to be forwarded to Wazuh. Use cases 6, 10 and 11 require File Integrity Monitoring on the monitored directories (the lab used `/var/customer_records/`).

## Future improvements

| Rule | Improvement |
|---|---|
| 100014 | Also match the shortened flags `-e` and `-ec`, which PowerShell accepts |
| 100056 | Also match `-exec bypass` and `-ep bypass` |
| 100015 | Add `AppData\Roaming`, a common malware location |
| 100051 | Detect inline scripts such as `mshta vbscript:` and `mshta javascript:` |
| 100059 | Also match `[Reflection.Assembly]` without the `System.` prefix |
| 100028, 100036 | Require both correlated events to come from the same host |
| 100030, 100031 | Narrow the broad `ET` match, exclude "Not Suspicious Traffic" classifications, and require the same destination IP. True interval-based beacon detection would need timing analysis outside Wazuh rules |
| All | Update the PCI DSS v3.2.1 tags to PCI DSS v4.0 requirement numbering |

## Author

Rana Almeshari · [LinkedIn](https://linkedin.com/in/rana-almeshari)

Built during the Tuwaiq Academy Advanced Cybercrime & Digital Forensic Investigation Bootcamp (2026).
