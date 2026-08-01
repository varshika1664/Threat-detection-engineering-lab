# Threat Detection Engineering Lab

A hands-on detection engineering lab built with Wazuh, Sysmon, and Atomic Red Team,
mapping attack simulations to MITRE ATT&CK techniques and custom detection rules.

## Lab Architecture

| Component | Role |
|---|---|
| Ubuntu 22.04 | Wazuh single-node (manager + indexer + dashboard) |
| Windows 10 VM | Monitored endpoint running Sysmon + Wazuh agent |
| Sysmon | Rich telemetry (process, network, registry, file events) |
| Atomic Red Team | ATT&CK-mapped attack simulation |
| Wazuh | SIEM — alert correlation + custom detection rules |

## Techniques Tested

| ATT&CK ID | Technique | Wazuh Detected | Rule ID |
|---|---|---|---|
| T1059.001 | PowerShell Execution | ✅ Yes | 92004 |
| T1082 | System Info Discovery | 🔄 Testing | - |
| T1547.001 | Registry Run Key Persistence | 🔄 Testing | - |
| T1136.001 | Local Account Creation | 🔄 Testing | - |
| T1070.004 | File Deletion | 🔄 Testing | - |
| T1003.001 | LSASS Credential Dump | 🔄 Testing | - |
| T1055 | Process Injection | 🔄 Testing | - |
| T1021.002 | SMB Lateral Movement | 🔄 Testing | - |
| T1110.001 | Password Brute Force | 🔄 Testing | - |
| T1486 | Data Encryption/Ransomware | 🔄 Testing | - |

## Repository Structure

├── README.md # This file
├── sysmon-config/ # Sysmon configuration used
├── detection-rules/
│ ├── wazuh/ # Custom Wazuh XML rules
│ └── sigma/ # Sigma rules (portable format)
├── atomic-tests/
│ └── results/ # Raw output from each ART test
├── detection-notebook/ # One markdown file per technique
└── screenshots/ # Wazuh dashboard alert screenshots


## Tools Used

- [Wazuh](https://wazuh.com) 4.9.2
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) with Olaf Hartong modular config
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [MITRE ATT&CK](https://attack.mitre.org) Enterprise framework

## Author

Varshika Srivastava — M.Sc. Cybersecurity, BBAU Lucknow
