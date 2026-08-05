# T1082 — System Information Discovery

## Technique Overview

| Field | Detail |
|---|---|
| ATT&CK ID | T1082 |
| Tactic | Discovery (TA0007) |
| Platform | Windows |
| Test date | 2026-08-05 |
| Tested using | Atomic Red Team — Invoke-AtomicTest T1082 |

## What the test does

Simulates an attacker running native Windows enumeration commands
immediately after gaining access — a standard post-exploitation
reconnaissance sequence. Commands executed include:
- `systeminfo` — full OS, hardware, patch level details
- `whoami` — current user and privilege context
- `hostname` — machine name
- `net user` — local user account enumeration
- `net localgroup administrators` — admin group membership

Attackers run these within seconds of initial access to decide
their next move — privilege escalation, lateral movement, or
direct objective pursuit.

## Detection Result

**Wazuh alerted: YES ✅**

Multiple rules fired across the test session:

| Rule ID | Description | Level | Sysmon EID |
|---|---|---|---|
| 92032 | Suspicious Windows cmd shell execution | 3 | 1 |
| 92052 | Windows command prompt started | 4 | 1 |
| 92002 | Scripting interpreter spawned Windows shell | 6 | 1 |
| 92910 | Explorer process was accessed | 12 | 10 |

## Alert Timeline

All alerts fired within a 20-second window (15:44:41 → 15:45:01),
which is itself a detection signal — legitimate users do not run
systeminfo, whoami, and net user in rapid succession.

## Detection Logic

### Rule 92002 (level 6) — Scripting interpreter spawned Windows shell
```xml
<rule id="92002" level="6">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.parentImage" type="pcre2">
    (?i)\\(cmd|powershell|wscript|cscript|mshta)\.exe
  </field>
  <field name="win.eventdata.image" type="pcre2">
    (?i)\\(cmd|powershell)\.exe
  </field>
  <description>Scripting interpreter spawned Windows shell instance</description>
</rule>
```

### Rule 92910 (level 12) — Explorer process accessed
```xml
<rule id="92910" level="12">
  <if_group>sysmon_event10</if_group>
  <field name="win.eventdata.targetImage" type="pcre2">
    (?i)\\explorer\.exe
  </field>
  <description>Explorer process was accessed by another process</description>
</rule>
```

### Rule 92052 (level 4) — Command prompt started
```xml
<rule id="92052" level="4">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">
    (?i)\\cmd\.exe
  </field>
  <description>Windows command prompt started</description>
</rule>
```

## Log Source

| Field | Value |
|---|---|
| Channel | Microsoft-Windows-Sysmon/Operational |
| Primary Event ID | 1 — ProcessCreate |
| Secondary Event ID | 10 — ProcessAccess (rule 92910) |
| Key fields | Image, CommandLine, ParentImage, ParentCommandLine, User |

## Key Forensic Indicators

A T1082 attack produces this recognizable process burst pattern:

cmd.exe
├── systeminfo.exe
├── whoami.exe
├── hostname.exe
├── net.exe (net user)
└── net.exe (net localgroup administrators)


All spawned within seconds of each other from the same parent —
this clustering is the strongest detection signal.

## Custom Correlation Rule (enhancement)

Built-in rules catch individual commands. This custom rule catches
the pattern of multiple discovery commands running in rapid
succession, which has much lower false positive rate:

```xml
<!-- Add to /var/ossec/etc/rules/local_rules.xml on Wazuh manager -->
<rule id="100001" level="10" frequency="4" timeframe="30">
  <if_matched_group>sysmon_event1</if_matched_group>
  <field name="win.eventdata.image" type="pcre2">
    (?i)\\(systeminfo|whoami|net|hostname|ipconfig|nltest)\.exe
  </field>
  <description>
    T1082 - Multiple system discovery commands executed in short
    timeframe - possible post-exploitation reconnaissance
  </description>
  <mitre>
    <id>T1082</id>
  </mitre>
</rule>
```

This fires only when 4+ discovery commands run within 30 seconds —
dramatically reducing false positives from legitimate admin use.

## False Positive Considerations

| Scenario | Likelihood | Mitigation |
|---|---|---|
| IT admin running systeminfo manually | Medium | Whitelist known admin accounts |
| Monitoring/RMM tools (e.g. SolarWinds) | Medium | Whitelist known tool parent processes |
| Scheduled maintenance scripts | Low | Whitelist specific scheduled task names |
| Developer environment setup scripts | Low | Time-based filtering (business hours) |

**Key FP reducer:** Legitimate use rarely involves ALL of these
commands running within 30 seconds. Correlation across multiple
commands is the strongest signal.

## MITRE ATT&CK Reference

- Technique: https://attack.mitre.org/techniques/T1082/
- Tactic: Discovery (TA0007)
- Related techniques: T1033 (System Owner Discovery), T1016
  (Network Configuration Discovery), T1057 (Process Discovery)
