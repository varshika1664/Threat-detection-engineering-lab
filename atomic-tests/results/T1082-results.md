# T1082 Atomic Test Results

- Date: 2026-08-05
- Command: Invoke-AtomicTest T1082
- Platform: Windows 10 VM (windows-lab-endpoint)

## Wazuh Alerts Generated

| Time | Rule ID | Description | Level |
|---|---|---|---|
| 15:44:41 | 92032 | Suspicious Windows cmd shell execution | 3 |
| 15:44:43 | 92002 | Scripting interpreter spawned Windows shell | 6 |
| 15:44:44 | 92032 | Suspicious Windows cmd shell execution | 3 |
| 15:44:44 | 92002 | Scripting interpreter spawned Windows shell | 6 |
| 15:44:50 | 92052 | Windows command prompt started | 4 |
| 15:44:53 | 92052 | Windows command prompt started | 4 |
| 15:44:57 | 92910 | Explorer process was accessed | 12 |
| 15:45:01 | 92032 | Suspicious Windows cmd shell execution | 3 |
| 15:45:01 | 92052 | Windows command prompt started | 4 |

## Verdict
Built-in Wazuh rules detected activity. Custom correlation rule
written to catch the full burst pattern with higher confidence.
