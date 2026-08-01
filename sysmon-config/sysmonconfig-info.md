# Sysmon Configuration

Using the Olaf Hartong sysmon-modular configuration.

Source: https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml

## Installation command used

Sysmon64.exe -accepteula -i sysmonconfig.xml


## Key event IDs enabled
- Event ID 1: Process Create
- Event ID 3: Network Connect
- Event ID 7: Image Load
- Event ID 8: CreateRemoteThread
- Event ID 10: ProcessAccess
- Event ID 11: FileCreate
- Event ID 12/13: Registry Create/Set
- Event ID 22: DNS Query
