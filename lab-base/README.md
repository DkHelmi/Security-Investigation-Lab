# Lab Base

Dokumentasi infrastruktur lab yang dipakai untuk semua case di Security-Investigation-Lab.
Setiap case berdiri sendiri dan menggunakan snapshot BASE-clean sebagai starting point.

## Topology

<p align="center">
  <img src="./topology.svg" alt="Lab Network Topology" width="100%">
</p>

## Hosts

| Host | IP | OS | Role |
|------|----|----|------|
| SIEM | 192.168.30.50 | Ubuntu 22.04 | Wazuh 4.9.2 All-in-One |
| DC01 | 192.168.30.100 | Windows Server 2022 | Domain Controller |
| WKS01 | 192.168.30.101 | Windows 10 22H2 | Workstation |
| Kali | 192.168.30.200 | Kali Linux | Attacker |

Network: `192.168.30.0/24` Host-Only VirtualBox

## Domain

- Domain: `lab.local`
- Users: `userAlpha`, `userBeta`
- Domain Admins: hanya `Administrator`

## Monitoring Stack

- Wazuh 4.9.2 agent di DC01 dan WKS01
- Sysmon di DC01 dan WKS01 (service name di DC01: `Sysmon64`)
- PowerShell ScriptBlock Logging enabled
- Windows Security, Sysmon, PowerShell Operational logs forwarded ke SIEM

### Wazuh Log Sources (agent.conf)
```xml
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>System</location>
  <log_format>eventchannel</log_format>
</localfile>
```

### Custom Rules Aktif

| Rule ID | Deskripsi | Action |
|---------|-----------|--------|
| 100010 | Suppress individual 4624 logon success | Suppress |
| 100011 | Multiple logon success >3 in 60s | Alert level 8 |
| 100020 | Suppress Sysmon process creation (67027) | Suppress |
| 100021 | Suppress Windows logoff (60137) | Suppress |
| 100022 | Suppress normal logon success (60106) | Suppress |
| 100023 | Suppress software protection service (60642) | Suppress |
| 100024 | Suppress Windows DB engine events (60804-60809, 60798) | Suppress |
