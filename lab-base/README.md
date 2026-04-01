# Lab Setup - INC-001

## Topology

<p align="center">
  <img src="./assets/topology.svg" alt="Lab Network Topology" width="100%">
</p>

## Hosts

| Host | IP | OS | Role |
|------|----|----|------|
| SIEM | 192.168.30.50 | Ubuntu 22.04 | Wazuh 4.9.2 All-in-One |
| DC01 | 192.168.30.100 | Windows Server 2022 | Domain Controller |
| WKS01 | 192.168.30.101 | Windows 10 22H2 | Workstation |
| Kali | 192.168.30.200 | Kali Linux | Attacker |

## Domain

- Domain: `lab.local`
- Users: `userAlpha`, `userBeta`
- Domain Admins: hanya `Administrator`

## Monitoring Stack

- Wazuh 4.9.2 agent di DC01 dan WKS01
- Sysmon di DC01 dan WKS01 (service name di DC01: Sysmon64)
- PowerShell ScriptBlock Logging enabled (registry manual, bukan GPO)
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

## Pre-Campaign Setup

Semua konfigurasi berikut sudah ada **sebelum** campaign INC-001 dijalankan:

- SMB port 445 di WKS01 di-enable via `Enable-NetFirewallRule SMB-In`
- userAlpha ditambahkan ke Remote Management Users di DC01 (untuk WinRM)
- Sysmon dan Wazuh agent running di kedua host

## Attacker Tools

- nmap (reconnaissance)
- crackmapexec (SMB password spray)
- xfreerdp (RDP client)
- evil-winrm (WinRM lateral movement)
- impacket (credential access attempt - gagal)

## Known Issues Lab

- Wazuh disk full → fix: disable vulnerability-detector di ossec.conf
- xfreerdp gagal → fix: tambah `/cert:ignore /sec:nla`
- SMB port 445 WKS01 blocked → fix: `Enable-NetFirewallRule SMB-In`
- schtasks gagal untuk userAlpha → standard user, attacker fallback ke registry Run key
