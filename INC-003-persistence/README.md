# INC-003 — Persistence via Scheduled Task & WMI Event Subscription

## Status
🔄 In Progress

## Skenario

UserBeta (domain user, non-admin) di WKS01 menerima email internal dengan attachment `.lnk` yang disguise sebagai PDF. Saat diklik, shortcut trigger PowerShell hidden yang establish reverse shell ke attacker. Attacker kemudian memasang dua mekanisme persistence:

1. **Scheduled Task** — jalan saat userBeta login
2. **WMI Event Subscription** — jalan saat system boot, survive logout

Investigator mulai dari Wazuh alert — ada unusual process creation dari WKS01 dengan encoded PowerShell argument. Tidak ada alert saat initial execution terjadi.

## Target

| VM | IP | User |
|----|----|------|
| WKS01 | 192.168.30.101 | userBeta |
| Kali | 192.168.30.200 | kalidhika (attacker) |
| SIEM | 192.168.30.50 | dhika (investigator) |

## Kill Chain

| Phase | Teknik | Detail |
|-------|--------|--------|
| Initial Access | LNK Phishing | `.lnk` file trigger PowerShell hidden reverse shell |
| Execution | PowerShell encoded command | `-WindowStyle Hidden -NonInteractive -EncodedCommand` |
| Persistence | Scheduled Task | Task creation via PowerShell, trigger on userBeta login |
| Persistence | WMI Event Subscription | `__EventFilter` + `CommandLineEventConsumer`, trigger on boot |
| Discovery | Local recon | `whoami`, `net user`, `systeminfo` dari dalam session |

## MITRE ATT&CK

| Technique ID | Name |
|---|---|
| T1547.001 | Boot or Logon Autostart: Registry Run Keys (ref INC-001) |
| T1053.005 | Scheduled Task/Job: Scheduled Task |
| T1546.003 | Event Triggered Execution: Windows Management Instrumentation |
| T1059.001 | Command and Scripting Interpreter: PowerShell |
| T1027 | Obfuscated Files or Information |

## Detection Gaps

1. Tidak ada alert saat `.lnk` diklik — initial execution invisible
2. Event ID 4698 (scheduled task creation) belum di-surface ke level cukup di Wazuh
3. WMI Event Subscription tidak ada default Wazuh rule
4. Encoded PowerShell tidak di-flag saat pertama muncul

## Investigator Starting Point

Alert Wazuh — Sysmon process creation unusual dari WKS01. Parent `powershell.exe`, child `powershell.exe` dengan encoded argument. Investigator tidak tau konteks awal, mulai triage dari sini.

## Case File

| File | Status |
|------|--------|
| 01-alert-triage.md | 📋 Planned |
| 02-investigation.md | 📋 Planned |
| 03-timeline.md | 📋 Planned |
| 04-mitre-mapping.md | 📋 Planned |
| 05-detection-gaps.md | 📋 Planned |
| 06-alert-tuning.md | 📋 Planned |

## Snapshot

| VM | Snapshot | Kondisi |
|----|----------|---------|
| WKS01 | INC-003-base | Clean state, Sysmon running, userBeta domain-joined |
| Kali | INC-003-base | Clean state, tools tersedia |
| SIEM | INC-003-base | Wazuh running, sebelum tuning |
