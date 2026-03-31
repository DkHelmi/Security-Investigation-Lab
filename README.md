# Security Investigation Lab

Repo ini dokumentasi investigasi insiden yang saya jalankan di lab pribadi. Bukan tutorial, bukan walkthrough - ini catatan kerja saya sebagai investigator NFIR yang trace aktivitas attacker dari alert sampai conclusion.

Setup lab: Windows AD environment (DC + workstation), Wazuh SIEM, attacker Kali Linux. Semua campaign dijalankan sendiri - saya yang generate aktivitas attacker, lalu investigasi dari sisi defender.

**Investigator:** Hardhika Helmi (DkHelmi)  
**Focus:** Network Forensics & Incident Response  
**Location:** Semarang, Indonesia

---

## Cases

| Case | Scenario | Status |
|------|----------|--------|
| [INC-001-rdp-intrusion](./INC-001-rdp-intrusion/) | Password spray via SMB, lateral movement ke DC01 via WinRM, persistence via registry Run key | ✅ Completed |
| [INC-002-c2-beaconing](./INC-002-c2-beaconing/) | C2 beaconing via persistence dari INC-001 | 📋 Planned |
| [INC-003-domain-dominance](./INC-003-domain-dominance/) | Living off the land, domain dominance | 📋 Planned |

## Skill Modules

| Module | Deskripsi |
|--------|-----------|
| [network-forensics](./network-forensics/) | PCAP analysis, C2 detection, exfil patterns |
| [network-security-monitoring](./network-security-monitoring/) | Zeek setup dan log analysis |
| [incident-response](./incident-response/) | Full IR simulation, INC-003 capstone |

---

## Lab Environment

| Host | IP | OS | Role |
|------|----|----|------|
| SIEM | 192.168.30.50 | Ubuntu 22.04 | Wazuh 4.9.2 |
| DC01 | 192.168.30.100 | Windows Server 2022 | Domain Controller |
| WKS01 | 192.168.30.101 | Windows 10 22H2 | Workstation |
| Kali | 192.168.30.200 | Kali Linux | Attacker |

Network: `192.168.30.0/24` Host-Only VirtualBox

---

## Pendekatan

Setiap case dimulai dari alert Wazuh, bukan dari tool atau teknik attacker. Investigasi berjalan dari alert → pivot → rekonstruksi aktivitas → conclusion. Format dokumen sengaja tidak kaku - ditulis sebagai real-time investigator notes, bukan laporan formal.

Attacker POV (tool output, terminal) disimpan di folder `attacker-logs/` per case sebagai referensi lab. Yang masuk ke case file hanya evidence dari sisi investigator: Wazuh alerts, Sysmon logs, Windows Event Log, dan konfirmasi langsung di host.

---

*Update status case dan penambahan case baru hanya dilakukan di file ini.*
