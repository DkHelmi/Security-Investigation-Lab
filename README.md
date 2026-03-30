# Security Investigation Lab

Repo ini dokumentasi investigasi insiden yang saya jalankan di lab pribadi. Bukan tutorial, bukan walkthrough - ini catatan kerja saya sebagai investigator NFIR yang trace aktivitas attacker dari alert sampai conclusion.

Setup lab: Windows AD environment (DC + workstation), Wazuh SIEM, attacker Kali Linux. Semua campaign dijalankan sendiri - saya yang generate aktivitas attacker, lalu investigasi dari sisi defender.

**Investigator:** Hardhika Helmi (DkHelmi)  
**Focus:** Network Forensics & Incident Response  
**Location:** Semarang, Indonesia

---

## Cases

| Case | Deskripsi | Status |
|------|-----------|--------|
| [INC-001-rdp-intrusion](./INC-001-rdp-intrusion/) | RDP brute force, lateral movement, persistence | In Progress |
| [INC-002-c2-beaconing](./INC-002-c2-beaconing/) | C2 beaconing via backdoor INC-001 | Planned |
| [INC-003-domain-dominance](./INC-003-domain-dominance/) | Living off the land, domain dominance | Planned |

## Skill Modules

| Module | Deskripsi |
|--------|-----------|
| [network-forensics](./network-forensics/) | PCAP analysis, C2 detection, exfil patterns |
| [network-security-monitoring](./network-security-monitoring/) | Zeek setup dan log analysis |
| [incident-response](./incident-response/) | Full IR simulation, INC-003 capstone |

---

## Lab Environment

- **SIEM:** Wazuh 4.9.2 - Ubuntu 22.04
- **DC01:** Windows Server 2022 - lab.local
- **WKS01:** Windows 10 22H2 - domain joined
- **Attacker:** Kali Linux

Network: `192.168.30.0/24` Host-Only VirtualBox
