# Security Investigation Lab

Dokumentasi investigasi insiden yang saya jalankan di lab pribadi. Bukan tutorial, bukan walkthrough. Ini catatan kerja saya sebagai investigator yang trace aktivitas attacker dari alert sampai conclusion.

Yang membedakan repo ini: semua investigasi dimulai dari alert Wazuh, bukan dari mengetahui apa yang attacker lakukan. Saya generate attack campaign, lalu pindah ke sisi defender dan mulai dari nol. Dead ends, hipotesis yang salah, alert yang missed karena confirmation bias, semuanya ditulis apa adanya.

**Investigator:** Hardhika Helmi  
**Focus:** Network Forensics & Incident Response  
**Location:** Semarang, Indonesia

---

## Cases

| Case | Scenario | Status |
|------|----------|--------|
| [INC-001-rdp-intrusion](./INC-001-rdp-intrusion/) | Password spray via SMB, lateral movement ke DC01 via WinRM, persistence via registry Run key | ✅ Completed |
| [INC-002-ssh-bruteforce](./INC-002-ssh-bruteforce/) | SSH brute force ke SIEM server, akun itstaff compromised, post-compromise blind spot total | ✅ Completed |
| [INC-003-persistence](./INC-003-persistence/) | LNK phishing delivery, compiled reverse shell bypass Defender, persistence via Scheduled Task | ✅ Completed |
| [INC-004-c2-beaconing](./INC-004-c2-beaconing/) | C2 beaconing via HTTP, periodic callback setiap 30 detik, Sysmon network data tidak sampai ke SIEM | ✅ Completed |

### Highlight dari Case yang Selesai

**INC-001:** Alert level 15 (tertinggi di Wazuh) muncul saat attacker drop executable di DC01, tapi saya missed karena sedang fokus ke narrative lateral movement. Persistence via registry Run key juga punya alert level 10 yang saya lewati. Dua-duanya confirmation bias, sudah punya hipotesis dan hanya cari evidence yang support.

**INC-002:** Attacker berhasil masuk ke SIEM server via SSH brute force. Sesi aktif 10 menit, tapi tidak ada satu pun log yang capture aktivitas selama sesi itu. journalctl, auth.log, wtmp, semuanya kosong. Blind spot total di server yang paling kritis.

**INC-003:** Dari 5 fase attack (initial access → execution → tool transfer → persistence → C2), Wazuh hanya effectively mendeteksi execution dan tool transfer. Trigger awal (malicious .lnk), persistence mechanism (Scheduled Task), dan reverse shell connection semuanya invisible. Investigator cuma lihat "tengah-tengah" attack chain tanpa tahu bagaimana attacker masuk dan apakah masih punya akses.

**INC-004:** Beacon exe dengan nama mirip system process (svchost-update.exe) melakukan HTTP callback setiap 30 detik ke C2 server. Wazuh menangkap process creation (cmd.exe di-spawn berulang kali), tapi network connection-nya tidak terlihat sama sekali di SIEM. Sysmon Event ID 3 tercatat di host, tapi tidak ter-forward ke Wazuh. Tanpa pivot langsung ke host, investigator tidak akan pernah tahu kemana malware itu berkomunikasi.

---

## Lab Environment

Dokumentasi lengkap lab ada di [lab-base/](./lab-base/).

![Lab Topology](./lab-base/assets/topology.svg)

| Host | IP | OS | Role |
|------|----|----|------|
| SIEM | 192.168.30.50 | Ubuntu 22.04 | Wazuh 4.9.2 |
| DC01 | 192.168.30.100 | Windows Server 2022 | Domain Controller |
| WKS01 | 192.168.30.101 | Windows 10 22H2 | Workstation |
| Kali | 192.168.30.200 | Kali Linux | Attacker |

---

## Pendekatan

Setiap case berdiri sendiri, tidak ada dependency antar case. Masing-masing punya lab snapshot sendiri sebagai starting point.

Investigasi selalu dimulai dari alert Wazuh. Saya tidak buka attacker logs atau tool output selama investigasi berjalan. Attacker POV disimpan terpisah di folder `attacker-logs/` per case sebagai referensi lab.

Setiap case punya 5 file standar:

| File | Isi |
|------|-----|
| 01-alert-triage | Alert pertama yang trigger investigasi, proses triage, initial assessment |
| 02-investigation | Rekonstruksi langkah demi langkah, pivot antar evidence, dead ends |
| 03-timeline | Kronologi event berdasarkan timestamp dari log dan alert |
| 04-mitre-mapping | MITRE ATT&CK mapping dengan konteks spesifik dari case |
| 05-detection-gaps | Apa yang missed, kenapa, dan rekomendasi perbaikan |

---

*Jika ada case baru akan di-update segera.*
