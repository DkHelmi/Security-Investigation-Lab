# 05 - Detection Gaps

**Case:** INC-002-ssh-bruteforce  
**Investigator:** Hardhika Helmi  
**Catatan:** Ini bukan blame document. Ini honest assessment tentang apa yang missed, kenapa, dan apa yang perlu diperbaiki.

---

## Konteks

Ada dua jenis gap di case ini:

1. **Alert tidak ada** - aktivitas terjadi tapi tidak ada coverage sama sekali
2. **Evidence tidak cukup** - alert ada, tapi investigator tidak bisa rekonstruksi apa yang terjadi

Berbeda dari INC-001 yang punya gap "alert ada tapi investigator missed", di INC-002 mayoritas gap adalah coverage gap - monitoring-nya yang tidak ada, bukan investigator yang tidak pivot.

---

## Gap 1: Aktivitas Awal Tidak Terdeteksi Wazuh

**Apa yang terjadi:**
btmp menunjukkan failed attempts itstaff dari 192.168.30.200 mulai **10:35 WIB** - sekitar 40 menit sebelum alert pertama muncul di Wazuh (11:15 WIB). Selama window 40 menit itu tidak ada satu pun alert.

**Kenapa:**
Wazuh baru trigger alert setelah failure rate mencapai threshold rule 5763 dan 5760. Sebelum threshold itu, attempts yang ada tidak generate alert meskipun terekam di btmp.

**Dampak:**
Investigator baru aware ada ancaman setelah 40 menit aktivitas berjalan. Kalau attacker lebih sabar dan rate-nya lebih rendah, bisa jadi tidak pernah trigger threshold Wazuh sama sekali.

**Remediation:**
- Turunkan threshold rule 5763 atau buat custom rule yang alert lebih awal
- Pertimbangkan alert untuk failed attempts dari IP yang sama ke satu target dalam window yang lebih panjang

---

## Gap 2: Reconnaissance Tidak Terdeteksi Sama Sekali

**Apa yang terjadi:**
Tidak ada evidence reconnaissance di log manapun - tidak di Wazuh, tidak di auth.log, tidak di btmp. Tapi attacker tahu port 22 open di siemserver sebelum mulai brute force. Fase recon terjadi tanpa jejak sama sekali.

**Kenapa:**
Network-level activity tidak ter-monitor. Tidak ada NIDS, tidak ada firewall log yang di-ingest ke Wazuh, tidak ada NetFlow. ICMP sweep dan TCP SYN scan tidak masuk ke log Linux manapun.

**Remediation:**
- Deploy Suricata sebagai NIDS, integrasikan ke Wazuh
- Minimal: aktifkan firewall logging dan ingest ke Wazuh

---

## Gap 3: Tidak Ada fail2ban - Brute Force Tidak Di-block

**Apa yang terjadi:**
Dari auth.log terlihat jelas: ratusan failed attempts masuk tanpa hambatan apapun sampai akhirnya berhasil. Tidak ada mekanisme yang block IP setelah N failures.

**Kenapa:**
fail2ban tidak terinstall di siemserver. Tidak ada rate limiting di level SSH maupun OS.

**Kenapa ini critical:**
Ini yang paling langsung menyebabkan insiden berhasil. Dengan fail2ban aktif, IP 192.168.30.200 akan ter-block jauh sebelum berhasil menemukan credential yang benar.

**Remediation:**
- Install fail2ban dengan konfigurasi yang ketat untuk SSH
- Atau enforce SSH key-based authentication dan disable PasswordAuthentication sepenuhnya - ini yang paling efektif

---

## Gap 4: Aktivitas Post-Compromise Tidak Ter-capture Sama Sekali

**Apa yang terjadi:**
Sesi itstaff berlangsung ~10 menit (11:17 - 11:28 WIB). Dari semua pivot yang saya lakukan - auth.log, journalctl, wtmp - tidak ada yang bisa tunjukkan apa yang dilakukan selama sesi itu. Aktivitas 10 menit itu adalah blind spot total.

**Kenapa:**
Tidak ada command execution logging untuk standard user SSH session. journalctl dengan filter UID=1001 tidak mengembalikan apapun - aktivitas itstaff tidak berinteraksi dengan systemd services atau tidak trigger journal logging.

**Dampak:**
Ini gap yang paling mengkhawatirkan dari sisi investigasi. Attacker bisa lakukan apapun selama sesi - enumerate file, baca konfigurasi, coba eskalasi privilege - dan tidak akan ada jejaknya di log yang tersedia saat ini. Investigator hanya tahu mereka masuk dan keluar, tapi tidak tahu apa yang terjadi di antaranya.

**Yang lebih serius:** target adalah SIEM server. Kalau ada yang bisa di-akses atau dimodifikasi dari akun itstaff, investigator tidak akan pernah tahu dari log yang ada.

**Remediation:**
- Deploy auditd dengan rules untuk capture command execution dari SSH sessions:
  ```
  -a always,exit -F arch=b64 -S execve -F uid>=1000 -k user_commands
  ```
- Integrasikan auditd ke Wazuh - ada native support
- Ini prioritas tinggi khusus untuk SIEM server

---

## Gap 5: SSH Expose ke Seluruh Network Segment

**Apa yang terjadi:**
Port 22 siemserver reachable dari 192.168.30.200 tanpa restriksi apapun. Tidak ada network-level control yang limit siapa yang boleh attempt SSH ke server ini.

**Remediation:**
- Restrict SSH access via firewall hanya dari IP atau range yang authorized
- SIEM server harusnya hanya bisa di-akses dari management host, bukan dari semua host di segment yang sama

---

## Summary

| # | Gap | Tipe | Severity | Prioritas |
|---|-----|------|----------|-----------|
| 1 | Aktivitas awal 40 menit tidak terdeteksi | Threshold terlalu tinggi | Medium | Menengah |
| 2 | Reconnaissance tidak terdeteksi | Tidak ada coverage | Medium | Menengah |
| 3 | Tidak ada fail2ban | Tidak ada kontrol | Critical | Segera |
| 4 | Aktivitas post-compromise blind spot total | Tidak ada logging | High | Tinggi |
| 5 | SSH expose ke seluruh segment | Misconfiguration | High | Tinggi |

---

## Rekomendasi Prioritas

**Segera:**
1. Install fail2ban di siemserver - ini yang paling langsung prevent insiden ini terulang
2. Restrict SSH access via firewall - hanya dari authorized management IP

**Jangka menengah:**
3. Deploy auditd + integrasi ke Wazuh untuk command execution logging
4. Disable PasswordAuthentication SSH, enforce key-based auth
5. Review dan turunkan threshold alert untuk SSH failures

**Jangka panjang:**
6. Deploy Suricata untuk network-level visibility

---

*Insiden ini bisa dicegah sepenuhnya hanya dengan Gap 3 - kalau fail2ban terinstall, brute force tidak akan berhasil.*
