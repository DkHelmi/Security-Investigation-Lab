# 05 - Detection Gaps

**Case:** INC-002-ssh-bruteforce  
**Investigator:** Hardhika Helmi  
**Catatan:** Ini bukan blame document. Ini honest assessment tentang apa yang missed, kenapa, dan apa yang perlu diperbaiki.

---

## Konteks

Ada perbedaan penting antara dua jenis gap:

1. **Alert ada, investigator missed** - Wazuh generate alertnya, tapi saat triage tidak di-pivot
2. **Alert tidak ada** - aktivitas terjadi tapi tidak ada rule yang catch, atau log-nya tidak masuk Wazuh sama sekali

Di case ini mayoritas gap adalah tipe kedua - coverage gap, bukan investigator error. Brute force-nya sendiri ter-deteksi dengan baik oleh Wazuh. Yang tidak terdeteksi adalah fase sebelum dan sesudahnya.

---

## Gap 1: Reconnaissance Tidak Terdeteksi Sama Sekali

**Apa yang terjadi:**
Attacker lakukan ping sweep ke 192.168.30.0/24 dan port scan ke 192.168.30.50 sebelum mulai brute force. Tidak ada satu pun alert di Wazuh untuk aktivitas ini.

**Kenapa tidak terdeteksi:**
Coverage gap yang fundamental. Wazuh collect dari system logs dan agent events - tidak ada network-level monitoring. ICMP sweep dan TCP SYN scan tidak masuk ke auth.log atau syslog sama sekali.

Tidak ada:
- Network-based IDS (Suricata, Snort, Zeek)
- NetFlow atau packet capture
- Firewall log yang di-ingest ke Wazuh

**Dampak:**
Attacker bisa lakukan reconnaissance tanpa jejak sama sekali. Investigator baru tahu ada ancaman saat brute force mulai (11:15) - padahal attacker sudah aktif di jaringan sebelumnya.

**Remediation:**
- Deploy Suricata di network segment sebagai NIDS, integrasikan ke Wazuh
- Minimal: aktifkan logging di level network interface untuk deteksi scan pattern
- Suricata adalah prioritas pertama karena paling straightforward di-integrate ke Wazuh yang sudah ada

---

## Gap 2: Tidak Ada fail2ban - Brute Force Tidak Di-block

**Apa yang terjadi:**
130 SSH authentication attempts dalam ~1.5 menit dari satu IP tidak mendapat blocking sama sekali. Hydra jalan sampai selesai tanpa hambatan.

**Kenapa tidak di-block:**
fail2ban tidak terinstall di siemserver. Tidak ada mekanisme apapun yang otomatis block IP setelah N failures dalam window waktu tertentu.

**Dampak:**
Ini yang paling direct menyebabkan insiden ini berhasil. Kalau fail2ban aktif dengan config default (5 failures dalam 10 menit = ban 10 menit), Hydra dengan 4 thread paralel akan ter-block jauh sebelum berhasil menemukan password yang benar.

**Kenapa ini gap serius:**
SIEM server adalah komponen paling kritis di lab. Justru di server ini tidak ada proteksi dasar seperti fail2ban. Endpoint Windows (WKS01, DC01) punya mekanisme lockout via Group Policy, tapi Linux server ini tidak punya equivalent-nya.

**Remediation:**
- Install dan konfigurasi fail2ban di siemserver:
  ```
  maxretry = 5
  findtime = 300
  bantime = 3600
  ```
- Pertimbangkan juga AllowUsers di sshd_config untuk restrict siapa yang boleh SSH - dhika saja, bukan semua user Linux
- Disable PasswordAuthentication, enforce SSH key-based authentication

---

## Gap 3: Tidak Ada Account Lockout Policy di Linux

**Apa yang terjadi:**
Tidak ada policy yang lock akun itstaff setelah sekian kali salah password. Di Windows ada account lockout via Group Policy. Di Linux tidak ada equivalent-nya secara default.

**Kenapa ini berbeda dari fail2ban:**
fail2ban block di level IP/network. Account lockout block di level akun - bahkan kalau attacker pakai banyak IP berbeda (distributed brute force), lockout tetap trigger setelah N failures ke akun yang sama.

**Remediation:**
- Konfigurasi PAM faillock atau pam_tally2:
  ```
  auth required pam_faillock.so preauth deny=5 unlock_time=900
  ```
- Kombinasi fail2ban + account lockout memberikan defense in depth untuk proteksi SSH

---

## Gap 4: Post-Compromise Activity Tidak Terdeteksi

**Apa yang terjadi:**
Selama ~10 menit sesi itstaff (11:17 - 11:28), attacker menjalankan beberapa discovery commands: whoami, id, uname, cat /etc/passwd, ls /home, ls /var/ossec/. Tidak ada satu pun alert Wazuh untuk aktivitas ini.

**Kenapa tidak terdeteksi:**
Tidak ada monitoring untuk bash command execution di level standard user. Wazuh collect auth.log (login/logout events) tapi tidak ada auditd rules yang log command execution dari SSH session.

Ini berarti attacker bisa lakukan apapun setelah login - selama tidak menyentuh system calls yang spesifik di-monitor - tanpa terdeteksi.

**Yang lebih mengkhawatirkan:**
Target adalah SIEM server itu sendiri. Kalau itstaff punya privilege lebih tinggi, atau kalau attacker berhasil eskalasi, mereka bisa modifikasi Wazuh rules, hapus alerts, atau exfiltrate log investigasi. Di case ini mereka stuck di level standard user, tapi gap-nya tetap ada.

**Remediation:**
- Deploy auditd dengan rules untuk monitor command execution dari SSH sessions:
  ```
  -a always,exit -F arch=b64 -S execve -F uid>=1000 -k user_commands
  ```
- Integrasikan auditd ke Wazuh - ada native support untuk ini
- Buat custom Wazuh rule untuk flag command execution dari sesi SSH yang baru saja established

---

## Gap 5: SSH Expose ke Seluruh Network Segment

**Apa yang terjadi:**
Port 22 siemserver reachable dari semua host di 192.168.30.0/24, termasuk dari Kali (192.168.30.200). Tidak ada network-level restriction untuk akses SSH ke SIEM server.

**Kenapa ini gap:**
SIEM server adalah komponen monitoring - seharusnya yang akses ke sana hanya admin dari host yang authorized, bukan semua host di network. Dengan port 22 terbuka ke seluruh segment, setiap host di jaringan bisa attempt SSH ke SIEM server.

**Remediation:**
- Konfigurasi iptables atau ufw untuk restrict SSH hanya dari IP management yang authorized:
  ```
  ufw allow from 192.168.30.100 to any port 22
  ufw deny 22
  ```
- Atau pindahkan SIEM ke separate management VLAN yang tidak directly accessible dari attacker segment

---

## Summary

| # | Gap | Tipe | Severity | Prioritas Remediation |
|---|-----|------|----------|----------------------|
| 1 | Reconnaissance tidak terdeteksi | Tidak ada coverage | Medium | Menengah |
| 2 | Tidak ada fail2ban | Tidak ada kontrol | Critical | Segera |
| 3 | Tidak ada account lockout Linux | Tidak ada kontrol | High | Tinggi |
| 4 | Post-compromise activity tidak terdeteksi | Tidak ada coverage | High | Tinggi |
| 5 | SSH expose ke seluruh segment | Misconfiguration | High | Tinggi |

---

## Rekomendasi Prioritas

**Jangka pendek (bisa dilakukan sekarang):**
1. Install fail2ban di siemserver - ini yang paling langsung prevent serangan ini terulang
2. Restrict SSH access via ufw - hanya dari authorized management IP
3. Ganti password semua akun yang lemah: itstaff, socl1, socl2, audit

**Jangka menengah:**
4. Deploy auditd + integrasi ke Wazuh untuk command execution logging
5. Enforce SSH key-based auth, disable PasswordAuthentication
6. Konfigurasi PAM faillock untuk account lockout policy

**Jangka panjang:**
7. Deploy Suricata untuk network-level visibility dan deteksi reconnaissance
8. Pertimbangkan separate management network untuk SIEM access

---

*Insiden ini bisa dicegah sepenuhnya hanya dengan Gap 2 - kalau fail2ban terinstall, Hydra tidak akan sempat menemukan password yang benar.*
