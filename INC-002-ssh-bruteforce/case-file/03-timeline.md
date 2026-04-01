# 03 - Timeline

**Case:** INC-002-ssh-bruteforce  
**Investigator:** Hardhika Helmi  
**Disusun dari:** Wazuh alerts, auth.log, PAM events

---

## Catatan

Timeline ini direkonstruksi dari evidence yang terekam di SIEM dan log - bukan dari POV attacker. Semua timestamp adalah timestamp absolut dari Wazuh alerts.

Ada gap antara timestamp Kali (UTC-4) dan timestamp Wazuh (UTC). Timestamp di bawah menggunakan timezone Wazuh (UTC) sebagai acuan utama karena itu yang akan dilihat investigator saat triage.

Fase reconnaissance (nmap) tidak punya timestamp Wazuh karena tidak terdeteksi - ini sendiri adalah finding yang dicatat di 05-detection-gaps.md.

---

## Kronologi Event

### Fase 0 - Kondisi Lab Sebelum Insiden

**State awal (sebelum 11:15):**
- SIEM server online, port 22 open dan reachable dari seluruh network segment
- User itstaff aktif dengan password lemah: `itstaff123`
- fail2ban tidak terinstall, tidak ada account lockout policy di Linux
- Wazuh agent berjalan di siemserver (self-monitoring)
- SSH PasswordAuthentication: yes (default)

Semua kondisi di atas yang membuat serangan ini berhasil.

---

### Fase 1 - Reconnaissance (Tidak Terdeteksi)

**Estimasi sebelum 11:15 - Network Discovery**
- Tidak ada alert Wazuh untuk aktivitas ini
- Dari konteks: attacker perlu tahu host mana yang aktif dan port apa yang open sebelum mulai brute force
- Port 22 yang dijadikan target ditemukan dari port scan ke 192.168.30.50
- Detail: lihat 05-detection-gaps.md

---

### Fase 2 - Brute Force

**11:15:28 - Authentication Failures Mulai Masuk**
- Alert: Rule 5760 - sshd: authentication failed
- Source: 192.168.30.200 → Target: siemserver port 22
- Multiple username dicoba: dari Wazuh terlihat mix antara username yang exist (itstaff) dan yang tidak exist (admin, administrator, dll)

**11:15:30 - 11:15:36 - Cluster Failures Berlanjut**
- Alert: Rule 5710 - sshd: Attempt to login using non-existent user (username tidak ada di sistem)
- Alert: Rule 2502 - syslog: User missed the password more than once (level 10)
- Alert: Rule 5763 - sshd: brute force (level 10) - Wazuh detect brute force pattern dari rate failures

![Wazuh Alert Overview](../evidence/evidence-01-wazuh-alerts-overview.png)
*Cluster alert 5760, 5710, 2502 mulai 11:15 - volume tinggi dalam window sempit*

**Rate serangan:** sekitar 94 attempts/menit berdasarkan attacker-logs. Total 130 kombinasi (10 username x 13 password).

---

### Fase 3 - Initial Access

**11:17:34 - Login Berhasil**
- Alert: Rule 5501 - PAM: Login session opened
- Alert: Rule 40112 level 12 - Multiple authentication failures followed by a success ← **ini trigger pivot investigasi**
- Source: 192.168.30.200 → siemserver
- Account: itstaff
- Method: SSH password authentication

![Alert 40112 Detail](../evidence/evidence-02-alert-40112-detail.png)
*Rule 40112 - srcip 192.168.30.200, dstuser itstaff, full_log: Accepted password for itstaff from 192.168.30.200 port 36484 ssh2*

Rule 40112 adalah correlation rule - Wazuh menggabungkan cluster failures sebelumnya dengan successful login ini menjadi satu alert level 12. Tanpa rule ini, investigator harus manual pivot dari failures ke success.

---

### Fase 4 - Discovery di SIEM Server

**11:23:14 - Reconnaissance Post-Compromise**
- Context: itstaff SSH session aktif
- Commands yang dijalankan (direkonstruksi dari attacker-logs):
  - `whoami` → itstaff
  - `id` → uid=1001(itstaff), tidak ada sudo/admin groups
  - `uname -a` → Linux siemserver 5.15.0-173-generic
  - `cat /etc/passwd` → terlihat user aktif: root, dhika, itstaff, socl1, socl2, audit
  - `ls -la /home` → 5 home directories: audit, dhika, itstaff, socl1, socl2
  - `ls -la /var/ossec/` → **Permission denied**

Attacker langsung coba `/var/ossec/` setelah melihat daftar user dan home directories - menunjukkan mereka tahu ini Wazuh server. Akses ke directory Wazuh gagal karena itstaff bukan member group yang punya permission ke sana.

---

### Fase 5 - Logout

**11:28:12 - Sesi Ditutup**
- Alert: Rule 5502 - PAM: Login session closed
- Total durasi sesi: sekitar 10 menit 38 detik

---

## Summary

```
~11:10       [RECON]    Nmap ping sweep + port scan (tidak terdeteksi)
11:15:28     [ACCESS]   SSH brute force mulai - cluster failures (ALERT 5760, 5710, 5763)
11:17:34     [ACCESS]   Login berhasil sebagai itstaff dari 192.168.30.200 (ALERT 40112 level 12)
11:17:34     [ACCESS]   PAM session opened (ALERT 5501)
11:23:14     [DISCOVERY] whoami, id, uname, /etc/passwd, ls /home, ls /var/ossec → denied
11:28:12     [END]      PAM session closed (ALERT 5502) - sesi ~10 menit
```

---

*Untuk mapping ke MITRE ATT&CK, lihat 04-mitre-mapping.md.*
