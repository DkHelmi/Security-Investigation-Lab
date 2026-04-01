# 04 - MITRE ATT&CK Mapping

**Case:** INC-002-ssh-bruteforce  
**Investigator:** Hardhika Helmi  
**Framework:** MITRE ATT&CK Enterprise v14

---

## Catatan Pendekatan

Mapping ini berdasarkan apa yang benar-benar terjadi di case ini, bukan copy-paste dari definisi ATT&CK. Beberapa teknik saya catat dengan caveat karena evidence-nya dari inference atau attacker-logs, bukan dari alert Wazuh langsung.

Wazuh sendiri sudah provide MITRE mapping di alert 40112: `T1078, T1110` dengan tactic `Initial Access, Credential Access`. Saya expand dari sana.

---

## Reconnaissance

### T1595.001 - Active Scanning: Scanning IP Blocks

**Apa yang terjadi:** Ping sweep ke 192.168.30.0/24 untuk host discovery. Dari sweep ini ditemukan 5 host aktif termasuk 192.168.30.50 (siemserver).

**Evidence:** Tidak ada alert Wazuh untuk ini - detection gap. Keberadaan fase ini diinfer dari konteks: attacker langsung tahu target IP dan port sebelum mulai brute force.

---

### T1046 - Network Service Discovery

**Apa yang terjadi:** Port scan ke 192.168.30.50 untuk identify service. Hasil: port 22/tcp open, OpenSSH 8.9p1 Ubuntu.

**Evidence:** Tidak ada alert. Diinfer dari attack path - pilihan SSH sebagai target serangan sesuai dengan hasil scan yang ada.

**Dampak:** Informasi versi OpenSSH yang terekspos dari banner bisa digunakan attacker untuk identify known vulnerabilities, meskipun di case ini mereka pilih brute force credential.

---

## Credential Access

### T1110.001 - Brute Force: Password Guessing

**Apa yang terjadi:** Hydra digunakan untuk brute force SSH dengan kombinasi username wordlist (10 entries) dan password wordlist (13 entries). Total 130 attempts dalam ~1.5 menit. Berhasil menemukan `itstaff:itstaff123`.

**Evidence:**
- Rule 5760 - sshd: authentication failed (cluster, 11:15:28)
- Rule 5710 - sshd: Attempt to login using non-existent user (username tidak exist)
- Rule 5763 level 10 - sshd: brute force
- Rule 2502 level 10 - syslog: User missed the password more than once
- Rule 40112 level 12 - Multiple authentication failures followed by a success (11:17:34)

**Kenapa berhasil:** Password `itstaff123` terlalu predictable - format `namauser + angka` adalah salah satu pattern paling umum yang ada di setiap wordlist. Tidak ada fail2ban atau lockout policy yang block attempt setelah N failures.

**Perbedaan dengan spray:** Ini lebih ke password guessing dengan single target user setelah username enumeration, bukan spray ke banyak akun. Meskipun username wordlist digunakan, focus akhirnya ke itstaff sebagai target.

---

## Initial Access

### T1078.003 - Valid Accounts: Local Accounts

**Apa yang terjadi:** Setelah dapat credential, attacker login SSH menggunakan akun `itstaff` yang valid di siemserver. Bukan exploit, bukan bypass - literally pakai username dan password yang sah.

**Evidence:**
- Rule 40112 - `full_log: Accepted password for itstaff from 192.168.30.200 port 36484 ssh2`
- Rule 5501 - PAM: Login session opened

**Yang bikin deteksi susah:** dari sistem perspective ini adalah legitimate SSH login. Bedanya hanya source IP yang tidak biasa (192.168.30.200, Kali) dan pattern - login dari IP yang sama yang baru saja generate puluhan failures.

---

### T1021.004 - Remote Services: SSH

**Apa yang terjadi:** Attacker masuk ke siemserver via SSH (port 22) menggunakan credential itstaff yang berhasil di-brute force.

**Evidence:** Rule 40112 - `ssh2` di full_log confirm SSH protocol digunakan.

---

## Discovery

### T1033 - System Owner/User Discovery

**Apa yang terjadi:** `whoami` dan `id` dijalankan untuk konfirmasi identity dan privilege level setelah login.

**Evidence:** Direkonstruksi dari attacker-logs. Tidak ada alert Wazuh untuk command ini - detection gap.

**Result:** `uid=1001(itstaff) gid=1001(itstaff) groups=1001(itstaff)` - tidak ada sudo, tidak ada elevated groups.

---

### T1082 - System Information Discovery

**Apa yang terjadi:** `uname -a` dan `cat /etc/os-release` untuk enumerate informasi OS dan kernel.

**Evidence:** Direkonstruksi dari attacker-logs. Tidak ada alert Wazuh.

**Result:** Linux siemserver 5.15.0-173-generic, Ubuntu 22.04.5 LTS.

---

### T1087.001 - Account Discovery: Local Account

**Apa yang terjadi:** `cat /etc/passwd` untuk enumerate semua user di sistem. Filter applied untuk exclude nologin dan false shell entries.

**Evidence:** Direkonstruksi dari attacker-logs. Tidak ada alert Wazuh.

**Result yang didapat attacker:** root, dhika (uid=1000), itstaff (uid=1001), socl1, socl2, audit - semua punya /bin/bash shell, semua punya home directory. Attacker tahu ada 5 akun lain di server ini selain itstaff.

---

### T1083 - File and Directory Discovery

**Apa yang terjadi:** `ls -la /home` untuk lihat home directories semua user. `ls -la /var/ossec/` untuk cek akses ke Wazuh directory.

**Evidence:** Direkonstruksi dari attacker-logs. `/var/ossec/` access menunjukkan attacker tahu ini Wazuh server.

**Result:** Akses ke `/var/ossec/` gagal - Permission denied. itstaff tidak punya akses ke directory Wazuh.

---

## Summary Table

| Tactic | Technique | Sub-technique | Status | Alert Caught? |
|--------|-----------|---------------|--------|---------------|
| Reconnaissance | T1595 | .001 Scanning IP Blocks | Inferred | Tidak |
| Reconnaissance | T1046 | Network Service Discovery | Inferred | Tidak |
| Credential Access | T1110 | .001 Password Guessing | Confirmed | Ya |
| Initial Access | T1078 | .003 Local Accounts | Confirmed | Ya |
| Initial Access | T1021 | .004 SSH | Confirmed | Ya |
| Discovery | T1033 | System Owner/User Discovery | Confirmed | Tidak |
| Discovery | T1082 | System Information Discovery | Confirmed | Tidak |
| Discovery | T1087 | .001 Local Account | Confirmed | Tidak |
| Discovery | T1083 | File and Directory Discovery | Confirmed | Tidak |

---

## Catatan

Semua teknik Discovery di atas tidak ter-capture oleh Wazuh alert. Aktivitas post-compromise di level command execution tidak generate alert karena tidak ada rule yang monitoring bash command execution untuk standard user. Ini adalah gap coverage yang signifikan - attacker bisa lakukan reconnaissance dalam SIEM server sendiri tanpa terdeteksi.

Detail di 05-detection-gaps.md.

---

*Alert yang "Ya" berarti Wazuh generate alertnya. Alert yang "Tidak" berarti tidak ada coverage sama sekali.*
