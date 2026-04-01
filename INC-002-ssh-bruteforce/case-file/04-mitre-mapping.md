# 04 - MITRE ATT&CK Mapping

**Case:** INC-002-ssh-bruteforce  
**Investigator:** Hardhika Helmi  
**Framework:** MITRE ATT&CK Enterprise v14

---

## Catatan Pendekatan

Mapping ini berdasarkan evidence yang saya temukan - Wazuh alerts, auth.log, last, wtmp, btmp. Teknik yang tidak punya evidence langsung saya catat sebagai "inferred" dengan penjelasan reasoning-nya. Wazuh sendiri sudah provide MITRE mapping di alert 40112: T1078 dan T1110 - saya expand dari sana.

Teknik discovery post-compromise tidak bisa di-mapping dengan confirmed karena tidak ada log yang capture aktivitas selama sesi.

---

## Reconnaissance

### T1595.001 - Active Scanning: Scanning IP Blocks

**Evidence:** Tidak ada alert Wazuh, tidak ada log yang capture ini.

**Inferred:** Attacker tahu port 22 open di 192.168.30.50 sebelum mulai brute force. Informasi ini hanya bisa didapat dari network scan sebelumnya. Keberadaan fase ini diinfer dari attack path yang diambil.

---

### T1046 - Network Service Discovery

**Evidence:** Tidak ada alert, tidak ada log.

**Inferred:** Pilihan SSH sebagai target serangan menunjukkan attacker sudah tahu service apa yang running di port 22 sebelum mulai. Diinfer dari konteks yang sama dengan T1595.001.

---

## Credential Access

### T1110 - Brute Force

**Evidence:**
- Rule 5760 - sshd: authentication failed (cluster, 11:15:28 WIB)
- Rule 5710 - sshd: Attempt to login using non-existent user
- Rule 5763 level 10 - sshd: brute force
- Rule 2502 level 10 - syslog: User missed the password more than once
- Rule 40112 level 12 - Multiple authentication failures followed by a success
- btmp: failed attempts itstaff dari 192.168.30.200 mulai 10:35 WIB

Rule 5710 yang muncul berulang menunjukkan ada username yang dicoba tidak exist di sistem - konsisten dengan pattern yang pakai username wordlist, bukan target single user dari awal.

Rule 5763 adalah Wazuh native detection untuk brute force pattern berdasarkan rate failures dalam window waktu tertentu.

---

## Initial Access

### T1078.003 - Valid Accounts: Local Accounts

**Evidence:**
- Rule 40112 - `full_log: Accepted password for itstaff from 192.168.30.200 port 36484 ssh2`
- Rule 5501 - PAM: Login session opened
- auth.log: dua `Accepted password` entries untuk itstaff dari 192.168.30.200
- last: satu sesi tercatat pts/1, 192.168.30.200, 04:17 - 04:28

Dari sistem perspective ini adalah legitimate SSH login menggunakan credential yang valid. Yang membedakan: source IP yang sama baru saja generate cluster failures sebelum login berhasil - pattern yang di-flag rule 40112.

---

### T1021.004 - Remote Services: SSH

**Evidence:** Rule 40112 `full_log` eksplisit menyebut `ssh2`. auth.log confirm protokol SSH digunakan untuk semua login attempts maupun successful login.

---

## Discovery

Tidak ada teknik discovery yang bisa di-confirm dari evidence yang tersedia. Aktivitas selama sesi 10 menit (11:17 - 11:28 WIB) tidak ter-capture oleh log apapun - Wazuh, auth.log, journalctl, maupun wtmp tidak punya record tentang apa yang dilakukan selama sesi berlangsung.

Teknik discovery yang mungkin terjadi selama sesi tidak bisa di-mapping tanpa evidence. Ini adalah gap investigasi yang significant - dibahas di 05-detection-gaps.md.

---

## Summary Table

| Tactic | Technique | Sub-technique | Status | Alert Caught? |
|--------|-----------|---------------|--------|---------------|
| Reconnaissance | T1595 | .001 Scanning IP Blocks | Inferred | Tidak |
| Reconnaissance | T1046 | Network Service Discovery | Inferred | Tidak |
| Credential Access | T1110 | Brute Force | Confirmed | Ya |
| Initial Access | T1078 | .003 Local Accounts | Confirmed | Ya |
| Initial Access | T1021 | .004 SSH | Confirmed | Ya |
| Discovery | - | Unknown | Tidak diketahui | Tidak |

---

*Alert yang "Ya" berarti Wazuh generate alertnya. "Inferred" berarti tidak ada alert tapi diinfer dari konteks. "Tidak diketahui" berarti tidak ada evidence sama sekali.*
