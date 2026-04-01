# 01 - Alert Triage

**Case:** INC-002-ssh-bruteforce  
**Investigator:** Hardhika Helmi  
**Started:** Apr 1, 2026 @ 11:15 WIB (berdasarkan timestamp alert pertama)  
**Status:** Active

---

## Kenapa Case Ini Dibuka

Mulai dari Wazuh dashboard - ada cluster alert yang tidak biasa dari agent `siemserver`. Yang pertama nangkap perhatian adalah banyaknya rule 5760 (*sshd: authentication failed*) yang masuk dalam window waktu sangat singkat, semua dari satu source IP.

Awalnya tidak langsung jelas ini serangan atau bukan. Bisa saja user IT lupa password dan retry berkali-kali. Tapi volume-nya tidak wajar untuk skenario itu - terlalu banyak, terlalu cepat.

Yang langsung bikin ini lebih serius: agent yang nge-report adalah `siemserver` - SIEM server itu sendiri. Bukan endpoint biasa.

---

## Alert Awal yang Jadi Trigger

**Rule 5760 - sshd: authentication failed (cluster)**

![Wazuh Alert Overview](../evidence/evidence-01-wazuh-alerts-overview.png)
*Alert list Wazuh - cluster 5760 authentication failed mulai 11:15 WIB, diikuti rule 40112 jam 11:17 WIB*

Dari cluster alert ini, beberapa hal yang saya perhatikan:

- Alert datang dari agent `siemserver` - ini SIEM server itu sendiri, bukan endpoint biasa
- Volume sangat tinggi dalam window waktu sempit (~2 menit)
- Ada rule 5710 (*sshd: Attempt to login using non-existent user*) yang muncul berulang - artinya ada username yang dicoba tapi tidak exist di sistem. Ini konsisten dengan pattern brute force yang pakai username wordlist
- Rule 5763 (*sshd: brute force*) muncul - Wazuh sendiri sudah flag ini sebagai brute force pattern

---

## Triage Awal - Seberapa Serius?

Tiga pertanyaan yang saya kejar duluan:

**1. Ada login SUCCESS setelah failures ini?**

Ya. Rule 40112 muncul jam 11:17:34 WIB - *Multiple authentication failures followed by a success*. Ini yang langsung naikkan prioritas. Bukan hanya ada yang coba masuk, tapi mereka berhasil.

![Alert 40112 Detail](../evidence/evidence-02-alert-40112-detail.png)
*Detail rule 40112 - data.srcip 192.168.30.200, data.dstuser itstaff, timestamp 11:17:34 WIB*

Dari detail alert ini informasinya cukup lengkap:

- `data.srcip`: 192.168.30.200 - source IP konsisten satu alamat
- `data.dstuser`: itstaff - akun yang berhasil login
- `full_log`: `Accepted password for itstaff from 192.168.30.200 port 36484 ssh2`
- `rule.level`: 12 - high severity
- `rule.mitre.id`: T1110, T1078
- `rule.mitre.technique`: Brute Force, Valid Accounts

**2. itstaff akun sensitif?**

Belum bisa dipastikan di tahap ini. Yang saya tahu: akun ini ada di SIEM server dan berhasil di-login dari IP yang baru saja generate ratusan failures. Perlu investigasi lebih lanjut untuk tahu privilege-nya.

**3. Ada aktivitas lanjutan setelah login berhasil?**

Rule 5501 (*PAM: Login session opened*) muncul bersamaan dengan 40112 di 11:17:34 WIB - confirm ada sesi aktif. Rule 5502 (*PAM: Login session closed*) muncul jam 11:28:12 WIB - sesi berlangsung sekitar 10 menit. Cukup untuk buka case.

---

## Alert Lain di Window Waktu yang Sama

- **5710 - sshd: Attempt to login using non-existent user** - username yang dicoba tidak exist di sistem, muncul berulang kali dalam cluster
- **5763 - sshd: brute force** - Wazuh flag rate failures sebagai brute force pattern
- **2502 - syslog: User missed the password more than once** - corroboration dari syslog layer
- **67028** dari DC01 - tidak terkait, kemungkinan activity normal DC01 yang terjadi bersamaan

---

## Initial Scope Assessment

| Host | Status | Catatan |
|------|--------|---------|
| siemserver / 192.168.30.50 | **Compromised** | SSH brute force berhasil, itstaff login dari 192.168.30.200 |
| 192.168.30.200 | Attacker | Source dari semua failures dan successful login |
| DC01 / 192.168.30.100 | Tidak terdampak | Alert 67028 tidak terkait insiden ini |
| WKS01 / 192.168.30.101 | Tidak terdampak | Tidak ada indikasi |

**Hipotesis awal:**
Ada yang melakukan SSH brute force ke SIEM server dari 192.168.30.200, berhasil login sebagai `itstaff`. Sesi berlangsung sekitar 10 menit (11:17 - 11:28 WIB). Belum diketahui apa yang dilakukan selama sesi tersebut - Wazuh tidak capture aktivitas post-compromise.

**Yang paling mengkhawatirkan:** target adalah SIEM server sendiri. Kalau itstaff punya akses ke Wazuh atau log di dalamnya, attacker bisa tahu apa saja yang sudah terdeteksi.

**Langkah selanjutnya:** Wazuh tidak cukup untuk rekonstruksi aktivitas selama sesi. Perlu pivot ke auth.log dan system logs langsung di siemserver untuk cari evidence tambahan.

---

*Timeline kronologi lengkap ada di 03-timeline.md. Document ini fokus ke proses triage dan decision point awal.*
