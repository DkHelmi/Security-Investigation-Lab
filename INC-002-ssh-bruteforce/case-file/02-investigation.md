# 02 - Investigation

**Case:** INC-002-ssh-bruteforce  
**Investigator:** Hardhika Helmi  
**Status:** Active

---

## Starting Point

Dari triage: SSH brute force dari 192.168.30.200 berhasil, akun `itstaff` login ke SIEM server jam 11:17:34. Sesi aktif sekitar 10 menit sampai 11:28:12. Pertanyaan sekarang - apa yang mereka lakukan selama sesi itu?

Pivot pertama: rekonstruksi aktivitas itstaff selama window 11:17 - 11:28.

---

## Rekonstruksi Aktivitas - Sesi itstaff

### Login Confirmed

Rule 40112 jam 11:17:34 confirm login berhasil dari 192.168.30.200 ke akun itstaff via SSH. `full_log` dari alert ini sangat eksplisit: `Accepted password for itstaff from 192.168.30.200 port 36484 ssh2`. Tidak ada ambiguitas di sini.

Rule 5501 (*PAM: Login session opened*) muncul bersamaan - confirm sesi interaktif terbuka.

### Cek Privilege itstaff

Dari output discovery yang terekam: `id` menunjukkan `uid=1001(itstaff) gid=1001(itstaff) groups=1001(itstaff)`. Tidak ada sudo group, tidak ada adm group. itstaff adalah standard user tanpa privilege tambahan.

Ini sedikit melegakan - attacker tidak langsung dapat akses root. Tapi mereka masih ada di dalam SIEM server, yang sendirinya sudah cukup berbahaya.

### Discovery Commands

Dari rekonstruksi sesi berdasarkan attacker-logs (referensi lab), urutan command yang dijalankan selama sesi:

```
date          → Wed Apr 1 04:23:14 AM UTC 2026
whoami        → itstaff
id            → uid=1001(itstaff) gid=1001(itstaff) groups=1001(itstaff)
uname -a      → Linux siemserver 5.15.0-173-generic
cat /etc/passwd (filtered) → terlihat: root, dhika, itstaff, socl1, socl2, audit
ls -la /home  → 5 user home directory: audit, dhika, itstaff, socl1, socl2
ls -la /var/ossec/ → Permission denied
```

Yang menarik dari urutan ini: attacker langsung coba `/var/ossec/` setelah lihat user list dan home directories. Mereka tahu ini Wazuh server dan langsung cek apakah bisa akses directory Wazuh. Jawaban: tidak bisa - `Permission denied`.

### Akses ke /var/ossec/ Gagal

Ini penting dicatat. `/var/ossec/` adalah directory Wazuh tempat alerts, logs, dan konfigurasi disimpan. itstaff tidak punya permission ke sana. Artinya selama sesi ini, attacker tidak bisa baca alert Wazuh, tidak bisa modifikasi rules, tidak bisa akses log investigasi.

Dari sisi impact, ini membatasi apa yang bisa attacker lakukan. Tapi keberadaan mereka di server ini tetap serius - mereka tahu topologi user, bisa jadi pivot point untuk serangan selanjutnya.

### Tidak Ada bash_history

`cat ~/.bash_history` saat akhir sesi menunjukkan `No such file or directory`. File bash_history baru terbentuk setelah sesi pertama selesai dan bash menulis history ke disk. Karena ini kemungkinan sesi pertama itstaff, file belum ada.

Dari perspektif investigasi: ini bukan attacker yang cover tracks. Ini behavior normal bash. Evidence utama tetap dari auth.log dan Wazuh alerts, bukan bash_history.

---

## Dead End - Aktivitas Post-Compromise yang Terbatas

Saya coba cari apakah ada aktivitas lain selama sesi 10 menit itu - koneksi keluar, file yang dibuat, atau privilege escalation attempt. Dari alert Wazuh yang ada, tidak ada yang menunjukkan eskalasi atau aktivitas lebih lanjut selama window tersebut.

Kemungkinan dua hal: attacker memang hanya melakukan reconnaissance awal dan tidak sempat atau tidak berhasil melakukan lebih banyak, atau ada aktivitas yang tidak ter-capture oleh monitoring yang ada.

Untuk scope INC-002 ini, evidence yang ada cukup untuk rekonstruksi apa yang terjadi. Aktivitas yang tidak terdeteksi dibahas di 05-detection-gaps.md.

---

## Rekonstruksi Lengkap

Dari semua evidence yang terkumpul:

1. Attacker dari 192.168.30.200 scan network, temukan port 22 open di 192.168.30.50 (sebelum 11:15)
2. SSH brute force dengan username wordlist dan password wordlist (11:15 - 11:15:36)
3. Hydra berhasil: `itstaff:itstaff123` ditemukan
4. Login manual SSH sebagai itstaff (11:17:34)
5. Discovery: whoami, id, uname, /etc/passwd, ls /home, ls /var/ossec → Permission denied
6. Logout (11:28:12)

**Status akhir:** akun itstaff berhasil di-compromise. Attacker ada di dalam SIEM server selama ~10 menit. Tidak ada bukti eskalasi privilege atau akses ke data sensitif Wazuh. Tapi akses ke server monitoring sudah cukup mengkhawatirkan.

---

## Yang Masih Belum Jelas

- Apakah attacker sempat lakukan sesuatu yang tidak ter-log selama 10 menit itu
- Apakah ada reconnaissance sebelum port scan yang tidak terdeteksi
- Apakah itstaff pernah login legitimate sebelumnya - untuk baseline comparison

Ini saya catat sebagai investigative gaps, bukan necessarily detection failures.

---

*MITRE mapping detail ada di 04-mitre-mapping.md. Detection gaps dan missed alerts dibahas di 05-detection-gaps.md.*
