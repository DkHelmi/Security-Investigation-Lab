# 02 - Investigation

**Case:** INC-001-rdp-intrusion  
**Investigator:** Hardhika Helmi  
**Status:** Active

---

## Starting Point

Dari triage: credential spray dari 192.168.30.200 berhasil, userAlpha masuk ke WKS01 via RDP. Pertanyaan sekarang - apa yang mereka lakukan setelah masuk?

Pivot pertama: cari aktivitas userAlpha di WKS01 setelah timestamp logon success.

---

## Rekonstruksi Aktivitas di WKS01

### Logon Confirmed

Alert 92653 confirm RDP session dari 192.168.30.200 ke WKS01 sebagai `LAB\userAlpha`. NTLM authentication (alert 92657 muncul bersamaan). Ini bukan pass-the-hash - attacker punya plaintext credential dari spray tadi.

Saat ini saya masih asumsi userAlpha adalah standard domain user. Perlu dicek apakah dia punya local admin di WKS01.

### Cek Privilege userAlpha

Dari Sysmon logs post-logon: tidak ada escalation attempt yang jelas terdeteksi. Tidak ada `net localgroup administrators` atau sejenisnya dari konteks userAlpha di WKS01 yang muncul. Saya cek Wazuh - alert 67028 (special privileges assigned) muncul, tapi ini normal behavior untuk beberapa tipe logon, bukan necessarily privilege escalation.

**Kesimpulan sementara:** userAlpha kemungkinan standard user, tidak ada local admin di WKS01. Tapi masih worth dicek apakah mereka coba sesuatu yang lain.

### Aktivitas Command Prompt

Alert 92052 muncul - *Windows command prompt started by abnormal process*. Ini menarik. Artinya ada cmd.exe atau powershell.exe yang dijalankan dari parent process yang tidak biasa dalam konteks sesi userAlpha.

Dari sini saya mulai curiga ada reconnaissance yang berjalan. Tapi saya tidak punya detail command-nya dari alert ini saja - perlu pivot ke Sysmon process creation logs untuk lihat apa yang dijalankan.

---

## Dead End Pertama - Mencari Recon Activity di WKS01

Saya coba cari Sysmon event 1 (process creation) yang terkait userAlpha di WKS01 sekitar timeframe logon. Hasilnya tidak banyak yang conclusive dari WKS01 side - attacker tampaknya tidak lama di sini, atau aktivitas recon-nya tidak generate alert yang significant di WKS01.

Kemungkinan dua hal: mereka langsung cari jalan ke sistem lain, atau mereka recon secara pasif (lihat-lihat drive, folder) yang tidak generate process creation event.

Saya putuskan pivot ke arah yang berbeda: cek apakah ada outbound connection dari WKS01 ke sistem lain di jaringan setelah logon userAlpha.

---

## Pivot ke Lateral Movement

### Trail ke DC01

Alert 92657 muncul lagi - tapi kali ini berbeda. *Successful Remote Logon* dengan NTLM, user yang sama (`LAB\userAlpha`), tapi target-nya DC01 (192.168.30.100), bukan WKS01. Timestamp-nya setelah logon RDP ke WKS01.

Ini konfirmasi lateral movement. Attacker pakai credential userAlpha yang sama untuk masuk ke DC01.

**Port yang digunakan:** 5985 (WinRM). Mereka tidak coba RDP ke DC01 - langsung WinRM. Ini menunjukkan attacker sudah tahu atau asumsi WinRM aktif di DC01 (mungkin dari recon nmap awal).

### Akses DC01

Alert 92052 muncul lagi di konteks DC01 - *command prompt started by abnormal process*. Kali ini di domain controller. Ini lebih serius daripada yang sama di WKS01.

Di titik ini, attacker sudah punya interactive shell di DC01 sebagai `LAB\userAlpha`.

### Apa yang Dilakukan di DC01?

Dari Sysmon dan Wazuh alert cluster di DC01, saya rekonstruksi beberapa command yang jalan:

- `whoami` - verify identity post-logon (standar)
- `hostname` - verify mereka di mesin yang benar
- `net group "Domain Admins" /domain` - enumerasi siapa yang admin domain
- `net user /domain` - list semua domain user

Hasilnya dari domain recon: Domain Admins cuma Administrator. Domain users: Administrator, Guest, krbtgt, userAlpha, userBeta. userAlpha tidak ada di Domain Admins - mereka stuck sebagai standard domain user bahkan di DC01.

**Ini penting:** attacker punya akses ke DC01, tapi privilege-nya terbatas. Mereka tidak bisa dump credentials (secretsdump akan butuh admin), tidak bisa modify domain objects.

---

## Cek Credential Access Attempt

Alert 92217 level 15 - *Executable file dropped in folder commonly used by malware* - muncul di DC01. Ini yang harusnya saya pivot ke sini lebih awal waktu triage. Waktu investigation ini, saya baru re-notice alert ini dan mulai cek.

Kemungkinan ini terkait dengan impacket atau tool credential dumping yang dicoba. Tapi dari hasil investigasi, tidak ada credential dump yang berhasil - tidak ada alert terkait LSASS access atau Ntds.dit copy yang successful.

Hipotesis: attacker coba secretsdump atau sejenisnya, gagal karena userAlpha bukan admin, tapi file executable sempat dropped ke disk sebelum execution gagal atau dibatalkan.

---

## Persistence - Yang Saya Temukan Belakangan

Saat saya lagi rekonstruksi aktivitas di WKS01 (bukan DC01), saya akhirnya lihat alert yang sebelumnya saya lewati:

**Level 6 - Registry entry to be executed on next logon was modified**

Lokasi: HKCU\Software\Microsoft\Windows\CurrentVersion\Run di WKS01, user context userAlpha.

Dari Sysmon registry event: value name `WindowsUpdateHelper`, data-nya command powershell dengan `-WindowStyle Hidden`. Ini persistence via registry Run key. Tidak butuh admin privilege karena HKCU (per-user, bukan HKLM).

Alert level 10 (Base64-like pattern di registry value) juga muncul terkait entry yang sama - saya missed ini waktu triage.

**Jadi attacker pasang persistence di WKS01 sebelum atau selama mereka pivot ke DC01.** Timeline pastinya ada di 03-timeline.md.

---

## Rekonstruksi Lengkap Aktivitas Attacker

Dari semua yang terkumpul, ini yang bisa saya rekonstruksi:

1. Attacker (192.168.30.200) lakukan credential spray ke WKS01 via SMB port 445
2. Berhasil dapat `userAlpha:P@ssw0rd123!` (dan kemungkinan userBeta juga)
3. Masuk WKS01 via RDP menggunakan userAlpha
4. Pasang persistence di HKCU Run key (WindowsUpdateHelper) - powershell hidden
5. Lateral movement ke DC01 via WinRM (port 5985) menggunakan credential yang sama
6. Lakukan domain recon di DC01 - whoami, net group Domain Admins, net user /domain
7. Attempt credential access (kemungkinan secretsdump) - gagal, userAlpha bukan admin
8. Attacker stuck, tidak ada eskalasi lebih lanjut yang terdeteksi

**Status attacker akhir:** punya persistence di WKS01, credentials userAlpha dan userBeta compromised, tapi gagal escalate privilege. Domain Admins tetap aman.

---

## Yang Masih Belum Jelas

- Apakah ada aktivitas lain di WKS01 yang tidak terdeteksi (living off the land techniques)
- Exact timestamp persistence dipasang relatif terhadap lateral movement ke DC01
- Apakah userBeta juga digunakan untuk sesuatu atau cuma userAlpha yang dipakai

Ini saya catat sebagai investigative gaps, bukan necessarily detection failures.

---

*MITRE mapping detail ada di 04-mitre-mapping.md. Detection gaps dan missed alerts dibahas di 05-detection-gaps.md.*
