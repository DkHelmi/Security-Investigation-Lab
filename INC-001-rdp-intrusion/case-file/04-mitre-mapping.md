# 04 - MITRE ATT&CK Mapping

**Case:** INC-001-rdp-intrusion  
**Investigator:** Hardhika Helmi  
**Framework:** MITRE ATT&CK Enterprise v14

---

## Catatan Pendekatan

Mapping ini bukan checklist yang diisi mekanis. Setiap teknik di sini saya tulis dengan konteks apa yang benar-benar terjadi di lab ini, bukan hanya copy-paste definisi dari ATT&CK website. Beberapa teknik saya catat dengan caveat karena evidence-nya tidak 100% conclusive.

---

## Reconnaissance

### T1595.001 - Active Scanning: Scanning IP Blocks

**Apa yang terjadi:** Attacker lakukan ping sweep ke 192.168.30.0/24 untuk discovery host yang aktif. Ditemukan tiga host: SIEM (.50), DC01 (.100), WKS01 (.101).

**Evidence:** Tidak ada alert Wazuh untuk ini. Recon phase ini invisible dari SIEM perspective - ini detection gap.

**Catatan:** nmap ping sweep menggunakan ICMP dan/atau TCP SYN ke port umum. Tidak ada network-based IDS di lab ini yang bisa catch ini.

---

### T1046 - Network Service Discovery

**Apa yang terjadi:** Setelah host discovery, attacker lakukan port scan service discovery ke semua host yang ditemukan. Dari sini mereka tahu WKS01 punya SMB (445) dan RDP (3389) terbuka, DC01 punya WinRM (5985).

**Evidence:** Sama seperti di atas - tidak ada alert. Informasi ini diketahui dari attacker POV, bukan dari SIEM.

**Dampak:** Informasi dari scan ini yang nentuin attack path selanjutnya. Kalau WinRM di DC01 tidak terdeteksi dari scan, mungkin attacker tidak akan coba WinRM lateral movement.

---

## Initial Access

### T1110.003 - Brute Force: Password Spraying

**Apa yang terjadi:** crackmapexec SMB digunakan untuk credential spray ke WKS01. Multiple kombinasi username/password dicoba dalam window waktu singkat ke port 445. Berhasil dapat `userAlpha:P@ssw0rd123!` dan `userBeta:P@ssw0rd123!`.

**Evidence:**
- Rule 60122 - Windows Logon Failures (volume tinggi)
- Rule 60204 - Multiple Windows Logon Failures
- Rule 92657 - Successful Remote Logon setelah cluster failures

**Kenapa spray bukan brute force?** Pattern-nya: banyak akun berbeda dengan password yang sama (atau sedikit variasi), bukan satu akun dicoba password terus-terusan. Ini untuk avoid account lockout.

**Kenapa berhasil?** Password `P@ssw0rd123!` adalah weak password yang memenuhi complexity requirement (uppercase, lowercase, number, symbol) tapi sangat predictable.

---

### T1078.002 - Valid Accounts: Domain Accounts

**Apa yang terjadi:** Setelah spray berhasil, attacker gunakan credential domain userAlpha yang valid untuk autentikasi. Bukan exploit, bukan token, tapi literally pakai username dan password yang sah.

**Evidence:**
- Rule 92657 - Successful Remote Logon (NTLM) dari 192.168.30.200
- Rule 92653 - User LAB\userAlpha logged via RDP

**Ini yang bikin deteksi susah:** dari sistem perspective, ini legitimate logon. Tidak ada malware, tidak ada exploit. Bedanya cuma source IP yang tidak biasa (192.168.30.200 bukan workstation biasa) dan jam/pattern logon.

---

### T1021.001 - Remote Services: Remote Desktop Protocol

**Apa yang terjadi:** Attacker masuk ke WKS01 menggunakan RDP (port 3389) dengan credential userAlpha yang didapat dari spray.

**Evidence:** Rule 92653 - User logged via RDP dari 192.168.30.200.

**Catatan:** xfreerdp digunakan dari Kali, dengan flag `/cert:ignore` dan `/sec:nla`. NLA (Network Level Authentication) tetap berjalan - attacker punya credential yang valid jadi bukan masalah.

---

## Execution

### T1059.001 - Command and Scripting Interpreter: PowerShell

**Apa yang terjadi:** Persistence payload menggunakan `powershell.exe -WindowStyle Hidden`. Selain itu, kemungkinan ada PowerShell usage lain dalam sesi WinRM (evil-winrm secara default pakai PowerShell sebagai shell).

**Evidence:** Rule 92052 - Windows command prompt started by abnormal process. PowerShell logging aktif, tapi saya belum fully pivot ke PS event logs untuk rekonstruksi command-nya.

---

## Persistence

### T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys

**Apa yang terjadi:** Attacker tambahkan entry ke HKCU\Software\Microsoft\Windows\CurrentVersion\Run dengan nama `WindowsUpdateHelper`. Value-nya: `powershell.exe -WindowStyle Hidden -Command 'Start-Sleep 1'`.

**Evidence:**
- Rule 92307 - Service creation in registry (Sysmon registry event)
- Rule Level 6 - Registry entry to be executed on next logon was modified
- Rule Level 10 - Registry value with Base64-like pattern (alert ini yang harusnya langsung di-investigate)

**Kenapa HKCU bukan HKLM?** userAlpha bukan admin, tidak bisa write ke HKLM. HKCU persistence lebih terbatas (hanya aktif saat userAlpha logon) tapi tidak butuh privilege. Ini calculated decision dari attacker - atau workaround karena schtasks gagal.

**Efektivitas:** Entry ini masih aktif di WKS01 sampai saat ini. Setiap kali userAlpha logon, powershell.exe -WindowStyle Hidden akan jalan. Payload saat ini cuma Start-Sleep (benign), tapi bisa diganti kapan saja selama attacker punya akses.

---

## Discovery

### T1087.002 - Account Discovery: Domain Account

**Apa yang terjadi:** Di DC01, attacker jalankan `net user /domain` dan `net group "Domain Admins" /domain`. Dari sini mereka tahu domain user list lengkap dan siapa yang Domain Admin.

**Evidence:** Sysmon process creation event untuk net.exe di DC01 dalam konteks userAlpha, rekonstruksi dari Wazuh.

**Hasil yang didapat attacker:** Domain Admins hanya Administrator. Users: Administrator, Guest, krbtgt, userAlpha, userBeta. Tidak ada service account atau user lain yang bisa di-target.

---

### T1018 - Remote System Discovery

**Apa yang terjadi:** Sebelum lateral movement, attacker sudah punya informasi tentang DC01 dari port scan awal (nmap). Di dalam sesi WKS01, kemungkinan juga ada DNS lookup atau ping ke hostname DC01 sebelum mereka WinRM ke sana.

**Evidence:** Tidak ada alert spesifik. Ini partly dari rekonstruksi attacker path.

---

## Lateral Movement

### T1021.006 - Remote Services: Windows Remote Management

**Apa yang terjadi:** Dari sesi di WKS01 (atau langsung dari Kali menggunakan credential yang sudah ada), attacker connect ke DC01 via WinRM port 5985 menggunakan `evil-winrm`. Credential: userAlpha yang sama.

**Evidence:**
- Rule 92657 - Successful Remote Logon (NTLM) ke DC01 dari 192.168.30.200
- Rule 92052 - Command prompt started by abnormal process di DC01

**Kenapa WinRM berhasil?** userAlpha sudah ditambahkan ke Remote Management Users group di DC01 sebagai bagian dari lab setup. Di real environment, ini harusnya restricted ke admin saja.

**Kenapa pakai WinRM bukan RDP ke DC01?** Kemungkinan dari hasil port scan: port 3389 di DC01 tidak open/filtered, tapi 5985 open. Attacker ikuti path yang available.

---

## Credential Access

### T1003 - OS Credential Dumping (Attempted, Gagal)

**Apa yang terjadi:** Attacker coba dump credentials, kemungkinan menggunakan impacket-secretsdump atau tool sejenis. Gagal karena userAlpha bukan local admin / Domain Admin - tidak punya privilege untuk akses LSASS atau Ntds.dit.

**Evidence:**
- Rule 92217 level 15 - Executable file dropped in folder commonly used by malware (DC01) - kemungkinan artifact dari tool ini
- Tidak ada alert successful credential dump

**Ini yang constrain attacker:** tanpa credential dump, mereka tidak bisa dapat DA credential, tidak bisa eskalasi lebih lanjut.

---

## Summary Table

| Tactic | Technique | Sub-technique | Status | Alert Caught? |
|--------|-----------|---------------|--------|---------------|
| Reconnaissance | T1595 | .001 - Scanning IP Blocks | Confirmed | Tidak |
| Reconnaissance | T1046 | Network Service Discovery | Confirmed | Tidak |
| Initial Access | T1110 | .003 - Password Spraying | Confirmed | Ya |
| Initial Access | T1078 | .002 - Domain Accounts | Confirmed | Ya |
| Initial Access | T1021 | .001 - RDP | Confirmed | Ya |
| Execution | T1059 | .001 - PowerShell | Partial | Ya |
| Persistence | T1547 | .001 - Registry Run Keys | Confirmed | Ya (missed) |
| Discovery | T1087 | .002 - Domain Account | Confirmed | Partial |
| Discovery | T1018 | Remote System Discovery | Partial | Tidak |
| Lateral Movement | T1021 | .006 - WinRM | Confirmed | Ya |
| Credential Access | T1003 | OS Credential Dumping | Attempted/Gagal | Partial |

---

*Alert yang "Ya (missed)" artinya Wazuh generate alertnya, tapi investigator tidak pivot ke sana saat triage. Detail di 05-detection-gaps.md.*
