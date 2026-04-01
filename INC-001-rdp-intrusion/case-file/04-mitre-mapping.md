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

**Apa yang terjadi:** Ping sweep ke 192.168.30.0/24 untuk host discovery sebelum serangan dimulai. Tiga host ditemukan: SIEM (.50), DC01 (.100), WKS01 (.101).

**Evidence:** Tidak ada alert Wazuh untuk ini - detection gap. Keberadaan fase ini diinfer dari konteks: attacker tahu port spesifik yang digunakan (5985 WinRM di DC01) sebelum mulai spray, informasi itu hanya bisa didapat dari scan awal.

---

### T1046 - Network Service Discovery

**Apa yang terjadi:** Port scan service discovery ke semua host yang ditemukan. Dari sini attacker tahu WKS01 buka SMB (445) dan RDP (3389), DC01 buka WinRM (5985).

**Evidence:** Sama - tidak ada alert. Diinfer dari attack path yang diambil: pilihan SMB sebagai target spray dan WinRM sebagai lateral movement channel sesuai dengan hasil scan yang ada.

**Dampak:** Informasi dari scan ini yang menentukan seluruh attack path. Tanpa visibility ke fase ini, investigator baru tahu attacker ada di jaringan setelah spray dimulai.

---

## Initial Access

### T1110.003 - Brute Force: Password Spraying

**Apa yang terjadi:** crackmapexec SMB digunakan untuk password spray ke WKS01 port 445. Multiple akun berbeda dicoba (admin1, userAlpha, userBeta) dalam window waktu sempit. Berhasil dapat `userAlpha:P@ssw0rd123!` dan `userBeta:P@ssw0rd123!`.

**Evidence:**
- Rule 60122 - Windows Logon Failures (volume tinggi, 07:17:37)
- Rule 60204 level 10 - Multiple Windows Logon Failures (07:17:38, firedtimes: 954)
- Rule 92657 - Successful Remote Logon setelah cluster failures (07:25:13)

**Kenapa spray bukan brute force:** Multiple `targetUserName` berbeda dari satu source IP dalam window waktu sempit. Brute force menyerang satu akun dengan banyak password - spray membaliknya untuk hindari account lockout.

**Kenapa berhasil:** Password `P@ssw0rd123!` memenuhi complexity requirement (uppercase, lowercase, number, symbol) tapi sangat predictable - masuk dalam wordlist password umum.

---

### T1078.002 - Valid Accounts: Domain Accounts

**Apa yang terjadi:** Setelah spray berhasil, attacker gunakan credential domain userAlpha yang valid untuk semua autentikasi selanjutnya. Bukan exploit, bukan token manipulation - literally pakai username dan password yang sah.

**Evidence:**
- Rule 92657 - Successful Remote Logon (NTLM) dari 192.168.30.200 (07:25:13)
- Rule 92653 - User LAB\userAlpha logged via RDP

**Yang bikin deteksi susah:** dari sistem perspective ini adalah legitimate logon. Bedanya cuma source IP yang tidak biasa (192.168.30.200, workstationName: kalidhika) dan pattern - logon dari IP yang sama yang sebelumnya generate ratusan failures.

---

### T1021.001 - Remote Services: Remote Desktop Protocol

**Apa yang terjadi:** Attacker masuk ke WKS01 via RDP (port 3389) menggunakan credential userAlpha.

**Evidence:** Rule 92653 - User logged via RDP dari 192.168.30.200 (07:25).

---

## Execution

### T1059.001 - Command and Scripting Interpreter: PowerShell

**Apa yang terjadi:** Persistence payload menggunakan `powershell.exe -WindowStyle Hidden`. evil-winrm secara default menggunakan PowerShell sebagai shell, jadi seluruh WinRM session di DC01 berjalan dalam konteks PowerShell.

**Evidence:** Alert 92052 - Windows command prompt started by abnormal process. Alert 92041 - `parentImage: powershell.exe` saat reg.exe dieksekusi untuk pasang Run key.

---

## Persistence

### T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys

**Apa yang terjadi:** Entry ditambahkan ke HKCU\Software\Microsoft\Windows\CurrentVersion\Run dengan nama `WindowsUpdateHelper`. Payload: `powershell.exe -WindowStyle Hidden -Command 'Start-Sleep 1'`.

**Evidence:**
- Alert 92041 level 10 - commandLine reg.exe add HKCU\...\Run\WindowsUpdateHelper (07:46:51)
- Alert 92302 level 6 - Registry entry to be executed on next logon was modified (07:46:51)
- Konfirmasi langsung: regedit di WKS01 sebagai userAlpha menunjukkan entry masih aktif

**Kenapa HKCU bukan HKLM:** userAlpha bukan admin, tidak bisa write ke HKLM. HKCU persistence hanya aktif saat userAlpha logon, tapi tidak butuh privilege - ini calculated workaround setelah schtasks gagal karena privilege issue.

**Status sekarang:** Entry masih aktif. Setiap kali userAlpha logon ke WKS01, powershell.exe -WindowStyle Hidden akan jalan. Payload saat ini benign (Start-Sleep), tapi bisa dimodifikasi kapan saja selama attacker punya akses.

---

## Discovery

### T1087.002 - Account Discovery: Domain Account

**Apa yang terjadi:** Di DC01, `net user /domain` dan `net group "Domain Admins" /domain` dijalankan dalam konteks WinRM session userAlpha.

**Evidence:** Sysmon Event ID 1 (process creation) di DC01 - net.exe dengan parent wsmprovhost.exe (WinRM process), user LAB\userAlpha.

**Hasil yang didapat:** Domain Admins hanya Administrator. Users: Administrator, Guest, krbtgt, userAlpha, userBeta. Tidak ada service account atau privileged user lain yang bisa di-target.

---

### T1018 - Remote System Discovery

**Apa yang terjadi:** Host discovery dan service enumeration sebelum spray dimulai.

**Evidence:** Tidak ada alert - diinfer dari attack path. Lihat T1595.001.

---

## Lateral Movement

### T1021.006 - Remote Services: Windows Remote Management

**Apa yang terjadi:** Koneksi ke DC01 via WinRM port 5985 menggunakan credential userAlpha yang sama. Tool: evil-winrm dari 192.168.30.200.

**Evidence:**
- Alert 92213 level 15 - Executable dropped di DC01 (07:36:25) - artifact PSScriptPolicyTest dari WinRM session
- Alert 92652 level 6 - Successful Remote Logon (NTLM) ke DC01 (07:49:52)
- Alert 92052 - Command prompt started by abnormal process di DC01

**Kenapa WinRM berhasil:** userAlpha sudah ada di Remote Management Users group di DC01 sebagai bagian lab setup. Di real environment, membership ini harusnya restricted ke admin saja.

---

## Credential Access

### T1003 - OS Credential Dumping (Attempted, Gagal)

**Apa yang terjadi:** Credential dump attempt di DC01, kemungkinan secretsdump atau tool sejenis. Gagal karena userAlpha bukan local admin / Domain Admin.

**Evidence:**
- Alert 92213 level 15 di DC01 (artifact dari tool, bukan successful dump)
- Tidak ada alert LSASS access atau Ntds.dit copy yang successful

**Ini yang constrain attacker:** tanpa credential dump, tidak ada path ke DA, tidak ada lateral movement lebih lanjut yang meaningful.

---

## Summary Table

| Tactic | Technique | Sub-technique | Status | Alert Caught? |
|--------|-----------|---------------|--------|---------------|
| Reconnaissance | T1595 | .001 Scanning IP Blocks | Inferred | Tidak |
| Reconnaissance | T1046 | Network Service Discovery | Inferred | Tidak |
| Initial Access | T1110 | .003 Password Spraying | Confirmed | Ya |
| Initial Access | T1078 | .002 Domain Accounts | Confirmed | Ya |
| Initial Access | T1021 | .001 RDP | Confirmed | Ya |
| Execution | T1059 | .001 PowerShell | Confirmed | Partial |
| Persistence | T1547 | .001 Registry Run Keys | Confirmed | Ya (missed) |
| Discovery | T1087 | .002 Domain Account | Confirmed | Partial |
| Discovery | T1018 | Remote System Discovery | Inferred | Tidak |
| Lateral Movement | T1021 | .006 WinRM | Confirmed | Ya |
| Credential Access | T1003 | OS Credential Dumping | Attempted/Gagal | Partial |

---

*Alert yang "Ya (missed)" artinya Wazuh generate alertnya tapi investigator tidak pivot saat triage. Detail di 05-detection-gaps.md.*
