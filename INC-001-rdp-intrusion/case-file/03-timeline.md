# 03 - Timeline

**Case:** INC-001-rdp-intrusion  
**Investigator:** Hardhika Helmi  
**Disusun dari:** Wazuh alerts, Sysmon logs, Windows Event Log

---

## Catatan

Timeline ini direkonstruksi murni dari evidence yang terekam di SIEM dan log - bukan dari POV attacker. Semua timestamp adalah timestamp absolut dari Wazuh alerts. Event yang tidak punya alert Wazuh (recon phase) dicatat sebagai "tidak terdeteksi" dengan timestamp estimasi berdasarkan konteks.

Fase reconnaissance tidak punya timestamp Wazuh karena memang tidak terdeteksi - ini sendiri adalah finding yang dicatat di 05-detection-gaps.md.

---

## Kronologi Event

### Fase 0 - Kondisi Lab Sebelum Insiden

**State awal (sebelum 07:17):**
- WKS01 online, domain-joined, SMB port 445 aktif
- WinRM aktif di DC01, userAlpha sudah di Remote Management Users
- Wazuh agent berjalan di WKS01 dan DC01, Sysmon deployed di kedua host
- PowerShell logging aktif

Semua monitoring sudah ada sebelum insiden. Tidak ada perubahan konfigurasi di tengah campaign.

---

### Fase 1 - Reconnaissance (Tidak Terdeteksi)

**Estimasi sebelum 07:17 - Network Discovery**
- Tidak ada alert Wazuh untuk aktivitas ini
- Dari konteks: attacker perlu tahu host mana yang aktif dan port apa yang buka sebelum mulai spray
- Port 5985 (WinRM) DC01 yang digunakan untuk lateral movement kemungkinan ditemukan dari fase ini
- Detail: lihat 05-detection-gaps.md

---

### Fase 2 - Initial Access

**07:17:37 - Logon Failures Mulai Masuk**
- Alert: Rule 60122 - Logon Failure - Unknown user or bad password
- Source: 192.168.30.200 → Target: WKS01 (192.168.30.101) port 445
- Multiple akun dicoba: admin1, userAlpha, userBeta (terlihat dari variasi targetUserName di cluster alert)

**07:17:38 - Multiple Logon Failures Triggered**
- Alert: Rule 60204 level 10 - Multiple Windows Logon Failures ← **ini trigger triage**
- rule.firedtimes: 954 - total failures yang terakumulasi
- Pattern: banyak akun berbeda dari satu IP → password spray, bukan brute force

![Logon Failure Detail Top](../evidence/wazuh-03-logon-failure-detail1.png)
*Cluster logon failure - source 192.168.30.200, NTLM, target WKS01*

![Logon Failure Detail Bottom](../evidence/wazuh-03-logon-failure-detail2.png)
*firedtimes 954, MITRE T1110 Credential Access*

**07:25:13 - Credential Spray Berhasil**
- Alert: Rule 92657 level 6 - Successful Remote Logon
- Source: 192.168.30.200 (workstationName: kalidhika) → Target: WKS01
- Account: LAB\userAlpha, method: NTLM
- Spray berhasil - plaintext credential didapat

![Successful Logon Detail Top](../evidence/wazuh-04-successful-logon-detail1.png)
*Alert 92657 - userAlpha, kalidhika, NTLM, 07:25:13*

![Successful Logon Detail Bottom](../evidence/wazuh-04-successful-logon-detail2.png)
*MITRE T1078.002 Domain Accounts, Initial Access*

**07:25:xx - RDP Session Aktif di WKS01**
- Alert: Rule 92653 - User LAB\userAlpha logged via RDP from 192.168.30.200
- Alert: Rule 67028 - Special privileges assigned to new logon (normal behavior untuk tipe logon ini)
- Sesi interaktif userAlpha di WKS01 dimulai

---

### Fase 3 - Persistence (di WKS01)

**07:46:51 - Registry Run Key Dipasang**
- Alert: Rule 92041 level 10 - Value added to registry key has Base64-like pattern ← **missed saat triage**
- Alert: Rule 92302 level 6 - Registry entry to be executed on next logon was modified ← **missed saat triage**
- Host: WKS01, User: LAB\userAlpha
- Path: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- Value: WindowsUpdateHelper = `powershell.exe -WindowStyle Hidden -Command 'Start-Sleep 1'`
- Tidak butuh admin privilege (HKCU, per-user)

![Registry Run Key Alert](../evidence/wazuh-06-registry-runkey-detail1.png)
*Alert 92302 - targetObject HKCU\...\Run\WindowsUpdateHelper, user LAB\userAlpha, 07:46:51*

![Registry Base64 Alert](../evidence/wazuh-05-registry-base64-detail1.png)
*Alert 92041 - commandLine reg.exe add HKCU\...\Run\WindowsUpdateHelper, parentImage powershell.exe*

Konfirmasi langsung di WKS01 saat investigasi:

![Regedit Run Key Detail](../evidence/wks01-regedit-runkey-detail.png)
*Regedit WKS01 (login sebagai userAlpha) - WindowsUpdateHelper masih aktif*

---

### Fase 4 - Lateral Movement ke DC01

**07:36:25 - Executable Dropped di DC01** *(timestamp lebih awal dari logon alert - artifact WinRM)*
- Alert: Rule 92213 level 15 - Executable file dropped in folder commonly used by malware ← **missed saat triage**
- Host: DC01, User: LAB\userAlpha
- File: `__PSScriptPolicyTest_psm345gv.ic2.ps1` di AppData\Local\Temp
- Image: wsmprovhost.exe (WinRM host process) - ini artifact normal evil-winrm saat establish connection
- Level 15 ini yang harusnya jadi immediate pivot

![Executable Dropped DC01](../evidence/wazuh-07-executable-dropped-dc01-detail1.png)
*Alert 92213 level 15 - DC01, wsmprovhost.exe, PSScriptPolicyTest, user LAB\userAlpha*

**07:49:52 - Successful Remote Logon ke WKS01 (side effect WinRM session)**
- Alert: Rule 92652 level 6 - Successful Remote Logon
- Source: 192.168.30.200 → WKS01, NTLM
- Ini terekam di WKS01 sebagai side effect dari WinRM session yang diinisiasi dari sana

![WinRM Logon Alert](../evidence/wazuh-08-winrm-dc01-logon-detail1.png)
*Alert 92652 - NTLM dari 192.168.30.200, 07:49:52*

---

### Fase 5 - Domain Reconnaissance di DC01

**Sekitar 07:36-07:49 - Domain Enumeration**
- Host: DC01, User context: LAB\userAlpha
- Terekam dari Sysmon Event ID 1 (process creation) - net.exe dieksekusi dengan parent wsmprovhost.exe
- Commands yang terekam di Sysmon:
  - `net group "Domain Admins" /domain` → hanya Administrator yang jadi member
  - `net user /domain` → user list: Administrator, Guest, krbtgt, userAlpha, userBeta
- Hasil: userAlpha bukan Domain Admin, tidak ada path eskalasi yang tersedia

---

### Fase 6 - Credential Access Attempt (Gagal)

**Sekitar 07:36-07:49 - Credential Dump Attempt**
- Tidak ada alert successful credential access
- Tidak ada alert LSASS access atau Ntds.dit copy
- Hipotesis: secretsdump atau tool sejenis dicoba tapi gagal karena userAlpha bukan local admin di DC01
- Artifact dari attempt ini kemungkinan adalah PSScriptPolicyTest file yang triggered alert 92213

**Attacker stuck.** Dengan privilege level userAlpha, tidak ada path untuk escalate ke Domain Admin.

---

### End State

**Kondisi setelah insiden:**
- WKS01: persistence aktif via HKCU Run key (WindowsUpdateHelper)
- Credentials userAlpha dan userBeta: compromised
- DC01: tidak ada persistent access, tidak ada credential yang berhasil di-dump
- Domain Administrator: tidak terdampak

---

## Summary

```
07:17  [ACCESS]   Password spray via SMB → 954 logon failures (ALERT - trigger triage)
07:25  [ACCESS]   Spray berhasil → userAlpha compromised (ALERT)
07:25  [ACCESS]   RDP session aktif di WKS01 sebagai userAlpha (ALERT)
07:36  [LATERAL]  Executable dropped di DC01 via WinRM (ALERT level 15 - missed)
07:46  [PERSIST]  Registry Run key WindowsUpdateHelper dipasang di WKS01 (ALERT - missed)
07:49  [LATERAL]  WinRM session aktif ke DC01, domain recon dijalankan (ALERT)
~      [CRED]     Credential dump attempt di DC01 → gagal, userAlpha bukan admin
~      [END]      Attacker stuck, tidak ada eskalasi lebih lanjut
```

---

*Untuk mapping ke MITRE ATT&CK, lihat 04-mitre-mapping.md.*
