# INC-001 - RDP Intrusion

**Status:** Completed  
**Periode:** Mar 31, 2026  
**Severity:** High

---

## Overview

Investigasi dimulai dari alert Wazuh yang mendeteksi cluster logon failures dari satu IP ke WKS01. Setelah di-trace, ditemukan attacker lakukan password spray via SMB, berhasil compromise userAlpha, masuk via RDP, lateral movement ke DC01 via WinRM, dan pasang persistence via registry Run key.

Yang menarik, persistence-nya ada alertnya di Wazuh (level 10), tapi missed saat triage karena tenggelam di noise waktu investigator sedang fokus ke trail lateral movement. Ini yang jadi salah satu detection gap utama di case ini.

## Entry Point

Password spray via SMB (port 445) ke WKS01. Credentials `userAlpha:P@ssw0rd123!` dan `userBeta:P@ssw0rd123!` berhasil didapat.

## Outcome

| Aktivitas | Terdeteksi? |
|-----------|-------------|
| Password spray via SMB | ✅ Ya (alert 60204, trigger triage) |
| Initial access via RDP | ✅ Ya (alert 92657, 92653) |
| Lateral movement ke DC01 via WinRM | ✅ Ya (alert 92652, 92213) |
| Persistence via registry Run key | ⚠️ Alert ada, missed saat triage |
| Credential dump attempt | ⚠️ Attempt gagal (userAlpha bukan admin), partial alert dari artifact |

