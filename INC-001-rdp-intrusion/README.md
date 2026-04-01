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
| Credential dump attempt | ✅ Gagal (userAlpha bukan admin) |

## Folder Structure
```
INC-001-rdp-intrusion/
├── case-file/          # Investigator notes
├── evidence/           # Screenshot investigator POV (Wazuh, regedit)
└── attacker-logs/      # Screenshot attacker POV (referensi lab)
```

## Case Files

| File | Isi |
|------|-----|
| [01-alert-triage](./case-file/01-alert-triage.md) | Alert pertama, membedakan spray vs brute force, initial assessment |
| [02-investigation](./case-file/02-investigation.md) | Pivot dari alert, rekonstruksi langkah demi langkah, dead ends |
| [03-timeline](./case-file/03-timeline.md) | Kronologi berdasarkan timestamp Wazuh |
| [04-mitre-mapping](./case-file/04-mitre-mapping.md) | MITRE ATT&CK mapping dengan konteks lab |
| [05-detection-gaps](./case-file/05-detection-gaps.md) | Alert yang missed dan kenapa, rekomendasi perbaikan |