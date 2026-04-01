# INC-002 - SSH Brute Force

**Status:** Completed  
**Periode:** Apr 1, 2026  
**Severity:** High

## Overview

Investigasi dimulai dari alert Wazuh rule 40112 level 12 yang mendeteksi cluster SSH authentication failures diikuti successful login dari satu IP ke SIEM server. Setelah di-trace via auth.log dan system logs, ditemukan ada brute force SSH ke port 22, berhasil compromise akun `itstaff`, dengan sesi aktif ~10 menit.

Yang paling mengkhawatirkan: aktivitas selama sesi 10 menit itu tidak ter-capture oleh log apapun - Wazuh, journalctl, maupun wtmp tidak punya record tentang apa yang dilakukan. Ini blind spot total di server yang paling kritis di lab.

## Entry Point

SSH brute force (port 22) ke SIEM server (192.168.30.50). Credential itstaff berhasil ditemukan setelah cluster failures yang terdeteksi Wazuh mulai 11:15 WIB, dengan login berhasil tercatat di 11:17:34 WIB.

## Outcome

| Aktivitas | Terdeteksi? |
|-----------|-------------|
| Reconnaissance (network scan) | ❌ Tidak terdeteksi |
| Aktivitas awal sebelum 11:15 WIB | ❌ Tidak terdeteksi (ada di btmp) |
| SSH brute force | ✅ Ya (alert 5760, 5763, 40112 - trigger triage) |
| Login berhasil sebagai itstaff | ✅ Ya (alert 40112 level 12, 5501) |
| Aktivitas selama sesi ~10 menit | ❌ Blind spot total - tidak ada log |

## Folder Structure
```
INC-002-ssh-bruteforce/
├── case-file/          # Investigator notes
├── evidence/           # Screenshot investigator POV (Wazuh, auth.log, system logs)
└── attacker-logs/      # Screenshot attacker POV (referensi lab)
```

## Case Files

| File | Isi |
|------|-----|
| [01-alert-triage](./case-file/01-alert-triage.md) | Alert pertama, analisis pattern brute force, initial assessment |
| [02-investigation](./case-file/02-investigation.md) | Pivot ke auth.log dan system logs, dua successful login, dead end aktivitas sesi |
| [03-timeline](./case-file/03-timeline.md) | Kronologi berdasarkan Wazuh + host logs, catatan timezone UTC vs WIB |
| [04-mitre-mapping](./case-file/04-mitre-mapping.md) | MITRE ATT&CK mapping - discovery tidak bisa di-confirm |
| [05-detection-gaps](./case-file/05-detection-gaps.md) | Blind spot post-compromise, tidak ada fail2ban, rekomendasi |
