# INC-002 - SSH Brute Force

**Status:** Completed  
**Periode:** Apr 1, 2026  
**Severity:** High

## Overview

Investigasi dimulai dari alert Wazuh rule 40112 level 12 yang mendeteksi cluster SSH authentication failures diikuti successful login dari satu IP ke SIEM server. Setelah di-trace, ditemukan attacker lakukan SSH brute force, berhasil compromise akun `itstaff` dengan password lemah, lalu melakukan reconnaissance di dalam SIEM server selama ~10 menit.

Yang menarik, targetnya adalah SIEM server itu sendiri. Attacker coba akses `/var/ossec/` tapi gagal karena itstaff tidak punya permission ke directory Wazuh. Post-compromise activity tidak ter-capture sama sekali - tidak ada command execution logging untuk standard user.

## Entry Point

SSH brute force (port 22) ke SIEM server (192.168.30.50). Credential `itstaff:itstaff123` berhasil didapat dari 130 attempts dalam ~1.5 menit menggunakan Hydra.

## Outcome

| Aktivitas | Terdeteksi? |
|-----------|-------------|
| Reconnaissance (nmap ping sweep + port scan) | ❌ Tidak terdeteksi |
| SSH brute force | ✅ Ya (alert 5763, 40112 - trigger triage) |
| Login berhasil sebagai itstaff | ✅ Ya (alert 40112 level 12, 5501) |
| Discovery di SIEM server | ❌ Tidak terdeteksi |
| Akses /var/ossec/ | ❌ Tidak terdeteksi (gagal di level OS) |

## Folder Structure
```
INC-002-ssh-bruteforce/
├── case-file/          # Investigator notes
├── evidence/           # Screenshot investigator POV (Wazuh alerts)
└── attacker-logs/      # Screenshot attacker POV (referensi lab)
```

## Case Files

| File | Isi |
|------|-----|
| [01-alert-triage](./case-file/01-alert-triage.md) | Alert pertama, analisis pattern brute force, initial assessment |
| [02-investigation](./case-file/02-investigation.md) | Pivot dari alert, rekonstruksi sesi itstaff, dead ends |
| [03-timeline](./case-file/03-timeline.md) | Kronologi berdasarkan timestamp Wazuh |
| [04-mitre-mapping](./case-file/04-mitre-mapping.md) | MITRE ATT&CK mapping dengan konteks lab |
| [05-detection-gaps](./case-file/05-detection-gaps.md) | Gap coverage dan rekomendasi perbaikan |
