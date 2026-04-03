# INC-004 - C2 Beaconing via HTTP

**Status:** Completed
**Periode:** Apr 2, 2026
**Severity:** High

## Overview

Investigasi dimulai dari alert rule 100030 (Explorer spawned command shell) di WKS01 yang menunjukkan explorer.exe melakukan spawn cmd.exe atas nama user LAB\userBeta. Alert ini menarik perhatian karena level 12 dan mapped ke T1204.002 (Malicious File). Saat di-pivot ke alert lain di timeframe yang sama, ditemukan puluhan alert rule 92052 (Windows command prompt started by an abnormal process) dengan parent process yang sama: `svchost-update.exe` dari folder Downloads userBeta.

Temuan paling signifikan dari case ini bukan hanya C2 beaconing itu sendiri, tapi fakta bahwa Sysmon Event ID 3 (Network Connection) tidak ter-forward ke Wazuh sama sekali. Data network connection hanya bisa ditemukan dengan pivot langsung ke host WKS01. Artinya, tanpa host-level access, investigator hanya bisa melihat command execution pattern tapi tidak bisa mengidentifikasi destination C2 server dari SIEM.

## Entry Point

Alert rule 100030 level 12 (Explorer spawned command shell) pada Apr 2, 2026 @ 23:31:01, menunjukkan explorer.exe spawn cmd.exe di WKS01 atas nama LAB\userBeta.

## Outcome

| Aktivitas | Terdeteksi |
|-----------|------------|
| Explorer spawn command shell | ✅ Rule 100030 (level 12) |
| cmd.exe spawn dari svchost-update.exe | ✅ Rule 92052 (level 4) |
| Beaconing pattern (interval 30 detik) | ⚠️ Visible dari timestamp rule 92052, tapi tidak ada rule khusus beaconing |
| Network connection ke C2 (192.168.30.200:8080) | ❌ Sysmon EID 3 tidak ter-forward ke Wazuh |
| Executable dari user Downloads folder | ⚠️ Tidak ada alert spesifik untuk exe dari Downloads |
| Data encoding (base64 dalam HTTP body) | ❌ Tidak ada HTTP content inspection |

## Folder Structure

```
INC-004-c2-beaconing/
├── README.md
├── case-file/
│   ├── 01-alert-triage.md
│   ├── 02-investigation.md
│   ├── 03-timeline.md
│   ├── 04-mitre-mapping.md
│   ├── 05-detection-gaps.md
│   └── 06-alert-tuning.md
├── evidence/
└── attacker-logs/
```

## Case Files

| File | Deskripsi |
|------|-----------|
| [01-alert-triage.md](case-file/01-alert-triage.md) | Triage awal dari Wazuh alerts |
| [02-investigation.md](case-file/02-investigation.md) | Deep dive investigasi, pivot ke host |
| [03-timeline.md](case-file/03-timeline.md) | Timeline kronologis event |
| [04-mitre-mapping.md](case-file/04-mitre-mapping.md) | Mapping ke MITRE ATT&CK framework |
| [05-detection-gaps.md](case-file/05-detection-gaps.md) | Gap analysis dan rekomendasi |
| [06-alert-tuning.md](case-file/06-alert-tuning.md) | Custom Wazuh rules untuk C2 beaconing |
