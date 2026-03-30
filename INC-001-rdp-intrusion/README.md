# INC-001 - RDP Intrusion

**Status:** In Progress  
**Periode:** 2026-03-30  
**Severity:** High

---

## Overview

Investigasi ini dimulai dari alert Wazuh yang mendeteksi anomali logon activity di WKS01. Setelah di-trace, ditemukan attacker masuk via RDP brute force, melakukan lateral movement ke DC01, dan berhasil establish persistence.

Yang menarik - persistence-nya tidak terdeteksi saat investigasi berlangsung. Scheduled task yang dipasang attacker lolos dari radar. Ini yang jadi cliffhanger ke INC-002.

## Entry Point

RDP (port 3389) exposed di WKS01, brute force berhasil dengan credentials domain user.

## Attacker Objective

Establish persistence, stay undetected, credential harvesting.

## Outcome

- Lateral movement terdeteksi
- Persistence **tidak terdeteksi**
- Credentials userAlpha dan userBeta compromised
- Scheduled task aktif di WKS01 - diwarisi ke INC-002

## Case Files

| File | Isi |
|------|-----|
| [01-alert-triage](./case-file/01-alert-triage.md) | Alert pertama, initial assessment |
| [02-investigation](./case-file/02-investigation.md) | Pivot, evidence, rekonstruksi |
| [03-timeline](./case-file/03-timeline.md) | Kronologi final |
| [04-mitre-mapping](./case-file/04-mitre-mapping.md) | MITRE ATT&CK mapping |
| [05-detection-gaps](./case-file/05-detection-gaps.md) | Yang missed dan kenapa |
