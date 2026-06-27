# 04 - MITRE ATT&CK Mapping

## Catatan Pendekatan

Detail evidence (alert ID, timestamp, source port) sudah ada di 02-investigation.md dan 03-timeline.md, jadi di sini tidak diulang. Yang ditulis hanya tabel ringkas dan catatan untuk teknik yang butuh konteks atau yang tidak terdeteksi.

## Summary

| Tactic | Technique | ID | Terdeteksi? |
|--------|-----------|----|-------------|
| Execution | User Execution: Malicious File | T1204.002 | ✅ Rule 100030 |
| Execution | Windows Command Shell | T1059.003 | ✅ Rule 92052 |
| Command and Control | Application Layer Protocol: Web | T1071.001 | ❌ EID 3 tidak ter-forward ke Wazuh |
| Command and Control | Scheduled Transfer | T1029 | ⚠️ hanya terlihat dari review timestamp manual |
| Defense Evasion | Masquerading | T1036.005 | ❌ |
| Discovery | System Information Discovery | T1082 | ⚠️ Partial |

## Catatan per Teknik

Hanya teknik yang butuh konteks tambahan; sisanya cukup jelas dari tabel.

- **T1204.002 (User Execution):** terdeteksi oleh rule **100030**, custom rule yang dibuat dari tuning INC-003. Ini bukti remediasi case sebelumnya berfungsi: `explorer.exe` spawn `cmd.exe` saat user double-click `svchost-update.exe`.
- **T1071.001 (Web Protocols):** beacon HTTP ke `192.168.30.200:8080` setiap 30 detik. Tidak terlihat di Wazuh karena Sysmon Event ID 3 tidak ter-forward, hanya ditemukan lewat query langsung di host. Ini gap utama case ini.
- **T1029 (Scheduled Transfer):** interval 30 detik yang presisi mengindikasikan beaconing terjadwal di dalam kode malware. Tidak ada rule yang mendeteksi pola interval, hanya terlihat kalau investigator me-review timestamp secara manual.
- **T1036.005 (Masquerading):** `svchost-update.exe` di folder Downloads, nama menyerupai Windows service host yang sah di System32.
- **T1082 (System Information Discovery):** `svchost-update.exe` spawn `cmd.exe` berulang untuk menjalankan command, tapi argumen command tidak selalu terlihat lengkap di alert, jadi discovery hanya bisa ditandai partial.

---

*Detection gaps dibahas di 05-detection-gaps.md. Rekomendasi custom rule ada di 06-alert-tuning.md.*
