# 04 - MITRE ATT&CK Mapping

## Catatan Pendekatan

Detail evidence (alert ID, timestamp, command line) sudah ada di 02-investigation.md dan 03-timeline.md, jadi di sini tidak diulang. Yang ditulis hanya tabel ringkas dan catatan untuk teknik yang butuh konteks atau yang tidak terdeteksi.

## Summary

| Tactic | Technique | ID | Terdeteksi? |
|--------|-----------|----|-------------|
| Initial Access | User Execution: Malicious File | T1204.002 | ❌ tidak ada alert untuk initial click |
| Execution | Windows Command Shell | T1059.003 | ✅ Rule 92005, 92032 |
| Command and Control | Ingress Tool Transfer | T1105 | ✅ Rule 92074, 92213 |
| Command and Control | Application Layer Protocol: Web | T1071.001 | ⚠️ terlihat sebagai file drop, bukan C2 |
| Defense Evasion | Masquerading | T1036.005 | ❌ |
| Persistence | Scheduled Task | T1053.005 | ❌ tidak ada Event ID 4698 |

## Catatan per Teknik

Hanya teknik yang butuh konteks tambahan; sisanya cukup jelas dari tabel.

- **T1204.002 (User Execution):** trigger awal tidak terdeteksi. Dihipotesiskan file `.lnk` yang menyamar sebagai dokumen PDF, diklik userBeta. Parent dari `cmd.exe` tidak muncul sebagai `explorer.exe` di alert manapun, jadi initial click hanya bisa disimpulkan dari konteks.
- **T1105 / T1071.001:** dua tahap download via `curl` (`install.cmd` lalu `PolicyUpdate.exe`) dari `192.168.30.200:8080`. Port 8080 di sini berfungsi sebagai HTTP server untuk hosting payload, terdeteksi sebagai file drop, bukan sebagai channel C2. Channel C2 sesungguhnya (reverse shell) tidak terlihat di Wazuh.
- **T1036.005 (Masquerading):** `PolicyUpdate.exe` sengaja dinamai mirip update software legitimate, agar lolos saat dilihat sekilas di Task Manager.
- **T1053.005 (Scheduled Task):** tidak ada Event ID 4698. Keberadaan persistence hanya disimpulkan dari pola eksekusi yang berulang (circumstantial), bukan dari alert langsung.

---

*Detection gaps dibahas di 05-detection-gaps.md. Rekomendasi custom rule ada di 06-alert-tuning.md.*
