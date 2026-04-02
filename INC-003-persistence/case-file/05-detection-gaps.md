# 05 - Detection Gaps

## Gap Summary

| # | Gap | Severity | Impact |
|---|---|---|---|
| 1 | Initial execution (LNK click) tidak terdeteksi | Critical | Investigator tidak bisa menentukan trigger awal tanpa forensic di host |
| 2 | Event ID 4698 (Scheduled Task creation) tidak di-surface | Critical | Persistence mechanism invisible di Wazuh |
| 3 | Outbound reverse shell connection tidak terdeteksi | High | C2 channel aktif tanpa alert |
| 4 | PolicyUpdate.exe process creation tidak ada alert spesifik | Medium | Payload execution terlewat |
| 5 | Filename masquerading tidak ada detection | Low | Nama file dibuat menyerupai software legitimate |

## Detail per Gap

### Gap 1 — Initial Execution Invisible

**Apa yang terjadi:** userBeta mengklik file (kemungkinan .lnk) di Desktop yang memicu `cmd.exe` secara hidden. `explorer.exe` spawn `cmd.exe` — tapi tidak ada satupun alert di Wazuh yang mencatat ini.

**Kenapa ini terjadi:** Wazuh rule 92052 (Windows command prompt started by abnormal process) hanya trigger untuk parent process tertentu yang dianggap "abnormal." `explorer.exe` → `cmd.exe` ternyata tidak masuk kategori ini, padahal ini salah satu vector paling umum untuk malicious LNK execution.

**Impact:** Investigator tidak punya visibility ke trigger awal. Tanpa informasi ini, sulit menentukan apakah ini phishing, drive-by download, atau insider threat. Investigator harus pivot ke host forensics (cek Desktop userBeta, cek Recent Files, cek browser history) untuk mengisi gap ini — dan itu butuh waktu.

**Rekomendasi:** Buat custom rule yang alert ketika `explorer.exe` spawn `cmd.exe` atau `powershell.exe` dengan argument mencurigakan (misalnya flag `/c`, `-WindowStyle Hidden`, atau URL di argument).

### Gap 2 — Scheduled Task Creation Not Surfaced

**Apa yang terjadi:** Attacker membuat Scheduled Task untuk persistence (terlihat dari pattern execution berulang). Tapi Event ID 4698 (A scheduled task was created) tidak muncul sebagai alert di Wazuh.

**Kenapa ini terjadi:** Kemungkinan dua hal: (1) Windows Security log untuk Event ID 4698 tidak di-forward ke Wazuh karena tidak ada di `agent.conf` log collection, atau (2) event-nya masuk tapi tidak ada rule yang memproses dan menaikkannya ke level alert yang visible.

**Impact:** Persistence mechanism sepenuhnya invisible. Investigator hanya bisa menyimpulkan keberadaannya dari circumstantial evidence (execution berulang). Tidak ada informasi tentang nama task, trigger condition, atau action yang dikonfigurasi.

**Rekomendasi:** Tambahkan rule untuk Event ID 4698 dan 4699 (task deleted) dengan level minimal 10. Pastikan juga Sysmon dikonfigurasi untuk capture Event ID 1 dari `schtasks.exe` dan PowerShell `Register-ScheduledTask` cmdlet.

### Gap 3 — Outbound Connection Not Detected

**Apa yang terjadi:** `PolicyUpdate.exe` kemungkinan besar establish connection ke IP attacker (reverse shell atau C2). Tapi tidak ada alert untuk outbound network connection.

**Kenapa ini terjadi:** Sysmon Event ID 3 (Network Connection) kemungkinan tidak di-configure atau tidak di-forward ke Wazuh. Tanpa ini, semua outbound connection dari proses yang compromised tidak terlihat.

**Impact:** Investigator tidak bisa menentukan apakah attacker sudah punya active session. Tidak ada informasi tentang destination IP/port untuk C2, durasi connection, atau volume data yang ditransfer.

**Rekomendasi:** Enable Sysmon Event ID 3 dengan filter yang targeted — setidaknya capture connection dari proses non-standard ke port yang tidak biasa (4444, 8080, dll) atau ke IP external/non-corporate.

### Gap 4 — Payload Execution Not Specifically Alerted

**Apa yang terjadi:** `PolicyUpdate.exe` di-execute setelah didownload, tapi tidak ada alert yang spesifik mengatakan "unknown executable dijalankan dari folder TEMP."

**Kenapa ini terjadi:** Wazuh mendeteksi file **drop** (92213) tapi bukan file **execution**. Ada alert untuk `cmd.exe` dan `curl.exe` (known Windows binaries), tapi tidak untuk binary yang baru saja di-drop.

**Impact:** Investigator tahu file didownload, tapi tidak punya konfirmasi bahwa file itu benar-benar dijalankan. Harus diasumsikan berdasarkan behavior chain.

**Rekomendasi:** Buat rule untuk Sysmon Event ID 1 yang alert ketika process image berasal dari folder TEMP, Downloads, atau folder user-writable lainnya — terutama kalau file baru saja dibuat (korelasi dengan Event ID 11).

### Gap 5 — No Filename Masquerading Detection

**Apa yang terjadi:** `PolicyUpdate.exe` adalah nama yang sengaja dibuat mirip software update. Tidak ada detection untuk ini.

**Kenapa ini terjadi:** Filename masquerading detection butuh baseline — daftar nama proses legitimate vs yang seharusnya tidak ada. Ini lebih cocok di EDR daripada SIEM.

**Impact:** Rendah secara isolated, tapi berkontribusi ke kemampuan attacker untuk blend in.

**Rekomendasi:** Ini lebih ke EDR territory. Di Wazuh, bisa dipertimbangkan rule yang alert untuk executable dengan nama mirip Windows/Microsoft process yang berjalan dari lokasi non-standard.

## Overall Assessment

Dari 5 fase attack yang terjadi (initial access → execution → tool transfer → persistence → C2), Wazuh hanya effectively mendeteksi **execution dan tool transfer**. Initial access, persistence, dan C2 sepenuhnya invisible.

Ini berarti kalau investigator hanya mengandalkan Wazuh, dia tahu "ada sesuatu yang mencurigakan terjadi" tapi tidak bisa menentukan bagaimana attacker masuk dan apakah attacker masih punya akses. Ini gap yang serius untuk incident response — responder tidak punya full picture tanpa forensic langsung di host.
