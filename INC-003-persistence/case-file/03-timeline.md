# 03 - Timeline

Semua timestamp dalam WIB (UTC+7), diambil dari Wazuh dashboard.

## Pre-Attack

| Waktu | Event |
|---|---|
| 16:35:16.xxx | Sysmon Event ID 13 — beberapa registry modification tercatat (Rule 92307). Konteks belum jelas, tapi ini muncul tepat sebelum cluster alert pertama |

## Initial Execution — Cluster 1

| Waktu | Source | Event |
|---|---|---|
| 16:35:28.188 | Sysmon EID 1 / Rule 92005 | `cmd.exe /c` dijalankan — trigger curl download `install.cmd` dari `192.168.30.200:8080` ke `%TEMP%\i.cmd`, lalu execute |
| 16:35:29.190 | Sysmon EID 11 / Rule 92213 | File `i.cmd` ditulis ke `C:\Users\userBeta\AppData\Local\Temp\` oleh `curl.exe` |
| 16:35:29.229 | Sysmon EID 1 / Rule 92074 | `curl.exe` download `PolicyUpdate.exe` dari `192.168.30.200:8080` ke `%TEMP%\PolicyUpdate.exe` |
| 16:35:29.258 | Sysmon EID 11 / Rule 92213 | File `PolicyUpdate.exe` ditulis ke `%TEMP%` |
| 16:35:29.394 | Sysmon EID 1 / Rule 92032 | Suspicious cmd shell execution terdeteksi |
| 16:35:31.586 | Sysmon EID 11 / Rule 92213 | Executable lain di-drop ke folder malware |
| 16:35:36.658 | Rule 61109 | DNS resolution untuk `129.113.98.118.in-addr.arpa` timeout — kemungkinan reverse DNS lookup dari koneksi yang baru terbentuk |

## Re-execution — Cluster 2

| Waktu | Source | Event |
|---|---|---|
| 16:35:54.441 | Sysmon EID 1 / Rule 92005 | `cmd.exe /c` — pattern yang sama dengan Cluster 1 |
| 16:35:55.271 | Sysmon EID 11 / Rule 92213 | File drop ke TEMP |
| 16:35:55.288 | Sysmon EID 1 / Rule 92074 | curl download binary |
| 16:35:55.289 | Sysmon EID 11 / Rule 92213 | File drop |
| 16:35:55.310 | Sysmon EID 1 / Rule 92032 | Suspicious cmd execution |

Pattern identik dengan Cluster 1 — **selisih ~26 detik**. Kemungkinan re-execution manual oleh attacker atau trigger otomatis.

## Re-execution — Cluster 3

| Waktu | Source | Event |
|---|---|---|
| 16:36:26.674 | Sysmon EID 1 / Rule 92005 | `cmd.exe /c` — pattern sama |
| 16:36:26.710 | Sysmon EID 11 / Rule 92213 | File drop |
| 16:36:26.729 | Sysmon EID 1 / Rule 92074 | curl download binary |
| 16:36:26.745 | Sysmon EID 11 / Rule 92213 | File drop |
| 16:36:26.761 | Sysmon EID 1 / Rule 92032 | Suspicious cmd execution |
| 16:36:26.807 | Sysmon EID 11 / Rule 92213 | File drop tambahan |

**Selisih ~31 detik** dari Cluster 2. Pattern yang berulang ini kuat mengindikasikan persistence mechanism — kemungkinan Scheduled Task yang men-trigger execution chain yang sama.

## Post-Execution

| Waktu | Source | Event |
|---|---|---|
| 16:39:25.886 | Sysmon EID 1 / Rule 92052 | Windows command prompt started by abnormal process — tapi setelah dicek, ini `dsregcmd.exe` (noise) |
| 16:40:32.921 | Rule 61102 | Windows System error event |
| 16:43:48.112 | Sysmon EID 11 / Rule 92217 | Executable dropped in Windows root folder — level 6, perlu verifikasi apakah terkait attacker atau proses lain |
| 16:47:38.796 | Rule 67028 | Special privileges assigned to new logon — Event ID 4672 |
| 16:47:40.184 | Sysmon EID 11 / Rule 92213 | Executable file dropped in malware folder — masih berlanjut ~12 menit setelah initial execution |

## Event yang TIDAK Tercatat

| Event yang Diharapkan | Status |
|---|---|
| explorer.exe spawn cmd.exe (LNK click) | ❌ Tidak ada alert |
| Event ID 4698 — Scheduled Task creation | ❌ Tidak ada alert |
| Outbound connection ke IP attacker (reverse shell) | ❌ Tidak ada alert |
| PolicyUpdate.exe process creation | ❌ Tidak ada alert spesifik |

## Ringkasan Timeline

Execution chain utama terjadi dalam waktu **kurang dari 2 detik** (16:35:28 → 16:35:29) — dari trigger `cmd.exe` hingga `PolicyUpdate.exe` ter-drop di disk. Kecepatan ini menunjukkan semua sudah di-script dan otomatis.

Pattern yang sama berulang 3 kali dalam 1 menit, mengindikasikan persistence mechanism sudah aktif. Namun mekanisme persistence itu sendiri tidak terdeteksi oleh Wazuh.
