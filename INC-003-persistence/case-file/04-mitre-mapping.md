# 04 - MITRE ATT&CK Mapping

## Techniques Identified

| Tactic | Technique ID | Technique Name | Evidence | Terdeteksi? |
|---|---|---|---|---|
| Initial Access | T1204.002 | User Execution: Malicious File | userBeta mengeksekusi file yang memicu cmd.exe — kemungkinan .lnk yang menyamar sebagai dokumen | ❌ Tidak ada alert untuk initial click |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | `cmd.exe /c` menjalankan curl download chain | ✅ Rule 92005, 92032 |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | `install.cmd` batch script dieksekusi setelah download | ✅ Rule 92005 |
| Command and Control | T1105 | Ingress Tool Transfer | `curl.exe` download `install.cmd` dan `PolicyUpdate.exe` dari `192.168.30.200:8080` | ✅ Rule 92074, 92213 |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | `PolicyUpdate.exe` — nama yang menyerupai software update legitimate | ❌ Tidak ada rule untuk filename masquerading |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | Execution chain yang berulang 3 kali mengindikasikan scheduled task, tapi tidak ada alert Event ID 4698 | ❌ Tidak ada alert |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | HTTP (port 8080) digunakan untuk C2 communication dan payload delivery | ⚠️ Terdeteksi sebagai file drop, tapi bukan sebagai C2 |

## Technique Detail

### T1204.002 — User Execution: Malicious File

userBeta menjalankan sesuatu yang memicu `cmd.exe` secara hidden. Dari evidence yang ada, parent process `cmd.exe` tidak menunjukkan `explorer.exe` di alert manapun — tapi fakta bahwa execution terjadi di user context `LAB\userBeta` dengan integrity level Medium menunjukkan ini bukan proses system.

Hipotesis: file `.lnk` (shortcut) yang menyamar sebagai dokumen PDF di Desktop userBeta. LNK file bisa menjalankan arbitrary command saat diklik tanpa memunculkan window.

### T1059.003 — Windows Command Shell

`cmd.exe` dijalankan dengan flag `/c` — artinya execute command lalu exit. Command-nya adalah chain: download file via curl → execute file yang didownload. Ini pola yang umum di malware delivery.

### T1105 — Ingress Tool Transfer

Two-stage download menggunakan `curl.exe` (built-in Windows 10):
1. Download `install.cmd` → dropper script
2. Download `PolicyUpdate.exe` → payload utama

Keduanya dari `http://192.168.30.200:8080`. Attacker menggunakan built-in tool (curl) supaya tidak perlu drop tools tambahan — teknik living-off-the-land.

### T1036.005 — Masquerading

`PolicyUpdate.exe` — nama yang sengaja dibuat mirip dengan proses update software legitimate. Kalau ada analyst yang lihat proses ini di Task Manager, kemungkinan besar dilewati karena terlihat seperti update biasa.

### T1053.005 — Scheduled Task

Tidak ada direct evidence berupa Event ID 4698 di Wazuh. Tapi circumstantial evidence kuat: execution chain yang identik muncul 3 kali dalam 1 menit dengan interval reguler (~26-31 detik). Ini tidak mungkin dilakukan manual — pasti ada trigger otomatis.

Kemungkinan task name menyerupai nama task legitimate (misalnya Microsoft Edge Update) supaya tidak mencurigakan saat dilihat di Task Scheduler.

## Kill Chain Summary

```
[?] User klik file    →    cmd.exe /c    →    curl download install.cmd    →    execute i.cmd
         ❌                   ✅ 92005            ✅ 92074/92213                     |
                                                                                    v
                                                                          curl download PolicyUpdate.exe
                                                                                ✅ 92074/92213
                                                                                    |
                                                                                    v
                                                                          PolicyUpdate.exe execute
                                                                                ❌ no alert
                                                                                    |
                                                                                    v
                                                                          Persistence (Scheduled Task?)
                                                                                ❌ no alert
                                                                                    |
                                                                                    v
                                                                          Re-execution (3x in 1 min)
                                                                                ✅ same pattern
```
