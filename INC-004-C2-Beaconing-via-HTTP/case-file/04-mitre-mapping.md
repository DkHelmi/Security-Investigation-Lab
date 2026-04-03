# 04 - MITRE ATT&CK Mapping

## Techniques yang Teridentifikasi

### T1204.002 - User Execution: Malicious File

**Evidence:** Rule 100030 (level 12) menunjukkan explorer.exe spawn cmd.exe pada 23:31:01. Parent process explorer.exe mengindikasikan user menjalankan file secara manual (double-click). File yang dijalankan adalah `svchost-update.exe` dari folder Downloads userBeta.

**Confidence:** Tinggi. Process tree explorer.exe > executable dari user folder adalah pattern klasik user execution.

**Wazuh Detection:** ✅ Rule 100030 (custom dari INC-003 tuning)

### T1059.003 - Command and Scripting Interpreter: Windows Command Shell

**Evidence:** Rule 92052 menunjukkan svchost-update.exe (PID 6020) secara berulang spawn cmd.exe dengan commandLine `"cmd.exe" /c [command]`. Tercatat 33 kali trigger (rule.firedtimes: 33).

**Confidence:** Tinggi. cmd.exe di-spawn secara programmatic oleh parent process yang bukan interactive user.

**Wazuh Detection:** ✅ Rule 92052 (level 4, Sysmon EID 1 detection)

### T1071.001 - Application Layer Protocol: Web Protocols

**Evidence:** Sysmon Event ID 3 di host menunjukkan outbound TCP connection dari svchost-update.exe ke 192.168.30.200 port 8080. Port 8080 adalah HTTP alternate port. Koneksi baru dibuat setiap 30 detik (source port sequential: 50059, 50060, 50061...).

**Confidence:** Tinggi. Outbound HTTP connection ke non-standard server dengan pattern reguler.

**Wazuh Detection:** ❌ Sysmon EID 3 tidak ter-forward ke Wazuh. Hanya ditemukan via host-level query.

### T1029 - Scheduled Transfer

**Evidence:** Interval koneksi yang presisi (30 detik) menunjukkan automated scheduled transfer, bukan human-initiated. Pattern ini terlihat dari timestamp alert rule 92052 di Wazuh dan dikonfirmasi oleh Sysmon EID 3 timestamps di host.

**Confidence:** Tinggi. Presisi interval 30 detik mengindikasikan timer-based atau sleep-based scheduling dalam kode malware.

**Wazuh Detection:** ⚠️ Tidak ada rule spesifik untuk mendeteksi interval reguler. Pattern hanya terlihat kalau investigator manually review timestamps.

### T1036.005 - Masquerading: Match Legitimate Name or Location

**Evidence:** File bernama `svchost-update.exe` yang berlokasi di folder Downloads. Nama ini dibuat menyerupai `svchost.exe` (Windows Service Host) yang legitimate dan berada di `C:\Windows\System32\`. Penambahan suffix "-update" membuat nama terlihat seperti update legitimate untuk service host.

**Confidence:** Medium. Naming convention suspicious tapi tidak bisa dibuktikan intent tanpa analisis binary lebih lanjut.

**Wazuh Detection:** ❌ Tidak ada rule yang mendeteksi process name masquerading.

### T1082 - System Information Discovery

**Evidence:** Dari alert rule 92052, svchost-update.exe spawn cmd.exe untuk menjalankan commands. Meskipun payload command tidak seluruhnya terlihat dari Wazuh alerts, pattern spawn cmd.exe yang berulang mengindikasikan automated command execution. Pada environment C2, initial commands biasanya berupa system discovery (whoami, ipconfig, systeminfo, dir).

**Confidence:** Medium. Tidak bisa konfirmasi command spesifik dari Wazuh data saja, tapi pattern-nya konsisten dengan discovery phase.

**Wazuh Detection:** ⚠️ cmd.exe execution terdeteksi via rule 92052, tapi command arguments tidak selalu terlihat lengkap.

## Mapping Summary

| Tactic | Technique | ID | Detected |
|--------|-----------|----|----------|
| Execution | User Execution: Malicious File | T1204.002 | ✅ Rule 100030 |
| Execution | Windows Command Shell | T1059.003 | ✅ Rule 92052 |
| Command and Control | Web Protocols | T1071.001 | ❌ EID 3 tidak di Wazuh |
| Command and Control | Scheduled Transfer | T1029 | ⚠️ Manual review only |
| Defense Evasion | Masquerading | T1036.005 | ❌ |
| Discovery | System Information Discovery | T1082 | ⚠️ Partial |

## Catatan

Dari 6 techniques yang ter-identify, hanya 2 yang terdeteksi secara langsung oleh Wazuh rules (T1204.002 dan T1059.003). Keduanya merupakan detection dari tuning INC-003 (rule 100030) dan built-in Sysmon detection (rule 92052). Technique yang paling kritikal untuk C2 detection (T1071.001 dan T1029) justru tidak terdeteksi oleh SIEM.
