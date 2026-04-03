# Attacker Logs - INC-004 C2 Beaconing via HTTP

## Skenario

Attacker sudah punya foothold di WKS01. Malware (svchost-update.exe) diletakkan di folder Downloads userBeta, menyerupai file update yang di-download dari browser. User double-click file tersebut, beacon mulai jalan di background tanpa console window.

## Tools Used

| Tool | Fungsi |
|------|--------|
| Flask (Python) | C2 server, listen di port 8080 |
| csc.exe (.NET C# Compiler) | Compile beacon source ke exe |
| curl (Windows built-in) | Transfer file dari Kali ke WKS01 |
| Python http.server | Host file untuk transfer |

## C2 Server

- **Lokasi script:** Kali, `~/c2-sim/c2_server.py`
- **Listener:** 0.0.0.0:8080
- **Endpoint:** POST /api/update
- **Behavior:** Terima beacon check-in (base64 encoded JSON), kirim command balik (base64 encoded JSON)
- **Commands yang dikirim:** whoami, ipconfig, dir C:\Users (hardcoded queue)

## Beacon Agent

- **Source:** `~/c2-sim/beacon.cs`
- **Compiled:** `svchost-update.exe` (6 KB, compiled via csc.exe /target:winexe di WKS01)
- **Lokasi di target:** `C:\Users\userBeta\Downloads\svchost-update.exe`
- **Interval:** 30 detik
- **Protocol:** HTTP POST ke http://192.168.30.200:8080/api/update
- **Payload format:** Base64 encoded JSON (hostname, username, timestamp, task_id, command output)
- **Custom headers:** User-Agent (Chrome-like), X-Session-ID (base64 encoded hostname|username), Content-Type: application/octet-stream
- **Command execution:** Decode response, parse cmd field, execute via cmd.exe /c, kirim output di beacon berikutnya
- **Stealth:** Compiled dengan /target:winexe sehingga tidak muncul console window saat dijalankan

## Timestamps

| Waktu (Wazuh UTC+7) | Event |
|----------------------|-------|
| ~23:19 | Run pertama beacon (instance sebelumnya, muncul console window) |
| ~23:23 | Process di-kill via taskkill |
| 23:31:01 | Run kedua, double-click dari File Explorer (compiled ulang dengan /target:winexe, no window) |
| 23:31:55 | First callback diterima C2 server |
| 23:42:20 | Last callback sebelum terminate |
| ~23:42 | Process di-kill via taskkill, C2 server Ctrl+C |

## Anomali yang Akan Ditemukan Investigator

1. Rule 100030 trigger karena explorer.exe spawn cmd.exe (saat double-click)
2. Rule 92052 trigger berulang kali, semua parent-nya svchost-update.exe dari Downloads
3. Interval 30 detik yang presisi terlihat dari timestamps alert
4. Sysmon EID 3 (Network Connection) ada di host tapi tidak ter-forward ke Wazuh, jadi investigator perlu pivot ke host untuk lihat destination IP
5. Nama file svchost-update.exe mirip dengan svchost.exe legitimate tapi lokasi di Downloads
6. Ada dua window aktivitas (23:19-23:23 dan 23:31-23:42) karena beacon sempat di-kill lalu dijalankan ulang

## Screenshots Index

| File | Deskripsi |
|------|-----------|
| att-01-beacon-in-downloads.png | File svchost-update.exe di folder Downloads WKS01 |
| att-02-first-callback.png | C2 server menerima callback pertama |
| att-03-beacon-interval.png | C2 server log menunjukkan interval 30 detik |
| att-04-beacon-stopped.png | C2 server setelah beacon di-terminate |
