# Attacker Logs — INC-003

> Catatan lab teknis. Ini bukan bagian dari investigasi, murni referensi untuk reproduksi lab.

## Attack Summary

| Item | Detail |
|---|---|
| Attacker | kalidhika @ Kali (192.168.30.200) |
| Target | userBeta @ WKS01 (192.168.30.101) |
| Listener | nc -lvnp 4444 |
| HTTP server | python3 -m http.server 8080 di /tmp/ |
| Delivery | LNK file menyamar sebagai PDF (IT-Policy-Q2-2026.pdf.lnk) |
| Payload | PolicyUpdate.exe, compiled C# reverse shell (Mono) |
| Persistence | Scheduled Task: MicrosoftEdgeUpdateTaskMachineUA |

## Kill Chain Executed

1. **Payload creation** C# reverse shell compiled dengan Mono (`mcs`), output `PolicyUpdate.exe`
2. **Dropper script** `install.cmd` yang download + execute `PolicyUpdate.exe`
3. **LNK creation** dibuat di WKS01 via COM object (`WScript.Shell`), target `cmd.exe /c curl...`, icon PDF dari Edge
4. **Delivery** LNK di Desktop userBeta (simulasi phishing delivery)
5. **Execution** userBeta double-click LNK -> cmd -> curl download install.cmd -> curl download PolicyUpdate.exe -> reverse shell
6. **Persistence** `Register-ScheduledTask` dari dalam reverse shell session

## Tools Used

| Tool | Purpose |
|---|---|
| Mono (mcs) | Cross-compile C# ke .exe Windows |
| python3 http.server | Serve payload via HTTP |
| nc (netcat) | Listener untuk reverse shell |
| curl.exe (Windows built-in) | Download payload di victim |
| WScript.Shell COM | Buat LNK file di Windows |

## Bypass Techniques

- **AMSI bypass:** Tidak menggunakan PowerShell script-based payload, compiled C# binary tidak di-scan AMSI
- **Defender bypass:** cmd.exe + curl chain tidak mengandung signature malicious di LNK. PolicyUpdate.exe compiled dari source jadi tidak ada known signature
- **Filename masquerading:** PolicyUpdate.exe, MicrosoftEdgeUpdateTaskMachineUA
- **Icon masquerading:** LNK menggunakan icon PDF dari msedge.exe index 11

## Anomali untuk Investigator

- Execution chain berulang 3x dalam 1 menit, karena ada multiple test + scheduled task trigger
- `install.cmd` dan `PolicyUpdate.exe` di TEMP folder, bisa ditemukan kalau investigator cek disk
- Scheduled Task `MicrosoftEdgeUpdateTaskMachineUA` namanya mirip tapi bukan task legitimate Microsoft Edge

## Screenshots Index

| File | Isi |
|---|---|
| inc003-01-payload-encoded.png | Terminal Kali, Base64 payload creation |
| inc003-02-lnk-created.png | Terminal Kali, LNK created via pylnk3 |
| inc003-03-http-server.png | Terminal Kali, HTTP server + GET 200 log |
| inc003-04-lnk-on-desktop.png | WKS01 Desktop, LNK file visible as PDF |
| inc003-05-reverse-shell-connect.png | Terminal Kali, nc listener connection masuk |
| inc003-06-discovery.png | Reverse shell, whoami, hostname, ipconfig |
| inc003-07-scheduled-task.png | Reverse shell, Register-ScheduledTask output |
