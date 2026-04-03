# 01 - Alert Triage

## Alert Awal

Saat membuka Wazuh Threat Hunting dashboard untuk WKS01, saya langsung notice satu alert yang beda dari yang lain: rule 100030, level 12. Ini rule custom dari tuning INC-003 yang mendeteksi explorer.exe spawn command shell.

**Alert detail:**

| Field | Value |
|-------|-------|
| Timestamp | Apr 2, 2026 @ 23:31:01.072 |
| Rule ID | 100030 |
| Rule Level | 12 |
| Description | Explorer spawned command shell, possible malicious shortcut execution |
| MITRE | T1204.002 (Malicious File) |
| Agent | WKS01 (192.168.30.101) |
| Image | C:\Windows\System32\cmd.exe |
| Parent Image | C:\Windows\explorer.exe |
| Parent Command Line | C:\Windows\Explorer.EXE |
| User | LAB\userBeta |
| Integrity Level | Medium |
| UTC Time | 2026-04-02 16:29:45.158 |

Ini pattern yang familiar: explorer.exe spawn cmd.exe. Di INC-003 ini terjadi karena user double-click malicious file. Kemungkinan situasi serupa di sini.

## Alert Lain di Timeframe yang Sama

Saat saya expand timeframe dan lihat semua alert dari WKS01, ada banyak sekali rule 92052 (level 4). Deskripsinya: "Windows command prompt started by an abnormal process." Ini Sysmon Event ID 1 (Process Creation) yang mendeteksi cmd.exe di-spawn oleh process yang tidak biasa.

Yang menarik perhatian saya: kolom `parentImage` di hampir semua alert 92052 menunjukkan path yang sama.

```
C:\Users\userBeta\Downloads\svchost-update.exe
```

Ini bukan svchost.exe yang legitimate (yang ada di `C:\Windows\System32\`). Ini executable terpisah yang ada di folder Downloads userBeta. Nama file-nya dibuat mirip dengan Windows service host, kemungkinan untuk menghindari deteksi visual.

## Observasi Awal dari Alert List

Beberapa hal yang langsung terlihat dari daftar alert:

**Pattern timestamp yang reguler.** Alert 92052 muncul dengan interval yang sangat konsisten. Saya lihat timestamp-nya: 23:19:18, 23:19:49, 23:20:19, 23:20:49, 23:21:19... Interval sekitar 30 detik. Ini bukan behavior normal dari user atau software biasa. Interval reguler seperti ini biasanya indikasi automated process, bisa jadi scheduled task atau beacon.

**Dua window aktivitas.** Ada gap di antara dua cluster alert. Cluster pertama sekitar 23:19 sampai 23:23, lalu ada jeda, dan cluster kedua mulai 23:31 sampai 23:42. Ini bisa berarti process sempat berhenti lalu jalan lagi, atau ada dua instance terpisah.

**Rule 100030 muncul di antara dua cluster.** Alert level 12 dari explorer spawn cmd muncul di 23:31:01, tepat di awal cluster kedua. Kemungkinan ini saat user (atau attacker) menjalankan ulang executable.

**Total firedtimes rule 92052 tinggi.** Di salah satu alert detail terlihat `rule.firedtimes: 33`. Ini berarti rule 92052 sudah trigger 33 kali, semua dari parent process yang sama.

## Keputusan Triage

Ini worth di-investigate lebih lanjut. Alasan:

1. Executable dengan nama menyerupai system process (svchost-update.exe) ada di folder Downloads user
2. Executable tersebut spawn cmd.exe secara berulang dengan interval reguler 30 detik
3. Pattern ini konsisten dengan C2 beaconing behavior
4. Rule 100030 menunjukkan ini dimulai dari user execution (explorer spawn)

Yang belum bisa saya jawab dari alert saja:
- Kemana svchost-update.exe melakukan koneksi? (tidak ada network connection data di Wazuh)
- Apa command yang dijalankan via cmd.exe?
- Sejak kapan file ini ada di Downloads?

Perlu deep dive ke investigation.
