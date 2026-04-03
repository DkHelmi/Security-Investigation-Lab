# 02 - Investigation

## Dari Mana Mulai

Dari triage, saya punya satu nama file yang jadi fokus: `svchost-update.exe` di `C:\Users\userBeta\Downloads\`. File ini spawn cmd.exe berulang kali dengan interval 30 detik. Sekarang saya perlu jawab: koneksi ke mana, apa yang dilakukan, dan bagaimana file ini bisa ada di sana.

## Analisis Alert Rule 92052

Saya buka detail salah satu alert rule 92052 untuk lihat informasi lebih lengkap.

| Field | Value |
|-------|-------|
| Timestamp | Apr 2, 2026 @ 23:32:26.394 |
| Rule ID | 92052 |
| Description | Windows command prompt started by an abnormal process |
| MITRE | T1059.003 (Windows Command Shell) |
| commandLine | "cmd.exe" /c : |
| parentImage | C:\Users\userBeta\Downloads\svchost-update.exe |
| parentProcessId | 6020 |
| processId | 6012 |
| User | LAB\userBeta |
| currentDirectory | C:\Users\userBeta\Downloads\ |
| UTC Time | 2026-04-02 16:31:29.825 |

Yang menarik: `commandLine` menunjukkan `"cmd.exe" /c :` diikuti command yang dijalankan. Process tree-nya jelas: svchost-update.exe (PID 6020) spawn cmd.exe (PID 6012) untuk execute command. Ini typical pattern dari malware yang menjalankan system commands via cmd.exe untuk reconnaissance atau data collection.

> Evidence: [inv-03-rule92052-cmd-spawn-01.png](../evidence/inv-03-rule92052-cmd-spawn-01.png), [inv-03-rule92052-cmd-spawn-02.png](../evidence/inv-03-rule92052-cmd-spawn-02.png)

## Mencari Network Connection di Wazuh

Saya coba cari Sysmon Event ID 3 (Network Connection) di Wazuh untuk melihat kemana svchost-update.exe melakukan koneksi.

Filter yang saya gunakan:

```
data.win.system.eventID: 3 AND agent.name: WKS01
```

Hasilnya: **kosong**. Tidak ada satu pun Sysmon Event ID 3 yang ter-index di Wazuh untuk WKS01.

Saya juga coba filter berdasarkan destination IP:

```
data.win.eventdata.destinationIp: 192.168.30.200
```

Juga kosong.

Ini berarti Sysmon Event ID 3 tidak ter-forward dari WKS01 ke Wazuh. Entah karena Sysmon config tidak capture Event ID 3, atau Wazuh agent tidak kirim event tersebut. Apapun alasannya, ini gap yang signifikan. Saya perlu pivot langsung ke host untuk dapat informasi network.

> Evidence: [inv-06-wazuh-eid3-search.png](../evidence/inv-06-wazuh-eid3-search.png)

## Pivot ke Host: Sysmon Event ID 3

Saya akses WKS01 dan query Sysmon log langsung untuk Event ID 3 dengan filter destination IP.

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=3] and EventData[Data[@Name='DestinationIp']='192.168.30.200']]" -MaxEvents 5 | Format-List TimeCreated, Message
```

Catatan: query ini memerlukan akses administrator. Standard user (userBeta) tidak bisa membaca Sysmon Operational log.

Hasilnya mengkonfirmasi dugaan saya:

| Field | Value |
|-------|-------|
| Image | C:\Users\userBeta\Downloads\svchost-update.exe |
| User | LAB\userBeta |
| Protocol | TCP |
| Initiated | true (outbound) |
| Source IP | 192.168.30.101 (WKS01) |
| Destination IP | 192.168.30.200 |
| Destination Port | 8080 |

Svchost-update.exe melakukan outbound TCP connection ke 192.168.30.200 port 8080. Setiap koneksi menggunakan source port yang berbeda (50059, 50060, 50061, 50062, 50063...) yang naik berurutan. Ini menunjukkan setiap beacon adalah koneksi baru, bukan persistent connection.

IP 192.168.30.200 bukan server yang dikenal di network 192.168.30.0/24 berdasarkan topology yang saya tahu. Port 8080 biasa dipakai untuk HTTP alternate atau web application, tapi dalam konteks ini lebih likely sebagai C2 listener.

> Evidence: [inv-05-sysmon-eid3-host.png](../evidence/inv-05-sysmon-eid3-host.png)

## Konfirmasi Beaconing Pattern

Dari Sysmon Event ID 3 di host, saya bisa lihat timestamp setiap koneksi:

```
16:35:24.778 UTC (SourcePort: 50059)
16:35:54.924 UTC (SourcePort: 50060)
16:36:25.065 UTC (SourcePort: 50061)
16:36:55.170 UTC (SourcePort: 50062)
16:42:19.433 UTC (SourcePort: 50063)
```

Interval antara koneksi pertama sampai keempat: tepat 30 detik. Ada gap antara 50062 dan 50063 (sekitar 5 menit), kemungkinan karena process sempat idle atau ada network issue sementara.

Pattern 30 detik yang konsisten ini bukan behavior normal. Software legitimate tidak melakukan HTTP connection ke IP yang sama setiap 30 detik dengan presisi seperti ini. Ini sangat kuat menunjukkan automated beaconing, dimana malware "check in" ke C2 server secara periodik untuk menerima instruksi.

## Analisis Process

Dari gabungan data Wazuh dan Sysmon di host:

**Process chain:**
```
explorer.exe (PID 3236)
  └── svchost-update.exe (PID 6020) [C:\Users\userBeta\Downloads\]
        └── cmd.exe /c [command] (multiple instances)
```

Explorer.exe sebagai parent menunjukkan file di-launch oleh user (double-click atau dari shell). svchost-update.exe kemudian secara periodik spawn cmd.exe untuk execute commands, sambil melakukan HTTP POST ke 192.168.30.200:8080 setiap 30 detik.

**Kenapa svchost-update.exe suspicious:**
1. Nama mirip svchost.exe (Windows service host) tapi lokasi di folder Downloads, bukan System32
2. File size kecil (6 KB) untuk executable
3. Spawn cmd.exe berulang kali dengan interval tetap
4. Outbound connection ke IP:port yang tidak dikenal

## Kesimpulan Investigation

Ini adalah C2 (Command and Control) beaconing. Executable `svchost-update.exe` di WKS01 melakukan periodic HTTP callback ke 192.168.30.200:8080 setiap 30 detik. Melalui channel ini, remote commands dijalankan via cmd.exe di host.

Beaconing activity terjadi dalam dua window:
1. Sekitar 23:19 - 23:23 (Wazuh timestamp)
2. Sekitar 23:31 - 23:42 (Wazuh timestamp)

Gap di antara kedua window kemungkinan karena process sempat di-terminate lalu dijalankan ulang (rule 100030 trigger di awal window kedua menunjukkan explorer spawn ulang).

Yang tidak bisa dijawab dari evidence yang ada:
- Bagaimana file svchost-update.exe sampai di Downloads (tidak ada log download)
- Apa saja command yang dikirim via C2 channel (HTTP body tidak ter-capture)
- Apakah ada data yang di-exfiltrate melalui channel ini
