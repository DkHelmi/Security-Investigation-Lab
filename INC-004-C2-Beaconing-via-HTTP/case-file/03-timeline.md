# 03 - Timeline

Semua timestamp menggunakan waktu Wazuh dashboard (UTC+7) kecuali disebutkan lain. UTC time dari Sysmon dicatat terpisah dimana tersedia.

## Window Pertama: 23:19 - 23:23

| Wazuh Timestamp | Event | Detail |
|-----------------|-------|--------|
| 23:19:18.931 | Rule 92052 | cmd.exe spawn dari svchost-update.exe |
| 23:19:49.062 | Rule 92052 | cmd.exe spawn dari svchost-update.exe |
| 23:20:19.162 | Rule 92052 | cmd.exe spawn dari svchost-update.exe |
| 23:20:49.280 | Rule 92052 | cmd.exe spawn dari svchost-update.exe |
| 23:21:19.435 | Rule 92052 | cmd.exe spawn dari svchost-update.exe |
| 23:21:49.543 | Rule 92052 | cmd.exe spawn dari svchost-update.exe |
| 23:22:19.678 | Rule 92052 | cmd.exe spawn dari svchost-update.exe |
| 23:22:49.786 | Rule 92052 | cmd.exe spawn dari svchost-update.exe |
| 23:23:19.896 | Rule 92052 | cmd.exe spawn dari svchost-update.exe |

Interval konsisten ~30 detik. Window pertama ini menunjukkan sekitar 9 beacon cycles. Tidak ada alert rule 100030 di awal window ini, kemungkinan svchost-update.exe sudah running dari sebelumnya (bisa jadi dari instance sebelum timeframe observasi).

**Gap: 23:23 - 23:31** (sekitar 8 menit tanpa aktivitas)

Process kemungkinan di-terminate selama gap ini. Tidak ada alert di period ini yang terkait svchost-update.exe.

## Window Kedua: 23:31 - 23:42

| Wazuh Timestamp | Event | Detail |
|-----------------|-------|--------|
| 23:31:01.072 | **Rule 100030 (level 12)** | Explorer spawned command shell. explorer.exe > cmd.exe. Ini menunjukkan user atau attacker menjalankan ulang executable dari Explorer. |
| 23:31:56.162 | Rule 92052 | cmd.exe spawn dari svchost-update.exe |
| 23:32:26.394 | Rule 92052 | cmd.exe spawn dari svchost-update.exe (detail: commandLine "cmd.exe" /c) |
| 23:32:56.514 | Rule 92052 | cmd.exe spawn dari svchost-update.exe |
| 23:33:26.663 | Rule 92052 | cmd.exe spawn dari svchost-update.exe |
| 23:33:56.717 | Rule 92052 | cmd.exe spawn dari svchost-update.exe |
| 23:34:26.899 | Rule 92052 | cmd.exe spawn dari svchost-update.exe |
| 23:34:57.008 | Rule 92052 | cmd.exe spawn dari svchost-update.exe |
| 23:35:27.120 | Rule 92052 | cmd.exe spawn dari svchost-update.exe |
| 23:35:57.280 | Rule 92052 | cmd.exe spawn dari svchost-update.exe |
| 23:36:27.404 | Rule 92052 | cmd.exe spawn dari svchost-update.exe |
| 23:36:57.514 | Rule 92052 | cmd.exe spawn dari svchost-update.exe |
| 23:42:22.047 | Rule 92052 | cmd.exe spawn dari svchost-update.exe (terakhir) |
| 23:57:21.855 | Rule 92052 | cmd.exe spawn, parent: System32\svchost.exe (ini svchost legitimate, bukan terkait beacon) |

Window kedua dimulai dengan rule 100030 (explorer spawn), menunjukkan executable dijalankan ulang via double-click. Setelah itu beacon resume dengan interval 30 detik.

Ada gap lagi antara 23:36:57 dan 23:42:22 (sekitar 5 menit). Kemungkinan network issue atau process sedang idle.

## Network Connection Timeline (dari Sysmon Event ID 3 di Host)

Data ini hanya tersedia dari query langsung di WKS01, tidak ada di Wazuh.

| UTC Time | Source Port | Destination | Catatan |
|----------|-------------|-------------|---------|
| 16:35:24.778 | 50059 | 192.168.30.200:8080 | TCP outbound |
| 16:35:54.924 | 50060 | 192.168.30.200:8080 | +30 detik |
| 16:36:25.065 | 50061 | 192.168.30.200:8080 | +30 detik |
| 16:36:55.170 | 50062 | 192.168.30.200:8080 | +30 detik |
| 16:42:19.433 | 50063 | 192.168.30.200:8080 | +5 menit (gap) |

Source port naik sequential, mengkonfirmasi setiap beacon adalah koneksi TCP baru. Semua initiated dari WKS01 ke 192.168.30.200.

## Ringkasan Timeline

```
23:19:18  ─── Window 1 mulai (beacon sudah running)
              │ 9 beacon cycles, interval 30 detik
23:23:19  ─── Window 1 berakhir
              │
              │ GAP ~8 menit (process terminated)
              │
23:31:01  ─── Rule 100030: Explorer spawn cmd (re-execution)
23:31:56  ─── Window 2 mulai
              │ 11+ beacon cycles, interval 30 detik
23:36:57  ─── Gap ~5 menit
23:42:22  ─── Beacon terakhir terdeteksi
```

Total durasi observasi: sekitar 23 menit, dengan ~20 beacon cycles yang tercatat di Wazuh.
