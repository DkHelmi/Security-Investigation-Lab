# INC-003 - Persistence via Scheduled Task

**Status:** ✅ Completed
**Periode:** 2 April 2026
**Severity:** High

## Overview

Alert cluster dari WKS01 menunjukkan `cmd.exe` menjalankan `curl` untuk download file dari IP internal yang tidak dikenal (192.168.30.200:8080). Dua file didownload secara berurutan, batch script `install.cmd` sebagai dropper, dan `PolicyUpdate.exe` sebagai payload utama. Semua terjadi di context domain user `LAB\userBeta` dalam waktu kurang dari 2 detik.

Yang menarik dari case ini bukan apa yang terdeteksi, tapi apa yang **tidak** terdeteksi. Trigger awal (kemungkinan malicious .lnk file), persistence mechanism (Scheduled Task), dan outbound C2 connection semuanya invisible di Wazuh. Investigator hanya melihat "tengah-tengah" attack chain, execution dan tool transfer, tanpa tahu bagaimana attacker masuk dan apakah masih punya akses.

## Entry Point

Wazuh alert Rule 92005 (Command shell started script with /c modifier) di 16:35:28 WIB dari WKS01, `cmd.exe` menjalankan curl download chain sebagai `LAB\userBeta`.

## Outcome

| Aktivitas | Terdeteksi? |
|---|---|
| User klik malicious .lnk file | ❌ |
| cmd.exe /c execution chain | ✅ Rule 92005 |
| curl download install.cmd | ✅ Rule 92074, 92213 |
| curl download PolicyUpdate.exe | ✅ Rule 92074, 92213 |
| PolicyUpdate.exe execution | ❌ |
| Outbound reverse shell connection | ❌ |
| Scheduled Task creation (persistence) | ❌ |
| Re-execution via persistence | ✅ Same alert pattern (3x) |

