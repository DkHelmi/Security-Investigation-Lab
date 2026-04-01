# 03 - Timeline

**Case:** INC-002-ssh-bruteforce  
**Investigator:** Hardhika Helmi  
**Disusun dari:** Wazuh alerts, auth.log, last, wtmp, btmp

---

## Catatan Timezone

Ada dua sumber timestamp di case ini dengan timezone berbeda:

| Sumber | Timezone | Contoh |
|--------|----------|--------|
| Wazuh alerts | UTC+7 (WIB) | 11:17:34 WIB |
| auth.log, last, wtmp, btmp | UTC+0 | 04:17:34 UTC |

Keduanya merujuk event yang sama - selisih tepat 7 jam. Timeline di bawah menggunakan **WIB sebagai acuan utama** karena itu yang terlihat di Wazuh saat triage, dengan keterangan UTC di kurung untuk cross-reference ke host logs.

Fase reconnaissance tidak punya timestamp karena tidak terdeteksi sama sekali - dibahas di 05-detection-gaps.md.

---

## Kronologi Event

### Aktivitas Awal yang Tidak Terdeteksi Wazuh

**10:35:57 WIB (03:35:57 UTC) - Failed Attempts Pertama**
- Sumber: btmp (`/var/log/btmp`)
- Failed login attempts itstaff dari 192.168.30.200 mulai terekam
- Tidak ada alert Wazuh untuk window ini
- Ini menunjukkan ada aktivitas dari IP yang sama jauh sebelum Wazuh mulai alert

![wtmp btmp](../evidence/evidence-06-wtmp-btmp.png)
*btmp - failed attempts itstaff dari 192.168.30.200 mulai 03:35:57 UTC*

---

### Brute Force Terdeteksi Wazuh

**11:15:28 WIB (04:15:28 UTC) - Cluster Failures Masuk**
- Alert: Rule 5760 - sshd: authentication failed
- Alert: Rule 5710 - sshd: Attempt to login using non-existent user
- Alert: Rule 2502 - syslog: User missed the password more than once (level 10)
- Alert: Rule 5763 - sshd: brute force (level 10)
- Source: 192.168.30.200 → siemserver port 22
- Rule 5710 muncul berulang - ada username yang dicoba tidak exist di sistem

![Wazuh Alert Overview](../evidence/evidence-01-wazuh-alerts-overview.png)
*Cluster alert 5760, 5710, 5763 mulai 11:15 WIB*

---

### Initial Access - Login Pertama

**11:14:30 WIB (04:14:30 UTC) - Accepted Password, Sesi Sangat Singkat**
- Sumber: auth.log
- `Accepted password for itstaff from 192.168.30.200 port 48808 ssh2`
- Session opened lalu langsung closed dalam ~1 detik
- Tidak ter-capture sebagai alert Wazuh yang meaningful
- Tidak muncul di `last` karena sesi terlalu singkat

![auth.log itstaff](../evidence/evidence-03-authlog-itstaff.png)
*auth.log - dua accepted password untuk itstaff dalam window berdekatan*

---

### Initial Access - Login Kedua (Yang Ter-capture Wazuh)

**11:17:34 WIB (04:17:34 UTC) - Login Berhasil, Sesi Aktif**
- Alert: Rule 5501 - PAM: Login session opened
- Alert: Rule 40112 level 12 - Multiple authentication failures followed by a success ← **trigger pivot investigasi**
- Source: 192.168.30.200 → siemserver, port 36484
- Account: itstaff

![Alert 40112 Detail](../evidence/evidence-02-alert-40112-detail.png)
*Rule 40112 - srcip 192.168.30.200, dstuser itstaff, full_log confirm accepted password*

Konfirmasi dari last dan lastlog:

![last lastlog](../evidence/evidence-04-last-lastlog.png)
*last itstaff - pts/1, 192.168.30.200, 04:17 - 04:28 (00:10)*

---

### Aktivitas Selama Sesi - Tidak Diketahui

**11:17:34 - 11:28:11 WIB (04:17:34 - 04:28:11 UTC) - Sesi Aktif ~10 Menit**
- journalctl UID=1001: no entries

![journalctl no entry](../evidence/evidence-05-journalctl-noentry.png)
*journalctl - tidak ada entries untuk UID=1001 selama window sesi*

Tidak ada log yang capture aktivitas selama sesi berlangsung. Apa yang dilakukan selama ~10 menit ini tidak bisa direkonstruksi dari evidence yang tersedia.

---

### Logout

**11:28:11 WIB (04:28:11 UTC) - Sesi Ditutup**
- Alert: Rule 5502 - PAM: Login session closed
- auth.log: `Disconnected from user itstaff 192.168.30.200 port 36484`
- Total durasi sesi: ~10 menit 37 detik

---

## Summary

```
10:35 WIB    [PRE]      Failed attempts itstaff dari 192.168.30.200 (btmp, tidak terdeteksi Wazuh)
11:15:28 WIB [ACCESS]   Cluster SSH failures terdeteksi (ALERT 5760, 5710, 5763)
11:14:30 WIB [ACCESS]   Accepted password - sesi singkat, langsung closed (auth.log)
11:17:34 WIB [ACCESS]   Accepted password - sesi aktif (ALERT 40112 level 12, 5501)
11:17-11:28  [UNKNOWN]  Aktivitas selama sesi tidak ter-capture
11:28:11 WIB [END]      Disconnect + session closed (ALERT 5502, auth.log)
```

---

*Untuk mapping ke MITRE ATT&CK, lihat 04-mitre-mapping.md.*
