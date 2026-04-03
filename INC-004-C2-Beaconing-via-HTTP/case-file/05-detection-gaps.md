# 05 - Detection Gaps

## Gap 1: Sysmon Event ID 3 Tidak Ter-forward ke Wazuh

**Severity: Critical**

Ini gap paling besar yang ditemukan di case ini. Sysmon Event ID 3 (Network Connection) tercatat dengan baik di host WKS01, menunjukkan outbound TCP connection dari svchost-update.exe ke 192.168.30.200:8080. Tapi data ini sama sekali tidak ada di Wazuh SIEM.

Implikasi: investigator yang hanya punya akses ke Wazuh dashboard tidak akan pernah melihat network behavior dari malware. Dia bisa lihat process creation (cmd.exe spawn), tapi tidak bisa menghubungkan process tersebut dengan network activity. Tanpa pivot ke host, C2 destination IP dan port tidak bisa diidentifikasi.

**Kemungkinan penyebab:**
- Sysmon configuration di WKS01 mungkin filter out Event ID 3 (atau tidak include secara eksplisit)
- Wazuh agent configuration mungkin tidak forward Sysmon Event ID 3
- Volume Event ID 3 bisa sangat tinggi, mungkin sengaja di-filter untuk performa

**Rekomendasi:** Review Sysmon config (`sysmonconfig-export.xml`) di WKS01 dan pastikan Event ID 3 ter-capture. Review juga Wazuh agent.conf untuk memastikan semua Sysmon events di-forward. Kalau volume menjadi concern, terapkan filter di Sysmon level (bukan Wazuh level) untuk hanya capture outbound connections ke non-private atau non-standard ports.

## Gap 2: Tidak Ada Detection untuk Beaconing Pattern

**Severity: High**

Wazuh rules yang ada saat ini tidak punya kemampuan mendeteksi beaconing pattern. Interval 30 detik dari svchost-update.exe hanya bisa diidentifikasi kalau investigator secara manual review timestamps dari alert list. Tidak ada rule yang aggregate connection count atau mendeteksi interval reguler.

**Implikasi:** Beaconing dengan interval lebih panjang (misalnya 5 menit atau 1 jam) kemungkinan tidak akan dinotice sama sekali, karena alert individual (rule 92052 level 4) akan tenggelam di antara noise.

**Rekomendasi:** Buat custom rule yang trigger kalau ada proses yang sama melakukan repeated action (process creation atau network connection) lebih dari N kali dalam window tertentu. Ini tidak sempurna (bisa false positive dari legitimate software), tapi minimal memberikan visibility.

## Gap 3: Executable dari Downloads Folder Tidak Di-flag

**Severity: Medium**

Rule 100032 dari INC-003 mendeteksi executable yang launched dari TEMP atau AppData folder. Tapi svchost-update.exe dijalankan dari `C:\Users\userBeta\Downloads\`, yang tidak termasuk dalam rule tersebut. Downloads folder adalah lokasi umum untuk file yang di-download user, dan seharusnya masuk dalam monitoring.

**Rekomendasi:** Extend rule 100032 atau buat rule baru yang juga cover executable yang dilaunched dari Downloads folder. Pattern `C:\Users\*\Downloads\*.exe` worth dipantau.

## Gap 4: Process Name Masquerading Tidak Terdeteksi

**Severity: Medium**

File bernama `svchost-update.exe` di lokasi non-standard (Downloads) tidak generate alert apapun terkait nama yang menyerupai system process. Attacker sering menggunakan nama yang mirip dengan Windows legitimate process (svchost, csrss, lsass, explorer) untuk menghindari deteksi visual.

**Rekomendasi:** Buat rule yang mendeteksi process execution dimana nama file mengandung keyword Windows system process (svchost, csrss, lsass, winlogon, services) tapi lokasi-nya bukan di `C:\Windows\System32\` atau `C:\Windows\SysWOW64\`. Ini bisa catch masquerading attempts.

## Gap 5: HTTP Content Tidak Ter-inspect

**Severity: Low (untuk scope Wazuh)**

Wazuh dan Sysmon tidak capture HTTP request/response body atau headers. Beacon ini menggunakan base64 encoded data di HTTP POST body dan custom headers (X-Session-ID). Data ini tidak terlihat di SIEM maupun di Sysmon logs.

**Rekomendasi:** Ini sebenarnya di luar scope Sysmon/Wazuh. Untuk HTTP content inspection, diperlukan network-level monitoring seperti Suricata, Zeek, atau proxy logs. Ini enhancement untuk masa depan, bukan quick fix.

## Gap 6: Tidak Ada Correlation Antara Process Creation dan Network Activity

**Severity: High**

Meskipun Wazuh punya data process creation (rule 92052) dan seharusnya punya data network connection (kalau Gap 1 di-fix), saat ini tidak ada rule yang correlate keduanya. Idealnya, ada rule yang flag: "process X yang baru dibuat dari user folder juga melakukan outbound connection ke IP non-standard."

**Rekomendasi:** Setelah Sysmon EID 3 di-forward ke Wazuh, buat correlation rule yang menghubungkan EID 1 (Process Creation) dari lokasi suspicious dengan EID 3 (Network Connection) dari process yang sama (match berdasarkan ProcessGuid).

## Prioritas Perbaikan

| Prioritas | Gap | Action |
|-----------|-----|--------|
| 1 | Sysmon EID 3 forwarding | Fix config, pastikan network events sampai di Wazuh |
| 2 | Beaconing pattern detection | Custom rule untuk repeated connections |
| 3 | Downloads folder monitoring | Extend rule 100032 |
| 4 | Process masquerading | New rule untuk nama suspicious di lokasi non-standard |
| 5 | Process-network correlation | Correlation rule setelah EID 3 fix |
| 6 | HTTP content inspection | Network-level monitoring (scope besar) |
