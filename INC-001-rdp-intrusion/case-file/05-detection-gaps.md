# 05 - Detection Gaps

**Case:** INC-001-rdp-intrusion  
**Investigator:** Hardhika Helmi  
**Catatan:** Ini bukan blame document. Ini honest assessment tentang apa yang missed, kenapa, dan apa yang perlu diperbaiki.

---

## Konteks

Ada perbedaan penting antara dua jenis gap:

1. **Alert ada, investigator missed** - Wazuh generate alertnya, tapi saat triage tidak di-pivot
2. **Alert tidak ada** - aktivitas terjadi tapi tidak ada rule yang catch, atau log-nya tidak masuk Wazuh sama sekali

Keduanya adalah gap, tapi remediation-nya berbeda. Yang pertama masalah proses investigasi, yang kedua masalah coverage.

---

## Gap 1: Persistence via Registry Run Key (Alert Ada, Missed)

**Apa yang terjadi:**
Attacker pasang persistence di HKCU\...\Run (WKS01) jam 07:46:51. Wazuh generate tiga alert terkait ini:

- Rule 92041 level 10 - Value added to registry key has Base64-like pattern
- Rule 92302 level 6 - Registry entry to be executed on next logon was modified
- Rule 92307 level 3 - Service creation in registry

**Kenapa missed:**
Alert level 10 (Base64-like pattern di registry) seharusnya menarik perhatian. Tapi saat itu saya sedang fokus pada cluster credential spray dan logon success - secara mental sudah lock-in ke narrative initial access dan lateral movement. Alert yang tidak langsung fit ke narrative itu saya lewati.

Ini adalah confirmation bias dalam investigasi. Saya sudah punya hipotesis dan saya cari evidence yang support hipotesis itu, bukan pivot ke semua alert yang ada.

**Apa yang harusnya dilakukan:**
Setiap registry modification alert - khususnya yang menyentuh Run keys - harusnya masuk ke checklist triage standard, independent dari narrative yang sedang dibangun. Persistence mechanism sering dipasang paralel atau bahkan sebelum lateral movement.

**Remediation:**
- Buat custom rule dengan level lebih tinggi (level 12+) khusus untuk Run key modification, bukan generic "service creation in registry"
- Filter rule lebih spesifik ke path: `HKCU\...\CurrentVersion\Run` dan `HKLM\...\CurrentVersion\Run`
- Pertimbangkan correlation rule: logon anomaly + registry Run key modification dari user yang sama dalam window 30 menit → auto-escalate level

---

## Gap 2: Reconnaissance Tidak Terdeteksi Sama Sekali

**Apa yang terjadi:**
Attacker lakukan ping sweep dan port scan ke seluruh /24 sebelum mulai serangan. Tidak ada satu pun alert di Wazuh untuk aktivitas ini.

**Kenapa tidak terdeteksi:**
Coverage gap yang fundamental. Wazuh di setup ini collect dari Windows event logs - Security, Sysmon, PowerShell. Network-level activity seperti ICMP sweep dan SYN scan tidak masuk ke Windows event log sama sekali.

Tidak ada:
- Network-based IDS (Suricata, Snort, Zeek)
- NetFlow/packet capture
- Firewall log yang di-ingest ke Wazuh

**Dampak:**
Attacker bisa lakukan reconnaissance sepenuhnya tanpa jejak. Timeline investigasi dimulai dari spray (07:17) - padahal attacker sudah aktif di jaringan sebelum itu.

**Remediation:**
- Deploy Suricata di network segment sebagai NIDS, integrasikan ke Wazuh
- Minimal: aktifkan Windows Firewall logging di WKS01 dan DC01, ingest ke Wazuh
- Zeek untuk network traffic analysis jika resources memungkinkan
- Prioritas pertama: Suricata - paling straightforward di-integrate ke Wazuh yang sudah ada

---

## Gap 3: Level 15 Alert Tidak Di-pivot

**Apa yang terjadi:**
Rule 92213 level 15 - *Executable file dropped in folder commonly used by malware* - muncul di dua host (DC01 jam 07:36:25 dan WKS01 jam 07:28:35) selama campaign.

**Kenapa missed:**
Ini yang paling saya sesali dari investigation ini. Alert level 15 adalah level tertinggi di Wazuh. Harusnya immediate pivot. Tapi saat itu saya sedang deep dive ke lateral movement narrative, dan alert ini tidak langsung connect ke apa yang sedang saya cari.

Ini lagi-lagi confirmation bias - sudah punya narrative, alert yang tidak fit di-defer.

Catatan: setelah di-investigate belakangan, alert level 15 di DC01 ternyata adalah artifact dari WinRM session (PSScriptPolicyTest file), bukan malware beneran. Tapi tetap - investigator tidak boleh tahu itu tanpa di-pivot dulu. Harusnya investigated, bukan di-skip.

**Apa yang seharusnya:**
Alert level 15 = hard stop. Pivot ke sana sebelum lanjut apapun. Tidak ada exception.

**Remediation:**
- SOP triage: level 12+ = mandatory immediate pivot, tidak boleh deferred
- Kalau sedang di tengah investigation lain, dokumentasikan dulu lalu pivot
- Pertimbangkan alerting channel terpisah untuk level 12+ (email, notification)

---

## Gap 4: Lateral Movement Preparation Tidak Terlihat

**Apa yang terjadi:**
Sebelum WinRM ke DC01, kemungkinan ada aktivitas di WKS01 - DNS lookup, ping, atau enumeration terhadap DC01. Tidak ada alert yang catch ini.

**Kenapa tidak terdeteksi:**
Network-level activity tidak termonitor. DNS lookup dari domain-joined host adalah sangat normal dan tidak akan generate alert bahkan kalau di-log.

**Remediation:**
Ini gap yang lebih sulit di-address. Opsi realistis:
- Log DNS queries (DNS debug logging di DC01, ingest ke Wazuh)
- NetFlow untuk lihat connection WKS01 → DC01 sebelum WinRM handshake
- Prioritas lebih rendah dari Gap 2 - Suricata sudah akan catch sebagian besar ini

---

## Gap 5: Domain Recon Command Ter-suppress

**Apa yang terjadi:**
net.exe dijalankan di DC01 untuk domain enumeration. Saya tahu ini dari Sysmon process creation, tapi tidak ada alert Wazuh yang spesifik flag "domain enumeration dari WinRM session".

**Kenapa:**
Rule 100020 di local_rules.xml suppress Sysmon process creation (67027) secara broad untuk reduce noise. Efek sampingnya: net.exe yang dijalankan dari WinRM session - yang suspicious - juga ikut ter-suppress.

**Ini trade-off yang perlu di-revisit:**
Rule 100020 efektif untuk reduce noise, tapi terlalu broad. Suppress process creation dari WinRM parent harusnya dikecualikan.

**Remediation:**
- Tambahkan exception di rule 100020: jangan suppress Sysmon process creation kalau parent process-nya wsmprovhost.exe (WinRM)
- Atau buat custom rule positif: alert kalau net.exe dengan parameter domain enumeration dijalankan dari WinRM session context
- Fine-tuning ini butuh waktu tapi impact-nya significant untuk lateral movement detection

---

## Summary

| # | Gap | Tipe | Severity | Prioritas Remediation |
|---|-----|------|----------|----------------------|
| 1 | Persistence registry Run key missed | Alert ada, investigator missed | High | Tinggi |
| 2 | Reconnaissance tidak terdeteksi | Tidak ada coverage | High | Tinggi |
| 3 | Level 15 alert tidak di-pivot | Alert ada, investigator missed | Critical | Segera |
| 4 | Lateral movement preparation invisible | Tidak ada coverage | Medium | Menengah |
| 5 | Domain recon command ter-suppress | Rule logic issue | Medium | Menengah |

---

## Rekomendasi Prioritas

**Jangka pendek (bisa dilakukan sekarang):**
1. Update SOP triage: alert level 12+ = mandatory immediate pivot, no exceptions
2. Tulis custom rule untuk Run key modification dengan level lebih tinggi
3. Review rule 100020 - tambahkan exception untuk wsmprovhost.exe parent context

**Jangka menengah:**
4. Deploy Suricata untuk network-level visibility, integrate ke Wazuh
5. Enable Windows Firewall logging di WKS01 dan DC01, ingest ke Wazuh

**Jangka panjang:**
6. DNS query logging di DC01
7. Alerting channel terpisah untuk level 12+ (email/notification)

---

*Ini bukan daftar exhaustive dari semua yang bisa diperbaiki. Ini yang paling impactful berdasarkan apa yang terjadi di case ini.*
