# 05 - Detection Gaps

**Case:** INC-001-rdp-intrusion  
**Investigator:** Hardhika Helmi  
**Catatan:** Ini bukan blame document. Ini honest assessment tentang apa yang missed, kenapa, dan apa yang perlu diperbaiki.

---

## Konteks

Ada perbedaan penting antara dua jenis gap:

1. **Alert ada, investigator missed** - Wazuh generate alertnya, tapi saat triage saya tidak pivot ke sana
2. **Alert tidak ada** - aktivitas terjadi tapi tidak ada rule yang catch, atau log-nya tidak masuk Wazuh sama sekali

Keduanya adalah gap, tapi remediation-nya berbeda. Yang pertama masalah proses investigasi, yang kedua masalah coverage.

---

## Gap 1: Persistence via Registry Run Key (Alert Ada, Missed)

**Apa yang terjadi:**
Attacker pasang persistence di HKCU\Software\Microsoft\Windows\CurrentVersion\Run (WKS01) sekitar T+10. Wazuh generate tiga alert terkait ini:

- Rule 92307 level 3 - Service creation in registry
- Rule level 6 - Registry entry to be executed on next logon was modified
- Rule level 10 - Value added to registry key has Base64-like pattern

**Kenapa missed:**
Alert level 10 (Base64-like pattern di registry) seharusnya menarik perhatian. Tapi saat itu saya sedang fokus pada cluster credential spray dan logon success - secara mental saya sudah "lock in" ke narrative initial access dan lateral movement. Alert yang tidak fit ke narrative itu saya lewati.

Level 3 dan 6 juga relatif tenggelam di antara noise alert lain. Kalau bukan ada level 10-nya, mungkin saya tidak akan notice sama sekali.

**Apa yang harusnya dilakukan:**
Setiap registry modification alert - khususnya yang menyentuh Run keys (HKCU dan HKLM) - harusnya masuk ke checklist triage standard, independent dari narrative yang lagi dibangun. Persistence mechanism sering dipasang paralel atau bahkan sebelum lateral movement.

**Remediation:**
- Buat custom rule dengan level lebih tinggi (level 12+) khusus untuk Run key modification, bukan generic "service creation in registry"
- Filter rule lebih spesifik ke path: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` dan `HKLM\...\Run`
- Pertimbangkan correlation rule: jika ada logon anomaly + registry Run key modification dari user yang sama dalam window 30 menit, auto-escalate level

---

## Gap 2: Reconnaissance Tidak Terdeteksi Sama Sekali

**Apa yang terjadi:**
Attacker lakukan ping sweep (nmap -sn) dan port scan lengkap ke seluruh /24 sebelum mulai serangan. Tidak ada satu pun alert di Wazuh untuk aktivitas ini.

**Kenapa tidak terdeteksi:**
Coverage gap yang fundamental. Wazuh di setup ini collect dari Windows event logs - Security, Sysmon, PowerShell. Tapi network-level activity seperti ICMP sweep dan SYN scan tidak masuk ke Windows event log.

Tidak ada:
- Network-based IDS (Suricata, Snort, Zeek)
- NetFlow/packet capture
- Firewall log yang di-ingest ke Wazuh

**Dampak:**
Attacker bisa lakukan reconnaissance sepenuhnya tanpa jejak. Dari perspektif SIEM, timeline investigasi dimulai dari credential spray - padahal attacker sudah di jaringan sejak sebelum itu.

**Remediation:**
- Deploy Suricata di network segment sebagai NIDS, integrasikan ke Wazuh
- Atau minimal: aktifkan Windows Firewall logging di WKS01 dan DC01, ingest ke Wazuh
- Zeek untuk network traffic analysis jika resources memungkinkan
- Prioritas pertama: Suricata karena paling straightforward di-integrate ke Wazuh existing

---

## Gap 3: Level 15 Alert Tidak Di-pivot Lebih Lanjut

**Apa yang terjadi:**
Rule 92217 level 15 - *Executable file dropped in folder commonly used by malware* - muncul di dua host (DC01 dan WKS01) selama campaign berlangsung. Level 15 adalah level tertinggi di Wazuh.

**Kenapa missed:**
Jujurnya, ini yang paling saya sesali dari investigation ini. Alert level 15 harusnya immediate response. Tapi saat itu saya sedang deep dive ke lateral movement narrative, dan secara tidak sadar saya "skip" alert ini karena tidak fit ke apa yang lagi saya cari.

Ini adalah confirmation bias dalam investigasi. Saya sudah punya hipotesis (credential spray → RDP → lateral movement) dan saya cari evidence yang support hipotesis itu. Alert yang tidak langsung connect ke narrative itu - meski levelnya tinggi - saya deferred.

**Apa yang seharusnya:**
Alert level 15 seharusnya jadi hard stop - pivot ke sana sebelum lanjut apapun. Mau narrativenya lagi ke mana pun, level 15 butuh immediate triage.

**Remediation:**
- SOP triage: level 12+ = mandatory immediate pivot, tidak boleh deferred
- Kalau sedang di tengah investigation lain, dokumentasikan dulu lalu pivot
- Pertimbangkan alerting channel terpisah untuk level 12+ (email, Slack notification)

---

## Gap 4: Tidak Ada Alert untuk Lateral Movement Preparation

**Apa yang terjadi:**
Sebelum WinRM ke DC01, kemungkinan ada aktivitas di WKS01 - mungkin DNS lookup, ping, atau enumeration terhadap DC01. Tidak ada alert yang catch ini.

**Kenapa tidak terdeteksi:**
Coverage gap. Network-level activity tidak termonitor. Selain itu, aktivitas seperti DNS lookup dari host domain-joined adalah sangat normal dan tidak akan generate alert bahkan kalau di-log.

**Remediation:**
Ini gap yang lebih sulit di-address. Opsi realistis:
- Log DNS queries (DNS debug logging di DC01, ingest ke Wazuh)
- NetFlow untuk lihat lateral connection WKS01 → DC01 sebelum WinRM handshake
- Tapi untuk lab ini, prioritasnya lebih ke network IDS dulu

---

## Gap 5: Domain Recon Command Tidak Fully Visible

**Apa yang terjadi:**
Saya tahu dari rekonstruksi bahwa attacker jalankan `net user /domain` dan `net group "Domain Admins" /domain` di DC01. Tapi visibility ini dari kombinasi Sysmon process creation (net.exe) dan asumsi dari attacker path - bukan dari alert eksplisit Wazuh yang langsung flag "domain enumeration".

**Kenapa:**
Tidak ada custom rule untuk flag penggunaan net.exe dengan parameter domain enumeration dari konteks yang anomalous (WinRM session dari external host). Rule generic untuk process creation di Sysmon (67027) malah di-suppress karena terlalu noisy (lihat local_rules.xml - rule 100020).

**Ini trade-off yang perlu di-revisit:**
Rule 100020 suppress Sysmon process creation (67027) secara broad untuk reduce noise. Tapi efek sampingnya: legitimate-looking commands yang dijalankan dalam konteks anomalous juga ikut ter-suppress.

**Remediation:**
- Buat exception di rule 100020: jangan suppress Sysmon process creation kalau parent process-nya WinRM atau PowerShell Remoting
- Atau buat custom rule positif: alert kalau net.exe dengan parameter `net group` atau `net user /domain` dijalankan dari konteks WinRM session
- Ini fine-tuning yang butuh waktu, tapi worth dilakukan

---

## Summary

| # | Gap | Tipe | Severity | Remediation Priority |
|---|-----|------|----------|---------------------|
| 1 | Persistence registry Run key missed | Alert ada, investigator missed | High | Tinggi |
| 2 | Reconnaissance tidak terdeteksi | Tidak ada coverage | High | Tinggi |
| 3 | Level 15 alert tidak di-pivot | Alert ada, investigator missed | Critical | Segera |
| 4 | Lateral movement preparation invisible | Tidak ada coverage | Medium | Menengah |
| 5 | Domain recon command ter-suppress | Rule logic issue | Medium | Menengah |

---

## Rekomendasi Prioritas

**Jangka pendek (bisa dilakukan sekarang):**
1. Update SOP: alert level 12+ = mandatory immediate pivot, no exceptions
2. Tulis custom rule untuk Run key modification dengan level lebih tinggi
3. Review rule 100020 suppress logic - tambahkan exception untuk WinRM context

**Jangka menengah:**
4. Deploy Suricata untuk network-level visibility, integrate ke Wazuh
5. Enable Windows Firewall logging, ingest ke Wazuh

**Jangka panjang:**
6. Pertimbangkan alerting channel terpisah untuk level 12+ (email/notification)
7. DNS query logging di DC01

---

*Ini bukan daftar exhaustive dari semua yang bisa diperbaiki. Ini yang paling impactful berdasarkan apa yang terjadi di case ini.*
