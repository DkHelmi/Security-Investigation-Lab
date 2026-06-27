# 04 - MITRE ATT&CK Mapping

**Case:** INC-002-ssh-bruteforce  
**Investigator:** Hardhika Helmi  
**Framework:** MITRE ATT&CK Enterprise v14

---

## Catatan Pendekatan

Mapping berdasarkan evidence yang ditemukan (Wazuh alerts, auth.log, last, wtmp, btmp). Detail alert dan timestamp sudah ada di 02-investigation.md dan 03-timeline.md, jadi di sini tidak diulang. Teknik discovery post-compromise tidak bisa di-mapping karena tidak ada log yang capture aktivitas selama sesi.

---

## Summary

| Tactic | Technique | Sub-technique | Status | Alert Caught? |
|--------|-----------|---------------|--------|---------------|
| Reconnaissance | T1595 | .001 Scanning IP Blocks | Inferred | Tidak |
| Reconnaissance | T1046 | Network Service Discovery | Inferred | Tidak |
| Credential Access | T1110 | Brute Force | Confirmed | Ya |
| Initial Access | T1078 | .003 Local Accounts | Confirmed | Ya |
| Initial Access | T1021 | .004 SSH | Confirmed | Ya |
| Discovery | - | Unknown | Tidak diketahui | Tidak |

Keterangan: "Inferred" berarti tidak ada alert, disimpulkan dari attack path. "Tidak diketahui" berarti aktivitas terjadi tapi tidak ada evidence sama sekali.

---

## Catatan per Teknik

Hanya teknik yang butuh konteks tambahan; sisanya cukup jelas dari tabel.

- **T1595.001 / T1046 (Recon, Inferred):** tidak ada alert maupun log. Disimpulkan dari fakta attacker tahu port 22 terbuka di siemserver sebelum mulai brute force.
- **T1110 (Brute Force):** rule 5710 (login user tidak ada) yang muncul berulang menunjukkan attacker pakai username wordlist, bukan target satu user dari awal. btmp mengungkap failed attempt mulai 40 menit sebelum Wazuh pertama kali alert, artinya threshold Wazuh baru tercapai jauh setelah serangan berjalan.
- **T1078.003 (Local Accounts):** itstaff adalah akun lokal di SIEM server, bukan domain account. Dari sisi sistem ini login SSH yang sah; pembedanya cuma source IP yang baru saja generate cluster failure sebelum berhasil.
- **Discovery (Unknown):** aktivitas selama sesi ~10 menit tidak ter-capture log apa pun (Wazuh, auth.log, journalctl, wtmp semua kosong untuk window itu). Teknik discovery yang mungkin terjadi tidak bisa di-mapping tanpa evidence. Ini blind spot utama case ini.

---

*Detection gaps dibahas di 05-detection-gaps.md.*
