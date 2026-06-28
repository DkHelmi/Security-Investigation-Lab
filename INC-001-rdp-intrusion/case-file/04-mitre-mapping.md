# 04 - MITRE ATT&CK Mapping


## Catatan Pendekatan

Mapping ini ditulis dengan konteks apa yang benar-benar terjadi di lab, bukan copy-paste definisi ATT&CK. Detail evidence (alert ID, timestamp, field) sudah ada di 02-investigation.md dan 03-timeline.md, jadi di sini tidak diulang. Yang ditulis hanya tabel ringkas dan catatan untuk teknik yang butuh konteks tambahan.

---

## Summary

| Tactic | Technique | Sub-technique | Status | Alert Caught? |
|--------|-----------|---------------|--------|---------------|
| Reconnaissance | T1595 | .001 Scanning IP Blocks | Inferred | Tidak |
| Reconnaissance | T1046 | Network Service Discovery | Inferred | Tidak |
| Initial Access | T1110 | .003 Password Spraying | Confirmed | Ya |
| Initial Access | T1078 | .002 Domain Accounts | Confirmed | Ya |
| Initial Access | T1021 | .001 RDP | Confirmed | Ya |
| Execution | T1059 | .001 PowerShell | Confirmed | Partial |
| Persistence | T1547 | .001 Registry Run Keys | Confirmed | Ya (missed) |
| Discovery | T1087 | .002 Domain Account | Confirmed | Partial |
| Discovery | T1018 | Remote System Discovery | Inferred | Tidak |
| Lateral Movement | T1021 | .006 WinRM | Confirmed | Ya |
| Credential Access | T1003 | OS Credential Dumping | Attempted/Gagal | Partial |

Keterangan: "Ya (missed)" berarti Wazuh generate alertnya tapi investigator tidak pivot saat triage (lihat 05-detection-gaps.md). "Inferred" berarti tidak ada alert, disimpulkan dari attack path.

---

## Catatan per Teknik

Hanya teknik yang butuh konteks tambahan; sisanya cukup jelas dari tabel.

- **T1595.001 / T1046 / T1018 (Recon, Inferred):** tidak ada satu pun alert. Keberadaan fase recon disimpulkan dari fakta attacker langsung tahu port yang dipakai (445 SMB untuk spray, 5985 WinRM untuk lateral movement), informasi yang hanya bisa didapat dari scan awal.
- **T1110.003 (Password Spraying):** disimpulkan spray, bukan brute force, karena banyak `targetUserName` berbeda dari satu IP dalam window sempit (hindari lockout). Berhasil karena `P@ssw0rd123!` memenuhi complexity tapi sangat predictable.
- **T1078.002 (Valid Accounts):** dari sisi sistem ini logon sah. Pembedanya cuma source IP tak biasa (workstationName `kalidhika`) dan pola logon dari IP yang sama yang baru saja generate ratusan failure.
- **T1547.001 (Registry Run Keys):** pakai HKCU, bukan HKLM, karena userAlpha bukan admin. Persistence per-user yang tidak butuh privilege, calculated workaround. Payload saat ini benign (`Start-Sleep`) tapi bisa diubah kapan saja selama attacker punya akses.
- **T1021.006 (WinRM):** berhasil karena userAlpha sudah ada di grup Remote Management Users di DC01 (bagian lab setup; di lingkungan nyata harusnya restricted ke admin).
- **T1003 (Credential Dumping, Attempted):** gagal karena userAlpha bukan admin di DC01, tidak ada alert LSASS atau Ntds.dit yang sukses. Inilah yang membuat attacker stuck tanpa path ke Domain Admin.

---

*Detection gaps dan missed alerts dibahas di 05-detection-gaps.md.*
