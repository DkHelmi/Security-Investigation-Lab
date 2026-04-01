# Snapshots

Snapshot diambil saat VM dalam kondisi powered off.
Untuk mulai case baru, akan di lakukan restore semua VM ke snapshot BASE-clean sebelum menjalankan campaign.

## BASE-clean

**Tanggal:** April 1, 2026  
**Kondisi:** Clean state.

| VM | Snapshot Name | Kondisi |
|----|--------------|---------|
| SIEM (192.168.30.50) | BASE-clean | Wazuh 4.9.2 running, semua agent terhubung |
| DC01 (192.168.30.100) | BASE-clean | Domain Controller lab.local up, Wazuh agent aktif |
| WKS01 (192.168.30.101) | BASE-clean | Domain-joined, Sysmon running, Wazuh agent aktif |
| Kali (192.168.30.200) | BASE-clean | Tools attacker tersedia, tidak ada payload aktif |

## Cara Restore

1. Matikan VM yang mau di-restore
2. Klik VM di VirtualBox → tab Snapshots
3. Klik snapshot BASE-clean → Restore
4. Boot VM

## Per-Case Snapshots

Setiap case yang selesai akan dicatat di sini beserta snapshot-nya.

| Case | Snapshot Name | Keterangan |
|------|--------------|------------|
| INC-001-rdp-intrusion | - | Tidak ada snapshot, case sudah selesai sebelum sistem snapshot dibuat |