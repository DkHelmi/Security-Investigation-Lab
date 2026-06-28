# Attacker Logs - INC-001 RDP Intrusion

> Catatan lab teknis. Bukan bagian dari investigasi, murni referensi attacker POV untuk reproduksi lab.

## Attack Summary

| Item | Detail |
|------|--------|
| Attacker | kalidhika @ Kali (192.168.30.200) |
| Target | WKS01 (192.168.30.101), lalu DC01 (192.168.30.100) |
| Credential didapat | userAlpha dan userBeta (P@ssw0rd123!) via password spray |
| Tools | crackmapexec (SMB spray), RDP client, evil-winrm, reg.exe |

## Kill Chain Executed

1. Reconnaissance, ping sweep dan port scan ke 192.168.30.0/24
2. Password spray SMB ke WKS01 via crackmapexec, dapat userAlpha dan userBeta
3. Initial access ke WKS01 via RDP memakai userAlpha
4. Lateral movement ke DC01 via WinRM (evil-winrm)
5. Domain recon di DC01 (net user /domain, net group "Domain Admins" /domain)
6. Persistence di WKS01 via registry Run key (WindowsUpdateHelper)
7. Credential dump attempt di DC01 gagal karena userAlpha bukan admin

## Screenshots Index

| File | Isi |
|------|-----|
| rdp-02-cme-spray-success.png | crackmapexec, password spray SMB berhasil dapat userAlpha dan userBeta |
| rdp-03-initial-access-success.png | Login RDP ke WKS01 berhasil sebagai userAlpha |
| wazuh-02-campaign-alerts.png | Tampilan cluster alert campaign di Wazuh |
| lateral-01-winrm-dc01-access.png | Akses DC01 via WinRM (evil-winrm) |
| lateral-02-dc01-domain-recon.png | Domain enumeration di DC01 (net user dan net group) |
| persist-01-registry-runkey.png | Pemasangan persistence registry Run key |
