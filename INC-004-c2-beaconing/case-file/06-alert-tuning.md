# 06 - Alert Tuning

## Custom Rules untuk INC-004

Berdasarkan detection gaps yang ditemukan, berikut custom Wazuh rules yang saya buat. Rules ini ditambahkan ke `/var/ossec/etc/rules/local_rules.xml` di SIEM server.

### Rule 100040: Sysmon Network Connection ke Non-Standard Port

Mendeteksi outbound network connection (Sysmon EID 3) ke port yang bukan standard service ports. Ini untuk catch C2 communication yang pakai port seperti 8080, 4444, 8443, dan lain-lain.

```xml
<rule id="100040" level="6">
  <if_sid>61650</if_sid>
  <field name="win.eventdata.initiated">true</field>
  <field name="win.eventdata.destinationPort" type="pcre2">^(4444|8080|8443|1234|9090|6666|7777|1337)$</field>
  <description>Sysmon: Outbound connection to non-standard port $(win.eventdata.destinationPort) by $(win.eventdata.image)</description>
  <mitre>
    <id>T1071.001</id>
  </mitre>
  <group>sysmon,network,c2,</group>
</rule>
```

Catatan: rule ini bergantung pada Sysmon EID 3 yang ter-forward ke Wazuh. Perlu fix Gap 1 (Sysmon EID 3 forwarding) terlebih dahulu. Parent rule `61650` adalah Wazuh built-in untuk Sysmon Event ID 3.

### Rule 100041: Executable dari Downloads Folder

Mendeteksi process execution dimana image path berada di folder Downloads user. Ini extension dari rule 100032 (INC-003) yang hanya cover TEMP dan AppData.

```xml
<rule id="100041" level="8">
  <if_sid>92052</if_sid>
  <field name="win.eventdata.parentImage" type="pcre2">\\Users\\[^\\]+\\Downloads\\</field>
  <description>Process spawned by executable in user Downloads folder: $(win.eventdata.parentImage)</description>
  <mitre>
    <id>T1204.002</id>
  </mitre>
  <group>sysmon,malware,</group>
</rule>
```

### Rule 100042: Repeated cmd.exe Spawn dari Proses yang Sama

Mendeteksi saat cmd.exe di-spawn lebih dari 5 kali dalam 120 detik oleh parent process yang sama. Ini indicator untuk automated command execution, bisa jadi C2 beaconing atau malware yang menjalankan batch commands.

```xml
<rule id="100042" level="10" frequency="5" timeframe="120">
  <if_matched_sid>92052</if_matched_sid>
  <same_field>win.eventdata.parentImage</same_field>
  <description>Repeated cmd.exe execution (>5 in 120s) from same parent: $(win.eventdata.parentImage) - possible C2 beaconing</description>
  <mitre>
    <id>T1059.003</id>
    <id>T1029</id>
  </mitre>
  <group>sysmon,c2,beaconing,</group>
</rule>
```

### Rule 100043: Process Name Masquerading

Mendeteksi process execution dimana nama file mengandung keyword system process Windows (svchost, csrss, lsass, winlogon, services) tapi lokasi-nya bukan di System32 atau SysWOW64.

```xml
<rule id="100043" level="10">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)(svchost|csrss|lsass|winlogon|services|smss|wininit)</field>
  <field name="win.eventdata.image" negate="yes" type="pcre2">(?i)(System32|SysWOW64|winsxs)</field>
  <description>Possible process masquerading: $(win.eventdata.image) executed outside System32</description>
  <mitre>
    <id>T1036.005</id>
  </mitre>
  <group>sysmon,evasion,masquerading,</group>
</rule>
```

## Cara Apply

Di SIEM server (192.168.30.50):

```bash
# Edit local_rules.xml
sudo nano /var/ossec/etc/rules/local_rules.xml

# Tambahkan rules di atas sebelum closing tag </group>

# Cek syntax
sudo /var/ossec/bin/wazuh-analysisd -t

# Restart Wazuh manager
sudo systemctl restart wazuh-manager
```

## Prerequisite: Fix Sysmon EID 3 Forwarding

Rule 100040 tidak akan berfungsi sampai Sysmon Event ID 3 ter-forward ke Wazuh. Untuk fix ini:

**1. Cek Sysmon config di WKS01:**

```powershell
# Export current Sysmon config
sysmon -c
```

Pastikan ada rule untuk Event ID 3 (NetworkConnect). Kalau tidak ada, update sysmon config untuk include:

```xml
<NetworkConnect onmatch="exclude">
  <!-- Exclude known legitimate connections jika perlu -->
</NetworkConnect>
```

**2. Cek Wazuh agent.conf:**

Pastikan `Microsoft-Windows-Sysmon/Operational` sudah ada di agent.conf (dari CONTEXT_MASTER, ini sudah ada). Kalau Sysmon EID 3 tetap tidak muncul, kemungkinan perlu cek apakah ada filter di ossec.conf manager yang drop event tertentu.

## Summary Rules Baru

| Rule ID | Level | Deteksi | Dependency |
|---------|-------|---------|------------|
| 100040 | 6 | Outbound connection ke non-standard port | Sysmon EID 3 forwarding (fix dulu) |
| 100041 | 8 | Exe launched dari Downloads folder | - |
| 100042 | 10 | Repeated cmd.exe spawn (>5 in 120s) | - |
| 100043 | 10 | Process name masquerading di luar System32 | - |

Rules 100041, 100042, dan 100043 bisa langsung di-apply tanpa menunggu fix Sysmon EID 3. Rule 100040 perlu menunggu sampai Gap 1 di-resolve.
