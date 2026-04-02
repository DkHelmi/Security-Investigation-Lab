# 06 - Alert Tuning

> File ini ditulis post-case sebagai remediation. Bukan bagian dari investigasi natural — ini rekomendasi tuning berdasarkan gap yang ditemukan.

## Custom Rules yang Direkomendasikan

### Rule 1 — Explorer spawns cmd/powershell with suspicious arguments

**Gap yang ditutup:** Initial LNK execution invisible

```xml
<rule id="100030" level="12">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)explorer\.exe</field>
  <field name="win.eventdata.image" type="pcre2">(?i)(cmd|powershell)\.exe</field>
  <description>Explorer spawned command shell - possible malicious shortcut execution</description>
  <mitre>
    <id>T1204.002</id>
  </mitre>
</rule>
```

Ini akan alert setiap kali `explorer.exe` menjalankan `cmd.exe` atau `powershell.exe`. Level 12 karena ini bisa legitimate (user buka CMD dari Start Menu), tapi cukup tinggi untuk visible di dashboard.

### Rule 2 — Scheduled Task creation detected

**Gap yang ditutup:** Persistence via Scheduled Task invisible

```xml
<rule id="100031" level="12">
  <if_sid>60009</if_sid>
  <field name="win.system.eventID">^4698$</field>
  <description>New scheduled task created - possible persistence mechanism</description>
  <mitre>
    <id>T1053.005</id>
  </mitre>
</rule>
```

Pastikan juga Windows Security log di-forward ke Wazuh via `agent.conf`:

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
  <query>Event/System[EventID=4698 or EventID=4699 or EventID=4700 or EventID=4701]</query>
</localfile>
```

### Rule 3 — Executable run from TEMP folder

**Gap yang ditutup:** Payload execution dari folder user-writable tidak terdeteksi

```xml
<rule id="100032" level="10">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\(Temp|AppData)\\.*\.exe</field>
  <description>Executable launched from temporary/user folder - possible malware execution</description>
  <mitre>
    <id>T1204.002</id>
  </mitre>
</rule>
```

### Rule 4 — curl/certutil download to suspicious location

**Gap yang ditutup:** Menambah context ke existing detection

```xml
<rule id="100033" level="12">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)(curl|certutil)\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(Temp|AppData|Downloads).*\.(exe|cmd|bat|ps1|vbs)</field>
  <description>Download tool writing to user-writable folder - possible ingress tool transfer</description>
  <mitre>
    <id>T1105</id>
  </mitre>
</rule>
```

## Agent Config Update

Tambahkan ke `agent.conf` untuk capture event yang saat ini tidak ter-forward:

```xml
<!-- Scheduled Task events -->
<localfile>
  <location>Microsoft-Windows-TaskScheduler/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

## Sysmon Config Update

Pastikan Sysmon configuration include:

- **Event ID 3** (Network Connection) — minimal untuk proses dari folder TEMP/AppData
- **Event ID 11** (File Created) — sudah aktif, tapi pastikan coverage di semua user-writable folders
- **Event ID 1** (Process Create) — sudah aktif

## Prioritas Implementasi

| Prioritas | Rule | Alasan |
|---|---|---|
| P1 | 100031 (Scheduled Task) | Persistence detection adalah gap paling critical — tanpa ini, attacker bisa maintain access tanpa terdeteksi |
| P1 | Agent config update (TaskScheduler log) | Prerequisite untuk rule 100031 |
| P2 | 100030 (Explorer → cmd/ps) | Initial access detection — membantu identifikasi trigger awal |
| P2 | 100032 (Exe from TEMP) | Payload execution detection |
| P3 | 100033 (curl/certutil download) | Enhancement untuk existing detection |
| P3 | Sysmon Event ID 3 | Network visibility — penting tapi butuh tuning supaya tidak terlalu noisy |
