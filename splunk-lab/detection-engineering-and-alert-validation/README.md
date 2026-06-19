# Detection Engineering & Alert Validation

## Overview

After deploying Splunk Enterprise, configuring Sysmon, and successfully ingesting Windows telemetry, I developed and validated several custom detections designed to identify common attacker behaviors. Each detection was mapped to relevant MITRE ATT&CK techniques, configured as a Splunk alert, and tested by generating the corresponding activity on a Windows 10 endpoint.

The objective of this phase was to gain hands-on experience with detection engineering, alert creation, and alert validation using real endpoint telemetry.

## Detection Summary

| Detection | Severity | MITRE ATT&CK |
|------------|------------|------------|
| Encoded PowerShell Execution Detected | High | T1059.001 - PowerShell |
| PowerShell Web Request Activity Detected | High | T1105 - Ingress Tool Transfer |
| Certutil Execution Detected | Medium | T1218 - System Binary Proxy Execution |
| Local Account Enumeration Detected | Medium | T1087 - Account Discovery |
| Multiple Failed Logons Detected | Medium | T1110 - Brute Force |

### Triggered Alerts Overview

![Triggered Alerts Overview](screenshots/triggered-alerts-overview.png)

---

## Detection 1: Encoded PowerShell Execution

### Objective

Detect PowerShell commands executed with Base64-encoded arguments, a technique commonly used to obfuscate malicious activity and evade detection.

### Detection Logic

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
(CommandLine="*-enc*" OR CommandLine="*-encodedcommand*")
```

### Validation

Generated activity by executing:

```powershell
powershell -enc aGVsbG8=
```

### Result

Successfully detected encoded PowerShell execution and triggered the corresponding alert.

![Encoded PowerShell Detection](screenshots/encoded-powershell-detection.png)

---

## Detection 2: PowerShell Web Request Activity

### Objective

Detect PowerShell commands commonly used to retrieve content from external sources.

### Detection Logic

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
(CommandLine="*Invoke-WebRequest*" OR CommandLine="*iwr*" OR CommandLine="*DownloadString*")
```

### Validation

Generated activity by executing:

```powershell
powershell.exe -NoProfile -Command "Invoke-WebRequest https://github.com"
```

### Result

Successfully detected PowerShell web request activity and triggered the corresponding alert.

![PowerShell Web Request Detection](screenshots/powershell-web-request-detection.png)

---

## Detection 3: Certutil Execution

### Objective

Detect execution of certutil.exe, a Windows Living-Off-the-Land Binary (LOLBin) frequently abused by attackers.

### Detection Logic

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
Image="*\\certutil.exe"
```

### Validation

Generated activity by executing:

```cmd
certutil -hashfile C:\Windows\System32\notepad.exe SHA256
```

### Result

Successfully detected certutil execution and triggered the corresponding alert.

![Certutil Detection](screenshots/certutil-detection.png)

---

## Detection 4: Local Account Enumeration

### Objective

Detect account discovery activity performed using the Windows net user command.

### Detection Logic

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
Image="*\\net.exe"
CommandLine="*user*"
```

### Validation

Generated activity by executing:

```cmd
net user
```

### Result

Successfully detected local account enumeration activity and triggered the corresponding alert.

![Account Enumeration Detection](screenshots/account-enumeration-detection.png)

---

## Detection 5: Multiple Failed Logons

### Objective

Detect repeated authentication failures that may indicate password spraying or brute-force activity.

### Detection Logic

```spl
index=main source="WinEventLog:Security"
EventCode=4625
| stats count by Account_Name
| where count >= 5
| search NOT Account_Name="*$"
```

### Validation

Generated activity by intentionally entering an incorrect password multiple times on the Windows endpoint.

### Result

Successfully detected repeated failed authentication attempts and triggered the corresponding alert.

![Failed Logon Detection](screenshots/failed-logon-detection.png)

---

## Alert Configuration Example

All detections were converted into Splunk alerts and validated using generated activity.

![Alert Configuration Example](screenshots/alert-configuration-example.png)

---

## Key Takeaways

- Developed custom detections using Sysmon and Windows Security telemetry.
- Mapped detections to MITRE ATT&CK techniques.
- Created and validated Splunk alerts for common attacker behaviors.
- Gained hands-on experience with the detection engineering lifecycle, including creation, testing, validation, and tuning.
- Improved understanding of alert fidelity, false positives, and severity classification.

