# Day 06 — Rundll32 DLL Execution Detection

## Objective

Analyze Windows process-creation telemetry and detect suspicious abuse of `rundll32.exe` using:

* `endswith`
* `contains`
* DLL execution
* Downloads directory
* Parent-child relationships
* False-positive analysis

---

## Event Analysis

### Event 01 — Likely Benign

```text
explorer.exe
    ↓
rundll32.exe
    ↓
shell32.dll,Control_RunDLL
```

`rundll32.exe` is a legitimate Windows utility, and Explorer can legitimately invoke Windows Control Panel functionality through `shell32.dll`.

**Assessment:** Likely benign.

> Important: `rundll32.exe` itself is not malicious.

---

### Event 02 — Highly Suspicious

```text
invoice.exe
    ↓
rundll32.exe
    ↓
C:\Users\john\Downloads\payload.dll
```

Multiple suspicious indicators are present:

* DLL executed through `rundll32.exe`
* DLL located in `Downloads`
* Suspicious parent executable from a temporary directory
* User-context execution

**Assessment:** Highly suspicious.

---

### Event 03 — Likely Benign / Requires Context

```text
explorer.exe
    ↓
rundll32.exe
    ↓
C:\Windows\System32\example.dll
```

The DLL is located inside a trusted Windows system directory and Explorer is the parent.

**Assessment:** Likely benign, although the DLL should be verified if this were a real investigation.

---

### Event 04 — Likely Benign

```text
explorer.exe
    ↓
rundll32.exe
    ↓
shell32.dll,Control_RunDLL
```

This is consistent with legitimate Windows functionality.

**Assessment:** Likely benign.

---

### Event 05 — Benign

```text
explorer.exe
    ↓
notepad.exe
    ↓
notes.txt
```

This is normal user activity.

**Assessment:** Benign.

---

# Task 02 — `endswith`

```yaml
Image|endswith: '\rundll32.exe'
```

This matches Events:

```text
Event 01
Event 02
Event 03
Event 04
```

It works even when the executable is located in different Windows directories:

```text
C:\Windows\System32\rundll32.exe
C:\Windows\SysWOW64\rundll32.exe
```

This is preferable to:

```yaml
Image: 'rundll32.exe'
```

because process telemetry commonly contains the complete executable path.

---

# Task 03 — `contains`

```yaml
CommandLine|contains: '\Downloads\'
```

This matches Event 02 because the DLL is executed from:

```text
C:\Users\john\Downloads\
```

However:

```text
Downloads ≠ malicious
```

Legitimate users can execute files from Downloads, so additional context is required.

---

# Task 04 — Detection Logic

```text
IF Image ends with rundll32.exe
AND CommandLine contains .dll
AND CommandLine contains \Downloads\
THEN generate a detection
```

A stronger version also considers the parent process:

```text
rundll32.exe
+
Downloads DLL
+
Suspicious Parent
```

This gives higher confidence.

---

# Task 05 — Parent Process Analysis

### Lower suspicion

```text
explorer.exe
    ↓
rundll32.exe
    ↓
DLL
```

### Higher suspicion

```text
invoice.exe
    ↓
rundll32.exe
    ↓
Downloads\payload.dll
```

The second chain is more suspicious because the parent executable is located in a temporary directory and launches a DLL from the user's Downloads directory.

This is an example of **process ancestry providing detection context**.

---

# Task 06 — Sigma Rule

```yaml
title: Suspicious Rundll32 DLL Execution from Downloads
id: 00000000-0000-0000-0000-000000000007
status: experimental
description: Detects rundll32.exe executing a DLL from a user's Downloads directory.
author: Amey Patil
date: 2026-08-14

logsource:
    product: windows
    category: process_creation

detection:

    selection_image:
        Image|endswith: '\rundll32.exe'

    selection_command:
        CommandLine|contains:
            - '\Downloads\'
            - '.dll'

    condition: selection_image and selection_command

falsepositives:
    - Legitimate DLL execution from Downloads
    - Software installation or troubleshooting
    - Security testing

level: high

tags:
    - attack.defense_evasion
    - attack.t1218.011
```

### Important corrections from the original rule

You wrote:

```yaml
Image|endswith: '\rundll.exe'
```

The correct executable is:

```yaml
Image|endswith: '\rundll32.exe'
```

Also, `T1059.001` is **PowerShell**, so it does not belong on this rule.

The relevant MITRE ATT&CK technique is:

```text
T1218.011 — System Binary Proxy Execution: Rundll32
```

---

# Task 07 — Detection Quality

A rule such as:

```yaml
Image|endswith: '\rundll32.exe'
```

is better than simply matching the string `rundll32.exe`, but it would still be **too broad for production**.

A more useful detection combines:

```text
rundll32.exe
      +
DLL
      +
Downloads
      +
Suspicious parent
```

This reduces noise while retaining useful coverage.

---

# Day 06 Key Lessons

### 1. Legitimate LOLBins can be abused

```text
rundll32.exe ≠ malicious
```

### 2. File location provides context

```text
Windows\System32
```

is generally different from:

```text
Users\john\Downloads
```

### 3. Parent-child relationships matter

```text
explorer.exe → rundll32.exe
```

and:

```text
invoice.exe → rundll32.exe
```

should not automatically receive the same risk score.

### 4. Don't label every suspicious event as malicious

A detection identifies **behavior worth investigating**. The analyst still needs to validate the DLL, parent process, signer, hash, user, and surrounding activity.

---

## Day 06 Result

**Detection created:** Suspicious Rundll32 DLL Execution from Downloads

**Skills practiced:**

* `endswith`
* `contains`
* LOLBin detection
* DLL execution analysis
* Parent-child process analysis
* False-positive analysis
* MITRE ATT&CK mapping
* Sigma rule construction

**GitHub commit:**

```text
feat(day06): add suspicious rundll32 DLL execution detection
```

**Day 06 complete.**
