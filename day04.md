# Day 04 — Sigma Modifiers & Detection Testing

## Objective

Practice Sigma modifiers, multiple conditions, positive/negative testing, and reducing false positives.

---

## Event Analysis

### Event 1 — Suspicious

`cmd.exe` launches PowerShell with an encoded command:

```text
powershell.exe -enc SQBFAFgA
```

**Assessment:** Suspicious.

The `-enc` parameter indicates encoded PowerShell command execution. The encoded content should be decoded and investigated before confirming maliciousness.

---

### Event 2 — Suspicious

PowerShell executes:

```text
-ExecutionPolicy Bypass
```

and runs a `.ps1` file.

**Assessment:** Suspicious.

However, `ExecutionPolicy Bypass` alone does not prove malicious activity. Context is required.

---

### Event 3 — Likely Benign

```text
services.exe
    ↓
powershell.exe
    ↓
Get-Service
```

Running as `SYSTEM` and executing `Get-Service` can be legitimate system or administrative activity.

**Assessment:** Likely benign.

---

### Event 4 — Highly Suspicious

Indicators include:

```text
PowerShell
+
WindowStyle Hidden
+
IEX
+
DownloadString
+
Remote .ps1
+
Temp-directory parent process
```

**Assessment:** Highly suspicious.

This is the strongest event in today's dataset.

---

### Event 5 — Likely Benign

```text
explorer.exe
    ↓
powershell.exe
    ↓
Get-Process
```

`Get-Process` can be legitimate system administration or troubleshooting.

**Assessment:** Likely benign.

---

# Task 02 — `contains`

```yaml
CommandLine|contains: 'DownloadString'
```

This matches:

```text
Event 04
```

It does not match Events 1, 2, 3, or 5.

`contains` is useful when the value appears somewhere inside a larger command line.

---

# Task 03 — `all`

```yaml
CommandLine|contains|all:
    - '-WindowStyle'
    - 'Hidden'
    - 'DownloadString'
```

`all` means **all specified values must be present for the selection to match**.

Therefore, Event 04 matches because it contains:

```text
-WindowStyle
Hidden
DownloadString
```

Without `all`:

```yaml
CommandLine|contains:
    - '-WindowStyle'
    - 'DownloadString'
```

the values represent alternatives within that selection rather than requiring every value to be present.

### Key Lesson

Use `all` when several indicators must occur together to increase detection confidence.

---

# Task 04 — Detection Logic

```text
IF Image is powershell.exe
AND CommandLine contains hidden execution
AND CommandLine contains DownloadString
THEN generate a detection
```

This is much better than:

```text
PowerShell = Alert
```

because it focuses on a specific suspicious behavior.

---

# Task 05 — Sigma Rule

```yaml
title: Suspicious PowerShell Remote Script Download
id: 00000000-0000-0000-0000-000000000005
status: experimental
description: Detects PowerShell using a hidden window and DownloadString to retrieve remote content.
author: Amey Patil
date: 2026-08-12

logsource:
    product: windows
    category: process_creation

detection:
    selection_image:
        Image|endswith: '\powershell.exe'

    selection_command:
        CommandLine|contains|all:
            - 'DownloadString'
            - 'IEX'
            - '-WindowStyle'
            - 'Hidden'

    condition: selection_image and selection_command

falsepositives:
    - Legitimate administrative activity
    - Authorized automation scripts
    - Security testing

level: high

tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1105
```

### Why `all` is better here

Your original rule used:

```yaml
CommandLine|contains:
    - 'DownloadString'
    - 'IEX'
    - '-WindowStyle Hidden'
```

That can be broader than intended.

Using:

```yaml
CommandLine|contains|all:
```

requires all the important indicators to exist in the same command line.

This improves precision.

---

# Task 06 — Positive & Negative Testing

### Positive Test

```text
Event 04
```

This should trigger because it contains all required indicators.

### Negative Tests

```text
Event 03
Event 05
```

These should not trigger because they do not contain the required suspicious command-line combination.

### Important

A detection should be tested against both:

```text
Positive events → SHOULD trigger
Negative events → SHOULD NOT trigger
```

This is an important part of detection engineering.

---

# Task 07 — Production Deployment

Your answer:

> "Yes, deploy the PowerShell rule and whitelist users/paths."

### Correction

Don't immediately deploy a broad:

```yaml
Image|endswith: '\powershell.exe'
```

rule to production.

It would generate significant noise.

Instead:

```text
Broad Detection
      ↓
Test
      ↓
Measure False Positives
      ↓
Tune
      ↓
Add Context
      ↓
Production
```

Also avoid relying only on whitelisting users or paths. Attackers can compromise legitimate accounts and use legitimate paths.

Better tuning can use:

* Parent process
* Command-line behavior
* User context
* Known administrative tools
* Expected automation
* Host role
* Frequency
* Network destination
* Additional correlated events

---

# Day 04 Key Lessons

### Sigma modifiers

```text
contains
startswith
endswith
contains|all
```

### Detection precision

```text
One indicator
     ↓
Multiple indicators
     ↓
Context
     ↓
Higher confidence
```

### Detection testing

```text
Positive Test
    +
Negative Test
    ↓
Detection Quality
```

### Most important lesson

> **Don't ask only "Will my rule detect the attack?" Ask "What legitimate activity will my rule accidentally detect?"**

That mindset is what separates basic Sigma writing from real detection engineering.

---

## Day 04 Result

**Detection created:** Suspicious PowerShell Remote Script Download

**Skills practiced:**

* Sigma `contains`
* Sigma `contains|all`
* Multiple selections
* Detection conditions
* Positive testing
* Negative testing
* False-positive tuning
* PowerShell detection
* MITRE ATT&CK mapping

**GitHub commit:**

```text
feat(day04): improve PowerShell detection precision and testing
```

**Day 04 complete.**
