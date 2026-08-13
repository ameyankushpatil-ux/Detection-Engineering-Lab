# Day 05 — Sigma AND, OR & NOT Conditions

## Objective

Learn how to combine Sigma selections using:

* `AND`
* `OR`
* `NOT`
* Filters
* Multiple detection conditions
* False-positive reduction
* Detection precision

---

## Event Analysis

### Event 01 — Suspicious

```text
cmd.exe
   ↓
powershell.exe -enc
```

The encoded PowerShell command is the important indicator. `cmd.exe` launching PowerShell is not automatically malicious, but the encoded command increases suspicion.

**Assessment:** Suspicious.

---

### Event 02 — Suspicious

```text
explorer.exe
   ↓
powershell.exe
   ↓
-ExecutionPolicy Bypass
   ↓
script.ps1
```

`ExecutionPolicy Bypass` and execution of a PowerShell script are suspicious indicators.

**Assessment:** Suspicious, but not automatically malicious.

---

### Event 03 — Likely Benign

```text
services.exe
   ↓
powershell.exe
   ↓
Get-Service
```

The process runs as `SYSTEM` and performs a common administrative/system operation.

**Assessment:** Likely benign, but SYSTEM activity should never be considered automatically safe.

---

### Event 04 — Suspicious Indicator

```text
explorer.exe
   ↓
powershell.exe
   ↓
-WindowStyle Hidden
   ↓
Get-Process
```

Hidden PowerShell execution is worth investigating, but `Get-Process` itself can be legitimate.

**Assessment:** Suspicious indicator, not enough evidence by itself to call it malicious.

---

### Event 05 — Highly Suspicious

```text
update.exe
   ↓
powershell.exe
   ↓
Hidden
   ↓
IEX
   ↓
DownloadString
   ↓
Remote .ps1
```

Multiple suspicious behaviors occur together.

**Assessment:** Highly suspicious.

---

# Task 2 — AND

```text
IF Image is powershell.exe
AND CommandLine contains -enc OR -EncodedCommand
THEN generate detection
```

This means:

```text
PowerShell
AND
(
    -enc
    OR
    -EncodedCommand
)
```

The parentheses are important conceptually because they show how the logic should be interpreted.

---

# Task 3 — OR

### AND

```text
-enc AND DownloadString
```

Both indicators must be present.

None of the current events contains both.

### OR

```text
-enc OR DownloadString
```

Either indicator can cause the selection to match.

Therefore:

```text
Event 01 → matches -enc
Event 05 → matches DownloadString
```

The key lesson:

> `OR` increases coverage, while `AND` generally increases precision.

---

# Task 4 — NOT

A condition such as:

```yaml
condition: selection and not filter
```

means:

```text
Match the selection
BUT
exclude events matching the filter
```

For example:

```yaml
filter:
    User: 'SYSTEM'
```

would exclude matching SYSTEM events.

### Important Detection Engineering Lesson

Do **not** assume:

```text
SYSTEM = benign
```

An attacker can execute malicious activity using SYSTEM privileges.

Therefore, excluding all SYSTEM PowerShell activity could create a detection blind spot.

---

# Task 5 — Detection Logic

Improved logic:

```text
IF Image is powershell.exe
AND
(
    CommandLine contains encoded PowerShell
    OR
    CommandLine contains DownloadString
)
AND
NOT known-benign activity
THEN generate detection
```

The important improvement is that **known-benign activity** should be narrowly defined rather than simply excluding every SYSTEM event.

---

# Task 6 — Sigma Rule

```yaml
title: Suspicious PowerShell Encoded Command or Remote Download
id: 00000000-0000-0000-0000-000000000006
status: experimental
description: Detects PowerShell using encoded commands or remote script download behavior while excluding a narrowly defined benign activity pattern.
author: Amey Patil
date: 2026-08-13

logsource:
    product: windows
    category: process_creation

detection:

    selection_image:
        Image|endswith: '\powershell.exe'

    selection_encoded:
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'

    selection_download:
        CommandLine|contains:
            - 'DownloadString'

    filter_benign:
        User: 'SYSTEM'
        CommandLine|contains: 'Get-Service'

    condition: selection_image and (selection_encoded or selection_download) and not filter_benign

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

## Why this is better than the original rule

Your original rule used:

```yaml
CommandLine|contains|all:
    - 'DownloadString'
    - 'IEX'
    - '-WindowStyle'
    - 'Hidden'
```

That would primarily detect **Event 05**.

But today's objective was:

```text
Event 01 → encoded PowerShell
Event 02 → suspicious PowerShell
Event 05 → remote download
```

Using separate selections allows us to express:

```text
Encoded PowerShell
        OR
Remote Download
```

instead of requiring every indicator to appear in the same command.

---

# Detection Logic

```text
                 PowerShell
                     │
            ┌────────┴────────┐
            │                 │
       Encoded CMD      Remote Download
            │                 │
            └────────┬────────┘
                     │
              Suspicious Event
                     │
             Known-benign filter
                     │
                     NOT
                     ↓
                  ALERT
```

---

# False-Positive Analysis

Potential legitimate activity:

* System administration
* Automation
* Software deployment
* Security testing

Avoid creating broad exclusions such as:

```text
User = SYSTEM → Ignore
```

Instead use narrow combinations of:

```text
User
+
CommandLine
+
ParentProcess
+
Host
+
Known automation
```

---

# Day 05 Key Lessons

### `AND`

Requires multiple conditions.

```text
A AND B
```

### `OR`

Allows either condition.

```text
A OR B
```

### `NOT`

Excludes matching activity.

```text
A AND NOT B
```

### Detection Engineering Principle

```text
Coverage
   ↓
Precision
   ↓
Testing
   ↓
False-positive analysis
   ↓
Tuning
```

The goal is **not the fewest alerts**.

The goal is:

> **High-value alerts with enough context for an analyst to investigate effectively.**

---

## Day 05 Result

**Detection created:** Suspicious PowerShell Encoded Command or Remote Download

**Skills practiced:**

* Sigma `AND`
* Sigma `OR`
* Sigma `NOT`
* Filters
* Multiple selections
* PowerShell detection
* False-positive reduction
* Detection logic design
* MITRE ATT&CK mapping

**GitHub commit:**

```text
feat(day05): add Sigma AND OR NOT detection logic
```

**Day 05 complete.**
