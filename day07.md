# Day 07 — MSHTA Remote Execution Detection & Week 1 Review

## Objective

Analyze `mshta.exe` activity and build a detection using Sigma regex matching, while practicing positive/negative testing and detection tuning.

---

## Task 1 — Event Analysis

### Event 01 — Potentially Suspicious / Requires Investigation

```text
explorer.exe
    ↓
mshta.exe
    ↓
C:\Users\john\Documents\company.hta
```

An `.hta` file executed from a user's Documents directory should be investigated, but this alone does not prove malicious activity.

**Assessment:** Potentially suspicious.

---

### Event 02 — Highly Suspicious

```text
invoice.exe
    ↓
mshta.exe
    ↓
http://example.com/update.hta
```

Multiple indicators are present:

* `mshta.exe`
* Remote URL
* Remote `.hta`
* Parent executable from a temporary directory

**Assessment:** Highly suspicious.

---

### Event 03 — Suspicious Indicator

```text
mshta.exe javascript:alert('Hello')
```

`javascript:` execution through `mshta.exe` is worth investigating. However, it does not automatically mean an XSS vulnerability is being exploited.

**Assessment:** Suspicious indicator.

---

### Event 04 — Benign

```text
explorer.exe
    ↓
notepad.exe
    ↓
notes.txt
```

Normal user activity.

**Assessment:** Benign.

---

### Event 05 — Highly Suspicious

```text
winword.exe
    ↓
mshta.exe
    ↓
http://malicious.example/payload.hta
```

This combines an Office application spawning `mshta.exe` with remote `.hta` execution.

**Assessment:** Highly suspicious.

---

# Task 2 — Regex

```yaml
CommandLine|re: '(?i).*https?://.*\.hta.*'
```

This attempts to identify a command line containing:

```text
http://
OR
https://
```

followed somewhere by:

```text
.hta
```

Meaning:

```text
Remote URL
      +
HTA file
```

---

# Task 3 — `contains` vs `re`

### `contains`

```yaml
CommandLine|contains: 'http://'
```

Detects the literal string:

```text
http://
```

It does not cover `https://`.

### Regex

```yaml
CommandLine|re: '(?i).*https?://.*\.hta.*'
```

Can match both:

```text
http://example.com/file.hta
https://example.com/file.hta
```

and specifically looks for `.hta`.

**Conclusion:** The regex is more precise for the specific detection objective.

---

# Task 4 — Detection Logic

```text
IF Image ends with mshta.exe
AND CommandLine matches a remote URL followed by .hta
THEN generate a detection
```

A stronger version would also consider the parent:

```text
mshta.exe
+
remote .hta
+
suspicious parent
```

This would increase confidence.

---

# Task 5 — Sigma Rule

```yaml
title: MSHTA Remote HTA Execution
id: 00000000-0000-0000-0000-000000000008
status: experimental
description: Detects mshta.exe executing a remote HTA file through HTTP or HTTPS.
author: Amey Patil
date: 2026-08-16

logsource:
    product: windows
    category: process_creation

detection:
    selection_image:
        Image|endswith: '\mshta.exe'

    selection_remote_hta:
        CommandLine|re: '(?i).*https?://.*\.hta.*'

    condition: selection_image and selection_remote_hta

falsepositives:
    - Legitimate applications using remote HTA content
    - Authorized administrative activity
    - Security testing

level: high

tags:
    - attack.execution
    - attack.t1218.005
```

### Rule Improvement

Your original condition was:

```text
selection_image AND
(
    selection_java
    OR
    selection_hta
    OR
    selection_image
)
```

The problem is that `selection_image` appears inside the `OR`.

That means the condition can effectively become true whenever `selection_image` matches.

For today's objective, we only need:

```text
selection_image AND selection_remote_hta
```

Also, `T1059.001` is **PowerShell**, so it should not be used for this MSHTA rule.

The relevant ATT&CK technique is:

```text
T1218.005 — System Binary Proxy Execution: Mshta
```

---

# Task 6 — Detection Objective

The goal is not:

> Alert whenever any file is downloaded.

Instead:

> Detect `mshta.exe` executing a remote `.hta` resource, particularly when combined with suspicious process ancestry or other execution indicators.

This distinction is important because legitimate downloads happen constantly.

---

# Task 7 — Detection Tuning

Your idea of reducing false positives is correct, but a new rule is not automatically "perfect."

The process should be:

```text
Initial Rule
     ↓
Positive Tests
     ↓
Negative Tests
     ↓
False Positive Analysis
     ↓
Tune
     ↓
Deploy
     ↓
Monitor
     ↓
Retune
```

A production detection should be evaluated using real telemetry and alert outcomes.

---

# Task 8 — Week 1 Review

### 1. `endswith`

```yaml
Image|endswith: '\powershell.exe'
```

Means the value of `Image` must end with:

```text
\powershell.exe
```

---

### 2. `contains|all`

```yaml
CommandLine|contains|all:
```

Means **all specified values must be present** for that selection to match.

---

### 3. `AND` vs `OR`

```text
A AND B
```

Both conditions must be satisfied.

```text
A OR B
```

At least one condition must be satisfied.

---

### 4. `AND NOT`

```text
A AND NOT B
```

Condition A must match while condition B must **not** match.

---

### 5. Why `powershell.exe = malicious` is bad

PowerShell is a legitimate Windows administration and automation tool.

Therefore:

```text
powershell.exe ≠ automatically malicious
```

The detection should focus on suspicious behavior and context.

---

### 6. Parent-child process information

Parent-child relationships show **which process launched another process**.

For example:

```text
winword.exe
    ↓
mshta.exe
```

is generally more interesting from a security perspective than:

```text
explorer.exe
    ↓
mshta.exe
```

Parent-child relationships therefore provide valuable behavioral context.

---

### 7. Detection vs Verdict

**Detection:**

> Identifies activity that matches suspicious behavior and deserves investigation.

**Verdict:**

> The analyst's final determination after investigating the evidence.

Example:

```text
MSHTA remote execution
        ↓
Detection
        ↓
Investigation
        ↓
Malicious / Benign
        ↓
Verdict
```

A detection should **not automatically be treated as a confirmed attack**.

---

# Week 1 Learning Summary

### Concepts Covered

```text
✓ Sigma structure
✓ logsource
✓ selection
✓ condition
✓ contains
✓ contains|all
✓ endswith
✓ startswith
✓ AND
✓ OR
✓ NOT
✓ Filters
✓ Regex
✓ Parent-child analysis
✓ PowerShell detection
✓ Rundll32 detection
✓ MSHTA detection
✓ Positive/negative testing
✓ False-positive analysis
✓ Detection tuning
✓ MITRE ATT&CK mapping
```

### My Week 1 Detection Engineering Learning

```text
Most important concept:
Detection should focus on behavior and context, not just process names.

Concept I still need to improve:
Regex and complex Sigma conditions.

Biggest mistake:
Assuming legitimate Windows processes such as PowerShell, Rundll32 and MSHTA are automatically malicious.

What I understand better now:
How telemetry fields, command lines and parent-child relationships can be combined to create more precise detections.

Week 2 focus:
Improve detection logic, create better test cases, and start thinking about detection coverage and investigation.
```

---

## Day 07 Result

**Detection created:** `MSHTA Remote HTA Execution`

**MITRE ATT&CK:** `T1218.005 — Mshta`

**GitHub commit:**

```text
feat(day07): add mshta remote execution detection and week one review
```

**Week 1 complete.**
