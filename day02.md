# Day 02 — Sigma Selection & Conditions

## Objective

Practice analyzing Windows process-creation events and writing Sigma detection logic using:

* `logsource`
* `selection`
* `condition`
* `contains`
* `endswith`
* Parent/child process relationships
* False-positive analysis

All events in this exercise involve user **john**.

---

## Event Analysis

### Event 1

**Parent:** `explorer.exe`
**Child:** `cmd.exe`
**Command:** `whoami`

`whoami` is used to identify the current logged-in user/account context. The Explorer → CMD relationship can occur during normal user activity.

**Assessment:** Likely benign.

---

### Event 2

**Parent:** `winword.exe`
**Child:** `cmd.exe`
**Command:** `net user`

`net user` can be used for account/user enumeration. The more unusual part is **Microsoft Word spawning CMD**, which can be suspicious and should be investigated.

**Assessment:** Suspicious.

**Reason:** Office application → command shell is a potentially suspicious parent/child relationship.

---

### Event 3

**Parent:** `explorer.exe`
**Child:** `cmd.exe`
**Command:** `ipconfig /all`

`ipconfig /all` displays detailed network configuration information such as IP addresses, DNS configuration, gateways and adapters.

Explorer → CMD is possible during normal activity.

**Assessment:** Likely benign.

---

### Event 4

**Parent:** `invoice.exe`
**Child:** `cmd.exe`
**Command:** `powershell.exe -enc SQBFAFgA`

This event contains multiple suspicious indicators:

* `invoice.exe` is the parent process.
* CMD launches PowerShell.
* PowerShell uses `-enc`.
* The command is encoded.

The encoded command should be decoded and investigated before making a final malicious/benign determination.

**Assessment:** Highly suspicious.

---

### Event 5

**Parent:** `explorer.exe`
**Child:** `cmd.exe`
**Command:** `dir C:\Users\john\Documents`

`dir` lists files and directories. Explorer → CMD is normal enough to occur during legitimate user activity.

**Assessment:** Likely benign.

---

# Task 2 — Detection Logic

## Initial Attempt

```text
IF Image contains cmd.exe
AND CommandLine contains cmd.exe
THEN trigger an offense
```

### Improvement

This logic is too broad because it can detect almost every CMD process.

A better detection for today's scenario is:

```text
IF Image is cmd.exe
AND CommandLine contains powershell.exe
AND CommandLine contains encoded PowerShell execution
THEN generate a detection
```

This focuses on **behavior**, rather than simply detecting CMD.

---

# Task 3 — Sigma Rule #1

## Suspicious CMD → PowerShell Encoded Command

```yaml
title: Suspicious CMD Executing Encoded PowerShell
id: 00000000-0000-0000-0000-000000000002
status: experimental
description: Detects CMD launching PowerShell with an encoded command.
author: Amey Patil
date: 2026-08-11

logsource:
    product: windows
    category: process_creation

detection:

    selection_image:
        Image|endswith: '\cmd.exe'

    selection_command:
        CommandLine|contains:
            - 'powershell.exe'
            - ' -enc '
            - ' -EncodedCommand '

    condition: selection_image and selection_command

falsepositives:
    - Legitimate administrative activity
    - Authorized automation scripts

level: medium

tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1027.010
```

### Detection Explanation

```text
selection_image
      ↓
CMD execution

selection_command
      ↓
PowerShell + encoded command indicator

condition
      ↓
Both selections must match
```

MITRE ATT&CK currently maps PowerShell to **T1059.001** and command obfuscation to **T1027.010**. MITRE specifically includes encoded PowerShell commands as an example of command obfuscation.

---

# Task 4 — Sigma Rule #2

## CMD Executing `net user`

```yaml
title: Windows CMD Executing Net User
id: 00000000-0000-0000-0000-000000000003
status: experimental
description: Detects cmd.exe executing the net user command for potential user account discovery.
author: Amey Patil
date: 2026-08-11

logsource:
    product: windows
    category: process_creation

detection:

    selection_image:
        Image|endswith: '\cmd.exe'

    selection_command:
        CommandLine|contains: 'net user'

    condition: selection_image and selection_command

falsepositives:
    - System administrators
    - Helpdesk activity
    - Legitimate troubleshooting

level: low

tags:
    - attack.discovery
```

---

# False-Positive Analysis

## Rule 1 — CMD → Encoded PowerShell

Potential false positives:

* Authorized administration
* Security testing
* Automation
* Software deployment

Therefore:

```text
PowerShell + encoded command
≠ automatically malicious
```

Additional context such as parent process, user, command contents and surrounding events can increase confidence.

---

## Rule 2 — `net user`

`net user` can legitimately be used by administrators and helpdesk personnel.

Therefore:

```text
net user
≠ automatically malicious
```

However:

```text
winword.exe
    ↓
cmd.exe
    ↓
net user
```

is more suspicious than:

```text
explorer.exe
    ↓
cmd.exe
    ↓
net user
```

This demonstrates why **parent-child process relationships are important detection context**.

---

# Day 02 Key Lessons

### 1. `logsource`

Defines **where** the detection should look.

```yaml
logsource:
    product: windows
    category: process_creation
```

### 2. `selection`

Defines **what characteristics** you're looking for.

```yaml
selection:
    Image|endswith: '\cmd.exe'
```

### 3. `condition`

Defines how selections must combine.

```yaml
condition: selection_image and selection_command
```

### 4. `contains`

Useful when the relevant value appears somewhere inside a larger string.

```yaml
CommandLine|contains: 'net user'
```

### 5. `endswith`

Useful when telemetry contains a full executable path.

```yaml
Image|endswith: '\cmd.exe'
```

### 6. Detection ≠ Verdict

A detection identifies activity worth investigating. It does not automatically prove that the activity is malicious.

---

## Day 02 GitHub Commit

```text
feat(day02): add CMD and PowerShell detection rules
```

## Skills Practiced

* Windows process creation telemetry
* CMD detection
* PowerShell detection
* Parent/child process analysis
* Sigma `selection`
* Sigma `condition`
* `contains`
* `endswith`
* False-positive analysis
* MITRE ATT&CK mapping

**Day 02 complete.**
