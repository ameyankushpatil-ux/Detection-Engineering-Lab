# Day 08 — Scheduled Task Persistence Detection

## Objective

Detect suspicious scheduled-task creation using Windows process-creation telemetry and identify potential persistence through `schtasks.exe`.

---

## Task 01 — Event Analysis

### Event 01 — Potentially Suspicious / Requires Investigation

```text
explorer.exe
    ↓
schtasks.exe /Create
    ↓
WindowsUpdate
    ↓
C:\Program Files\Updater\update.exe
```

A scheduled task named `WindowsUpdate` is created to execute an updater. This could be legitimate software activity, but the task name and executable should be verified.

**Assessment:** Potentially suspicious; requires investigation.

---

### Event 02 — Likely Benign

```text
services.exe
    ↓
schtasks.exe /Create
    ↓
Microsoft\TeamsUpdate
    ↓
Microsoft Teams Update.exe
```

The task runs at logon and points to a Microsoft Teams update location. This could be legitimate software-update activity.

**Assessment:** Likely benign, but verify the executable and signer in a real investigation.

---

### Event 03 — Benign

```text
cmd.exe
    ↓
schtasks.exe /Query
```

`/Query` only retrieves information about existing scheduled tasks.

**Assessment:** Likely benign.

---

### Event 04 — Highly Suspicious

```text
invoice.exe
    ↓
schtasks.exe /Create
    ↓
Every 5 minutes
    ↓
powershell.exe
    ↓
-WindowStyle Hidden
    ↓
-EncodedCommand
```

Multiple suspicious indicators are present:

* Scheduled task creation
* Execution every 5 minutes
* PowerShell
* Hidden execution
* Encoded command
* Suspicious parent executable from a temporary directory

**Assessment:** Highly suspicious.

---

### Event 05 — Likely Benign / Requires Context

```text
cmd.exe
    ↓
schtasks.exe /Delete
```

Deleting a scheduled task can be legitimate administration or cleanup activity.

**Assessment:** Likely benign, but investigate if unexpected.

---

# Task 02 — Scheduled Task Parameters

| Parameter | Meaning                                                        |
| --------- | -------------------------------------------------------------- |
| `/Create` | Creates a scheduled task                                       |
| `/SC`     | Defines the schedule frequency, such as DAILY, MINUTE, ONLOGON |
| `/MO`     | Specifies a schedule modifier/interval                         |
| `/TN`     | Specifies the task name                                        |
| `/TR`     | Specifies the program or command executed by the task          |

### Important Correction

You identified `/TN` as the PowerShell command.

It is actually the **task name**.

For example:

```text
/TN WindowsTelemetry
```

means the scheduled task is named:

```text
WindowsTelemetry
```

The command to execute is specified by:

```text
/TR "powershell.exe ..."
```

---

# Task 03 — Important Detection Fields

### 1. `CommandLine`

Most important because it reveals:

```text
/Create
powershell.exe
-EncodedCommand
```

### 2. `Image`

Identifies the process creating the scheduled task:

```text
schtasks.exe
```

### 3. `ParentImage`

Provides process ancestry:

```text
invoice.exe
    ↓
schtasks.exe
```

This increases confidence when the parent is suspicious.

### 4. `User`

Provides account context and helps determine whether the activity is expected.

---

# Task 04 — Detection Logic

```text
IF Image is schtasks.exe
AND CommandLine contains /Create
AND CommandLine contains powershell.exe
AND CommandLine contains -EncodedCommand
THEN generate a high-confidence detection
```

This is much more precise than:

```text
schtasks.exe = alert
```

---

# Task 05 — Sigma Rule

```yaml
title: Suspicious Scheduled Task Creating Encoded PowerShell
id: 00000000-0000-0000-0000-000000000009
status: experimental
description: Detects scheduled task creation that launches PowerShell with an encoded command.
author: Amey Patil
date: 2026-08-16

logsource:
    product: windows
    category: process_creation

detection:
    selection_image:
        Image|endswith: '\schtasks.exe'

    selection_create:
        CommandLine|contains: '/Create'

    selection_powershell:
        CommandLine|contains: 'powershell.exe'

    selection_encoded:
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc'

    condition: selection_image and selection_create and selection_powershell and selection_encoded

falsepositives:
    - Legitimate administrative automation
    - Authorized software deployment
    - Security testing
    - Legitimate scheduled PowerShell tasks

level: high

tags:
    - attack.persistence
    - attack.execution
    - attack.t1053.005
    - attack.t1059.001
```

### Rule Logic

```text
schtasks.exe
      +
/Create
      +
PowerShell
      +
Encoded Command
      ↓
High-confidence detection
```

This should detect **Event 04** while avoiding the normal `/Query` and `/Delete` activity in Events 03 and 05.

---

# Detection Quality

Your original idea of using all four conditions is good because it increases precision.

However, don't assume:

```text
schtasks.exe + PowerShell = malicious
```

Legitimate administrators and automation systems can create scheduled PowerShell tasks.

The strongest additional context in Event 04 is:

```text
invoice.exe
    ↓
schtasks.exe
    ↓
PowerShell
    ↓
EncodedCommand
```

combined with the **5-minute execution interval**.

---

# MITRE ATT&CK

Primary technique:

```text
T1053.005 — Scheduled Task/Job: Scheduled Task
```

PowerShell execution:

```text
T1059.001 — PowerShell
```

Scheduled tasks can be abused for **persistence and execution**.

---

# Day 08 Key Lessons

```text
✓ schtasks.exe is legitimate
✓ /Create creates a scheduled task
✓ /SC defines the schedule
✓ /MO modifies the schedule interval
✓ /TN specifies the task name
✓ /TR specifies the action/command
✓ CommandLine is critical telemetry
✓ ParentImage provides attack context
✓ Scheduled tasks can provide persistence
✓ Detection ≠ confirmed malicious activity
✓ Multiple indicators produce higher-confidence detections
```

## Investigation After Alert

For a real alert, investigate:

```text
1. Task name
2. Task action / /TR command
3. Schedule frequency
4. Parent process
5. User/account
6. Executable path
7. File hash and signer
8. Process/network activity
```

---

## Day 08 Result

**Detection created:** Suspicious Scheduled Task Creating Encoded PowerShell

**MITRE ATT&CK:** `T1053.005`, `T1059.001`

**GitHub commit:**

```text
feat(day08): add suspicious scheduled task PowerShell detection
```

**Day 08 complete.**
