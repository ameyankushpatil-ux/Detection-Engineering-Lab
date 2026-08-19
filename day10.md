# Day 10 — Registry Run Keys Persistence Detection

## Objective

Detect suspicious Windows Registry Run Key persistence using `reg.exe`, while separating legitimate startup software from attacker-controlled persistence.

**MITRE ATT&CK:** `T1547.001 — Registry Run Keys / Startup Folder`
`T1060` is the historical ATT&CK technique ID.

---

## Event Analysis

### Event 01 — Likely Benign / Validate

```text
HKCU\...\Run
    ↓
OneDriveUpdate
    ↓
C:\Program Files\Microsoft OneDrive\OneDrive.exe
```

`OneDrive.exe` under `Program Files` with `explorer.exe` as the parent is consistent with legitimate startup software.

**Assessment:** Likely benign, but validate the executable, signer and expected installation.

---

### Event 02 — Highly Suspicious

```text
invoice.exe
    ↓
reg.exe
    ↓
HKCU\...\Run
    ↓
WindowsUpdate
    ↓
C:\Users\john\AppData\Local\Temp\update.exe
```

Strong indicators:

* Misleading `WindowsUpdate` value name
* Executable in a user's Temp directory
* Suspicious `invoice.exe` parent
* Persistence established through a Run key

**Assessment:** Highly suspicious.

---

### Event 03 — Benign / Informational

```text
cmd.exe
    ↓
reg.exe query
    ↓
HKCU\...\Run
```

This is a **query**, not a registry modification.

The presence of `cmd.exe` alone does not make it malicious.

**Assessment:** Likely benign.

---

### Event 04 — Critical / Highly Suspicious

```text
invoice.exe
    ↓
reg.exe
    ↓
HKLM\...\RunOnce
    ↓
powershell.exe
    ↓
-WindowStyle Hidden
    ↓
-EncodedCommand
```

Multiple high-confidence indicators are combined:

* Registry persistence
* `RunOnce`
* Suspicious parent
* PowerShell
* Hidden execution
* Encoded command

**Assessment:** Highly suspicious / high priority.

> **Important:** Don't immediately eradicate a file based only on one detection. First preserve evidence, validate the payload, scope related activity, and follow the incident-response process.

---

### Event 05 — Likely Benign / Validate

```text
installer.exe
    ↓
reg.exe
    ↓
HKCU\...\Run
    ↓
C:\Program Files\BackupApp\backup.exe
```

A software installer creating a startup entry for a backup application is plausible.

**Assessment:** Likely benign, but validate publisher, installer activity and file signature.

---

# Task 02 — Registry Concepts

### HKCU

`HKEY_CURRENT_USER` contains Registry settings associated with the currently logged-in user.

```text
HKCU
 ↓
Current User
```

### HKLM

`HKEY_LOCAL_MACHINE` contains machine-wide configuration affecting the computer and its users.

```text
HKLM
 ↓
Computer / System
```

### Run vs RunOnce

| Key       | Behavior                                                                                      |
| --------- | --------------------------------------------------------------------------------------------- |
| `Run`     | Program is configured to execute at user logon                                                |
| `RunOnce` | Program is intended to execute once and is then removed/handled according to Windows behavior |

These keys can be legitimate **and** can be abused for persistence.

---

# Task 03 — Important Fields

Your ranking is reasonable:

```text
1. ParentImage
2. CommandLine
3. Image
4. User
```

However, for this specific detection, **CommandLine is arguably the most important field**, because it exposes the Registry key and payload.

### `/v`

Specifies the Registry **value name**.

Example:

```text
/v WindowsUpdate
```

### `/d`

Specifies the **data/value** being written.

Example:

```text
/d "C:\Users\john\AppData\Local\Temp\update.exe"
```

This is extremely important because the data tells us **what will execute when the persistence mechanism is triggered**.

---

# Task 04 — Detection Logic

Your logic:

```text
IF Image is reg.exe
AND CommandLine contains /d
AND CommandLine contains powershell.exe
THEN alert
```

works for detecting PowerShell-based Registry persistence, but it misses non-PowerShell payloads such as Event 02.

A stronger detection for today's objective is:

```text
IF Image is reg.exe
AND CommandLine modifies Run or RunOnce
AND CommandLine contains a suspicious payload
THEN generate detection
```

For high-confidence PowerShell persistence:

```text
IF reg.exe
AND Run/RunOnce modification
AND powershell.exe
AND encoded/hidden execution
THEN high-confidence alert
```

---

# Task 05 — Detection Quality

**Detection D** provides the strongest precision:

```text
reg.exe
 +
Create/modify Run key
 +
Temp executable
 +
Suspicious parent
```

However, a production rule shouldn't rely on only one suspicious path.

A better detection strategy is:

```text
Registry persistence
        +
Payload context
        +
Process ancestry
        +
File reputation
```

This provides better coverage without treating every Run-key modification as malicious.

---

# Task 06 — Sigma Rule

```yaml
title: Suspicious Registry Run Key PowerShell Persistence
id: 00000000-0000-0000-0000-000000000011
status: experimental
description: Detects reg.exe modifying Windows Run or RunOnce keys to establish PowerShell persistence with encoded commands.
author: Amey Patil
date: 2026-08-19

logsource:
    product: windows
    category: process_creation

detection:
    selection_image:
        Image|endswith: '\reg.exe'

    selection_registry:
        CommandLine|contains:
            - '\Software\Microsoft\Windows\CurrentVersion\Run'
            - '\Software\Microsoft\Windows\CurrentVersion\RunOnce'

    selection_modify:
        CommandLine|contains:
            - ' add '
            - '/d '

    selection_powershell:
        CommandLine|contains:
            - 'powershell.exe'
            - 'pwsh.exe'

    selection_encoded:
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc'

    condition: selection_image and selection_registry and selection_modify and selection_powershell and selection_encoded

falsepositives:
    - Legitimate software installation
    - Authorized administrative automation
    - Security testing
    - Enterprise management tools

level: high

tags:
    - attack.persistence
    - attack.t1547.001
    - attack.t1059.001
```

### Important Improvements

Your original rule used:

```text
selection_registry
    +
powershell
    +
encoded
```

but it didn't explicitly require the Registry operation to be an **addition/modification**.

Adding:

```yaml
selection_modify:
    CommandLine|contains:
        - ' add '
        - '/d '
```

helps distinguish modification from a simple query such as Event 03.

Also:

```text
T1060
```

is historical. Use:

```text
T1547.001
```

for the current ATT&CK mapping.

---

# Task 07 — Why RunOnce Is Interesting

`RunOnce` can provide short-lived persistence or execute something during a specific logon/startup cycle.

However, don't assume:

```text
RunOnce = malicious
```

The important detection opportunity is:

```text
RunOnce
+
Suspicious payload
+
Suspicious process ancestry
+
Other malicious indicators
```

The fact that a persistence mechanism may disappear does **not** mean defenders have no opportunity to detect it. Process creation, Registry modification telemetry, file creation and other correlated events can provide evidence.

---

# Task 08 — False-Positive Tuning

Correct principle:

> **Don't blindly whitelist a path or filename.**

For example:

```text
C:\Program Files\BackupApp\
```

isn't automatically trustworthy.

A stronger validation approach checks:

```text
Path
+
Publisher
+
Digital Signature
+
Hash
+
Parent Process
+
User
+
Installation Event
```

A legitimate application can also be compromised, so static allowlisting should be used carefully.

---

# Task 09 — L3 Investigation Checklist

When this detection fires:

```text
1. Registry key
2. Value name
3. Value data
4. Creating process
5. Parent process
6. Creating user
7. Executable path
8. File hash
9. Digital signature
10. File creation/modification time
11. First execution
12. Network connections
13. Other persistence mechanisms
14. Related process creation events
15. Related authentication/activity
```

### Recommended Investigation Flow

```text
Registry Modification
        ↓
Identify Payload
        ↓
Check Parent Process
        ↓
Analyze File
        ↓
Check Execution
        ↓
Check Network Activity
        ↓
Search for Additional Persistence
        ↓
Scope Host / User
        ↓
Determine Verdict
```

---

# Day 10 Key Lessons

```text
✓ HKCU = current-user Registry configuration
✓ HKLM = machine-wide Registry configuration
✓ Run = logon persistence
✓ RunOnce = one-time startup mechanism
✓ reg.exe is legitimate
✓ Registry persistence can be abused by attackers
✓ CommandLine reveals the Registry operation and payload
✓ Parent process provides valuable context
✓ Filename/value name can be deceptive
✓ Don't blindly whitelist paths
✓ Detection ≠ confirmed compromise
✓ Preserve evidence before eradication
✓ Correlation produces stronger detections
```

## Day 10 Result

**Detection created:** `Suspicious Registry Run Key PowerShell Persistence`

**MITRE ATT&CK:** `T1547.001 — Registry Run Keys / Startup Folder`

**GitHub commit:**

```text
feat(day10): add registry run key PowerShell persistence detection
```

**Day 10 complete.**
