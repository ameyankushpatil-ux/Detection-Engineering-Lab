# Day 09 — Windows Service Creation Detection

## Objective

Detect suspicious Windows service creation using `sc.exe` and identify potential persistence or execution through malicious service configurations.

---

## Event Analysis

### Event 01 — Likely Benign / Requires Validation

```text
cmd.exe
   ↓
sc.exe create WindowsUpdate
   ↓
C:\Program Files\Updater\update.exe
   ↓
start= auto
```

The service is configured to start automatically. `C:\Program Files\` is a common legitimate software location, but the executable and signer should be validated.

**Assessment:** Likely benign, but requires validation.

---

### Event 02 — Highly Suspicious

```text
invoice.exe
   ↓
sc.exe create SecurityUpdate
   ↓
C:\Users\john\AppData\Local\Temp\update.exe
   ↓
start= auto
```

Important indicators:

* Service created for persistence
* Executable located in a user's Temp directory
* Suspicious parent process
* Generic service name
* Automatic startup

**Assessment:** Highly suspicious.

---

### Event 03 — Likely Benign

```text
cmd.exe
   ↓
sc.exe query WinDefend
```

`/query` is used to retrieve service information rather than create a service.

**Assessment:** Likely benign, although unexpected service enumeration should still be investigated in the right context.

---

### Event 04 — Likely Benign / Requires Validation

```text
BackupApp\installer.exe
   ↓
sc.exe create BackupService
   ↓
C:\Program Files\BackupApp\backup.exe
   ↓
start= auto
```

This is consistent with legitimate software installation.

**Assessment:** Likely benign, but validate the application, signer and installation activity.

---

### Event 05 — Highly Suspicious

```text
invoice.exe
   ↓
sc.exe create WindowsTelemetry
   ↓
powershell.exe
   ↓
-WindowStyle Hidden
   ↓
-EncodedCommand
   ↓
start= auto
```

Multiple high-risk indicators are combined:

* Service creation
* Automatic startup
* PowerShell execution
* Hidden PowerShell
* Encoded command
* Suspicious parent from Temp
* Misleading service name

**Assessment:** Highly suspicious.

---

# Task 02 — Understanding `sc.exe`

| Parameter        | Meaning                                       |
| ---------------- | --------------------------------------------- |
| `sc.exe`         | Windows Service Control utility               |
| `create`         | Creates a Windows service                     |
| `SecurityUpdate` | Service name                                  |
| `binPath=`       | Program/command executed by the service       |
| `start= auto`    | Configures the service to start automatically |

### Important Correction

`sc.exe` does **not** create an "automatic script."

It manages **Windows services**.

The important relationship is:

```text
Service
   ↓
binPath
   ↓
Executable / Command
   ↓
Service startup
```

---

# Task 03 — Most Important Fields

For today's detection:

```text
1. CommandLine
2. ParentImage
3. Image
4. User
```

### Why?

**CommandLine** tells us whether the service is being created and what it will execute.

**ParentImage** provides process ancestry and can reveal suspicious execution chains.

**Image** confirms that `sc.exe` is involved.

**User** provides identity context and helps determine whether the activity is expected.

---

# Task 04 — Detection Logic

A basic detection:

```text
IF Image is sc.exe
AND CommandLine contains create
AND CommandLine contains powershell.exe
THEN generate a detection
```

A stronger detection:

```text
IF Image is sc.exe
AND CommandLine contains create
AND CommandLine contains powershell.exe
AND CommandLine contains encoded PowerShell
THEN generate a high-confidence detection
```

---

# Task 05 — Detection Quality

**Detection D** is the strongest starting point from the four options because it combines multiple behavioral indicators:

```text
sc.exe
 +
create
 +
PowerShell
 +
encoded command
```

However, for production we should also consider:

```text
Suspicious binary path
+
Suspicious parent
+
Automatic startup
```

This produces stronger contextual confidence.

---

# Task 06 — Sigma Rule

```yaml
title: Suspicious Windows Service Creating Encoded PowerShell
id: 00000000-0000-0000-0000-000000000010
status: experimental
description: Detects Windows service creation through sc.exe that configures an encoded PowerShell command for execution.
author: Amey Patil
date: 2026-08-17

logsource:
    product: windows
    category: process_creation

detection:
    selection_image:
        Image|endswith: '\sc.exe'

    selection_create:
        CommandLine|contains: ' create '

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
    - attack.t1543.003
    - attack.execution
    - attack.t1059.001
```

### Rule Logic

```text
sc.exe
   ↓
create
   ↓
PowerShell
   ↓
EncodedCommand
   ↓
High-confidence detection
```

**Note:** Your original title said "scheduled task"; this is a **Windows service**, not a scheduled task.

---

# Task 07 — Additional Detection

Your idea is correct.

Don't make one giant rule for everything.

Create separate detections for:

```text
Service creation
        +
Suspicious Temp binary
```

and:

```text
Service creation
        +
PowerShell
        +
EncodedCommand
```

and potentially:

```text
Service creation
        +
Suspicious parent
```

Then correlate them when appropriate.

---

# Task 08 — MITRE ATT&CK

**T1543.003 — Create or Modify System Process: Windows Service**

Windows services can be abused for **persistence** because an attacker can configure a malicious service to execute automatically.

They can also be used for **execution**, because the service's `binPath` determines what program or command is launched.

---

# Task 09 — L3 Investigation Approach

When this alert fires, investigate:

### 1. Service Name

Is it legitimate or suspicious?

Names such as:

```text
WindowsUpdate
SecurityUpdate
WindowsTelemetry
```

should not automatically be trusted.

### 2. Service Binary Path

Determine:

* Where is the executable?
* Is it in `System32`?
* `Program Files`?
* `Temp`?
* User profile?
* Does the path exist?

A Temp-directory executable is significantly more concerning.

### 3. Service Account

Determine which account runs the service.

Check whether the account is:

* Expected
* Privileged
* Newly created
* Compromised

Don't immediately assume a SYSTEM service is malicious.

### 4. Start Type

Determine whether the service starts:

```text
Automatically
Manually
On demand
```

Automatic startup increases persistence relevance.

### 5. Parent Process

Investigate the process that created the service.

Example:

```text
invoice.exe
    ↓
sc.exe
    ↓
Malicious Service
```

is highly suspicious.

### 6. Creating User

Identify who created the service and whether the activity matches their expected role.

### 7. File Hash

Collect the binary hash and check it against approved threat-intelligence and internal reputation sources.

### 8. Digital Signature

Check:

* Publisher
* Certificate
* Signature validity
* Whether the signer matches the expected software

### 9. File Timeline

Correlate:

```text
File creation
      ↓
Service creation
      ↓
Service execution
      ↓
Network activity
```

Don't use "night-time activity" alone as evidence of compromise; timezone, shift patterns and automation matter.

### 10. Network Connections

Determine whether the service subsequently communicates with:

* External IPs
* Suspicious domains
* Known C2 infrastructure
* Unusual destinations

---

# Day 09 Key Lessons

```text
✓ sc.exe is a legitimate Windows utility
✓ sc.exe create creates a Windows service
✓ binPath defines the service executable/command
✓ start= auto can provide persistence
✓ Service names can be deceptive
✓ Temp-directory binaries require investigation
✓ Parent process adds important context
✓ PowerShell + encoded command increases confidence
✓ Detection ≠ confirmed compromise
✓ L3 investigation requires process + file + identity + network context
```

## Day 09 Result

**Detection created:** `Suspicious Windows Service Creating Encoded PowerShell`

**MITRE ATT&CK:** `T1543.003`, `T1059.001`

**GitHub commit:**

```text
feat(day09): add suspicious Windows service creation detection
```

**Day 09 complete.**
