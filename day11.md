# Day 11 — WMI Event Subscription Persistence Detection

## Objective

Detect suspicious **WMI Event Subscription** activity that can be abused for persistence and execution.

**MITRE ATT&CK:** `T1546.003 — Event Triggered Execution: WMI Event Subscription`

---

## Event Analysis

### Event 01 — Suspicious Indicator / Requires Context

```text
cmd.exe
   ↓
wmic.exe
   ↓
__EventFilter
   ↓
Win32_ProcessStartTrace
```

The query monitors process-start events. This can be legitimate monitoring activity, but it becomes more interesting when combined with a consumer that executes commands.

**Assessment:** Requires investigation; not malicious by itself.

---

### Event 02 — Highly Suspicious

```text
invoice.exe
   ↓
wmic.exe
   ↓
CommandLineEventConsumer
   ↓
powershell.exe
   ↓
-WindowStyle Hidden
   ↓
-EncodedCommand
```

Strong indicators:

* Suspicious parent from Temp
* WMI consumer creation
* PowerShell execution
* Hidden execution
* Encoded command

**Assessment:** Highly suspicious.

---

### Event 03 — Likely Benign

```text
cmd.exe
   ↓
wmic.exe process get name,processid
```

This is process enumeration and does not establish WMI persistence.

**Assessment:** Likely benign, although context should be considered.

---

### Event 04 — Enumeration / Investigation Required

```text
explorer.exe
   ↓
powershell.exe
   ↓
Get-CimInstance
   ↓
__EventFilter
```

This command is querying existing WMI event filters rather than creating persistence.

**Assessment:** Requires context; not inherently malicious.

---

### Event 05 — Highly Suspicious

```text
invoice.exe
   ↓
wmic.exe
   ↓
__FilterToConsumerBinding
   ↓
WindowsUpdateFilter
   +
WindowsUpdateConsumer
```

This connects the WMI trigger to the command consumer.

Combined with the suspicious `invoice.exe` parent, this represents a strong persistence indicator.

**Assessment:** Highly suspicious.

---

# Task 02 — WMI Persistence Structure

A common WMI persistence chain is:

```text
__EventFilter
      ↓
CommandLineEventConsumer
      ↓
__FilterToConsumerBinding
```

### `__EventFilter`

Defines **what event should trigger** the action.

Example:

```text
Win32_ProcessStartTrace
```

means the filter can react to process-start events.

### `CommandLineEventConsumer`

Defines **what command should execute** when the trigger occurs.

Example:

```text
powershell.exe -WindowStyle Hidden -EncodedCommand ...
```

### `__FilterToConsumerBinding`

Connects the filter and consumer.

```text
Trigger
  ↓
__EventFilter
  ↓
Binding
  ↓
Consumer
  ↓
Command
```

This relationship is extremely important when investigating WMI persistence.

---

# Task 03 — Strongest Event

**Event 05** is the strongest persistence indicator because it creates the binding between the event filter and consumer.

However, the strongest overall malicious chain is:

```text
Event 01
   +
Event 02
   +
Event 05
```

Together:

```text
Event Filter
     ↓
Command Consumer
     ↓
Filter/Consumer Binding
     ↓
PowerShell Payload
```

This is much stronger than treating Event 05 in isolation.

---

# Task 04 — Detection Logic

Your original logic focused on specific names:

```text
WindowsUpdateFilter
WindowsUpdateConsumer
```

That would be fragile because attackers can choose different names.

A better detection is:

```text
IF Image is wmic.exe
AND CommandLine contains root\subscription
AND CommandLine creates a WMI consumer
AND CommandLine contains PowerShell
AND CommandLine contains encoded execution
THEN generate a high-confidence detection
```

---

# Task 05 — Detection Strategy

**Detection A is too broad.**

```text
wmic.exe = alert
```

would create significant noise.

A better approach is:

```text
WMI activity
     ↓
Identify persistence-related classes
     ↓
Identify consumer
     ↓
Identify payload
     ↓
Analyze parent
     ↓
Correlate events
```

For example:

```text
__EventFilter
+
CommandLineEventConsumer
+
__FilterToConsumerBinding
+
Suspicious PowerShell
```

provides much stronger evidence.

---

# Task 06 — Sigma Rule

```yaml
title: Suspicious WMI Event Subscription with Encoded PowerShell
id: 00000000-0000-0000-0000-000000000012
status: experimental
description: Detects WMIC activity creating a WMI event subscription that executes encoded PowerShell.
author: Amey Patil
date: 2026-08-20

logsource:
    product: windows
    category: process_creation

detection:

    selection_image:
        Image|endswith: '\wmic.exe'

    selection_namespace:
        CommandLine|contains: '\root\subscription'

    selection_create:
        CommandLine|contains: 'CREATE'

    selection_consumer:
        CommandLine|contains: 'CommandLineEventConsumer'

    selection_powershell:
        CommandLine|contains:
            - 'powershell.exe'
            - 'pwsh.exe'

    selection_encoded:
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc'

    condition: selection_image and selection_namespace and selection_create and selection_consumer and selection_powershell and selection_encoded

falsepositives:
    - Legitimate enterprise management tools
    - Authorized administrative automation
    - Security testing
    - Monitoring software

level: high

tags:
    - attack.persistence
    - attack.execution
    - attack.t1546.003
    - attack.t1059.001
```

### Important Improvements

Your original rule was already heading in the right direction, but there were several improvements:

**1. Don't depend on specific names**

Avoid:

```text
WindowsUpdateFilter
WindowsUpdateConsumer
```

Attackers can simply change the names.

**2. Detect the actual WMI consumer**

```text
CommandLineEventConsumer
```

is more meaningful than just detecting `CREATE`.

**3. Correct Sigma syntax**

Use:

```yaml
Image|endswith:
CommandLine|contains:
```

rather than inconsistent capitalization such as `endwith`, `Contain`, and `CommmandLine`.

---

# Task 07 — Parent Process Analysis

This chain is highly suspicious:

```text
invoice.exe
     ↓
wmic.exe
     ↓
WMI persistence
     ↓
PowerShell
```

Why?

Because several independent signals align:

```text
Suspicious parent
      +
Administrative utility
      +
Persistence mechanism
      +
PowerShell
      +
Encoded command
```

This is much stronger than:

```text
explorer.exe
     ↓
powershell.exe
```

Context determines the risk.

---

# Task 08 — False-Positive Tuning

Don't create:

```text
wmic.exe → Alert
```

as the final production rule.

WMI is widely used by:

* Enterprise management
* Monitoring
* IT administration
* Security software
* Automation

Instead, focus on suspicious combinations.

### Better signals

```text
1. WMI persistence classes
2. CommandLineEventConsumer
3. Suspicious payload
4. Suspicious parent process
5. Encoded/hidden PowerShell
```

This provides better detection quality than simply alerting on `wmic.exe`.

---

# Task 09 — L3 Investigation Checklist

When this alert fires, investigate:

```text
1. WMI namespace
2. EventFilter name
3. WQL query
4. Consumer type
5. Consumer command
6. Filter-to-consumer binding
7. Creating process
8. Parent process
9. Creating user
10. PowerShell command
11. Encoded payload
12. File hash
13. Digital signature
14. Process execution after trigger
15. Network connections
16. Other persistence mechanisms
17. Related hosts/users
```

### L3 Investigation Flow

```text
WMI Alert
    ↓
Identify Filter
    ↓
Identify Consumer
    ↓
Identify Binding
    ↓
Analyze Payload
    ↓
Identify Trigger
    ↓
Trace Process Execution
    ↓
Check Network Activity
    ↓
Search Other Persistence
    ↓
Scope Environment
    ↓
Determine Verdict
```

---

# Day 11 Key Lessons

```text
✓ WMI can be used for legitimate administration
✓ WMI can also provide stealthy persistence
✓ __EventFilter defines the trigger
✓ CommandLineEventConsumer defines the action
✓ __FilterToConsumerBinding connects them
✓ wmic.exe alone is not malicious
✓ Specific object names should not be hardcoded
✓ Parent process adds important context
✓ Encoded PowerShell increases detection confidence
✓ Multiple events can form one attack chain
✓ Detection ≠ confirmed compromise
✓ L3 investigation should correlate process, WMI, file and network evidence
```

## Day 11 Result

**Detection created:** `Suspicious WMI Event Subscription with Encoded PowerShell`

**MITRE ATT&CK:**

```text
T1546.003 — Event Triggered Execution: WMI Event Subscription
T1059.001 — PowerShell
```

**GitHub commit:**

```text
feat(day11): add WMI event subscription persistence detection
```

**Day 11 complete.**
