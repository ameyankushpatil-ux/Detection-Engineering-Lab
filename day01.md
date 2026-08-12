# Day 01 — Suspicious PowerShell Detection

## Objective

The objective of Day 01 was to understand how a detection engineer analyzes Windows process-creation telemetry and develops a basic Sigma detection for suspicious PowerShell activity.

The main lesson was:

> PowerShell execution by itself is not malicious. Detection logic should focus on suspicious behavior and supporting context.

## Scenario

The dataset contains Windows process-creation events involving PowerShell and other processes.

The investigation focused on:

* Process image
* Command line
* Parent process
* User
* Process creation event
* Suspicious PowerShell parameters
* Potential false positives

## Event Analysis

| Event   | Assessment           | Reason                                                                                                                                                              |
| ------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Event 1 | Suspicious           | PowerShell uses `-ExecutionPolicy Bypass`, which can weaken PowerShell execution restrictions.                                                                      |
| Event 2 | Likely Benign        | PowerShell runs `Get-Process`, which can be legitimate administrative activity.                                                                                     |
| Event 3 | Suspicious Indicator | PowerShell uses `-enc` / encoded command execution. The encoded content should be decoded and investigated before determining maliciousness.                        |
| Event 4 | Benign               | Notepad is launched normally from Explorer and no suspicious command-line behavior is present.                                                                      |
| Event 5 | Highly Suspicious    | PowerShell is hidden, uses `IEX`, downloads a remote script, and is launched by an executable in a temporary directory. Multiple suspicious indicators are present. |

## Detection Logic

The initial detection objective was to identify PowerShell processes using encoded commands.

Conceptually:

```text
IF process = powershell.exe
AND command line contains -enc or -EncodedCommand
THEN generate a detection
```

## Sigma Rule

The first detection created during Day 01 detects encoded PowerShell execution.

## False Positive Considerations

PowerShell is commonly used by:

* System administrators
* IT automation
* Software deployment systems
* Configuration management tools
* Security tools

Therefore, detecting every PowerShell execution would generate excessive false positives.

A better detection focuses on suspicious PowerShell behaviors and contextual indicators.

## Lessons Learned

### 1. Process name alone is insufficient

The presence of:

```text
powershell.exe
```

does not automatically indicate malicious activity.

### 2. Command-line arguments provide important context

Examples include:

```text
-enc
-EncodedCommand
-ExecutionPolicy Bypass
-WindowStyle Hidden
```

### 3. Parent-child relationships matter

A PowerShell process launched by a suspicious executable or unusual parent process can increase detection confidence.

### 4. Encoded commands require investigation

An encoded PowerShell command should not automatically be classified as malicious. The analyst should decode and inspect the content.

### 5. Multiple weak indicators can become a strong detection

For example:

```text
PowerShell
+
Hidden Window
+
IEX
+
DownloadString
+
Temporary Directory Parent
```

provides significantly stronger context than simply detecting PowerShell.

## Day 01 Outcome

Skills practiced:

* Windows process telemetry analysis
* PowerShell detection
* Command-line analysis
* Parent-child process analysis
* False-positive identification
* Basic Sigma syntax
* Detection engineering methodology

## Next Step

Day 02 will focus on Sigma YAML structure, field matching, detection selections, conditions, and creating more precise detection logic.
