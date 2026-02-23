# SecureWin.ps1  
Windows Hardening Script – Competition Edition  

SecureWin.ps1 is a modular Windows hardening script built for blue team competition environments.

It performs rapid, rule-aware system hardening while preserving required scoring infrastructure access.

---

## REQUIRED PRE-RUN CONFIGURATION

Before running the script, you MUST edit the configuration variables at the top of the script.

### Required Variables to Review

- `$AuthorizedAdmins`  
  Add your blue team administrator usernames. This should be already completed for you :)

- `$SetAllUserPasswords`  
  Set this to the approved competition password. `YOU MUST DO THIS INDEPENDENTLY TO ENSURE SECRECY! (LINE 251)`

- `$SafeUsers` (Optional but recommended)  
  Ensure all authorized competition users are protected.

Failure to configure these variables properly may result in breaking scoring services or violating competition rules.

---

## Competition Rule Awareness

This script is designed to comply with common blue team competition rules, including:

- Do not disable valid packet users  
- Do not disable RDP on Windows systems  
- Do not block entire subnets  
- Do not modify artifacts containing “greyteam”  
- Password changes must follow competition policy  
- Preserve scoring infrastructure connectivity  

Safeguards are built in to reduce accidental rule violations.

---

## Hardening Phases

The script supports running all phases at once or executing individual phases independently.

---

### Phase 1 – User Account Management

- Removes unauthorized local users  
- Audits 16 privileged groups  
- Detects blank passwords and suspicious SIDs  
- Resets user passwords (competition compliant)  
- Generates a user audit report  

---

### Phase 2 – Password Policy Hardening

- Enforces minimum 16-character password length  
- Sets password aging policy  
- Configures account lockout threshold  

---

### Phase 3 – Firewall Hardening

- Enables Windows Firewall on all profiles  
- Configures allowed ports for scored services  
- Whitelists scoring engine and jumpbox IP addresses  
- Prevents improper subnet blocking  

---

### Phase 4 – SSH Review (Conditional)

If SSH is present:

- Reviews SSH configuration  
- Removes insecure access  
- Ensures rule compliance  

---

### Phase 5 – Network Security Hardening

- Disables SMBv1  
- Disables LLMNR  
- Disables NetBIOS (where appropriate)  
- Preserves SMBv2/3 compatibility  

---

### Phase 6 – Persistence and Backdoor Detection

- Scans scheduled tasks  
- Scans services  
- Reviews startup locations  
- Identifies common persistence mechanisms  

---

### Phase 7 – System Hardening

- Configures UAC settings  
- Enables DEP  
- Enables Windows Defender  
- Disables AutoRun  
- Disables Windows Script Host  
- Disables PowerShell v2  

---

### Phase 8 – Audit Logging Configuration

- Enables advanced audit policies  
- Enables PowerShell logging  
- Enables command-line logging  
- Improves forensic visibility  

---

## Compatibility

Confirmed working on:

- Windows Server 2025  
- Windows Server 2022  
- Windows Server 2019  
- Windows Server 2016  
- Windows 11
- Windows 10

Requires:

- PowerShell 5.1 or later  
- Administrator privileges  
- Execution policy allowing script execution  

---

## Installation and Execution

### 1. Run PowerShell as Administrator

Open Start  
Search for PowerShell  
Right-click → Run as Administrator  

---

### 2. Temporarily Allow Script Execution (if required)

```powershell
Set-ExecutionPolicy Bypass
```

Type `A` and press Enter to allow all runs.

---

### 3. Navigate to Script Location

```powershell
cd C:\Path\To\Script
```

---

### 4. Execute the Script

#### Run All Phases

```powershell
.\SecureWin.ps1
```

or

```powershell
.\SecureWin.ps1 -All
```

---

#### Run a Single Phase

```powershell
.\SecureWin.ps1 -Phase1
```

---

#### Run Multiple Phases

```powershell
.\SecureWin.ps1 -Phase1 -Phase3 -Phase8
```

or

```powershell
.\SecureWin.ps1 -Phases 1,3,8
```

---

#### Display the Help Menu

```powershell
.\SecureWin.ps1 -Help
```

---

## Argument Reference

| Argument | Description |
|----------|------------|
| `-Help` | Displays the help menu |
| `-All` | Runs all phases |
| `-Phase1` | User Account Management |
| `-Phase2` | Password Policy Hardening |
| `-Phase3` | Firewall Hardening |
| `-Phase4` | SSH Review |
| `-Phase5` | Network Security |
| `-Phase6` | Persistence Scan |
| `-Phase7` | System Hardening |
| `-Phase8` | Audit Logging |
| `-Phases 1,3,8` | Run selected phases by number |

---

## Logging

Logs are written to:

```
C:\BlueTeam\Logs\
```

### Naming Convention

Full run:  
`Hardening-YYYY-MM-DD-HHMMSS.log`

Selected phases:  
`Hardening-Phases-1-3-8-YYYY-MM-DD-HHMMSS.log`

Logs include:

- Hostname  
- Script run count  
- Timestamp  
- Phase execution details  
- Critical alerts  

---

## Operational Notes

- The script must be run as Administrator.  
- Individual phases do not force a system restart.  
- A full run may trigger a restart depending on configuration.  
- Each phase is independently executable.  

---
