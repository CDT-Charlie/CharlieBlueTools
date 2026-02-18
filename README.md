# SecureWin.ps1  
Windows Hardening Script  

SecureWin.ps1 is a modular Windows hardening script designed for blue team.

It supports running all hardening phases at once or executing individual phases independently.

---

## Overview of Phases

### Phase 1 – User Account Management
- Removes unauthorized user accounts  
- Audits 16 privileged groups  
- Detects blank passwords and suspicious SIDs  
- Resets all passwords to the team password  
- Generates a user audit report  

### Phase 2 – Password Policy Hardening
- Enforces minimum 16-character password length  
- Sets maximum password age to 90 days  
- Sets minimum password age to 1 day  
- Configures 3-attempt account lockout threshold  

### Phase 3 – Firewall Hardening
- Enables Windows Firewall on all profiles  
- Configures allowed ports for scored services  
- Whitelists scoring and jumpbox IP addresses  

### Phase 4 – SSH Hardening
- Restricts SSH access to authorized users  
- Enforces strong ciphers and authentication methods  

### Phase 5 – Network Security
- Disables SMBv1  
- Disables LLMNR  
- Disables NetBIOS  
- Maintains SMBv2/3 compatibility where required  

### Phase 6 – Backdoor Detection
- Scans scheduled tasks  
- Scans services  
- Reviews startup locations  
- Identifies common persistence mechanisms  

### Phase 7 – System Hardening
- Configures UAC settings  
- Enables DEP  
- Enables Windows Defender  
- Disables AutoRun  
- Disables Windows Script Host  
- Disables PowerShell v2  

### Phase 8 – Audit Logging Configuration
- Enables advanced audit policies  
- Enables PowerShell logging  
- Enables command-line logging  

---

## Requirements

- Windows system  
- Administrator privileges  
- PowerShell 5.1 or later  
- Execution policy that allows script execution  

---

## Installation and Execution

### 1. Download the Script

Clone or download this repository from GitHub and place `SecureWin.ps1` on the target system.

---

### 2. Open PowerShell as Administrator

1. Open Start  
2. Search for **PowerShell**  
3. Right-click → **Run as Administrator**  

Administrator privileges are required.

---

### 3. Temporarily Allow Script Execution

```powershell
Set-ExecutionPolicy Bypass
```
Then, type "A" and then enter to Allow all runs.

---

### 4. Navigate to the Script Location

```powershell
cd ~\Downloads
```

---

### 5. Execute the Script
Run All Phases
```powershell
.\SecureWin.ps1
```
OR
```powershell
.\SecureWin.ps1 -All
```
This performs a full system hardening and runs all phases

---

Running a Single Phase
```powershell
.\SecureWin.ps1 -Phase1
```

---

Running Multiple Phases
```powershell
.\SecureWin.ps1 -Phase1 -Phase3 -Phase8
```
Run Multiple Phases (Numeric List Format)
```powershell
.\SecureWin.ps1 -Phases 1,3,8
```
OR
```powershell
.\SecureWin.ps1 -Phases 1 3 8
```

---

Display the Help Menu
```powershell
.\SecureWin.ps1 -Help
```

---

### Argument Reference
| Argument | Description |
|---|---|
| `-Help` | Displays the help menu |
| `-All` | Runs all phases |
| `-Phase1` | User Account Management |
| `-Phase2` | Password Policy Hardening |
| `-Phase3` | Firewall Hardening |
| `-Phase4` | SSH Hardening |
| `-Phase5` | Network Security |
| `-Phase6` | Backdoor Detection |
| `-Phase7` | System Hardening |
| `-Phase8` | Audit Logging Configuration |
| `-Phases 1,3,8` | Rund selected phases by number |

---

### Logging
Logs are written to:
```makefile
C:\BlueTeam\Logs\
```

---

Naming Convention:
- Full run: `Hardening-YYYY-MM-DD-HHMMSS.log`
- Selected phases: `Hardening-Phases-1-3-8-YYYY-MM-DD-HHMMSS.log`

---

### Operational Notes
- The script must be run as Administrator.
- Running individual phases does not trigger a system restart.
- A full run may trigger a restart depending on configuration.
- Each phase is designed to be independently executable.
