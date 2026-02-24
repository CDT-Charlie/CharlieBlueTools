#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Blue Team Windows Hardening Script for CDT Competition - Team Charlie Spring 2026
.DESCRIPTION
    Comprehensive hardening script designed for Blue vs Red team competitions.
    Removes unauthorized users, hardens SSH, configures firewall, and locks down the system
    while preserving competition infrastructure through whitelisting.
    
.BEFORE_RUNNING
    **REQUIRED CONFIGURATION - EDIT THESE VARIABLES:**
    
    1. $AuthorizedAdmins - Add your blue team usernames (I did this for you already!)
    
    2. $SetAllUserPasswords - Change to YOUR secure password @(line 258)
    
    3. $SafeIPAddresses - Verify scoring engine/jumpbox IPs (Should be done already as well!)
    
    **OPTIONAL:** Review $SafeUsers to ensure all competition users are protected
    
.CRITICAL_RULES
    Rule 9: DO NOT disable any valid user accounts listed in the packet
    Rule 10: DO NOT disable RDP on Windows (SSH on Windows is NOT required - remove it!)
    Rule 15: Blue Team may request up to 3 host reverts per competition day
    Rule 7: DO NOT block entire subnets (no subnet blocking)
    Rule 14: Password changes limited to 3 per host per comp session
    Rule 5: DO NOT modify artifacts with "greyteam" in their name
    
.SCORED_SERVICES
    Windows Servers: canterlot (AD), manehatten (MSSQL), las-pegasus (IIS), appleloosa (SMB)
    Linux Servers: ponyville (Apache2), seaddle (MariaDB), trotsylvania (CUPS), 
                   crystal-empire (vsftpd), everfree-forest (IRC), griffonstone (Nginx)
    Workstations: 3x Windows 10, 3x Ubuntu 24.04
    
.NOTES
    Author: Christian Tomassetti + Claude AI
    Requires: PowerShell 5.1+ and Administrator privileges
    Last Updated: 02/23/2026
    
.EXAMPLE
    # Run the script (after configuring variables above)
    .\SecureWin.ps1

.COMPATABILITY
    Works with:
        Windows Server 2025: CONFIRMED
        Windows Server 2022: CONFIRMED
        Windows Server 2019: CONFIRMED
        Windows Server 2016: CONFIRMED
        Windows 11: CONFIRMED
        Windows 10: CONFIRMED
#>
[CmdletBinding()]
param(
    [switch]$Help,

    # Run all phases (same as no args)
    [switch]$All,

    # Run specific phases via individual switches
    [switch]$Phase1,
    [switch]$Phase2,
    [switch]$Phase3,
    [switch]$Phase4,
    [switch]$Phase5,
    [switch]$Phase6,
    [switch]$Phase7,
    [switch]$Phase8,

    # Run specific phases via a list (e.g., -Phases 1,3,8)
    [int[]]$Phases
)

# Display help menu
if ($Help) {
    Write-Host @"

================================================================================
                    SecureWin.ps1 - Windows Hardening Script
                    CDT Team Charlie - Spring 2026
                    Time to lock out Red... For good :)
================================================================================

USAGE:
    .\SecureWin.ps1 [OPTIONS]

OPTIONS:
    -Help          Display this help menu               - See how to use the script as a multitool!

    -All           Run ALL phases (same as no args)     - Run the entire script (FIRST RUN THIS!)

    -Phase1        User Account Management (Enhanced)   - Handle unwanted users and change passwords!

    -Phase2        Password Policy Hardening            - Ensures passwords are strong and reliable!

    -Phase3        Firewall Hardening                   - Removes default vulnerable rules + adds allow rules!

    -Phase4        SSH Removal                          - Nukes SSH on Windows!

    -Phase5        Network Security                     - Disables vulnerable protocols!

    -Phase6        Backdoor Detection                   - Checks for sneaky persistence!

    -Phase7        System Hardening                     - Hardens/disables vulnerable Windows features!

    -Phase8        Audit Logging Configuration          - Enables advanced auditing!

    -Phases        Run selected phases by number        - e.g., "./SecureWin -Phases 1,3,8"

DEFAULT:
    (no args)      Run ALL phases                       - Runs the entire script by default!

EXAMPLES:
    .\SecureWin.ps1
    .\SecureWin.ps1 -All
    .\SecureWin.ps1 -Phase1
    .\SecureWin.ps1 -Phase1 -Phase3 -Phase8
    .\SecureWin.ps1 -Phases 1,3,8
    .\SecureWin.ps1 -Help

================================================================================
"@ -ForegroundColor Cyan
    exit 0
}

# Determine which phases to run
$noArgs = (-not $PSBoundParameters.Count)

# If -All is supplied or no args are supplied, run everything
if ($All -or $noArgs) {
    $RunPhase1 = $true
    $RunPhase2 = $true
    $RunPhase3 = $true
    $RunPhase4 = $true
    $RunPhase5 = $true
    $RunPhase6 = $true
    $RunPhase7 = $true
    $RunPhase8 = $true

    $RunningIndividualPhase = $false
    $SelectedPhases = @(1,2,3,4,5,6,7,8)
} else {
    # Build selected phase list from -Phases and -PhaseX switches (can be mixed)
    $SelectedPhases = @()

    if ($Phases) {
        foreach ($p in $Phases) { $SelectedPhases += $p }
    }
    if ($Phase1) { $SelectedPhases += 1 }
    if ($Phase2) { $SelectedPhases += 2 }
    if ($Phase3) { $SelectedPhases += 3 }
    if ($Phase4) { $SelectedPhases += 4 }
    if ($Phase5) { $SelectedPhases += 5 }
    if ($Phase6) { $SelectedPhases += 6 }
    if ($Phase7) { $SelectedPhases += 7 }
    if ($Phase8) { $SelectedPhases += 8 }

    # Normalize: unique + sorted
    $SelectedPhases = $SelectedPhases | Where-Object { $_ -ne $null } | ForEach-Object { [int]$_ } | Sort-Object -Unique

    # Validate range
    $invalid = $SelectedPhases | Where-Object { $_ -lt 1 -or $_ -gt 8 }
    if ($invalid) {
        Write-Host "ERROR: Invalid phase number(s): $($invalid -join ', '). Valid phases are 1-8." -ForegroundColor Red
        exit 1
    }

    # Set run flags
    $RunPhase1 = $SelectedPhases -contains 1
    $RunPhase2 = $SelectedPhases -contains 2
    $RunPhase3 = $SelectedPhases -contains 3
    $RunPhase4 = $SelectedPhases -contains 4
    $RunPhase5 = $SelectedPhases -contains 5
    $RunPhase6 = $SelectedPhases -contains 6
    $RunPhase7 = $SelectedPhases -contains 7
    $RunPhase8 = $SelectedPhases -contains 8

    $RunningIndividualPhase = $true

    # Banner
    $phaseLabel = ($SelectedPhases -join ", ")
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RUNNING SELECTED PHASE(S): $phaseLabel" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

# ============================================================================
# CRITICAL COMPETITION VARIABLES - CDT TEAM CHARLIE SPRING 2026
# ============================================================================

# USER MANAGEMENT - CDT Competition Users (DO NOT REMOVE OR DISABLE!)
# Per Rule 9: Do not disable any valid user accounts listed in the competition packet
$SafeUsers = @(
    # Windows Default Users
    "Administrator",
    "DefaultAccount", # should be disabled (if not disable it)
    "Guest", # should be disabled (if not disable it)
    "WDAGUtilityAccount", # should be disabled (if not disable it)
    
    # Local Users (from competition packet)
    "twilight",
    "pinkiepie",
    "applejack",
    "rarity",
    "rainbowdash",
    "fluttershy",
    
    # Local Admin Users (from competition packet)
    "bigmac",
    "mayormare",
    "shiningarmor",
    "cadance",
    
    # Domain Users (from competition packet)
    "spike",
    "starlight",
    "trixie",
    "derpy",
    "snips",
    "snails",
    
    # Domain Admin Users (from competition packet)
    "celestia",
    "discord",
    "luna",
    "starswirl",
    
    # Gray Team (anything with "greyteam" per Rule 3 & 5)
    "greyteam",
    "grayteam",
    "gray_team",
    "grey_team",
    "scoring" # Added scoring user to ensure scoring is not interupted
)

# List of users that should have admin access and password reset
# These are YOUR blue team users - add them here
$AuthorizedAdmins = @(
    "blueadmin"
    # Add your blue team members here
)

# Password to set for all authorized blue team users (CHANGE THIS BEFORE RUNNING!)
# NOTE: Use only these special characters: ! @ $ % ^ & * ( ) - _ = + [ ] { } ; : , . ?
# The # symbol can cause issues with Windows password complexity

# IMPORTANT: This password must NOT contain 3+ consecutive characters from any authorized admin username.
# Windows complexity policy will reject the password at user-creation time if it does.
# For "blueadmin", avoid these substrings: blu, lue, uea, ead, adm, dmi, min





# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

$SetAllUserPasswords = "<CHANGE-PASSWORD-HERE-BEFORE-RUNNING>" # DO NOT SHARE THIS PASSWORD WITH ANYONE!

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!






# NETWORK SECURITY - CDT Competition Network
# IP addresses that should NEVER be blocked (scoring engine, gray team, jumpboxes)
# Per Rule 7: Do not configure firewall rules that block large IP ranges
$SafeIPAddresses = @(
    "172.20.0.100",      # Scoring engine (critical!)
    "172.20.0.41",       # jumpblue1
    "172.20.0.42",       # jumpblue2
    "172.20.0.43",       # jumpblue3
    "172.20.0.44",       # jumpblue4
    "172.20.0.45",       # jumpblue5
    "172.20.0.46",       # jumpblue6
    "172.20.0.47",       # jumpblue7
    "172.20.0.48",       # jumpblue8
    "172.20.0.49",       # jumpblue9
    "172.20.0.40"        # jumpblue10
)

# IP ranges to allow (in CIDR notation)
# IMPORTANT: Per Rule 7, do NOT block entire subnets
# These ranges are for ALLOW rules only, not BLOCK rules
$SafeIPRanges = @(
    "10.0.10.0/24",      # Core Subnet (scored services)
    "10.0.20.0/24",      # DMZ Subnet (scored services)
    "10.0.30.0/24"       # Internal Subnet (workstations)
)

# SSH CONFIGURATION
# Rule 10: SSH is NOT required on Windows - if found it must be REMOVED and BLOCKED.
# Only RDP must remain open on Windows machines.
# (SSH hardening is handled in Phase 4 - it will nuke SSH entirely if found)

# FIREWALL CONFIGURATION
$BlockAllInboundByDefault = $true        # Block all inbound except allowed
# Port 3389 (RDP) is always opened - it is required per Rule 10.
# All other service ports are determined interactively in Phase 3 based on
# which scored service is running on THIS host. Do NOT open ports for services
# that are not running here - that is an unnecessary attack surface.
#
# Windows service -> ports mapping (for reference):
#   Active Directory : 88 (Kerberos), 135 (RPC), 389 (LDAP), 445 (SMB),
#                      636 (LDAPS), 3268 (GC), 3269 (GC SSL), 49152-65535 (RPC dynamic)
#   MSSQL            : 1433
#   IIS              : 80, 443
#   SMB              : 445
#   Workstation      : (no additional service port - RDP only)
$LogDroppedPackets = $true               # Log all dropped packets
$LogAllowedConnections = $true           # Log allowed connections

# BACKDOOR DETECTION
$ScanForBackdoors = $true                # Scan for common backdoors
$RemoveSuspiciousScheduledTasks = $true  # Remove suspicious scheduled tasks
$DisableSuspiciousServices = $true       # Disable suspicious services

# AUDIT AND LOGGING
$VerboseLogging = $true                  # Enable verbose logging to console
$AuditLogSize = 2048MB                   # Maximum size for Security event log
$EnableAdvancedAuditing = $true          # Enable detailed audit policies
# Log file path (phase-aware)
if ($RunningIndividualPhase) {
    $phaseSuffix = ""
    if ($SelectedPhases) {
        $phaseSuffix = "Phases-" + ($SelectedPhases -join "-") + "-"
    } else {
        $phaseSuffix = "Phase-"
    }
    $LogFilePath = "C:\BlueTeam\Logs\Hardening-$phaseSuffix$(Get-Date -Format yyyy-MM-dd-HHmmss).log"
} else {
    $LogFilePath = "C:\BlueTeam\Logs\Hardening-$(Get-Date -Format yyyy-MM-dd-HHmmss).log"
}

# PASSWORD POLICY
$MinPasswordLength = 16                  # Minimum password length
$MaxPasswordAge = 90                     # Maximum password age in days
$MinPasswordAge = 1                      # Minimum password age in days
$PasswordHistoryCount = 24               # Passwords to remember
$AccountLockoutThreshold = 3             # Failed attempts before lockout
$AccountLockoutDuration = 30             # Lockout duration in minutes

# SYSTEM HARDENING
$DisableSMBv1 = $true                    # Disable SMBv1 (critical!)
$DisableRDP = $false                     # CRITICAL: Per Rule 10 - CANNOT disable RDP!
$EnableWindowsDefender = $false           # Disable Windows Defender - enable is not allowed!
$DisableUSBStorage = $false              # Disable USB storage devices
$DisablePowerShellV2 = $true             # Disable PowerShell v2

# PERSISTENCE SCANNING
$ScanStartupLocations = $true            # Scan common persistence locations
$BackupRegistryBeforeChanges = $true     # Backup registry keys before modification

# REPORTING
$CreateDetailedReport = $true            # Generate detailed hardening report

# ============================================================================
# SCRIPT INITIALIZATION - Do not modify below
# ============================================================================

$ErrorActionPreference = "Continue"
$ScriptStartTime = Get-Date
$Changes = @()
$SecurityIssues = @()
$RemovedUsers = @()
$RemovedItems = @()

# Detect hostname to prevent breaking scored services
$hostname = $env:COMPUTERNAME.ToLower()
Write-Host "Detected hostname: $hostname" -ForegroundColor Cyan

# Track script runs
$runCounterPath = "C:\BlueTeam\script-run-counter.txt"
$runCounterDir = Split-Path -Path $runCounterPath -Parent
if (-not (Test-Path $runCounterDir)) {
    New-Item -ItemType Directory -Path $runCounterDir -Force | Out-Null
}

$scriptRunCount = 1
if (Test-Path $runCounterPath) {
    try {
        $scriptRunCount = [int](Get-Content $runCounterPath) + 1
    } catch {
        $scriptRunCount = 1
    }
}
Set-Content -Path $runCounterPath -Value $scriptRunCount

Write-Host "Script run count: $scriptRunCount" -ForegroundColor Cyan
if ($scriptRunCount -gt 1) {
    Write-Host "NOTE: This is run #$scriptRunCount - idempotent operations will be skipped" -ForegroundColor Yellow
}

# Create log directory if it doesn't exist
$LogDirectory = Split-Path -Path $LogFilePath -Parent
if (-not (Test-Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}

function Write-BlueTeamLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [switch]$Critical
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Color coding for console output
    switch ($Level) {
        "ERROR"   { Write-Host $logMessage -ForegroundColor Red }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        "CRITICAL" { Write-Host $logMessage -ForegroundColor Magenta }
        "REMOVED" { Write-Host $logMessage -ForegroundColor Cyan }
        default   { if ($VerboseLogging) { Write-Host $logMessage -ForegroundColor White } }
    }
    
    # Write to log file
    Add-Content -Path $LogFilePath -Value $logMessage
    
    if ($Critical) {
        $script:SecurityIssues += $Message
    }
}

function Add-Change {
    param([string]$Category, [string]$Setting, [string]$Action, [string]$Details = "")
    $script:Changes += [PSCustomObject]@{
        Category = $Category
        Setting = $Setting
        Action = $Action
        Details = $Details
        Timestamp = Get-Date
    }
}

Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "BLUE TEAM WINDOWS HARDENING SCRIPT - COMPETITION MODE" "CRITICAL"
Write-BlueTeamLog "CDT TEAM CHARLIE - SPRING 2026" "CRITICAL"
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "Script started at: $ScriptStartTime" "INFO"
Write-BlueTeamLog "Script run count: $scriptRunCount" "INFO"
if ($scriptRunCount -gt 1) {
    Write-BlueTeamLog "Note: This is not the first run - idempotent operations will be skipped" "INFO"
}
Write-BlueTeamLog "Log file: $LogFilePath" "INFO"
Write-BlueTeamLog "Hostname: $hostname" "INFO"
Write-BlueTeamLog "" "INFO"

# CONFIGURATION VALIDATION
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "CONFIGURATION VALIDATION" "CRITICAL"
Write-BlueTeamLog "============================================================" "INFO"

$configWarnings = @()

# Check if default password was changed
if ($SetAllUserPasswords -eq "FriendshipIsMagic0!") {
    $configWarnings += "Default password detected - you should change `$SetAllUserPasswords to your team password!"
}

# Check if default admin users are still set
if ($AuthorizedAdmins -contains "blueadmin" -and $AuthorizedAdmins.Count -eq 3) {
    $configWarnings += "Default admin usernames detected - you should customize `$AuthorizedAdmins with your team members!"
}

# Validate password meets basic complexity
if ($SetAllUserPasswords.Length -lt 8) {
    $configWarnings += "Password is too short (minimum 8 characters required)"
}

if ($SetAllUserPasswords -match '#') {
    $configWarnings += "Password contains # symbol which may cause issues - use ! @ $ % ^ & * instead"
}

if ($configWarnings.Count -gt 0) {
    Write-BlueTeamLog "Configuration warnings detected:" "WARNING"
    foreach ($warning in $configWarnings) {
        Write-BlueTeamLog "  ! $warning" "WARNING"
    }
    Write-BlueTeamLog "" "INFO"
    Write-BlueTeamLog "Press Ctrl+C to cancel and edit configuration, or wait 5 seconds to continue..." "WARNING"
    Start-Sleep -Seconds 5
} else {
    Write-BlueTeamLog "Configuration validation passed" "SUCCESS"
}

Write-BlueTeamLog "" "INFO"

# PRE-FLIGHT RULES COMPLIANCE CHECK
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "PRE-FLIGHT RULES COMPLIANCE CHECK" "CRITICAL"
Write-BlueTeamLog "============================================================" "INFO"

$complianceIssues = @()

# Check Rule 10: SSH/RDP disable
if ($DisableRDP -eq $true) {
    $complianceIssues += "Rule 10 VIOLATION: DisableRDP is set to TRUE - this violates competition rules!"
    Write-BlueTeamLog "WARNING: DisableRDP is enabled - will be skipped to comply with Rule 10" "WARNING"
}

# Check Rule 9: Protected users
$protectedUserCount = $SafeUsers.Count
Write-BlueTeamLog "Protected users count: $protectedUserCount (includes all competition users)" "INFO"

# Check firewall configuration for Rule 7
Write-BlueTeamLog "Firewall configuration: Individual IP/port rules (compliant with Rule 7)" "INFO"

if ($complianceIssues.Count -eq 0) {
    Write-BlueTeamLog "Pre-flight check PASSED: Configuration is rules-compliant" "SUCCESS"
} else {
    Write-BlueTeamLog "Pre-flight check WARNING: $($complianceIssues.Count) potential issues detected" "WARNING"
    foreach ($issue in $complianceIssues) {
        Write-BlueTeamLog "  - $issue" "WARNING"
    }
}

Write-BlueTeamLog "" "INFO"

# ============================================================================
if ($RunPhase1) {
# 1. USER ACCOUNT MANAGEMENT AND CLEANUP (ENHANCED)
# ============================================================================
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "PHASE 1: USER ACCOUNT MANAGEMENT (ENHANCED)" "CRITICAL"
Write-BlueTeamLog "============================================================" "INFO"

# Initialize audit data structures
$UserAuditData = @()
$BlankPasswordUsers = @()
$SuspiciousSIDUsers = @()
$GroupViolations = @()

# Define privileged groups to audit
$PrivilegedGroups = @(
    "Administrators",
    "Remote Desktop Users",
    "Remote Management Users",
    "Backup Operators",
    "Server Operators",
    "Account Operators",
    "Print Operators",
    "Hyper-V Administrators",
    "Power Users",
    "Network Configuration Operators",
    "Cryptographic Operators",
    "Distributed COM Users",
    "Event Log Readers",
    "Performance Log Users",
    "Performance Monitor Users",
    "IIS_IUSRS"
)

# Helper function to test for blank passwords
function Test-BlankPassword {
    param([string]$Username)
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction SilentlyContinue
        $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Machine
        $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($contextType)
        $hasBlankPassword = $principalContext.ValidateCredentials($Username, "")
        return $hasBlankPassword
    } catch {
        return $false
    }
}

# Helper function to analyze SID for suspicious patterns
function Test-SuspiciousSID {
    param([Microsoft.PowerShell.Commands.LocalUser]$User)
    
    $suspicious = @()
    $sid = $User.SID.Value
    
    try {
        # Parse RID (Relative ID - last part of SID)
        $ridMatch = $sid -match '-(\d+)$'
        if ($ridMatch) {
            $rid = [int]$Matches[1]
            
            # Check for suspiciously high RID (recently created accounts)
            # Typical RIDs: 500=Admin, 501=Guest, 503=DefaultAccount
            # User accounts typically start at 1000+
            # Threshold of 5000 catches accounts created well after initial setup
            if ($rid -gt 5000) {
                $suspicious += "High RID ($rid) - recently created account"
            }
            
            # Check for well-known SID range violations
            # RIDs 500-999 are reserved for built-in accounts
            if ($rid -ge 500 -and $rid -lt 1000 -and $User.Name -notin @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount','krbtgt')) {
                $suspicious += "Reserved RID range ($rid) with non-standard name - possible SID manipulation"
            }
        }
        
        # Check SID structure (should be S-1-5-21-... for local accounts)
        if ($sid -notmatch '^S-1-5-21-') {
            $suspicious += "Non-standard SID structure - not a typical local account SID"
        }
    } catch {
        $suspicious += "Error analyzing SID: $_"
    }
    
    return $suspicious
}

# Helper function to get all groups for a user
function Get-UserGroups {
    param([string]$Username)
    $groups = @()
    try {
        $userObj = [ADSI]"WinNT://./$Username,user"
        $userObj.Groups() | ForEach-Object {
            $groups += $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
        }
    } catch {
        # Fallback method
        try {
            $groups = (Get-LocalGroup | Where-Object {
                (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$Username" }) -ne $null
            }).Name
        } catch {}
    }
    return $groups
}

# ============================================================================
# 1.1 - GET ALL USERS AND CLASSIFY
# ============================================================================
Write-BlueTeamLog "Step 1.1: Gathering all local user accounts..." "INFO"

# Get ALL local users (enabled and disabled)
$AllLocalUsers = Get-LocalUser
$EnabledUsers = $AllLocalUsers | Where-Object { $_.Enabled -eq $true }
$DisabledUsers = $AllLocalUsers | Where-Object { $_.Enabled -eq $false }

Write-BlueTeamLog "Found $($AllLocalUsers.Count) total local users ($($EnabledUsers.Count) enabled, $($DisabledUsers.Count) disabled)" "INFO"

# Define default Windows users that should typically exist
$DefaultWindowsUsers = @(
    "Administrator",
    "DefaultAccount",
    "Guest",
    "WDAGUtilityAccount"
)

# Auto-protect the currently logged-in user so the script never removes the operator
$CurrentUser = $env:USERNAME
if ($CurrentUser -and ($CurrentUser -notin $SafeUsers) -and ($CurrentUser -notin $AuthorizedAdmins)) {
    Write-BlueTeamLog "AUTO-PROTECT: Adding current operator account '$CurrentUser' to safe list to prevent self-lockout" "WARNING"
}

# Combine safe users (includes default + competition + blue team users + current operator)
$AllSafeUsers = $SafeUsers + $DefaultWindowsUsers + $AuthorizedAdmins + @($CurrentUser) | Select-Object -Unique
Write-BlueTeamLog "Protected user list ($($AllSafeUsers.Count) users): $($AllSafeUsers -join ', ')" "INFO"
Write-BlueTeamLog "  (Note: '$CurrentUser' auto-added as current operator)" "INFO"
Write-BlueTeamLog "" "INFO"

# ============================================================================
# 1.2 - AUDIT PRIVILEGED GROUP MEMBERSHIPS
# ============================================================================
Write-BlueTeamLog "Step 1.2: Auditing privileged group memberships..." "INFO"

foreach ($groupName in $PrivilegedGroups) {
    try {
        $group = Get-LocalGroup -Name $groupName -ErrorAction SilentlyContinue
        if (-not $group) { continue }
        
        $members = Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue
        
        if ($members) {
            Write-BlueTeamLog "Checking group: $groupName ($($members.Count) members)" "INFO"
            
            foreach ($member in $members) {
                # Extract just the username (remove domain prefix if present)
                $memberName = $member.Name
                if ($memberName -like "*\*") {
                    $memberName = $memberName.Split('\')[-1]
                }
                
                # Check if member is authorized
                if ($AllSafeUsers -notcontains $memberName) {
                    Write-BlueTeamLog "  UNAUTHORIZED: $memberName in $groupName" "CRITICAL" -Critical
                    $GroupViolations += [PSCustomObject]@{
                        Group = $groupName
                        User = $memberName
                        Action = "Removed"
                    }
                    
                    try {
                        Remove-LocalGroupMember -Group $groupName -Member $member.Name -ErrorAction Stop
                        Write-BlueTeamLog "  REMOVED: $memberName from $groupName" "REMOVED"
                        Add-Change "Group Security" "Removed from $groupName" $memberName "Unauthorized group membership"
                    } catch {
                        Write-BlueTeamLog "  Failed to remove $memberName from $groupName : $_" "ERROR"
                    }
                } else {
                    Write-BlueTeamLog "  Authorized: $memberName" "INFO"
                }
            }
        }
    } catch {
        Write-BlueTeamLog "Could not audit group $groupName : $_" "WARNING"
    }
}

Write-BlueTeamLog "Group audit complete. Found $($GroupViolations.Count) unauthorized group memberships" "INFO"
Write-BlueTeamLog "" "INFO"

# ============================================================================
# 1.3 - SCAN FOR BLANK PASSWORDS AND SUSPICIOUS SIDS
# ============================================================================
Write-BlueTeamLog "Step 1.3: Scanning for blank passwords and analyzing SIDs..." "INFO"

foreach ($user in $AllLocalUsers) {
    # Check for blank password
    if ($user.Enabled) {
        Write-BlueTeamLog "Checking user: $($user.Name)" "INFO"
        
        $hasBlankPassword = Test-BlankPassword -Username $user.Name
        if ($hasBlankPassword) {
            Write-BlueTeamLog "  CRITICAL: User has BLANK PASSWORD!" "CRITICAL" -Critical
            $BlankPasswordUsers += $user.Name
        }
    }
    
    # Analyze SID
    $sidIssues = Test-SuspiciousSID -User $user
    if ($sidIssues.Count -gt 0) {
        Write-BlueTeamLog "  SUSPICIOUS SID detected for $($user.Name):" "WARNING" -Critical
        foreach ($issue in $sidIssues) {
            Write-BlueTeamLog "    - $issue" "WARNING"
        }
        $SuspiciousSIDUsers += [PSCustomObject]@{
            Username = $user.Name
            SID = $user.SID.Value
            Issues = $sidIssues -join '; '
            OnSafeList = ($AllSafeUsers -contains $user.Name)
        }
    }
}

Write-BlueTeamLog "Blank password scan complete. Found $($BlankPasswordUsers.Count) users with blank passwords" "INFO"
Write-BlueTeamLog "SID analysis complete. Found $($SuspiciousSIDUsers.Count) users with suspicious SIDs" "INFO"
Write-BlueTeamLog "" "INFO"

# ============================================================================
# 1.4 - REMOVE UNAUTHORIZED USERS
# ============================================================================
Write-BlueTeamLog "Step 1.4: Removing unauthorized users..." "INFO"

foreach ($user in $EnabledUsers) {
    if ($AllSafeUsers -notcontains $user.Name) {
        try {
            Write-BlueTeamLog "REMOVING unauthorized user: $($user.Name)" "REMOVED"
            
            # Check if this user had SUSPICIOUS SID
            $wasSuspicious = $SuspiciousSIDUsers | Where-Object { $_.Username -eq $user.Name }
            if ($wasSuspicious) {
                Write-BlueTeamLog "  (This user had SUSPICIOUS SID: $($wasSuspicious.Issues))" "WARNING"
            }
            
            Remove-LocalUser -Name $user.Name -Confirm:$false
            $RemovedUsers += $user.Name
            Add-Change "User Management" "Removed User" $user.Name "Unauthorized user removed"
            Write-BlueTeamLog "Successfully removed user: $($user.Name)" "SUCCESS"
        } catch {
            Write-BlueTeamLog "Failed to remove user $($user.Name): $_" "ERROR"
        }
    } else {
        Write-BlueTeamLog "Keeping safe user: $($user.Name)" "INFO"
        
        # If safe user had SUSPICIOUS SID, log it but don't remove
        $wasSuspicious = $SuspiciousSIDUsers | Where-Object { $_.Username -eq $user.Name }
        if ($wasSuspicious) {
            Write-BlueTeamLog "  NOTE: This user has SUSPICIOUS SID but is on safe list (not removed)" "WARNING"
            Write-BlueTeamLog "  Issues: $($wasSuspicious.Issues)" "WARNING"
        }
    }
}

if ($RemovedUsers.Count -gt 0) {
    Write-BlueTeamLog "Total unauthorized users removed: $($RemovedUsers.Count)" "SUCCESS"
    Write-BlueTeamLog "Removed users: $($RemovedUsers -join ', ')" "SUCCESS"
} else {
    Write-BlueTeamLog "No unauthorized users found" "INFO"
}
Write-BlueTeamLog "" "INFO"

# ============================================================================
# 1.5 - SELECTIVE PASSWORD RESET (MAX 3 USERS PER HOST PER DAY)
# ============================================================================
Write-BlueTeamLog "Step 1.5: Selective password reset (max 3 users per host per competition day)..." "CRITICAL"
Write-BlueTeamLog "A menu will be displayed. Select up to 3 users to reset to the configured team password." "INFO"

# Ensure log directory exists
$LogDir = Split-Path -Parent $LogFilePath
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

# Dedicated log for password changes (required for competition tracking)
$PasswordChangeLogPath = Join-Path $LogDir ("3-user-password-changes-{0}.log" -f (Get-Date -Format "yyyy-MM-dd-HHmmss"))

function Write-PasswordChangeLog {
    param(
        [Parameter(Mandatory=$true)][string]$Message
    )
    try {
        Add-Content -Path $PasswordChangeLogPath -Value ("[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message) -Encoding UTF8
    } catch {
        # Fallback to main log if dedicated log write fails
        Write-BlueTeamLog "Failed to write to password change log ($PasswordChangeLogPath): $_" "WARNING"
    }
}

Write-PasswordChangeLog ("Host: {0}" -f $env:COMPUTERNAME)
Write-PasswordChangeLog "Purpose: Track up to 3 password changes per host per competition day"
Write-PasswordChangeLog "Selected password changes:"

# Initialize counters here so they are always defined even if the user skips selection
$passwordSuccessCount = 0
$passwordFailCount = 0

# Get fresh user list after removals
$RemainingUsers = Get-LocalUser | Sort-Object Name

# Build a map of user -> privileged group memberships for display
$UserPrivGroups = @{}
foreach ($g in $PrivilegedGroups) {
    try {
        $members = Get-LocalGroupMember -Group $g -ErrorAction Stop
        foreach ($m in $members) {
            if ($m.ObjectClass -eq "User") {
                $n = $m.Name
                if ($n -match "^[^\\]+\\(.+)$") { $n = $Matches[1] }  # strip COMPUTER\ prefix
                if (-not $UserPrivGroups.ContainsKey($n)) { $UserPrivGroups[$n] = New-Object System.Collections.Generic.List[string] }
                if (-not $UserPrivGroups[$n].Contains($g)) { $UserPrivGroups[$n].Add($g) }
            }
        }
    } catch {
        # Some groups may not exist on certain editions; ignore quietly
    }
}

# Display user menu
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "USER LIST (SELECT UP TO 3 FOR PASSWORD RESET)" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$menu = @()
$idx = 1
foreach ($u in $RemainingUsers) {
    $groups = ""
    if ($UserPrivGroups.ContainsKey($u.Name)) {
        $groups = ($UserPrivGroups[$u.Name] | Sort-Object) -join ", "
    } else {
        $groups = "(none of audited privileged groups)"
    }

    $menu += [pscustomobject]@{
        Index   = $idx
        User    = $u.Name
        Enabled = $u.Enabled
        PrivilegedGroups = $groups
    }
    $idx++
}

$menu | Format-Table -AutoSize | Out-Host

Write-Host ""
Write-Host "Selection format examples:" -ForegroundColor DarkGray
Write-Host "  1,3,5    (comma-separated)" -ForegroundColor DarkGray
Write-Host "  1 3 5    (space-separated)" -ForegroundColor DarkGray
Write-Host ""

# Prompt for selection (up to 3)
$SelectedIndices = @()
while ($true) {
    $raw = Read-Host "Enter up to 3 user numbers to reset (or press Enter to skip)"
    if ([string]::IsNullOrWhiteSpace($raw)) {
        Write-BlueTeamLog "No users selected for password reset in Step 1.5 (skipped)" "WARNING"
        Write-PasswordChangeLog "No users selected (skipped)."
        break
    }

    if ($raw.Trim().ToLower() -in @("q","quit","exit")) {
        Write-BlueTeamLog "User aborted password selection in Step 1.5" "WARNING"
        Write-PasswordChangeLog "Selection aborted by operator."
        break
    }

    $parts = $raw -split "[,\s]+" | Where-Object { $_ -and $_.Trim() -ne "" }
    $nums = @()
    $bad = $false
    foreach ($p in $parts) {
        $n = 0
        if (-not [int]::TryParse($p, [ref]$n)) { $bad = $true; break }
        if ($n -lt 1 -or $n -gt $menu.Count) { $bad = $true; break }
        if (-not ($nums -contains $n)) { $nums += $n }
    }

    if ($bad) {
        Write-Host "Invalid selection. Enter user numbers between 1 and $($menu.Count)." -ForegroundColor Red
        continue
    }

    if ($nums.Count -gt 3) {
        Write-Host "Rule enforcement: You may select at most 3 users per host per day." -ForegroundColor Red
        continue
    }

    $SelectedIndices = $nums
    break
}

if ($SelectedIndices.Count -gt 0) {
    $SelectedUsers = $SelectedIndices | ForEach-Object { $menu[$_ - 1].User }

    Write-Host ""
    Write-Host "Selected users for password reset:" -ForegroundColor Yellow
    $SelectedUsers | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host ""

    $confirm = Read-Host "Proceed with resetting passwords for these users to the team password? (Y/N)"
    if ($confirm.Trim().ToUpper() -ne "Y") {
        Write-BlueTeamLog "Password reset cancelled by operator in Step 1.5" "WARNING"
        Write-PasswordChangeLog ("Cancelled. Intended selections: {0}" -f ($SelectedUsers -join ", "))
    } else {
        $passwordSuccessCount = 0
        $passwordFailCount = 0

        foreach ($userName in $SelectedUsers) {
            # Skip disabled built-in accounts that can't have passwords set
            $uobj = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
            if ($null -eq $uobj) {
                Write-BlueTeamLog "Cannot reset password: user not found: $userName" "ERROR"
                Write-PasswordChangeLog ("FAILED: {0} (user not found)" -f $userName)
                $passwordFailCount++
                continue
            }

            if ($uobj.Name -in @('Guest', 'DefaultAccount', 'WDAGUtilityAccount') -and -not $uobj.Enabled) {
                Write-BlueTeamLog "Skipping disabled built-in account: $($uobj.Name)" "INFO"
                Write-PasswordChangeLog ("SKIPPED: {0} (disabled built-in account)" -f $uobj.Name)
                continue
            }

            try {
                $SecurePassword = ConvertTo-SecureString $SetAllUserPasswords -AsPlainText -Force
                Set-LocalUser -Name $uobj.Name -Password $SecurePassword -ErrorAction Stop

                if ($BlankPasswordUsers -contains $uobj.Name) {
                    Write-BlueTeamLog "Password set for $($uobj.Name) (previously had BLANK PASSWORD)" "SUCCESS"
                    Write-PasswordChangeLog ("SUCCESS: {0} (previously blank password)" -f $uobj.Name)
                } else {
                    Write-BlueTeamLog "Password set for $($uobj.Name)" "SUCCESS"
                    Write-PasswordChangeLog ("SUCCESS: {0}" -f $uobj.Name)
                }

                $passwordSuccessCount++
                Add-Change "User Management" "Password Reset (Selective)" $uobj.Name "Password set to team password (operator-selected; max 3 per host/day)"
            } catch {
                if ($_.Exception.Message -like "*minimum password age*" -or $_.Exception.Message -like "*password policy*") {
                    Write-BlueTeamLog "Cannot reset password for $($uobj.Name) - minimum password age restriction" "WARNING"
                    Write-PasswordChangeLog ("FAILED: {0} (minimum password age restriction)" -f $uobj.Name)
                    $passwordFailCount++
                } else {
                    Write-BlueTeamLog "Failed to set password for $($uobj.Name): $_" "ERROR"
                    Write-PasswordChangeLog ("FAILED: {0} ({1})" -f $uobj.Name, $_)
                    $passwordFailCount++
                }
            }
        }

        Write-BlueTeamLog "Selective password reset complete: $passwordSuccessCount successful, $passwordFailCount failed" "INFO"
        Write-PasswordChangeLog ("Summary: {0} successful, {1} failed" -f $passwordSuccessCount, $passwordFailCount)
        Write-PasswordChangeLog ("Completed. Log: {0}" -f $PasswordChangeLogPath)

        Write-Host ""
        Write-Host "Password change log written to:" -ForegroundColor Cyan
        Write-Host "  $PasswordChangeLogPath" -ForegroundColor Cyan
        Write-Host ""
    }
}

Write-BlueTeamLog "" "INFO"

# ============================================================================
# 1.6 - CREATE/CONFIGURE AUTHORIZED ADMIN USERS

# ============================================================================
Write-BlueTeamLog "Step 1.6: Configuring authorized admin users..." "INFO"

foreach ($adminUser in $AuthorizedAdmins) {
    try {
        # Check if user exists
        $userExists = Get-LocalUser -Name $adminUser -ErrorAction SilentlyContinue
        
        if (-not $userExists) {
            # Create the user
            Write-BlueTeamLog "Creating new admin user: $adminUser" "INFO"

            # Windows complexity policy rejects passwords that contain 3+ consecutive characters
            # from the account name being created. Pre-check here so we can use a safe interim
            # password instead of silently failing with InvalidPasswordException.
            $passwordToUse = $SetAllUserPasswords
            $usernameSubstringFound = $false
            if ($adminUser.Length -ge 3) {
                for ($si = 0; $si -le $adminUser.Length - 3; $si++) {
                    $chunk = $adminUser.Substring($si, 3).ToLower()
                    if ($passwordToUse.ToLower().Contains($chunk)) {
                        $usernameSubstringFound = $true
                        Write-BlueTeamLog "WARNING: Team password contains '$chunk' (substring of '$adminUser') - Windows will reject it for this account." "WARNING"
                        Write-BlueTeamLog "Using a safe interim password for account creation. You should update `$SetAllUserPasswords to avoid substrings of all admin usernames." "WARNING"
                        # Use an interim password that avoids the username substring.
                        # Built by replacing the conflicting section; guaranteed to meet complexity.
                        $passwordToUse = "TmpCreate@" + (Get-Date -Format "HHmmss") + "Z!"
                        break
                    }
                }
            }

            $SecurePassword = ConvertTo-SecureString $passwordToUse -AsPlainText -Force
            $userCreated = $false
            try {
                New-LocalUser -Name $adminUser -Password $SecurePassword -FullName "Blue Team Admin" -Description "Authorized Blue Team Administrator" -PasswordNeverExpires:$true -ErrorAction Stop
                $userCreated = $true
                Add-Change "User Management" "Created User" $adminUser "New authorized admin user"
                Write-BlueTeamLog "Successfully created user: $adminUser" "SUCCESS"

                # If we used an interim password, immediately update to the real team password
                # now that the account exists (Set-LocalUser is not subject to the same
                # name-in-password restriction as New-LocalUser on account creation).
                if ($usernameSubstringFound) {
                    try {
                        $RealPassword = ConvertTo-SecureString $SetAllUserPasswords -AsPlainText -Force
                        Set-LocalUser -Name $adminUser -Password $RealPassword -ErrorAction Stop
                        Write-BlueTeamLog "Real team password applied to $adminUser after creation" "SUCCESS"
                    } catch {
                        Write-BlueTeamLog "Could not apply real team password to $adminUser after creation (interim password is active): $_" "WARNING"
                    }
                }
            } catch {
                Write-BlueTeamLog "Failed to create user $adminUser : $_" "ERROR"
            }
            if (-not $userCreated) {
                Write-BlueTeamLog "Skipping group configuration for $adminUser because user creation failed" "WARNING"
                continue
            }
        } else {
            Write-BlueTeamLog "User $adminUser already exists" "INFO"
        }
        
        # Ensure user is in Administrators group (idempotent operation)
        $isMember = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$adminUser" }
        
        if (-not $isMember) {
            try {
                Add-LocalGroupMember -Group "Administrators" -Member $adminUser -ErrorAction Stop
                Write-BlueTeamLog "Added $adminUser to Administrators group" "SUCCESS"
                Add-Change "User Management" "Admin Rights" $adminUser "Added to Administrators group"
            } catch {
                if ($_.Exception.Message -like "*already a member*") {
                    Write-BlueTeamLog "User $adminUser already in Administrators group" "INFO"
                } else {
                    Write-BlueTeamLog "Failed to add $adminUser to Administrators: $_" "WARNING"
                }
            }
        } else {
            Write-BlueTeamLog "User $adminUser already in Administrators group" "INFO"
        }
        
        # Ensure user is in Remote Desktop Users group for competition access
        try {
            $rdpGroup = Get-LocalGroup -Name "Remote Desktop Users" -ErrorAction SilentlyContinue
            if ($rdpGroup) {
                $isRDPMember = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$adminUser" }
                if (-not $isRDPMember) {
                    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $adminUser -ErrorAction SilentlyContinue
                    Write-BlueTeamLog "Added $adminUser to Remote Desktop Users group" "SUCCESS"
                }
            }
        } catch {
            # Non-critical, continue
        }
        
        # Enable the user account (idempotent)
        try {
            Enable-LocalUser -Name $adminUser -ErrorAction Stop
        } catch {
            Write-BlueTeamLog "User $adminUser is already enabled" "INFO"
        }
        
    } catch {
        Write-BlueTeamLog "Failed to configure admin user $adminUser : $_" "ERROR"
    }
}

Write-BlueTeamLog "" "INFO"

# ============================================================================
# 1.7 - GENERATE COMPREHENSIVE AUDIT REPORT
# ============================================================================
Write-BlueTeamLog "Step 1.7: Generating comprehensive user audit report..." "INFO"

$auditReportPath = "C:\BlueTeam\user-audit-report-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').txt"
$auditReportDir = Split-Path -Path $auditReportPath -Parent
if (-not (Test-Path $auditReportDir)) {
    New-Item -ItemType Directory -Path $auditReportDir -Force | Out-Null
}

# Collect detailed information for each user
Write-BlueTeamLog "Collecting detailed user information..." "INFO"

foreach ($user in $RemainingUsers) {
    try {
        # Get user groups
        $userGroups = Get-UserGroups -Username $user.Name
        
        # Determine if user had issues
        $hadBlankPassword = $BlankPasswordUsers -contains $user.Name
        $suspiciousSID = $SuspiciousSIDUsers | Where-Object { $_.Username -eq $user.Name }
        $isOnSafeList = $AllSafeUsers -contains $user.Name
        $wasInViolation = ($GroupViolations | Where-Object { $_.User -eq $user.Name }).Count -gt 0
        
        # Get last logon (if available)
        $lastLogon = "Never"
        try {
            $userObj = Get-LocalUser -Name $user.Name
            if ($userObj.LastLogon) {
                $lastLogon = $userObj.LastLogon.ToString("yyyy-MM-dd HH:mm:ss")
            }
        } catch {}
        
        # Build security status
        $securityStatus = "SECURE"
        $securityIssues = @()
        
        if ($hadBlankPassword) {
            $securityIssues += "Had blank password (now fixed)"
        }
        if ($suspiciousSID) {
            $securityIssues += "SUSPICIOUS SID: $($suspiciousSID.Issues)"
        }
        if ($wasInViolation) {
            $securityIssues += "Was in unauthorized groups (removed)"
        }
        if (-not $isOnSafeList) {
            $securityIssues += "NOT on safe list"
        }
        
        if ($securityIssues.Count -gt 0) {
            $securityStatus = "WARNING"
        }
        
        $UserAuditData += [PSCustomObject]@{
            Username = $user.Name
            SID = $user.SID.Value
            Enabled = $user.Enabled
            Description = $user.Description
            LastLogon = $lastLogon
            PasswordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
            PasswordNeverExpires = $user.PasswordNeverExpires
            PasswordRequired = $user.PasswordRequired
            AccountLocked = $user.LockoutTime -ne $null
            Groups = ($userGroups -join ', ')
            GroupCount = $userGroups.Count
            HadBlankPassword = $hadBlankPassword
            SuspiciousSID = if ($suspiciousSID) { "YES" } else { "NO" }
            SIDIssues = if ($suspiciousSID) { $suspiciousSID.Issues } else { "None" }
            OnSafeList = $isOnSafeList
            SecurityStatus = $securityStatus
            SecurityIssues = if ($securityIssues.Count -gt 0) { $securityIssues -join '; ' } else { "None" }
        }
    } catch {
        Write-BlueTeamLog "Failed to collect data for user $($user.Name): $_" "WARNING"
    }
}

# Build audit report
$auditReport = @"
================================================================================
                      USER ACCOUNT AUDIT REPORT
================================================================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Hostname: $hostname
Script Version: 2.2-CDT
Script Run: #$scriptRunCount

================================================================================
                           SUMMARY STATISTICS
================================================================================
Total Users Found:                $($AllLocalUsers.Count)
  - Enabled:                      $($EnabledUsers.Count)
  - Disabled:                     $($DisabledUsers.Count)

Safe/Protected Users:             $($AllSafeUsers.Count)
Unauthorized Users Removed:       $($RemovedUsers.Count)
Users Remaining After Cleanup:    $($RemainingUsers.Count)

Security Issues Detected:
  - Blank Passwords Found:        $($BlankPasswordUsers.Count)
  - Suspicious SIDs Found:        $($SuspiciousSIDUsers.Count)
  - Unauthorized Group Members:   $($GroupViolations.Count)

Password Resets:
  - Successful:                   $passwordSuccessCount
  - Failed:                       $passwordFailCount

================================================================================
                        USERS WITH BLANK PASSWORDS
================================================================================
"@

if ($BlankPasswordUsers.Count -gt 0) {
    foreach ($blankUser in $BlankPasswordUsers) {
        $auditReport += "`n[CRITICAL] $blankUser - PASSWORD HAS BEEN RESET"
    }
} else {
    $auditReport += "`nNo users with blank passwords detected."
}

$auditReport += "`n`n"
$auditReport += @"
================================================================================
                        SUSPICIOUS SID DETECTIONS
================================================================================
"@

if ($SuspiciousSIDUsers.Count -gt 0) {
    foreach ($suspUser in $SuspiciousSIDUsers) {
        $auditReport += "`n"
        $auditReport += "User: $($suspUser.Username)`n"
        $auditReport += "  SID: $($suspUser.SID)`n"
        $auditReport += "  Issues: $($suspUser.Issues)`n"
        $auditReport += "  On Safe List: $(if ($suspUser.OnSafeList) { 'YES (not removed)' } else { 'NO (removed if found)' })`n"
    }
} else {
    $auditReport += "`nNo suspicious SIDs detected."
}

$auditReport += "`n`n"
$auditReport += @"
================================================================================
                     UNAUTHORIZED GROUP MEMBERSHIPS
================================================================================
"@

if ($GroupViolations.Count -gt 0) {
    foreach ($violation in $GroupViolations) {
        $auditReport += "`n[REMOVED] User '$($violation.User)' from group '$($violation.Group)'"
    }
} else {
    $auditReport += "`nNo unauthorized group memberships detected."
}

$auditReport += "`n`n"
$auditReport += @"
================================================================================
                       DETAILED USER INFORMATION
================================================================================
"@

foreach ($userData in $UserAuditData) {
    $auditReport += "`n"
    $auditReport += "----------------------------------------`n"
    $auditReport += "USERNAME: $($userData.Username)`n"
    $auditReport += "----------------------------------------`n"
    $auditReport += "SID:                    $($userData.SID)`n"
    $auditReport += "Enabled:                $($userData.Enabled)`n"
    $auditReport += "Description:            $($userData.Description)`n"
    $auditReport += "Last Logon:             $($userData.LastLogon)`n"
    $auditReport += "Password Last Set:      $($userData.PasswordLastSet)`n"
    $auditReport += "Password Never Expires: $($userData.PasswordNeverExpires)`n"
    $auditReport += "Password Required:      $($userData.PasswordRequired)`n"
    $auditReport += "Account Locked:         $($userData.AccountLocked)`n"
    $auditReport += "Groups ($($userData.GroupCount)):         $($userData.Groups)`n"
    $auditReport += "Had Blank Password:     $($userData.HadBlankPassword)`n"
    $auditReport += "Suspicious SID:         $($userData.SuspiciousSID)`n"
    if ($userData.SuspiciousSID -eq "YES") {
        $auditReport += "  SID Issues:           $($userData.SIDIssues)`n"
    }
    $auditReport += "On Safe List:           $($userData.OnSafeList)`n"
    $auditReport += "Security Status:        $($userData.SecurityStatus)`n"
    if ($userData.SecurityIssues -ne "None") {
        $auditReport += "Security Issues:        $($userData.SecurityIssues)`n"
    }
    $auditReport += "`n"
    
    if ($userData.SecurityStatus -eq "SECURE") {
        $auditReport += "[OK] SECURE`n"
    } else {
        $auditReport += "[!] REVIEW REQUIRED`n"
    }
}

$auditReport += "`n"
$auditReport += @"
================================================================================
                         REMOVED USERS (UNAUTHORIZED)
================================================================================
"@

if ($RemovedUsers.Count -gt 0) {
    foreach ($removedUser in $RemovedUsers) {
        $auditReport += "`n[REMOVED] $removedUser"
    }
} else {
    $auditReport += "`nNo unauthorized users were removed."
}

$auditReport += "`n`n"
$auditReport += @"
================================================================================
                              END OF REPORT
================================================================================
"@

# Write audit report to file
$auditReport | Set-Content -Path $auditReportPath -Force
Write-BlueTeamLog "Audit report generated: $auditReportPath" "SUCCESS"
Add-Change "User Management" "Audit Report" "Generated" "Comprehensive user audit completed"

Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "PHASE 1 COMPLETE: User account management finished" "SUCCESS"
Write-BlueTeamLog "  - Users removed: $($RemovedUsers.Count)" "INFO"
Write-BlueTeamLog "  - Blank passwords fixed: $($BlankPasswordUsers.Count)" "INFO"
Write-BlueTeamLog "  - Suspicious SIDs found: $($SuspiciousSIDUsers.Count)" "INFO"
Write-BlueTeamLog "  - Group violations: $($GroupViolations.Count)" "INFO"
Write-BlueTeamLog "  - Passwords reset: $passwordSuccessCount" "INFO"
Write-BlueTeamLog "  - Audit report: $auditReportPath" "INFO"
Write-BlueTeamLog "" "INFO"

# Disable Guest account (security best practice)
# NOTE: Guest is a default Windows account, not a competition user
Write-BlueTeamLog "Checking Guest account status..." "INFO"
try {
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guestAccount -and $guestAccount.Enabled) {
        Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        Add-Change "User Management" "Guest Account" "Disabled" "Security hardening"
        Write-BlueTeamLog "Guest account disabled" "SUCCESS"
    } else {
        Write-BlueTeamLog "Guest account already disabled" "INFO"
    }
} catch {
    Write-BlueTeamLog "Could not modify Guest account: $_" "WARNING"
}

# ============================================================================
}
if ($RunPhase2) {
# 2. PASSWORD POLICY HARDENING
# ============================================================================
Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "PHASE 2: PASSWORD POLICY HARDENING" "CRITICAL"
Write-BlueTeamLog "============================================================" "INFO"

try {
    Write-BlueTeamLog "Setting password policies..." "INFO"
    
    # Get current settings to avoid unnecessary changes
    $needsUpdate = $false
    
    # Set account policies (net accounts always succeeds, so we'll just run it)
    net accounts /minpwlen:$MinPasswordLength /maxpwage:$MaxPasswordAge /minpwage:$MinPasswordAge /uniquepw:$PasswordHistoryCount 2>&1 | Out-Null
    net accounts /lockoutthreshold:$AccountLockoutThreshold /lockoutduration:$AccountLockoutDuration /lockoutwindow:$AccountLockoutDuration 2>&1 | Out-Null
    
    Add-Change "Password Policy" "Password Requirements" "Configured" "Min: $MinPasswordLength chars, Max age: $MaxPasswordAge days"
    Add-Change "Password Policy" "Account Lockout" "Configured" "Threshold: $AccountLockoutThreshold attempts"
    Write-BlueTeamLog "Password policy configured successfully" "SUCCESS"
    Write-BlueTeamLog "  - Min length: $MinPasswordLength" "INFO"
    Write-BlueTeamLog "  - Max age: $MaxPasswordAge days" "INFO"
    Write-BlueTeamLog "  - Min age: $MinPasswordAge days (prevents rapid password changes)" "INFO"
    Write-BlueTeamLog "  - Lockout threshold: $AccountLockoutThreshold attempts" "INFO"
} catch {
    Write-BlueTeamLog "Failed to configure password policy: $_" "ERROR"
}

# Enable password complexity
try {
    secedit /export /cfg C:\Windows\Temp\secpol.cfg | Out-Null
    $secpolContent = Get-Content C:\Windows\Temp\secpol.cfg
    $secpolContent = $secpolContent -replace "PasswordComplexity = .*", "PasswordComplexity = 1"
    $secpolContent | Set-Content C:\Windows\Temp\secpol.cfg
    secedit /configure /db C:\Windows\security\local.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY | Out-Null
    Remove-Item C:\Windows\Temp\secpol.cfg -Force -ErrorAction SilentlyContinue
    Add-Change "Password Policy" "Password Complexity" "Enabled"
    Write-BlueTeamLog "Password complexity enabled" "SUCCESS"
} catch {
    Write-BlueTeamLog "Failed to enable password complexity: $_" "ERROR"
}

# ============================================================================
}
if ($RunPhase3) {
# 3. FIREWALL HARDENING
# ============================================================================
Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "PHASE 3: FIREWALL HARDENING" "CRITICAL"
Write-BlueTeamLog "============================================================" "INFO"

try {
    # Enable firewall on all profiles
    Write-BlueTeamLog "Enabling Windows Firewall on all profiles..." "INFO"
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction SilentlyContinue
    Add-Change "Firewall" "Firewall Status" "Enabled" "All profiles with default deny inbound"
    Write-BlueTeamLog "Firewall enabled on all profiles" "SUCCESS"
    
    # Enable logging
    if ($LogDroppedPackets -or $LogAllowedConnections) {
        Write-BlueTeamLog "Configuring firewall logging..." "INFO"
        $logPath = "C:\BlueTeam\Logs\Firewall"
        if (-not (Test-Path $logPath)) {
            New-Item -ItemType Directory -Path $logPath -Force | Out-Null
        }
        
        # Convert boolean to GpoBoolean type
        $logAllowed = if ($LogAllowedConnections) { "True" } else { "False" }
        $logBlocked = if ($LogDroppedPackets) { "True" } else { "False" }
        
        Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed $logAllowed -LogBlocked $logBlocked -LogFileName "$logPath\pfirewall.log" -LogMaxSizeKilobytes 32767 -ErrorAction SilentlyContinue
        Write-BlueTeamLog "Firewall logging configured" "SUCCESS"
    }
    
} catch {
    Write-BlueTeamLog "Failed to configure firewall: $_" "ERROR"
}

# ---------------------------------------------------------------------------
# FAIL-SAFE: KEEP RDP ALIVE BEFORE ANY INTERACTIVE PROMPTS
# ---------------------------------------------------------------------------
# If we remove inbound rules or set default deny BEFORE opening 3389, any RDP
# session running this script will lock itself out mid-run (bricking access).
# This emergency rule is created FIRST and is preserved because its DisplayName
# begins with "Blue Team".
function Ensure-BlueTeamRDPFailSafe {
    param(
        [string]$RuleName = "Blue Team - Allow RDP 3389 (Fail-Safe)",
        [string]$RuleDesc = "Fail-safe RDP rule created before inbound rules are modified."
    )

    try {
        $existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue

        $needsRecreate = $false
        if ($existing) {
            $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $existing -ErrorAction SilentlyContinue
            if (-not $pf -or $pf.Protocol -ne "TCP" -or $pf.LocalPort -ne "3389") {
                $needsRecreate = $true
            }
        }

        if ($existing -and $needsRecreate) {
            Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Out-Null
            $existing = $null
        }

        if (-not $existing) {
            New-NetFirewallRule `
                -DisplayName $RuleName `
                -Description $RuleDesc `
                -Direction Inbound `
                -Action Allow `
                -Protocol TCP `
                -LocalPort 3389 `
                -Profile Any `
                -Enabled True `
                -EdgeTraversalPolicy Allow | Out-Null

            Write-BlueTeamLog "Created RDP fail-safe firewall rule (3389) BEFORE removing inbound rules" "SUCCESS"
            Add-Change "Firewall" "RDP Fail-Safe" "Created" $RuleName
        } else {
            Set-NetFirewallRule -DisplayName $RuleName -Enabled True -Action Allow -Direction Inbound -Profile Any | Out-Null
            Write-BlueTeamLog "Verified RDP fail-safe firewall rule is enabled (3389)" "INFO"
        }
    } catch {
        Write-BlueTeamLog "WARNING: Could not create/verify RDP fail-safe rule. You may lose RDP access! Error: $_" "WARNING"
    }
}

# Create/verify the fail-safe rule immediately (before any rule deletion or prompts)
Ensure-BlueTeamRDPFailSafe
# Remove all existing inbound rules (except safe ones)
if ($BlockAllInboundByDefault) {
    Write-BlueTeamLog "" "INFO"
    Write-BlueTeamLog "Removing potentially malicious inbound firewall rules..." "INFO"
    
    $existingRules = Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue
    $removedRulesCount = 0
    
    foreach ($rule in $existingRules) {
        # Keep Windows default rules and our safe rules
        if ($rule.DisplayName -notlike "Blue Team*" -and 
            $rule.DisplayName -notlike "*Core Networking*" -and
            $rule.DisplayName -notlike "*Windows Remote Management*" -and
            $rule.Owner -eq $null) {
            
            try {
                Remove-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
                $removedRulesCount++
                Write-BlueTeamLog "Removed firewall rule: $($rule.DisplayName)" "REMOVED"
            } catch {
                Write-BlueTeamLog "Could not remove rule $($rule.DisplayName): $_" "WARNING"
            }
        }
    }
    
    Write-BlueTeamLog "Removed $removedRulesCount potentially malicious firewall rules" "SUCCESS"
}

# SERVICE-SPECIFIC FIREWALL RULES:
# Ask the operator which scored Windows service is on this host so we only open
# the ports that are actually needed. Opening every service port on every host
# is unnecessary attack surface. RDP (3389) is always opened per Rule 10.
Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "SERVICE PORT SELECTION" "CRITICAL"
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "Each Windows host runs ONE scored service. Only open ports for YOUR service." "WARNING"
Write-BlueTeamLog "RDP (3389) will always be opened regardless of selection." "INFO"
Write-BlueTeamLog "" "INFO"

# Port definitions per service
$ServicePortMap = @{
    "1" = @{ Name = "Active Directory (canterlot)";  Ports = @(88, 135, 389, 445, 636, 3268, 3269); RpcDynamic = $true }
    "2" = @{ Name = "MSSQL (manehatten)";            Ports = @(1433);                               RpcDynamic = $false }
    "3" = @{ Name = "IIS (las-pegasus)";             Ports = @(80, 443);                            RpcDynamic = $false }
    "4" = @{ Name = "SMB (appleloosa)";              Ports = @(445);                                RpcDynamic = $false }
    "5" = @{ Name = "Workstation (no service port)"; Ports = @();                                   RpcDynamic = $false }
}

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "        WHICH SCORED SERVICE IS RUNNING ON THIS WINDOWS HOST?" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  [1]  Active Directory   - canterlot  (10.0.10.1)" -ForegroundColor White
Write-Host "       Ports: 88, 135, 389, 445, 636, 3268, 3269 + RPC dynamic (49152-65535)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  [2]  MSSQL              - manehatten (10.0.10.2)" -ForegroundColor White
Write-Host "       Ports: 1433" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  [3]  IIS                - las-pegasus (10.0.20.1)" -ForegroundColor White
Write-Host "       Ports: 80, 443" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  [4]  SMB                - appleloosa (10.0.20.2)" -ForegroundColor White
Write-Host "       Ports: 445" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  [5]  Workstation        - baltamare / neighara-falls / fillydelphia" -ForegroundColor White
Write-Host "       No additional service port (RDP only)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  (All options also open RDP port 3389 - required per Rule 10)" -ForegroundColor DarkYellow
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan

$serviceChoice = $null
while ($null -eq $serviceChoice) {
    Write-Host "Enter service number [1-5]: " -NoNewline -ForegroundColor Cyan
    $raw = Read-Host
    $raw = $raw.Trim()
    if ($ServicePortMap.ContainsKey($raw)) {
        $serviceChoice = $raw
    } else {
        Write-Host "  Invalid selection. Please enter a number between 1 and 5." -ForegroundColor Red
    }
}

$SelectedService = $ServicePortMap[$serviceChoice]
Write-BlueTeamLog "Operator selected service: $($SelectedService.Name)" "CRITICAL"
Add-Change "Firewall" "Service Selection" $SelectedService.Name "Ports will be restricted to this service only"

# Always include RDP
$AllowedInboundPorts = @(3389) + $SelectedService.Ports

Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "Creating firewall rules for allowed ports..." "INFO"
Write-BlueTeamLog "  Service: $($SelectedService.Name)" "INFO"
Write-BlueTeamLog "  Ports to open: $(($AllowedInboundPorts | Sort-Object) -join ', ')" "INFO"

# Helper: create or verify a single TCP inbound rule
function Set-InboundPortRule {
    param([int]$Port, [string]$Label)
    $ruleName = "Blue Team - Allow Port $Port ($Label)"
    try {
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($existingRule) {
            $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $existingRule -ErrorAction SilentlyContinue
            if ($portFilter.LocalPort -eq $Port -and $existingRule.Enabled -eq $true -and $existingRule.Action -eq "Allow") {
                Write-BlueTeamLog "Firewall rule for port $Port ($Label) already correct" "INFO"
                return
            }
            Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        }
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Inbound -Protocol TCP -LocalPort $Port `
            -Action Allow -Enabled True -Profile Any `
            -ErrorAction SilentlyContinue | Out-Null
        Write-BlueTeamLog "Created firewall rule: port $Port ($Label)" "SUCCESS"
        Add-Change "Firewall" "Allowed Port" "$Port ($Label)" "Inbound TCP allowed"
    } catch {
        Write-BlueTeamLog "Failed to create firewall rule for port ${Port}: $_" "ERROR"
    }
}

# RDP - always
Set-InboundPortRule -Port 3389 -Label "RDP - Required Rule 10"

# Service-specific ports
foreach ($port in $SelectedService.Ports) {
    Set-InboundPortRule -Port $port -Label $SelectedService.Name
}

# Active Directory also needs the RPC dynamic port range
if ($SelectedService.RpcDynamic) {
    Write-BlueTeamLog "Creating RPC dynamic port range rule for Active Directory (49152-65535)..." "INFO"
    $rpcRuleName = "Blue Team - Allow RPC Dynamic (AD)"
    $existingRpc = Get-NetFirewallRule -DisplayName $rpcRuleName -ErrorAction SilentlyContinue
    if ($existingRpc) { Remove-NetFirewallRule -DisplayName $rpcRuleName -ErrorAction SilentlyContinue }
    New-NetFirewallRule -DisplayName $rpcRuleName `
        -Direction Inbound -Protocol TCP -LocalPort "49152-65535" `
        -Action Allow -Enabled True -Profile Any `
        -ErrorAction SilentlyContinue | Out-Null
    Write-BlueTeamLog "Created RPC dynamic port range rule (49152-65535)" "SUCCESS"
    Add-Change "Firewall" "Allowed Port Range" "49152-65535 (RPC Dynamic - AD)" "Required for Active Directory"
}

Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "Service port rules complete. Only $($SelectedService.Name) ports are open." "SUCCESS"

# Create rules for safe IP addresses
Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "Creating firewall rules for safe IP addresses..." "INFO"
foreach ($ip in $SafeIPAddresses) {
    try {
        $ruleName = "Blue Team - Safe IP $ip"
        
        # Check if rule already exists correctly
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        
        if ($existingRule -and $existingRule.Enabled -eq $true -and $existingRule.Action -eq "Allow") {
            Write-BlueTeamLog "Firewall rule for safe IP $ip already exists and is correctly configured" "INFO"
            continue
        } elseif ($existingRule) {
            Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        }
        
        # Create new rule allowing all traffic from this IP
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Inbound `
            -RemoteAddress $ip `
            -Action Allow `
            -Enabled True `
            -Profile Any -ErrorAction SilentlyContinue | Out-Null
        
        Write-BlueTeamLog "Created firewall rule for safe IP: $ip" "SUCCESS"
        Add-Change "Firewall" "Safe IP Address" $ip "All traffic allowed"
    } catch {
        Write-BlueTeamLog "Failed to create firewall rule for IP ${ip}: $_" "ERROR"
    }
}

# Create rules for safe IP ranges
foreach ($ipRange in $SafeIPRanges) {
    try {
        $ruleName = "Blue Team - Safe Range $ipRange"
        
        # Check if rule already exists correctly
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        
        if ($existingRule -and $existingRule.Enabled -eq $true -and $existingRule.Action -eq "Allow") {
            Write-BlueTeamLog "Firewall rule for safe IP range $ipRange already exists and is correctly configured" "INFO"
            continue
        } elseif ($existingRule) {
            Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        }
        
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Inbound `
            -RemoteAddress $ipRange `
            -Action Allow `
            -Enabled True `
            -Profile Any -ErrorAction SilentlyContinue | Out-Null
        
        Write-BlueTeamLog "Created firewall rule for safe IP range: $ipRange" "SUCCESS"
        Add-Change "Firewall" "Safe IP Range" $ipRange "All traffic allowed"
    } catch {
        Write-BlueTeamLog "Failed to create firewall rule for IP range ${ipRange}: $_" "ERROR"
    }
}

# ============================================================================
}
if ($RunPhase4) {
# 4. SSH REMOVAL (Windows - SSH not required, only RDP is)
# ============================================================================
Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "PHASE 4: SSH REMOVAL (SSH not required on Windows - NUKE IT)" "CRITICAL"
Write-BlueTeamLog "============================================================" "INFO"

# ── SSH REMOVAL (Windows only) ───────────────────────────────────────────────
# Rule 10 only requires RDP to remain open on Windows. SSH is NOT required and
# is an unnecessary attack surface. If OpenSSH Server is installed, REMOVE IT.
# Block port 22 at the firewall and remove any existing SSH firewall rules.
Write-BlueTeamLog "Checking for OpenSSH Server - will REMOVE if found (not required on Windows)..." "CRITICAL"

# Step 1: Nuke any existing firewall rules for port 22 / SSH
Write-BlueTeamLog "Removing any SSH (port 22) firewall rules..." "INFO"
$sshFwRulesRemoved = 0
try {
    # Remove by well-known rule names
    $knownSSHRuleNames = @("OpenSSH-Server-In-TCP", "OpenSSH SSH Server (sshd)")
    foreach ($rn in $knownSSHRuleNames) {
        $r = Get-NetFirewallRule -Name $rn -ErrorAction SilentlyContinue
        if (-not $r) { $r = Get-NetFirewallRule -DisplayName $rn -ErrorAction SilentlyContinue }
        if ($r) {
            Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue
            Write-BlueTeamLog "  Removed SSH firewall rule: $($r.DisplayName)" "REMOVED"
            $sshFwRulesRemoved++
        }
    }
    # Also sweep for any rule touching port 22
    Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue | ForEach-Object {
        $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_ -ErrorAction SilentlyContinue
        if ($pf -and $pf.LocalPort -eq 22) {
            Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
            Write-BlueTeamLog "  Removed inbound firewall rule for port 22: $($_.DisplayName)" "REMOVED"
            $sshFwRulesRemoved++
        }
    }
    # Also remove any Blue Team SSH allow rule left from a previous run
    $btSSH = Get-NetFirewallRule -DisplayName "Blue Team - Allow Port 22*" -ErrorAction SilentlyContinue
    if ($btSSH) {
        Remove-NetFirewallRule -DisplayName "Blue Team - Allow Port 22*" -ErrorAction SilentlyContinue
        Write-BlueTeamLog "  Removed Blue Team SSH allow rule" "REMOVED"
        $sshFwRulesRemoved++
    }
} catch {
    Write-BlueTeamLog "Error while sweeping SSH firewall rules: $_" "WARNING"
}

# Step 2: Add an explicit BLOCK rule for port 22 so nothing can sneak through
try {
    $blockRuleName = "Blue Team - BLOCK SSH Port 22"
    $existing = Get-NetFirewallRule -DisplayName $blockRuleName -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-NetFirewallRule -DisplayName $blockRuleName `
            -Direction Inbound -Protocol TCP -LocalPort 22 `
            -Action Block -Enabled True -Profile Any `
            -ErrorAction Stop | Out-Null
        Write-BlueTeamLog "Created explicit BLOCK rule for port 22" "SUCCESS"
        Add-Change "Firewall" "Blocked Port" "22 (SSH)" "SSH is not required on Windows - hard blocked"
    } else {
        Write-BlueTeamLog "Explicit BLOCK rule for port 22 already exists" "INFO"
    }
} catch {
    Write-BlueTeamLog "Failed to create port 22 block rule: $_" "ERROR"
}
Write-BlueTeamLog "SSH firewall cleanup complete. Removed $sshFwRulesRemoved SSH rule(s)." "SUCCESS"

# Step 3: Stop and disable the sshd service if it exists
try {
    $sshdService = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($sshdService) {
        Write-BlueTeamLog "OpenSSH sshd service found - stopping and disabling..." "WARNING"
        Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
        Set-Service -Name sshd -StartupType Disabled -ErrorAction SilentlyContinue
        Write-BlueTeamLog "sshd service stopped and set to Disabled" "SUCCESS"
        Add-Change "SSH Removal" "sshd Service" "Stopped + Disabled" "SSH not required on Windows"
    } else {
        Write-BlueTeamLog "sshd service not found (already removed or never installed)" "INFO"
    }
} catch {
    Write-BlueTeamLog "Error stopping sshd service: $_" "WARNING"
}

# Step 4: Also stop ssh-agent if running
try {
    $sshAgent = Get-Service -Name ssh-agent -ErrorAction SilentlyContinue
    if ($sshAgent -and $sshAgent.Status -eq "Running") {
        Stop-Service -Name ssh-agent -Force -ErrorAction SilentlyContinue
        Set-Service -Name ssh-agent -StartupType Disabled -ErrorAction SilentlyContinue
        Write-BlueTeamLog "ssh-agent service stopped and disabled" "SUCCESS"
        Add-Change "SSH Removal" "ssh-agent Service" "Stopped + Disabled" "SSH not required on Windows"
    }
} catch {
    # Non-critical
}

# Step 5: Uninstall OpenSSH Server feature if installed
$sshServerFeature = $null
try {
    $sshServerFeature = Get-WindowsCapability -Online -ErrorAction Stop | Where-Object Name -like 'OpenSSH.Server*'
} catch {
    Write-BlueTeamLog "Get-WindowsCapability failed (common after user account changes) - skipping feature removal check" "WARNING"
}

if ($sshServerFeature -and $sshServerFeature.State -eq "Installed") {
    Write-BlueTeamLog "OpenSSH.Server feature is installed - REMOVING IT NOW..." "CRITICAL"
    try {
        Remove-WindowsCapability -Online -Name $sshServerFeature.Name -ErrorAction Stop | Out-Null
        Write-BlueTeamLog "OpenSSH.Server feature successfully REMOVED" "SUCCESS"
        Add-Change "SSH Removal" "OpenSSH.Server Feature" "Uninstalled" "SSH not required on Windows"
    } catch {
        Write-BlueTeamLog "Failed to remove OpenSSH.Server feature: $_" "ERROR"
        Write-BlueTeamLog "  Service is stopped/disabled and port 22 is blocked even if feature removal failed" "WARNING"
    }
} elseif ($sshServerFeature -and $sshServerFeature.State -ne "Installed") {
    Write-BlueTeamLog "OpenSSH.Server feature is not installed - nothing to remove" "INFO"
} else {
    Write-BlueTeamLog "Could not verify OpenSSH.Server feature state - service and firewall have been handled above" "WARNING"
}

Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "Phase 4 complete: SSH fully removed/blocked on this Windows host" "SUCCESS"

# ============================================================================
}
if ($RunPhase5) {
# 5. NETWORK SECURITY HARDENING
# ============================================================================
Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "PHASE 5: NETWORK SECURITY" "CRITICAL"
Write-BlueTeamLog "============================================================" "INFO"

# Disable SMBv1 (critical vulnerability)
if ($DisableSMBv1) {
    try {
        Write-BlueTeamLog "Checking SMB protocol configuration..." "INFO"
        
        # Check if this is the SMB scored service host (appleloosa - 10.0.20.2)
        if ($hostname -eq "appleloosa") {
            Write-BlueTeamLog "WARNING: This is the SMB scored service host!" "WARNING"
            Write-BlueTeamLog "SMBv1 will be disabled, but SMBv2/v3 will remain enabled for scoring" "INFO"
        }
        
        # Check current SMB configuration
        $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        $madeChanges = $false
        
        if ($smbConfig) {
            # Disable SMBv1 if it's enabled
            if ($smbConfig.EnableSMB1Protocol -eq $true) {
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
                $madeChanges = $true
                Write-BlueTeamLog "SMBv1 protocol disabled" "SUCCESS"
            } else {
                Write-BlueTeamLog "SMBv1 protocol already disabled" "INFO"
            }
            
            # Ensure SMBv2/v3 is enabled (critical for SMB scored service)
            if ($smbConfig.EnableSMB2Protocol -eq $false) {
                Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force -ErrorAction Stop
                $madeChanges = $true
                Write-BlueTeamLog "SMBv2/v3 protocol enabled" "SUCCESS"
            } else {
                Write-BlueTeamLog "SMBv2/v3 protocol already enabled" "INFO"
            }
        }
        
        # Also disable the Windows feature for SMBv1
        try {
            $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
            if ($smb1Feature -and $smb1Feature.State -eq "Enabled") {
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
                $madeChanges = $true
                Write-BlueTeamLog "SMBv1 Windows feature disabled" "SUCCESS"
            } elseif ($smb1Feature -and $smb1Feature.State -eq "Disabled") {
                Write-BlueTeamLog "SMBv1 Windows feature already disabled" "INFO"
            }
        } catch {
            Write-BlueTeamLog "SMBv1 feature management not available or already handled" "INFO"
        }
        
        if ($madeChanges) {
            Add-Change "Network Security" "SMBv1" "Disabled" "Critical vulnerability mitigation (SMBv2/3 still enabled)"
            Write-BlueTeamLog "SMB protocol configuration updated successfully" "SUCCESS"
        } else {
            Write-BlueTeamLog "SMB protocol already properly configured" "INFO"
        }
    } catch {
        Write-BlueTeamLog "Failed to configure SMB protocols: $_" "ERROR"
    }
}

# Disable LLMNR (Link-Local Multicast Name Resolution)
try {
    Write-BlueTeamLog "Checking LLMNR configuration..." "INFO"
    $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    
    # Create path if it doesn't exist
    if (-not (Test-Path $llmnrPath)) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name "DNSClient" -Force | Out-Null
    }
    
    $currentValue = (Get-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
    
    if ($currentValue -ne 0) {
        Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord -Force
        Add-Change "Network Security" "LLMNR" "Disabled" "Prevents credential theft"
        Write-BlueTeamLog "LLMNR disabled" "SUCCESS"
    } else {
        Write-BlueTeamLog "LLMNR already disabled" "INFO"
    }
} catch {
    Write-BlueTeamLog "Failed to disable LLMNR: $_" "ERROR"
}

# Disable NetBIOS over TCP/IP
try {
    Write-BlueTeamLog "Checking NetBIOS over TCP/IP configuration..." "INFO"
    $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 'True'" -ErrorAction Stop
    $disabledCount = 0
    $alreadyDisabledCount = 0
    
    foreach ($adapter in $adapters) {
        try {
            # Check current NetBIOS setting (0 = Default, 1 = Enabled, 2 = Disabled)
            $currentSetting = $adapter.TcpipNetbiosOptions
            
            if ($currentSetting -ne 2) {
                $result = $adapter.SetTcpipNetbios(2)
                if ($result.ReturnValue -eq 0) {
                    $disabledCount++
                }
            } else {
                $alreadyDisabledCount++
            }
        } catch {
            Write-BlueTeamLog "Could not modify NetBIOS on adapter: $($adapter.Description)" "WARNING"
        }
    }
    
    if ($disabledCount -gt 0) {
        Add-Change "Network Security" "NetBIOS" "Disabled" "$disabledCount adapter(s) updated"
        Write-BlueTeamLog "NetBIOS disabled on $disabledCount network adapter(s)" "SUCCESS"
    }
    
    if ($alreadyDisabledCount -gt 0) {
        Write-BlueTeamLog "NetBIOS already disabled on $alreadyDisabledCount adapter(s)" "INFO"
    }
    
    if ($disabledCount -eq 0 -and $alreadyDisabledCount -eq 0) {
        Write-BlueTeamLog "No network adapters found or NetBIOS configuration unavailable" "WARNING"
    }
} catch {
    Write-BlueTeamLog "Failed to configure NetBIOS: $_" "ERROR"
}

# Disable IPv6 if not needed (optional)
# Commented out by default as it may break some networks
# try {
#     Write-BlueTeamLog "Disabling IPv6..." "INFO"
#     New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xFF -PropertyType DWord -Force | Out-Null
#     Add-Change "Network Security" "IPv6" "Disabled"
#     Write-BlueTeamLog "IPv6 disabled (requires restart)" "SUCCESS"
# } catch {
#     Write-BlueTeamLog "Failed to disable IPv6: $_" "ERROR"
# }

# ============================================================================
}
if ($RunPhase6) {
# 6. BACKDOOR AND PERSISTENCE DETECTION
# ============================================================================
Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "PHASE 6: BACKDOOR DETECTION AND REMOVAL" "CRITICAL"
Write-BlueTeamLog "============================================================" "INFO"

if ($ScanForBackdoors) {
    # Scan for suspicious scheduled tasks
    if ($RemoveSuspiciousScheduledTasks) {
        Write-BlueTeamLog "Scanning for suspicious scheduled tasks..." "INFO"
        
        # Whitelist of legitimate software task paths
        $legitimateTaskPaths = @(
            "\Microsoft\",
            "\Mozilla\",
            "\GoogleUpdateTask",
            "\Adobe\",
            "\Apple\",
            "\CCleanerSkipUAC",
            "\Opera\",
            "\Avast\",
            "\AVG\",
            "\McAfee\",
            "\Symantec\"
        )
        
        $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Disabled" }
        $suspiciousCount = 0
        
        foreach ($task in $allTasks) {
            # CRITICAL: Per Rule 3 & 5 - Do not modify artifacts with "greyteam" in name
            if ($task.TaskName -like "*greyteam*" -or $task.TaskName -like "*grayteam*") {
                Write-BlueTeamLog "Skipping Gray Team task: $($task.TaskName) (protected by rules)" "INFO"
                continue
            }
            
            # Check for suspicious indicators
            $suspicious = $false
            $reason = ""
            
            # Check if task path is in legitimate list
            $isLegitimate = $false
            foreach ($legitPath in $legitimateTaskPaths) {
                if ($task.TaskPath -like "*$legitPath*") {
                    $isLegitimate = $true
                    break
                }
            }
            
            # Check task path (tasks not in Microsoft or known legitimate paths are suspicious)
            if (-not $isLegitimate -and $task.TaskPath -ne "\") {
                $suspicious = $true
                $reason = "Non-standard task path"
            }
            
            # Check for suspicious actions (PowerShell downloads, etc.)
            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
            $actions = (Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath).Actions
            
            foreach ($action in $actions) {
                if ($action.Execute -like "*powershell*" -and 
                    ($action.Arguments -like "*DownloadString*" -or 
                     $action.Arguments -like "*IEX*" -or
                     $action.Arguments -like "*Invoke-Expression*" -or
                     $action.Arguments -like "*-enc*" -or
                     $action.Arguments -like "*-EncodedCommand*")) {
                    $suspicious = $true
                    $reason = "Suspicious PowerShell command"
                }
            }
            
            if ($suspicious) {
                $suspiciousCount++
                Write-BlueTeamLog "SUSPICIOUS TASK FOUND: $($task.TaskName) - Reason: $reason" "CRITICAL" -Critical
                Write-BlueTeamLog "  Path: $($task.TaskPath)" "WARNING"
                Write-BlueTeamLog "  Action: $($actions[0].Execute) $($actions[0].Arguments)" "WARNING"
                
                # Optionally remove (be careful!)
                # Uncomment the next line to auto-remove suspicious tasks
                # Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false
                # Write-BlueTeamLog "Removed suspicious task: $($task.TaskName)" "REMOVED"
                # $RemovedItems += "Scheduled Task: $($task.TaskName)"
            }
        }
        
        Write-BlueTeamLog "Found $suspiciousCount suspicious scheduled tasks" "WARNING"
    }
    
    # Scan startup locations
    if ($ScanStartupLocations) {
        Write-BlueTeamLog "" "INFO"
        Write-BlueTeamLog "Scanning startup locations for persistence..." "INFO"
        
        # Whitelist of legitimate startup entries
        $legitimateStartupEntries = @(
            "SecurityHealth",
            "OneDrive",
            "Teams",
            "WindowsDefender",
            "AzureArcSetup",
            "VMware",
            "VBoxTray",
            "NvBackend",
            "RtkAudioManager",
            "Intel",
            "AMD",
            "NVIDIA",
            "msedge",          # Microsoft Edge and EdgeWebView cleanup tasks are legitimate
            "MicrosoftEdge",
            "EdgeWebView",
            "MsEdge"
        )
        
        $startupLocations = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        
        foreach ($location in $startupLocations) {
            try {
                if (Test-Path $location) {
                    $items = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
                    if ($items) {
                        $items.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                            # Check if entry is in whitelist
                            $isLegitimate = $false
                            foreach ($legitEntry in $legitimateStartupEntries) {
                                if ($_.Name -like "*$legitEntry*" -or $_.Value -like "*$legitEntry*") {
                                    $isLegitimate = $true
                                    break
                                }
                            }
                            
                            # Only log if not legitimate
                            if (-not $isLegitimate) {
                                Write-BlueTeamLog "SUSPICIOUS startup entry in $location : $($_.Name) = $($_.Value)" "CRITICAL" -Critical
                            } else {
                                Write-BlueTeamLog "Legitimate startup entry: $($_.Name)" "INFO"
                            }
                        }
                    }
                }
            } catch {
                # Ignore errors for non-existent keys
            }
        }
    }
    
    # Check for suspicious services
    if ($DisableSuspiciousServices) {
        Write-BlueTeamLog "" "INFO"
        Write-BlueTeamLog "Scanning for suspicious services..." "INFO"
        
        $allServices = Get-Service | Where-Object { $_.Status -eq "Running" }
        
        foreach ($service in $allServices) {
            try {
                $servicePath = (Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'").PathName
                
                # Check for suspicious paths (temp directories, user directories, etc.)
                if ($servicePath -like "*\Temp\*" -or 
                    $servicePath -like "*\AppData\*" -or
                    $servicePath -like "*\Downloads\*" -or
                    $servicePath -like "*\Users\Public\*") {
                    
                    Write-BlueTeamLog "SUSPICIOUS SERVICE: $($service.Name)" "CRITICAL" -Critical
                    Write-BlueTeamLog "  Display Name: $($service.DisplayName)" "WARNING"
                    Write-BlueTeamLog "  Path: $servicePath" "WARNING"
                    
                    # Optionally stop and disable (be very careful!)
                    # Uncomment to auto-disable suspicious services
                    # Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
                    # Set-Service -Name $service.Name -StartupType Disabled
                    # Write-BlueTeamLog "Disabled suspicious service: $($service.Name)" "REMOVED"
                    # $RemovedItems += "Service: $($service.Name)"
                }
            } catch {
                # Ignore errors for services without path info
            }
        }
    }
}

# ============================================================================
}
if ($RunPhase7) {
# 7. SYSTEM HARDENING
# ============================================================================
Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "PHASE 7: SYSTEM HARDENING" "CRITICAL"
Write-BlueTeamLog "============================================================" "INFO"

# Disable AutoRun/AutoPlay
try {
    Write-BlueTeamLog "Disabling AutoRun/AutoPlay..." "INFO"
    
    # Check if already set to avoid unnecessary changes
    $hklmValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
    if ($hklmValue.NoDriveTypeAutoRun -ne 255) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force
        Write-BlueTeamLog "AutoRun disabled for HKLM" "SUCCESS"
    } else {
        Write-BlueTeamLog "AutoRun already disabled for HKLM" "INFO"
    }
    
    # Create HKCU path if it doesn't exist
    if (-not (Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
    }
    
    $hkcuValue = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
    if ($hkcuValue.NoDriveTypeAutoRun -ne 255) {
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force
        Write-BlueTeamLog "AutoRun disabled for HKCU" "SUCCESS"
    } else {
        Write-BlueTeamLog "AutoRun already disabled for HKCU" "INFO"
    }
    
    Add-Change "System Security" "AutoRun" "Disabled" "All drive types"
    Write-BlueTeamLog "AutoRun configuration complete" "SUCCESS"
} catch {
    Write-BlueTeamLog "Failed to disable AutoRun: $_" "ERROR"
}

# Enable UAC
try {
    Write-BlueTeamLog "Enabling User Account Control (UAC)..." "INFO"
    
    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $currentLUA = (Get-ItemProperty -Path $uacPath -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
    $currentPrompt = (Get-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    $currentSecure = (Get-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -ErrorAction SilentlyContinue).PromptOnSecureDesktop
    
    $madeChanges = $false
    
    if ($currentLUA -ne 1) {
        Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 1 -Type DWord -Force
        $madeChanges = $true
    }
    if ($currentPrompt -ne 2) {
        Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord -Force
        $madeChanges = $true
    }
    if ($currentSecure -ne 1) {
        Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -Force
        $madeChanges = $true
    }
    
    if ($madeChanges) {
        Add-Change "System Security" "UAC" "Enabled" "Maximum security level"
        Write-BlueTeamLog "UAC enabled with secure desktop prompt" "SUCCESS"
    } else {
        Write-BlueTeamLog "UAC already properly configured" "INFO"
    }
} catch {
    Write-BlueTeamLog "Failed to enable UAC: $_" "ERROR"
}

# Disable PowerShell v2 (vulnerable)
if ($DisablePowerShellV2) {
    try {
        Write-BlueTeamLog "Disabling PowerShell v2..." "INFO"
        
        # Check if PowerShell v2 feature exists (different names on different Windows versions)
        $psv2Feature = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2* -ErrorAction SilentlyContinue
        
        if ($psv2Feature) {
            Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction SilentlyContinue | Out-Null
            Add-Change "System Security" "PowerShell v2" "Disabled" "Prevents downgrade attacks"
            Write-BlueTeamLog "PowerShell v2 disabled" "SUCCESS"
        } else {
            Write-BlueTeamLog "PowerShell v2 not present on this system (already secure)" "INFO"
        }
    } catch {
        Write-BlueTeamLog "PowerShell v2 not available on this Windows version" "INFO"
    }
}

# Enable Windows Defender Real-time Protection
if ($EnableWindowsDefender) {
    try {
        Write-BlueTeamLog "Configuring Windows Defender..." "INFO"
        
        # Get current preferences
        $currentPrefs = Get-MpPreference -ErrorAction SilentlyContinue
        
        if ($currentPrefs) {
            $madeChanges = $false
            
            if ($currentPrefs.DisableRealtimeMonitoring -eq $true) {
                Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
                $madeChanges = $true
            }
            if ($currentPrefs.DisableBehaviorMonitoring -eq $true) {
                Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
                $madeChanges = $true
            }
            if ($currentPrefs.DisableIOAVProtection -eq $true) {
                Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
                $madeChanges = $true
            }
            if ($currentPrefs.DisableScriptScanning -eq $true) {
                Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
                $madeChanges = $true
            }
            
            # Always try to update signatures
            Write-BlueTeamLog "Updating Windows Defender signatures..." "INFO"
            Update-MpSignature -ErrorAction SilentlyContinue
            
            if ($madeChanges) {
                Add-Change "System Security" "Windows Defender" "Enabled" "Real-time protection active"
                Write-BlueTeamLog "Windows Defender enabled and updated" "SUCCESS"
            } else {
                Write-BlueTeamLog "Windows Defender already properly configured and signatures updated" "INFO"
            }
        } else {
            Write-BlueTeamLog "Windows Defender not available or not installed" "WARNING"
        }
    } catch {
        Write-BlueTeamLog "Failed to configure Windows Defender: $_" "ERROR"
    }
}

# Disable Remote Desktop if configured
# CRITICAL: Per Rule 10 - Teams may NOT disable RDP on Windows machines
if ($DisableRDP) {
    Write-BlueTeamLog "" "INFO"
    Write-BlueTeamLog "WARNING: RDP disable is configured, but this violates Rule 10!" "CRITICAL"
    Write-BlueTeamLog "Per competition rules: 'Teams may not disable SSH on Linux machines or RDP on Windows machines'" "CRITICAL"
    Write-BlueTeamLog "Skipping RDP disable to remain compliant with competition rules" "WARNING"
    Write-BlueTeamLog "RDP will be hardened instead of disabled" "INFO"
    
    # Harden RDP instead of disabling it
    try {
        # Require Network Level Authentication
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Force
        
        # Set encryption level to high
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Value 3 -Force
        
        # Disable "Always prompt for password"
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "fPromptForPassword" -Value 1 -Force
        
        Add-Change "System Security" "Remote Desktop" "Hardened" "NLA enabled, high encryption"
        Write-BlueTeamLog "RDP hardened (NLA required, high encryption)" "SUCCESS"
    } catch {
        Write-BlueTeamLog "Failed to harden RDP: $_" "ERROR"
    }
}

# Disable USB storage (optional)
if ($DisableUSBStorage) {
    try {
        Write-BlueTeamLog "Disabling USB storage devices..." "INFO"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4 -Type DWord -Force
        Add-Change "System Security" "USB Storage" "Disabled" "Prevents data exfiltration"
        Write-BlueTeamLog "USB storage disabled" "SUCCESS"
    } catch {
        Write-BlueTeamLog "Failed to disable USB storage: $_" "ERROR"
    }
}

# Restrict anonymous access
try {
    Write-BlueTeamLog "Restricting anonymous access..." "INFO"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWord -Force
    Add-Change "System Security" "Anonymous Access" "Restricted"
    Write-BlueTeamLog "Anonymous access restricted" "SUCCESS"
} catch {
    Write-BlueTeamLog "Failed to restrict anonymous access: $_" "ERROR"
}

# Enable DEP (Data Execution Prevention) for all processes
try {
    Write-BlueTeamLog "Enabling Data Execution Prevention (DEP)..." "INFO"
    bcdedit /set nx AlwaysOn | Out-Null
    Add-Change "System Security" "DEP" "Enabled" "All processes"
    Write-BlueTeamLog "DEP enabled for all processes" "SUCCESS"
} catch {
    Write-BlueTeamLog "Failed to enable DEP: $_" "ERROR"
}

# Disable Windows Script Host (prevents .vbs, .js malware)
# IMPORTANT: Setting Enabled=0 in the registry still lets wscript.exe/cscript.exe
# launch and show a popup dialog every time anything calls WSH. The silent fix is to
# deny execute permissions on the binaries directly - they cannot run at all and
# produce no dialog. The registry key is kept as a second layer.
try {
    Write-BlueTeamLog "Disabling Windows Script Host (revoking execute access on wscript/cscript)..." "INFO"

    $wshBinaries = @(
        "$env:SystemRoot\System32\wscript.exe",
        "$env:SystemRoot\System32\cscript.exe",
        "$env:SystemRoot\SysWOW64\wscript.exe",
        "$env:SystemRoot\SysWOW64\cscript.exe"
    )
    foreach ($binary in $wshBinaries) {
        if (Test-Path $binary) {
            try {
                & takeown /f $binary /A 2>&1 | Out-Null
                & icacls $binary /grant "Administrators:F" 2>&1 | Out-Null
                & icacls $binary /deny "Everyone:(X)" 2>&1 | Out-Null
                & icacls $binary /deny "Users:(X)" 2>&1 | Out-Null
                Write-BlueTeamLog "  Revoked execute access: $binary" "SUCCESS"
            } catch {
                Write-BlueTeamLog "  Could not modify permissions on $binary : $_" "WARNING"
            }
        }
    }

    # Registry key as a second layer
    $wshRegPath = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
    if (-not (Test-Path $wshRegPath)) { New-Item -Path $wshRegPath -Force | Out-Null }
    Set-ItemProperty -Path $wshRegPath -Name "Enabled" -Value 0 -Type DWord -Force

    Add-Change "System Security" "Windows Script Host" "Disabled" "Execute access denied on wscript.exe/cscript.exe (no popup)"
    Write-BlueTeamLog "Windows Script Host disabled silently (no popup)" "SUCCESS"
} catch {
    Write-BlueTeamLog "Failed to disable Windows Script Host: $_" "ERROR"
}

# ============================================================================
}
if ($RunPhase8) {
# 8. AUDIT LOGGING
# ============================================================================
Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "PHASE 8: AUDIT LOGGING CONFIGURATION" "CRITICAL"
Write-BlueTeamLog "============================================================" "INFO"

try {
    Write-BlueTeamLog "Configuring Security event log..." "INFO"
    wevtutil sl Security /retention:true /maxsize:$($AuditLogSize) | Out-Null
    Add-Change "Auditing" "Security Log Size" "Configured" "$($AuditLogSize/1MB)MB"
    Write-BlueTeamLog "Security event log configured" "SUCCESS"
} catch {
    Write-BlueTeamLog "Failed to configure event log: $_" "ERROR"
}

if ($EnableAdvancedAuditing) {
    try {
        Write-BlueTeamLog "Enabling advanced audit policies..." "INFO"
        
        # Enable comprehensive auditing
        $auditCategories = @(
            "Account Logon",
            "Account Management",
            "Detailed Tracking",
            "Logon/Logoff",
            "Object Access",
            "Policy Change",
            "Privilege Use",
            "System"
        )
        
        foreach ($category in $auditCategories) {
            auditpol /set /category:"$category" /success:enable /failure:enable | Out-Null
            Write-BlueTeamLog "  Enabled auditing for: $category" "INFO"
        }
        
        # Specific critical audit policies
        auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"Logoff" /success:enable | Out-Null
        auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable | Out-Null
        
        Add-Change "Auditing" "Advanced Audit Policies" "Enabled" "All categories"
        Write-BlueTeamLog "Advanced audit policies enabled" "SUCCESS"
    } catch {
        Write-BlueTeamLog "Failed to configure audit policies: $_" "ERROR"
    }
}

# Enable command line logging in process creation events
try {
    Write-BlueTeamLog "Enabling command line logging..." "INFO"
    if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
    Add-Change "Auditing" "Command Line Logging" "Enabled" "Process creation events"
    Write-BlueTeamLog "Command line logging enabled" "SUCCESS"
} catch {
    Write-BlueTeamLog "Failed to enable command line logging: $_" "ERROR"
}

# Enable PowerShell logging
try {
    Write-BlueTeamLog "Enabling PowerShell logging..." "INFO"
    
    # Module logging
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Type DWord -Force
    
    # Script block logging
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
    
    # Transcription
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\BlueTeam\Logs\PowerShell" -Type String -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Value 1 -Type DWord -Force
    
    Add-Change "Auditing" "PowerShell Logging" "Enabled" "Module, ScriptBlock, and Transcription logging"
    Write-BlueTeamLog "PowerShell logging enabled" "SUCCESS"
} catch {
    Write-BlueTeamLog "Failed to enable PowerShell logging: $_" "ERROR"
}

# ============================================================================
}
if (-not $RunningIndividualPhase) {
# 9. FINAL REPORT GENERATION
# ============================================================================
Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "GENERATING FINAL REPORT" "CRITICAL"
Write-BlueTeamLog "============================================================" "INFO"

$ScriptEndTime = Get-Date
$Duration = $ScriptEndTime - $ScriptStartTime

# Summary statistics
Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "EXECUTION SUMMARY:" "INFO"
Write-BlueTeamLog "  Start time: $ScriptStartTime" "INFO"
Write-BlueTeamLog "  End time: $ScriptEndTime" "INFO"
Write-BlueTeamLog "  Duration: $($Duration.TotalSeconds) seconds" "INFO"
Write-BlueTeamLog "  Script run number: $scriptRunCount" "INFO"
Write-BlueTeamLog "  Total changes applied: $($Changes.Count)" "INFO"
if ($scriptRunCount -gt 1) {
    Write-BlueTeamLog "  Note: Some operations were skipped as they were already completed in previous runs" "INFO"
}
Write-BlueTeamLog "  Users removed: $($RemovedUsers.Count)" "INFO"
Write-BlueTeamLog "  Security issues found: $($SecurityIssues.Count)" "INFO"

# Changes by category
Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "CHANGES BY CATEGORY:" "INFO"
$Changes | Group-Object Category | Sort-Object Count -Descending | ForEach-Object {
    Write-BlueTeamLog "  $($_.Name): $($_.Count) changes" "INFO"
}

# List removed users
if ($RemovedUsers.Count -gt 0) {
    Write-BlueTeamLog "" "INFO"
    Write-BlueTeamLog "REMOVED USERS:" "REMOVED"
    $RemovedUsers | ForEach-Object {
        Write-BlueTeamLog "  - $_" "REMOVED"
    }
}

# List security issues
if ($SecurityIssues.Count -gt 0) {
    Write-BlueTeamLog "" "INFO"
    Write-BlueTeamLog "SECURITY ISSUES DETECTED:" "CRITICAL"
    $SecurityIssues | ForEach-Object {
        Write-BlueTeamLog "  ! $_" "CRITICAL"
    }
}

# Authorized users
Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "AUTHORIZED ADMIN USERS:" "INFO"
$AuthorizedAdmins | ForEach-Object {
    Write-BlueTeamLog "  - $_" "INFO"
}

# Safe IPs
Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "WHITELISTED IP ADDRESSES:" "INFO"
$SafeIPAddresses | ForEach-Object {
    Write-BlueTeamLog "  - $_" "INFO"
}
$SafeIPRanges | ForEach-Object {
    Write-BlueTeamLog "  - $_ (range)" "INFO"
}

# Recommendations
Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "BLUE TEAM RECOMMENDATIONS - CDT COMPETITION:" "CRITICAL"
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "1. RESTART the system to apply all changes" "WARNING"
Write-BlueTeamLog "2. REVIEW the log file for any errors: $LogFilePath" "WARNING"
Write-BlueTeamLog "3. VERIFY connectivity to scoring engine at https://scoring.mlp.local:443" "WARNING"
Write-BlueTeamLog "4. CHECK that all scored services are still running" "WARNING"
Write-BlueTeamLog "5. VERIFY all competition users can still access the system" "WARNING"
Write-BlueTeamLog "6. REMEMBER: You can only change passwords 3 times per host per session!" "CRITICAL"
Write-BlueTeamLog "7. DO NOT disable RDP on Windows - SSH on Windows should be REMOVED (Rule 10)" "CRITICAL"
Write-BlueTeamLog "8. DO NOT remove competition users (Rule 9 violation)" "CRITICAL"
Write-BlueTeamLog "9. DO NOT block entire subnets (Rule 7 violation)" "CRITICAL"
Write-BlueTeamLog "10. MONITOR the Security event log for Red Team activity" "WARNING"
Write-BlueTeamLog "11. REVIEW and REMOVE any suspicious tasks/services manually" "WARNING"
Write-BlueTeamLog "12. CHECK for Red Team persistence mechanisms" "WARNING"
Write-BlueTeamLog "13. VERIFY firewall rules aren't blocking scoring traffic" "WARNING"
Write-BlueTeamLog "14. DOCUMENT all actions taken for inject responses" "WARNING"
Write-BlueTeamLog "15. RUN this script periodically to maintain security posture" "WARNING"

Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "HARDENING COMPLETE - SYSTEM READY FOR COMPETITION" "SUCCESS"
Write-BlueTeamLog "============================================================" "INFO"

# Save completion state
$completionState = @{
    LastRunTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    RunCount = $scriptRunCount
    ChangesApplied = $Changes.Count
    UsersRemoved = $RemovedUsers.Count
    SecurityIssues = $SecurityIssues.Count
    Hostname = $hostname
    ScriptVersion = "2.1-CDT"
}
$completionState | ConvertTo-Json | Set-Content "C:\BlueTeam\last-completion-state.json"

# Final status message
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "                    BLUE TEAM HARDENING COMPLETE" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Script Run: " -NoNewline -ForegroundColor White
Write-Host "#$scriptRunCount" -ForegroundColor $(if ($scriptRunCount -gt 1) { "Yellow" } else { "Green" })
Write-Host "Log File: " -NoNewline -ForegroundColor White
Write-Host "$LogFilePath" -ForegroundColor Yellow
Write-Host "Changes Applied: " -NoNewline -ForegroundColor White
Write-Host "$($Changes.Count)" -ForegroundColor Green
Write-Host "Users Removed: " -NoNewline -ForegroundColor White
Write-Host "$($RemovedUsers.Count)" -ForegroundColor Cyan
Write-Host "Security Issues: " -NoNewline -ForegroundColor White
Write-Host "$($SecurityIssues.Count)" -ForegroundColor $(if ($SecurityIssues.Count -gt 0) { "Red" } else { "Green" })
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Smart restart logic - only force restart on first run or if significant changes were made
$shouldRestart = $false
$restartReason = ""

if ($scriptRunCount -eq 1) {
    $shouldRestart = $true
    $restartReason = "First run - restart required to apply all system changes"
} elseif ($Changes.Count -ge 5) {
    $shouldRestart = $true
    $restartReason = "Significant changes made ($($Changes.Count) changes) - restart recommended"
} else {
    Write-Host "This is run #$scriptRunCount with $($Changes.Count) change(s) applied." -ForegroundColor Yellow
    Write-Host "Most settings are already configured - restart may not be necessary." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Do you want to restart now? (Y/N): " -NoNewline -ForegroundColor Cyan
    $restartChoice = Read-Host
    
    if ($restartChoice -eq "Y" -or $restartChoice -eq "y") {
        $shouldRestart = $true
        $restartReason = "Manual restart requested by user"
    } else {
        Write-Host ""
        Write-Host "Restart skipped. You can manually restart later with: Restart-Computer -Force" -ForegroundColor Yellow
        Write-Host ""
        exit 0
    }
}

if ($shouldRestart) {
    # Countdown to restart
    Write-BlueTeamLog "Initiating system restart to apply all changes..." "CRITICAL"
    Write-BlueTeamLog "Reason: $restartReason" "INFO"
    Write-Host ""
    Write-Host $restartReason -ForegroundColor Yellow
    Write-Host ""
    
    for ($i = 10; $i -gt 0; $i--) {
        Write-Host "System will restart to apply all changes in " -NoNewline -ForegroundColor Yellow
        Write-Host "$i " -NoNewline -ForegroundColor Red
        Write-Host "seconds... (Press Ctrl+C to cancel)" -ForegroundColor Yellow
        Start-Sleep -Seconds 1
    }
    
    Write-Host ""
    Write-Host "RESTARTING NOW..." -ForegroundColor Red
    Write-BlueTeamLog "System restart initiated" "CRITICAL"
    
    # Force restart (cannot be stopped)
    Start-Sleep -Seconds 1
    Restart-Computer -Force
}
} else {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Individual Phase Complete" -ForegroundColor Green
    Write-Host "Phase(s) executed successfully." -ForegroundColor Green
    Write-Host "Check log file: $LogFilePath" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
}