#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Blue Team Windows Hardening Script for CDT Competition - Team Alpha Spring 2026
.DESCRIPTION
    Comprehensive hardening script designed for Blue vs Red team competitions.
    Removes unauthorized users, hardens SSH, configures firewall, and locks down the system
    while preserving competition infrastructure through whitelisting.
    
    COMPETITION: CDT Team Alpha Spring 2026
    DOMAIN: mlp.local
    DEFAULT PASSWORD: FriendshipIsMagic0!
    SCORING ENGINE: https://172.20.0.100:443
    
.BEFORE_RUNNING
    **REQUIRED CONFIGURATION - EDIT THESE VARIABLES:**
    
    1. $AuthorizedAdmins (Line ~48) - Add your blue team usernames
       Example: @("blueteam1", "blueteam2", "blueteam3")
    
    2. $SetAllUserPasswords (Line ~56) - Change to YOUR secure password
       Example: "YourTeamPassword2026!Secure"
       NOTE: Avoid using # symbol - use ! @ $ % ^ & * instead
    
    3. $SafeIPAddresses (Line ~61) - Verify scoring engine/jumpbox IPs
       (Default values should work for CDT competition)
    
    **OPTIONAL:** Review $SafeUsers (Line ~27) to ensure all competition users are protected
    
.CRITICAL_RULES
    Rule 9: DO NOT disable any valid user accounts listed in the packet
    Rule 10: DO NOT disable SSH on Linux or RDP on Windows
    Rule 7: DO NOT block entire subnets (no subnet blocking)
    Rule 14: Password changes limited to 3 per host per comp session
    Rule 5: DO NOT modify artifacts with "greyteam" in their name
    
.SCORED_SERVICES
    Windows Servers: canterlot (AD), manehatten (MSSQL), las-pegasus (IIS), appleloosa (SMB)
    Linux Servers: ponyville (Apache2), seaddle (MariaDB), trotsylvania (CUPS), 
                   crystal-empire (vsftpd), everfree-forest (IRC), griffonstone (Nginx)
    Workstations: 3x Windows 10, 3x Ubuntu 24.04
    
.NOTES
    Author: Blue Team Security Script - CDT Competition Edition
    Version: 2.2-CDT
    Requires: PowerShell 5.1+ and Administrator privileges
    Competition Ready: Yes
    Last Updated: February 2026
    
.EXAMPLE
    # Run the script (after configuring variables above)
    .\BlueTeam-Hardening-Script.ps1
#>

# ============================================================================
# CRITICAL COMPETITION VARIABLES - CDT TEAM ALPHA SPRING 2026
# ============================================================================

# USER MANAGEMENT - CDT Competition Users (DO NOT REMOVE OR DISABLE!)
# Per Rule 9: Do not disable any valid user accounts listed in the competition packet
$SafeUsers = @(
    # Windows Default Users
    "Administrator",
    "DefaultAccount",
    "Guest",
    "WDAGUtilityAccount",
    "cyberrange",
    
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
    "cadence",
    
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
    "starswirlthebearded",
    
    # Gray Team (anything with "greyteam" per Rule 3 & 5)
    "greyteam",
    "grayteam"
)

# List of users that should have admin access and password reset
# These are YOUR blue team users - add them here
$AuthorizedAdmins = @(
    "blueteam1",
    "blueteam2",
    "blueteam3",
    "cyberrange"
    # Add your blue team members here
)

# Password to set for all authorized blue team users (CHANGE THIS BEFORE RUNNING!)
# Keep it strong - competition default is FriendshipIsMagic0!
# NOTE: Use only these special characters: ! @ $ % ^ & * ( ) - _ = + [ ] { } ; : , . ?
# The # symbol can cause issues with Windows password complexity
$SetAllUserPasswords = "FriendshipIsMagic0!"

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
    "172.20.0.0/24",     # Management/Competition network (scoring, jumpboxes)
    "10.0.10.0/24",      # Core Subnet (scored services)
    "10.0.20.0/24",      # DMZ Subnet (scored services)
    "10.0.30.0/24"       # Internal Subnet (workstations)
)

# SSH CONFIGURATION
# CRITICAL: Per Rule 10 - Teams may NOT disable SSH on Linux or RDP on Windows
$EnableSSHHardening = $true              # Enable SSH hardening (but not disable)
$SSHPort = 22                            # SSH port (change if non-standard)
$AllowSSHPasswordAuth = $false           # Disable password auth (use keys only)
$SSHMaxAuthTries = 3                     # Maximum authentication attempts
$SSHLoginGraceTime = 30                  # Seconds to complete authentication

# FIREWALL CONFIGURATION
$BlockAllInboundByDefault = $true        # Block all inbound except allowed
# Per competition topology - these ports are critical for scored services
$AllowedInboundPorts = @(
    22,    # SSH (required per Rule 10)
    80,    # HTTP (Apache2, IIS, Nginx scored services)
    443,   # HTTPS (IIS scored service)
    3389,  # RDP (required per Rule 10)
    445,   # SMB (scored service on appleloosa)
    3306,  # MySQL/MariaDB (scored service on seaddle)
    1433,  # MSSQL (scored service on manehatten)
    21,    # FTP (vsftpd scored service on crystal-empire)
    631,   # CUPS (scored service on trotsylvania)
    6667   # IRC (scored service on everfree-forest)
)
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
$LogFilePath = "C:\BlueTeam\Logs\Hardening-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').log"

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
$EnableWindowsDefender = $true           # Enable Windows Defender
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
Write-BlueTeamLog "CDT TEAM ALPHA - SPRING 2026" "CRITICAL"
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
if ($SetAllUserPasswords -eq "BlueDefender2026!Secure@CDT") {
    $configWarnings += "Default password detected - you should change `$SetAllUserPasswords to your team password!"
}

# Check if default admin users are still set
if ($AuthorizedAdmins -contains "blueteam1" -and $AuthorizedAdmins.Count -eq 3) {
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
# 1. USER ACCOUNT MANAGEMENT AND CLEANUP
# ============================================================================
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "PHASE 1: USER ACCOUNT MANAGEMENT" "CRITICAL"
Write-BlueTeamLog "============================================================" "INFO"

# Get all local users
$AllLocalUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
Write-BlueTeamLog "Found $($AllLocalUsers.Count) enabled local users" "INFO"

# Define default Windows users that should typically exist
$DefaultWindowsUsers = @(
    "Administrator",
    "DefaultAccount",
    "Guest",
    "WDAGUtilityAccount"
)

# Combine safe users (includes default + competition users)
$AllSafeUsers = $SafeUsers + $DefaultWindowsUsers + $AuthorizedAdmins | Select-Object -Unique
Write-BlueTeamLog "Protected user list: $($AllSafeUsers -join ', ')" "INFO"

# Remove unauthorized users
Write-BlueTeamLog "Scanning for unauthorized users..." "INFO"
foreach ($user in $AllLocalUsers) {
    if ($AllSafeUsers -notcontains $user.Name) {
        try {
            Write-BlueTeamLog "REMOVING unauthorized user: $($user.Name)" "REMOVED"
            Remove-LocalUser -Name $user.Name -Confirm:$false
            $RemovedUsers += $user.Name
            Add-Change "User Management" "Removed User" $user.Name "Unauthorized user removed"
            Write-BlueTeamLog "Successfully removed user: $($user.Name)" "SUCCESS"
        } catch {
            Write-BlueTeamLog "Failed to remove user $($user.Name): $_" "ERROR"
        }
    } else {
        Write-BlueTeamLog "Keeping safe user: $($user.Name)" "INFO"
    }
}

if ($RemovedUsers.Count -gt 0) {
    Write-BlueTeamLog "Total unauthorized users removed: $($RemovedUsers.Count)" "SUCCESS"
    Write-BlueTeamLog "Removed users: $($RemovedUsers -join ', ')" "SUCCESS"
} else {
    Write-BlueTeamLog "No unauthorized users found" "INFO"
}

# Create and configure authorized admin users
Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "Configuring authorized admin users..." "INFO"
foreach ($adminUser in $AuthorizedAdmins) {
    try {
        # Check if user exists
        $userExists = Get-LocalUser -Name $adminUser -ErrorAction SilentlyContinue
        
        if (-not $userExists) {
            # Create the user
            Write-BlueTeamLog "Creating new admin user: $adminUser" "INFO"
            $SecurePassword = ConvertTo-SecureString $SetAllUserPasswords -AsPlainText -Force
            New-LocalUser -Name $adminUser -Password $SecurePassword -FullName "Blue Team Admin" -Description "Authorized Blue Team Administrator" -PasswordNeverExpires:$true
            Add-Change "User Management" "Created User" $adminUser "New authorized admin user"
            Write-BlueTeamLog "Successfully created user: $adminUser" "SUCCESS"
            
            # Add to Administrators group
            $adminGroup = Get-LocalGroup -Name "Administrators"
            Add-LocalGroupMember -Group "Administrators" -Member $adminUser -ErrorAction SilentlyContinue
            Write-BlueTeamLog "Added $adminUser to Administrators group" "SUCCESS"
            Add-Change "User Management" "Admin Rights" $adminUser "Added to Administrators group"
            
        } else {
            # User exists - try to reset password
            Write-BlueTeamLog "User $adminUser exists - attempting password reset..." "INFO"
            
            # Test if the password is already set to our target password
            $testPassword = ConvertTo-SecureString $SetAllUserPasswords -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential($adminUser, $testPassword)
            
            # Try to validate the credential (this won't work on domain accounts, but that's okay)
            $passwordAlreadySet = $false
            try {
                # This is a best-effort check - if it fails, we'll try to set the password anyway
                Add-Type -AssemblyName System.DirectoryServices.AccountManagement
                $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Machine
                $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($contextType)
                $passwordAlreadySet = $principalContext.ValidateCredentials($adminUser, $SetAllUserPasswords)
            } catch {
                # If validation fails, assume password needs to be set
                $passwordAlreadySet = $false
            }
            
            if ($passwordAlreadySet) {
                Write-BlueTeamLog "Password for $adminUser is already set correctly - skipping password reset" "INFO"
            } else {
                # Try to set the password
                try {
                    $SecurePassword = ConvertTo-SecureString $SetAllUserPasswords -AsPlainText -Force
                    Set-LocalUser -Name $adminUser -Password $SecurePassword -ErrorAction Stop
                    Write-BlueTeamLog "Password reset for user: $adminUser" "SUCCESS"
                    Add-Change "User Management" "Password Reset" $adminUser "Password updated"
                } catch {
                    if ($_.Exception.Message -like "*minimum password age*" -or $_.Exception.Message -like "*password policy*") {
                        Write-BlueTeamLog "Cannot reset password for $adminUser - minimum password age restriction (script may have been run recently)" "WARNING"
                        Write-BlueTeamLog "  This is normal if the script was run within the minimum password age period" "INFO"
                    } else {
                        Write-BlueTeamLog "Failed to reset password for $adminUser : $_" "ERROR"
                    }
                }
            }
            
            # Ensure user is in Administrators group (idempotent operation)
            $adminGroup = Get-LocalGroup -Name "Administrators"
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

# Disable Guest account (security best practice)
# NOTE: Guest is a default Windows account, not a competition user
Write-BlueTeamLog "" "INFO"
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

# Create rules for allowed inbound ports
Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "Creating firewall rules for allowed ports..." "INFO"
foreach ($port in $AllowedInboundPorts) {
    try {
        $ruleName = "Blue Team - Allow Port $port"
        
        # Check if rule already exists with correct configuration
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        
        if ($existingRule) {
            # Rule exists - verify it's configured correctly
            $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $existingRule -ErrorAction SilentlyContinue
            
            if ($portFilter.LocalPort -eq $port -and $existingRule.Enabled -eq $true -and $existingRule.Action -eq "Allow") {
                Write-BlueTeamLog "Firewall rule for port $port already exists and is correctly configured" "INFO"
                continue
            } else {
                Write-BlueTeamLog "Firewall rule for port $port exists but needs updating" "INFO"
                Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            }
        }
        
        # Create new rule
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort $port `
            -Action Allow `
            -Enabled True `
            -Profile Any -ErrorAction SilentlyContinue | Out-Null
        
        Write-BlueTeamLog "Created firewall rule for port $port" "SUCCESS"
        Add-Change "Firewall" "Allowed Port" $port "Inbound traffic allowed"
    } catch {
        Write-BlueTeamLog "Failed to create firewall rule for port ${port}: $_" "ERROR"
    }
}

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
# 4. SSH HARDENING
# ============================================================================
Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "PHASE 4: SSH HARDENING" "CRITICAL"
Write-BlueTeamLog "============================================================" "INFO"

if ($EnableSSHHardening) {
    # Check if OpenSSH Server is installed
    $sshServerFeature = Get-WindowsCapability -Online -ErrorAction SilentlyContinue | Where-Object Name -like 'OpenSSH.Server*'
    
    if ($sshServerFeature.State -eq "Installed") {
        Write-BlueTeamLog "OpenSSH Server detected, applying hardening..." "INFO"
        
        # Ensure SSH service is started (creates config if needed)
        try {
            Start-Service sshd -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        } catch {
            Write-BlueTeamLog "SSH service start skipped: $_" "INFO"
        }
        
        # Configure sshd_config
        $sshdConfigPath = "C:\ProgramData\ssh\sshd_config"
        
        # Create config directory if it doesn't exist
        $sshDir = "C:\ProgramData\ssh"
        if (-not (Test-Path $sshDir)) {
            New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
            Write-BlueTeamLog "Created SSH directory: $sshDir" "INFO"
        }
        
        try {
            # Backup original config if it exists
            $skipSSHConfig = $false
            
            if (Test-Path $sshdConfigPath) {
                # Check if config is already hardened
                $currentConfig = Get-Content $sshdConfigPath -Raw
                
                if ($currentConfig -like "*Blue Team Hardened SSH Configuration*") {
                    Write-BlueTeamLog "SSH configuration already hardened - skipping config rewrite" "INFO"
                    $skipSSHConfig = $true
                    
                    # Still ensure SSH service is running and set to automatic
                    try {
                        $sshService = Get-Service -Name sshd -ErrorAction SilentlyContinue
                        if ($sshService.Status -ne "Running") {
                            Start-Service sshd -ErrorAction SilentlyContinue
                            Write-BlueTeamLog "Started SSH service" "SUCCESS"
                        }
                        if ($sshService.StartType -ne "Automatic") {
                            Set-Service -Name sshd -StartupType Automatic
                            Write-BlueTeamLog "Set SSH service to automatic startup" "SUCCESS"
                        }
                    } catch {
                        Write-BlueTeamLog "Failed to configure SSH service: $_" "WARNING"
                    }
                }
                
                if (-not $skipSSHConfig) {
                    $backupPath = "$sshdConfigPath.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
                    Copy-Item $sshdConfigPath $backupPath
                    Write-BlueTeamLog "Backed up SSH config to: $backupPath" "INFO"
                }
            } else {
                Write-BlueTeamLog "Creating new SSH config file" "INFO"
            }
            
            if (-not $skipSSHConfig) {
                
                # Create hardened config
                $hardenedConfig = @"
# Blue Team Hardened SSH Configuration
# Generated: $(Get-Date)

Port $SSHPort
Protocol 2
PermitRootLogin no
MaxAuthTries $SSHMaxAuthTries
LoginGraceTime $SSHLoginGraceTime
StrictModes yes
PubkeyAuthentication yes
PasswordAuthentication $(if ($AllowSSHPasswordAuth) { 'yes' } else { 'no' })
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM no
X11Forwarding no
PrintMotd yes
ClientAliveInterval 300
ClientAliveCountMax 2
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no

# Only allow specific users
AllowUsers $($AuthorizedAdmins -join ' ')

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Use strong ciphers only
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256

# Subsystem
Subsystem       sftp    sftp-server.exe
"@
                
                # Write hardened config
                $hardenedConfig | Set-Content $sshdConfigPath -Force
                
                Write-BlueTeamLog "SSH configuration hardened" "SUCCESS"
                Write-BlueTeamLog "  - Port: $SSHPort" "INFO"
                Write-BlueTeamLog "  - Password auth: $(if ($AllowSSHPasswordAuth) { 'Enabled' } else { 'Disabled' })" "INFO"
                Write-BlueTeamLog "  - Allowed users: $($AuthorizedAdmins -join ', ')" "INFO"
                Write-BlueTeamLog "  - Max auth tries: $SSHMaxAuthTries" "INFO"
                
                Add-Change "SSH" "Configuration" "Hardened" "Restricted to authorized users only"
                
                # Restart SSH service
                Write-BlueTeamLog "Restarting SSH service..." "INFO"
                Restart-Service sshd -Force
                Write-BlueTeamLog "SSH service restarted" "SUCCESS"
                
                # Set SSH service to start automatically
                Set-Service -Name sshd -StartupType Automatic
                
                # Configure SSH firewall rule
                $sshFirewallRule = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
                if ($sshFirewallRule) {
                    Enable-NetFirewallRule -Name "OpenSSH-Server-In-TCP"
                    Write-BlueTeamLog "SSH firewall rule enabled" "SUCCESS"
                }
                
            } # End of if (-not $skipSSHConfig)
                
        } catch {
            Write-BlueTeamLog "Failed to harden SSH configuration: $_" "ERROR"
        }
        
        # Set proper permissions on SSH directory
        try {
            $sshDir = "C:\ProgramData\ssh"
            $acl = Get-Acl $sshDir
            $acl.SetAccessRuleProtection($true, $false)
            
            # Remove all existing rules
            $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
            
            # Add SYSTEM full control
            $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.AddAccessRule($systemRule)
            
            # Add Administrators full control
            $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.AddAccessRule($adminRule)
            
            Set-Acl $sshDir $acl
            Write-BlueTeamLog "SSH directory permissions hardened" "SUCCESS"
        } catch {
            Write-BlueTeamLog "Failed to set SSH directory permissions: $_" "ERROR"
        }
        
    } else {
        Write-BlueTeamLog "OpenSSH Server is not installed, skipping SSH hardening" "WARNING"
    }
} else {
    Write-BlueTeamLog "SSH hardening disabled in configuration" "INFO"
}

# ============================================================================
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
            "NVIDIA"
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
try {
    Write-BlueTeamLog "Disabling Windows Script Host..." "INFO"
    if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Type DWord -Force
    Add-Change "System Security" "Windows Script Host" "Disabled" "Prevents script-based malware"
    Write-BlueTeamLog "Windows Script Host disabled" "SUCCESS"
} catch {
    Write-BlueTeamLog "Failed to disable Windows Script Host: $_" "ERROR"
}

# ============================================================================
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
Write-BlueTeamLog "3. VERIFY connectivity to scoring engine at https://172.20.0.100:443" "WARNING"
Write-BlueTeamLog "4. CHECK that all scored services are still running" "WARNING"
Write-BlueTeamLog "5. VERIFY all competition users can still access the system" "WARNING"
Write-BlueTeamLog "6. REMEMBER: You can only change passwords 3 times per host per session!" "CRITICAL"
Write-BlueTeamLog "7. DO NOT disable SSH or RDP (Rule 10 violation)" "CRITICAL"
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
