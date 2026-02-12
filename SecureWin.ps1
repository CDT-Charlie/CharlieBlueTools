#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Blue Team Windows Hardening Script for Cyber Competitions
.DESCRIPTION
    Comprehensive hardening script designed for Blue vs Red team competitions.
    Removes unauthorized users, hardens SSH, configures firewall, and locks down the system
    while preserving competition infrastructure through whitelisting.
.NOTES
    Author: Blue Team Security Script
    Version: 2.0
    Requires: PowerShell 5.1+ and Administrator privileges
    Competition Ready: Yes
#>

# ============================================================================
# CRITICAL COMPETITION VARIABLES - CONFIGURE THESE FIRST!
# ============================================================================

# USER MANAGEMENT
# List of users that should NOT be removed (competition infrastructure users)
$SafeUsers = @(
    "Administrator",
    "DefaultAccount",
    "Guest",
    "WDAGUtilityAccount",
    "grayteam",           # Example: Gray team user
    "scoring"             # Example: Scoring engine user
    # Add any other competition-specific users here
)

# List of users that should have admin access and password reset
$AuthorizedAdmins = @(
    "blueteam",
    "sysadmin",
    "defender"
    # Add your blue team usernames here
)

# Password to set for all authorized users (CHANGE THIS!)
$SetAllUserPasswords = "BlueTeam2024!Secure"

# NETWORK SECURITY
# IP addresses that should NEVER be blocked (scoring engine, gray team, etc.)
$SafeIPAddresses = @(
    "10.0.0.1",          # Example: Scoring engine
    "192.168.1.100",     # Example: Gray team
    "172.16.0.5"         # Example: Competition infrastructure
    # Add competition-specific IPs here
)

# IP ranges to allow (in CIDR notation)
$SafeIPRanges = @(
    "10.0.0.0/24",       # Example: Competition network
    "192.168.1.0/24"     # Example: Management network
    # Add allowed IP ranges here
)

# SSH CONFIGURATION
$EnableSSHHardening = $true              # Enable SSH hardening
$SSHPort = 22                            # SSH port (change if non-standard)
$AllowSSHPasswordAuth = $false           # Disable password auth (use keys only)
$SSHMaxAuthTries = 3                     # Maximum authentication attempts
$SSHLoginGraceTime = 30                  # Seconds to complete authentication

# FIREWALL CONFIGURATION
$BlockAllInboundByDefault = $true        # Block all inbound except allowed
$AllowedInboundPorts = @(22, 80, 443)   # Ports to allow inbound (SSH, HTTP, HTTPS)
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
$DisableRDP = $false                     # Disable RDP if not needed
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
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "Script started at: $ScriptStartTime" "INFO"
Write-BlueTeamLog "Log file: $LogFilePath" "INFO"
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
        } else {
            # Reset password for existing user
            Write-BlueTeamLog "Resetting password for existing user: $adminUser" "INFO"
            $SecurePassword = ConvertTo-SecureString $SetAllUserPasswords -AsPlainText -Force
            Set-LocalUser -Name $adminUser -Password $SecurePassword
            Write-BlueTeamLog "Password reset for user: $adminUser" "SUCCESS"
        }
        
        # Add to Administrators group
        $adminGroup = Get-LocalGroup -Name "Administrators"
        $isMember = Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.Name -like "*$adminUser" }
        
        if (-not $isMember) {
            Add-LocalGroupMember -Group "Administrators" -Member $adminUser -ErrorAction SilentlyContinue
            Write-BlueTeamLog "Added $adminUser to Administrators group" "SUCCESS"
            Add-Change "User Management" "Admin Rights" $adminUser "Added to Administrators group"
        } else {
            Write-BlueTeamLog "User $adminUser already in Administrators group" "INFO"
        }
        
        # Enable the user account
        Enable-LocalUser -Name $adminUser
        
    } catch {
        Write-BlueTeamLog "Failed to configure admin user $adminUser : $_" "ERROR"
    }
}

# Disable Guest account (security best practice)
Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "Disabling Guest account..." "INFO"
try {
    Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    Add-Change "User Management" "Guest Account" "Disabled" "Security hardening"
    Write-BlueTeamLog "Guest account disabled" "SUCCESS"
} catch {
    Write-BlueTeamLog "Failed to disable Guest account: $_" "ERROR"
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
    net accounts /minpwlen:$MinPasswordLength /maxpwage:$MaxPasswordAge /minpwage:$MinPasswordAge /uniquepw:$PasswordHistoryCount | Out-Null
    net accounts /lockoutthreshold:$AccountLockoutThreshold /lockoutduration:$AccountLockoutDuration /lockoutwindow:$AccountLockoutDuration | Out-Null
    
    Add-Change "Password Policy" "Password Requirements" "Configured" "Min: $MinPasswordLength chars, Max age: $MaxPasswordAge days"
    Add-Change "Password Policy" "Account Lockout" "Configured" "Threshold: $AccountLockoutThreshold attempts"
    Write-BlueTeamLog "Password policy configured successfully" "SUCCESS"
    Write-BlueTeamLog "  - Min length: $MinPasswordLength" "INFO"
    Write-BlueTeamLog "  - Max age: $MaxPasswordAge days" "INFO"
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
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
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
        
        Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed $logAllowed -LogBlocked $logBlocked -LogFileName "$logPath\pfirewall.log" -LogMaxSizeKilobytes 32767
        Write-BlueTeamLog "Firewall logging configured" "SUCCESS"
    }
    
} catch {
    Write-BlueTeamLog "Failed to configure firewall: $_" "ERROR"
}

# Remove all existing inbound rules (except safe ones)
if ($BlockAllInboundByDefault) {
    Write-BlueTeamLog "" "INFO"
    Write-BlueTeamLog "Removing potentially malicious inbound firewall rules..." "INFO"
    
    $existingRules = Get-NetFirewallRule -Direction Inbound -Enabled True
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
        
        # Remove existing rule if it exists
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        
        # Create new rule
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort $port `
            -Action Allow `
            -Enabled True `
            -Profile Any | Out-Null
        
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
        
        # Remove existing rule if it exists
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        
        # Create new rule allowing all traffic from this IP
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Inbound `
            -RemoteAddress $ip `
            -Action Allow `
            -Enabled True `
            -Profile Any | Out-Null
        
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
        
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Inbound `
            -RemoteAddress $ipRange `
            -Action Allow `
            -Enabled True `
            -Profile Any | Out-Null
        
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
    $sshServerFeature = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
    
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
            if (Test-Path $sshdConfigPath) {
                $backupPath = "$sshdConfigPath.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
                Copy-Item $sshdConfigPath $backupPath
                Write-BlueTeamLog "Backed up SSH config to: $backupPath" "INFO"
            } else {
                Write-BlueTeamLog "Creating new SSH config file" "INFO"
            }
                
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
        Write-BlueTeamLog "Disabling SMBv1 protocol..." "INFO"
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Add-Change "Network Security" "SMBv1" "Disabled" "Critical vulnerability mitigation"
        Write-BlueTeamLog "SMBv1 disabled successfully" "SUCCESS"
    } catch {
        Write-BlueTeamLog "Failed to disable SMBv1: $_" "ERROR"
    }
}

# Disable LLMNR (Link-Local Multicast Name Resolution)
try {
    Write-BlueTeamLog "Disabling LLMNR..." "INFO"
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name "DNSClient" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord -Force
    Add-Change "Network Security" "LLMNR" "Disabled" "Prevents credential theft"
    Write-BlueTeamLog "LLMNR disabled" "SUCCESS"
} catch {
    Write-BlueTeamLog "Failed to disable LLMNR: $_" "ERROR"
}

# Disable NetBIOS over TCP/IP
try {
    Write-BlueTeamLog "Disabling NetBIOS over TCP/IP..." "INFO"
    $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 'True'"
    foreach ($adapter in $adapters) {
        $adapter.SetTcpipNetbios(2) | Out-Null
    }
    Add-Change "Network Security" "NetBIOS" "Disabled" "All network adapters"
    Write-BlueTeamLog "NetBIOS disabled on all adapters" "SUCCESS"
} catch {
    Write-BlueTeamLog "Failed to disable NetBIOS: $_" "ERROR"
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
        
        $allTasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
        $suspiciousCount = 0
        
        foreach ($task in $allTasks) {
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
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force
    
    # Create HKCU path if it doesn't exist
    if (-not (Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force
    
    Add-Change "System Security" "AutoRun" "Disabled" "All drive types"
    Write-BlueTeamLog "AutoRun disabled" "SUCCESS"
} catch {
    Write-BlueTeamLog "Failed to disable AutoRun: $_" "ERROR"
}

# Enable UAC
try {
    Write-BlueTeamLog "Enabling User Account Control (UAC)..." "INFO"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -Force
    Add-Change "System Security" "UAC" "Enabled" "Maximum security level"
    Write-BlueTeamLog "UAC enabled with secure desktop prompt" "SUCCESS"
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
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
        Update-MpSignature -ErrorAction SilentlyContinue
        Add-Change "System Security" "Windows Defender" "Enabled" "Real-time protection active"
        Write-BlueTeamLog "Windows Defender enabled and updated" "SUCCESS"
    } catch {
        Write-BlueTeamLog "Failed to configure Windows Defender: $_" "ERROR"
    }
}

# Disable Remote Desktop if configured
if ($DisableRDP) {
    try {
        Write-BlueTeamLog "Disabling Remote Desktop..." "INFO"
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -Force
        Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
        Stop-Service -Name "TermService" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "TermService" -StartupType Disabled -ErrorAction SilentlyContinue
        Add-Change "System Security" "Remote Desktop" "Disabled"
        Write-BlueTeamLog "Remote Desktop disabled" "SUCCESS"
    } catch {
        Write-BlueTeamLog "Failed to disable Remote Desktop: $_" "ERROR"
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
Write-BlueTeamLog "  Total changes applied: $($Changes.Count)" "INFO"
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
Write-BlueTeamLog "BLUE TEAM RECOMMENDATIONS:" "CRITICAL"
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "1. RESTART the system to apply all changes" "WARNING"
Write-BlueTeamLog "2. REVIEW the log file for any errors: $LogFilePath" "WARNING"
Write-BlueTeamLog "3. MONITOR the Security event log for suspicious activity" "WARNING"
Write-BlueTeamLog "4. VERIFY all authorized users can still access the system" "WARNING"
Write-BlueTeamLog "5. TEST network connectivity to scoring infrastructure" "WARNING"
Write-BlueTeamLog "6. CHECK firewall rules are not blocking competition traffic" "WARNING"
Write-BlueTeamLog "7. REVIEW and REMOVE any suspicious tasks/services manually" "WARNING"
Write-BlueTeamLog "8. ENABLE additional monitoring tools if available" "WARNING"
Write-BlueTeamLog "9. DOCUMENT any Red Team persistence mechanisms found" "WARNING"
Write-BlueTeamLog "10. KEEP this script running periodically to maintain posture" "WARNING"

Write-BlueTeamLog "" "INFO"
Write-BlueTeamLog "============================================================" "INFO"
Write-BlueTeamLog "HARDENING COMPLETE - SYSTEM READY FOR COMPETITION" "SUCCESS"
Write-BlueTeamLog "============================================================" "INFO"

# Final status message
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "                    BLUE TEAM HARDENING COMPLETE" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
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

# Countdown to restart
Write-BlueTeamLog "Initiating system restart to apply all changes..." "CRITICAL"
Write-Host ""

for ($i = 10; $i -gt 0; $i--) {
    Write-Host "System will restart to apply all changes in " -NoNewline -ForegroundColor Yellow
    Write-Host "$i " -NoNewline -ForegroundColor Red
    Write-Host "seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 1
}

Write-Host ""
Write-Host "RESTARTING NOW..." -ForegroundColor Red
Write-BlueTeamLog "System restart initiated" "CRITICAL"

# Force restart (cannot be stopped)
Start-Sleep -Seconds 1
Restart-Computer -Force
