#
# Automatic adding whitelist & blacklist IPs & rules to firewall  2025-03-16 Emin Akbulut
#

# Settings
$settings = @{
    # Rule names
    WhitelistRuleName = "_WhitelistIPs"
    BlacklistRuleName = "_BlacklistIPs"
    BannedRuleName = "_Banned"

    # Log file names
    BlockedIPLogFile = ".\_log-blacklist-added.txt"
    WhitelistRemovalLogFile = ".\_log-whitelist-removed.txt"
    WhitelistAdditionLogFile = ".\_log-whitelist-added.txt"

    # Time range for log scanning (in hours)
    LogScanRangeHours = 24

    # Thresholds for blocking IPs
    NonWhitelistFailedAttempts = 6  # Block non-whitelisted IPs after 6 failed attempts
    WhitelistFailedAttempts = 20    # Block whitelisted IPs after 20 failed attempts

    # Time range for failed attempts (in minutes)
    NonWhitelistTimeRangeMinutes = 10  # Check non-whitelisted IPs in the last 10 minutes
    WhitelistTimeRangeMinutes = 60     # Check whitelisted IPs in the last 60 minutes

    # Clear old logs settings
    ClearOldLogs = 30  # Clear logs older than 30 hours (0 to disable)
    ClearOldFailedLogs = $true  # Clear old failed login logs
    ClearOldSuccessLogs = $true  # Clear old successful login logs
    
    # Dummy IP address for initial rule creation
    DummyIP = "0.0.0.0/255.255.255.255"
}

# Get current time
$currentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Function to clear old logs
function Clear-OldLogs {
    param (
        [string]$logName,
        [int]$hoursOld,
        [int[]]$eventIDs
    )
    if ($hoursOld -gt 0) {
        $oldestDate = (Get-Date).AddHours(-$hoursOld).ToString("yyyy-MM-dd HH:mm:ss")
        Write-Host "Clearing logs older than $hoursOld hours from $logName..."
        Get-WinEvent -LogName $logName | Where-Object {
            $_.TimeCreated -lt $oldestDate -and $eventIDs -contains $_.Id
        } | ForEach-Object {
            Remove-EventLog -RecordId $_.RecordId -LogName $logName
        }
    }
}

# Clear old logs if enabled
if ($settings.ClearOldLogs -gt 0) {
    if ($settings.ClearOldFailedLogs) {
        Clear-OldLogs -logName "Security" -hoursOld $settings.ClearOldLogs -eventIDs @(4625)  # Failed logins
        Clear-OldLogs -logName "Application" -hoursOld $settings.ClearOldLogs -eventIDs @(17836)  # Failed SQL logins
    }
    if ($settings.ClearOldSuccessLogs) {
        Clear-OldLogs -logName "Security" -hoursOld $settings.ClearOldLogs -eventIDs @(4624)  # Successful logins
    }
}

# Get current time and calculate time ranges for log scanning
$logScanRange = (Get-Date).AddHours(-$settings.LogScanRangeHours).ToString("yyyy-MM-dd HH:mm:ss")
$nonWhitelistTimeRange = (Get-Date).AddMinutes(-$settings.NonWhitelistTimeRangeMinutes).ToString("yyyy-MM-dd HH:mm:ss")
$whitelistTimeRange = (Get-Date).AddMinutes(-$settings.WhitelistTimeRangeMinutes).ToString("yyyy-MM-dd HH:mm:ss")

function Test-ValidIPAddress {
    param (
        [string]$ipAddress
    )
    # Check IPv4 and IPv6 addresses
    if ([System.Net.IPAddress]::TryParse($ipAddress, [ref]$null)) {
        return $true
    }
    return $false
}

# Function to get failed login attempts from Windows Security logs (Event ID 4625)
function Get-FailedWindowsLogins {
    param (
        [DateTime]$startTime
    )
    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4625
        StartTime = $startTime
    } | ForEach-Object {
        $eventXml = [xml]$_.ToXml()
        $ipAddress = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" } | Select-Object -ExpandProperty "#text"
        if ($ipAddress) {
            [PSCustomObject]@{
                IpAddress = $ipAddress
                TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            }
        }
    } | Where-Object { $_.IpAddress -ne $null }
}

# Function to get failed SQL login attempts (Event ID 17836)
function Get-FailedSQLLogins {
    param (
        [DateTime]$startTime
    )
    Get-WinEvent -FilterHashtable @{
        LogName = 'Application'
        ID = 17836
        StartTime = $startTime
    } | ForEach-Object {
        $eventXml = [xml]$_.ToXml()
        $ipAddress = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" } | Select-Object -ExpandProperty "#text"
        if ($ipAddress) {
            [PSCustomObject]@{
                IpAddress = $ipAddress
                TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            }
        }
    } | Where-Object { $_.IpAddress -ne $null }
}

# Get failed login attempts
$failedWindowsLogins = Get-FailedWindowsLogins -startTime $logScanRange
$failedSQLLogins = Get-FailedSQLLogins -startTime $logScanRange
$allFailedLogins = $failedWindowsLogins + $failedSQLLogins

# Initialize firewall COM object
$fw = New-Object -ComObject hnetcfg.fwpolicy2

# Check and create Whitelist rule if it doesn't exist
$whitelistRule = $fw.Rules | Where-Object { $_.Name -eq $settings.WhitelistRuleName }
if ($whitelistRule -eq $null) {
    Write-Host "Firewall rule '$($settings.WhitelistRuleName)' does not exist. Creating it..."
    $rule = New-Object -ComObject HNetCfg.FWRule
    $rule.Name = $settings.WhitelistRuleName
    $rule.Description = "Allow IP addresses with successful logins"
    $rule.Protocol = 6  # TCP
    $rule.Action = 1     # Allow
    $rule.Direction = 1  # Inbound
    $rule.Enabled = $true
    $rule.RemoteAddresses = $settings.DummyIP  # Start with a dummy IP
    $fw.Rules.Add($rule)
    $whitelistRule = $fw.Rules | Where-Object { $_.Name -eq $settings.WhitelistRuleName }
}

# Check and create Banned rule if it doesn't exist
$bannedRule = $fw.Rules | Where-Object { $_.Name -eq $settings.BannedRuleName }
if ($bannedRule -eq $null) {
    Write-Host "Firewall rule '$($settings.BannedRuleName)' does not exist. Creating it..."
    $rule = New-Object -ComObject HNetCfg.FWRule
    $rule.Name = $settings.BannedRuleName
    $rule.Description = "Block IP addresses manually banned by admin"
    $rule.Protocol = 6  # TCP
    $rule.Action = 0     # Block
    $rule.Direction = 1  # Inbound
    $rule.Enabled = $true
    $rule.RemoteAddresses = $settings.DummyIP  # Start with a dummy IP
    $fw.Rules.Add($rule)
    $bannedRule = $fw.Rules | Where-Object { $_.Name -eq $settings.BannedRuleName }
}

# Get current whitelist IPs
$whitelistIPs = $whitelistRule.RemoteAddresses -split ',' | Where-Object { $_ -ne $settings.DummyIP }

# Get current banned IPs
$bannedIPs = $bannedRule.RemoteAddresses -split ',' | Where-Object { $_ -ne $settings.DummyIP }



# Get successful logins (Event ID 4624)
$successfulLogins = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624
    StartTime = $logScanRange
} | ForEach-Object {
    $eventXml = [xml]$_.ToXml()
    $ipAddress = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" } | Select-Object -ExpandProperty "#text"
    $targetUserName = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" } | Select-Object -ExpandProperty "#text"

    # Filter ANONYMOUS LOGON or SYSTEM logins
    if ($targetUserName -notin @("ANONYMOUS LOGON", "SYSTEM")) {
        if ($ipAddress) {
            [PSCustomObject]@{
                IpAddress = $ipAddress
            }
        }
    }
} | Where-Object { $_.IpAddress -ne $null -and $_.IpAddress -ne "" }  # Flter empty IP addresses


# Add successful login IPs to whitelist
foreach ($ip in $successfulLogins) {
    $ipAddress = $ip.IpAddress
    if (Test-ValidIPAddress -ipAddress $ipAddress) {  # IP adresinin geçerli olup olmadığını kontrol et
        if (-not ($bannedIPs -contains "$ipAddress/255.255.255.255")) {  # IP adresinin _Banned kuralında olup olmadığını kontrol et
            if (-not ($whitelistIPs -contains "$ipAddress/255.255.255.255")) {  # IP adresinin zaten whitelist'te olup olmadığını kontrol et
                if ($whitelistRule.RemoteAddresses -eq $settings.DummyIP) {
                    # Replace dummy IP with the new IP
                    $whitelistRule.RemoteAddresses = "$ipAddress/255.255.255.255"
                } else {
                    # Add the new IP to the existing list
                    $whitelistRule.RemoteAddresses += ",$ipAddress/255.255.255.255"
                }
                Write-Host "Added IP $ipAddress to whitelist."
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')    Added IP $ipAddress to whitelist." >> $settings.WhitelistAdditionLogFile
                # Whitelist IPs listesini güncelle
                $whitelistIPs += "$ipAddress/255.255.255.255"
            } else {
                Write-Host "IP $ipAddress is already in the whitelist. Skipping."
            }
        } else {
            Write-Host "IP $ipAddress is banned. Skipping whitelist addition."
        }
    } else {
        Write-Host "Invalid IP address '$ipAddress' skipped."
    }
}

# Check and create Block rule if it doesn't exist
$blockRule = $fw.Rules | Where-Object { $_.Name -eq $settings.BlacklistRuleName }
if ($blockRule -eq $null) {
    Write-Host "Firewall rule '$($settings.BlacklistRuleName)' does not exist. Creating it..."
    $rule = New-Object -ComObject HNetCfg.FWRule
    $rule.Name = $settings.BlacklistRuleName
    $rule.Description = "Block IP addresses with multiple failed login attempts"
    $rule.Protocol = 6  # TCP
    $rule.Action = 0     # Block
    $rule.Direction = 1  # Inbound
    $rule.Enabled = $true
    $rule.RemoteAddresses = $settings.DummyIP  # Start with a dummy IP
    $fw.Rules.Add($rule)
    $blockRule = $fw.Rules | Where-Object { $_.Name -eq $settings.BlacklistRuleName }
}

# Get current blocklist IPs
$blocklistIPs = $blockRule.RemoteAddresses -split ',' | Where-Object { $_ -ne $settings.DummyIP }

# Process failed logins
$blockIPs = @()
$removeFromWhitelist = @()

foreach ($ip in ($allFailedLogins | Group-Object -Property IpAddress)) {
    $ipAddress = $ip.Name
    $failedAttempts = $ip.Group.Count

    # Check if IP is in whitelist
    if ($whitelistIPs -contains $ipAddress) {
        # If IP is in whitelist, check if it exceeds the whitelist threshold
        if ($failedAttempts -ge $settings.WhitelistFailedAttempts) {
            $removeFromWhitelist += $ipAddress
            $blockIPs += $ipAddress
            Write-Host "Whitelisted IP $ipAddress exceeded the failed attempt threshold. Removing from whitelist and adding to blocklist."
        }
    } else {
        # If IP is not in whitelist, check if it exceeds the non-whitelist threshold
        if ($failedAttempts -ge $settings.NonWhitelistFailedAttempts) {
            $blockIPs += $ipAddress
            Write-Host "Non-whitelisted IP $ipAddress exceeded the failed attempt threshold. Adding to blocklist."
        }
    }
}

# Remove IPs from whitelist and add to blocklist
foreach ($ip in $removeFromWhitelist) {
    $whitelistRule.RemoteAddresses = ($whitelistRule.RemoteAddresses -split ',' | Where-Object { $_ -ne "$ip/255.255.255.255" }) -join ','
    Write-Host "Removed IP $ip from whitelist."
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')    Removed IP $ip from whitelist and added to blocklist." >> $settings.WhitelistRemovalLogFile
}

# Add IPs to blocklist
foreach ($ip in $blockIPs) {
    if (Test-ValidIPAddress -ipAddress $ip) {  # IP adresinin geçerli olup olmadığını kontrol et
        if (-not ($blocklistIPs -contains "$ip/255.255.255.255")) {
            if ($blockRule.RemoteAddresses -eq $settings.DummyIP) {
                # Replace dummy IP with the new IP
                $blockRule.RemoteAddresses = "$ip/255.255.255.255"
            } else {
                # Add the new IP to the existing list
                $blockRule.RemoteAddresses += ",$ip/255.255.255.255"
            }
            Write-Host "Added IP $ip to blocklist."
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')    Added IP $ip to blocklist." >> $settings.BlockedIPLogFile
        }
    } else {
        Write-Host "Invalid IP address '$ip' skipped."
    }
}