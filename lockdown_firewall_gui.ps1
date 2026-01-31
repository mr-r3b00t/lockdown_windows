#Requires -Version 5.0

<#
.SYNOPSIS
    Windows Network Hardening GUI Tool
.DESCRIPTION
    A graphical interface to view and harden Windows network security settings including:
    - Windows Defender Firewall
    - Local Inbound Firewall Rules
    - NetBIOS over TCP/IP
    - WPAD (Web Proxy Auto-Discovery)
    - mDNS (Multicast DNS)
    - LLMNR (Link-Local Multicast Name Resolution)
    
    Features backup and rollback capability.
.NOTES
    Must be run as Administrator for hardening to work.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

#region Check Admin Status
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
#endregion

#region Configuration
$script:BackupFolder = Join-Path $env:USERPROFILE "NetworkHardeningBackups"
$script:LatestBackupFile = Join-Path $script:BackupFolder "latest_backup.json"
#endregion

#region Backup Functions

function Get-CurrentConfiguration {
    $config = @{
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        ComputerName = $env:COMPUTERNAME
        Firewall = @{}
        InboundRules = @()
        NetBIOS = @{}
        WPAD = @{}
        MDNS = @{}
        LLMNR = @{}
        NTLM = @{}
    }
    
    # Firewall Profiles
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($profile in $profiles) {
            $config.Firewall[$profile.Name] = @{
                Enabled = $profile.Enabled
            }
        }
    }
    catch {
        $config.Firewall.Error = $_.Exception.Message
    }
    
    # Inbound Rules - store only enabled rules to reduce file size
    try {
        $rules = Get-NetFirewallRule -Direction Inbound -PolicyStore PersistentStore -ErrorAction Stop
        foreach ($rule in $rules) {
            $config.InboundRules += @{
                Name = $rule.Name
                DisplayName = $rule.DisplayName
                Enabled = $rule.Enabled.ToString()
            }
        }
    }
    catch {
        $config.InboundRules = @{ Error = $_.Exception.Message }
    }
    
    # NetBIOS settings
    try {
        $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop
        $config.NetBIOS.Adapters = @()
        foreach ($adapter in $adapters) {
            $config.NetBIOS.Adapters += @{
                Description = $adapter.Description
                Index = $adapter.Index
                TcpipNetbiosOptions = $adapter.TcpipNetbiosOptions
            }
        }
        
        # lmhosts service
        $lmhosts = Get-Service -Name "lmhosts" -ErrorAction SilentlyContinue
        if ($lmhosts) {
            $config.NetBIOS.LmhostsService = @{
                Status = $lmhosts.Status.ToString()
                StartType = $lmhosts.StartType.ToString()
            }
        }
    }
    catch {
        $config.NetBIOS.Error = $_.Exception.Message
    }
    
    # WPAD settings
    try {
        # Service
        $wpadService = Get-Service -Name "WinHttpAutoProxySvc" -ErrorAction SilentlyContinue
        if ($wpadService) {
            $config.WPAD.Service = @{
                Status = $wpadService.Status.ToString()
                StartType = $wpadService.StartType.ToString()
            }
        }
        
        # Registry - AutoDetect
        $autoDetect = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoDetect" -ErrorAction SilentlyContinue
        $config.WPAD.AutoDetect = if ($autoDetect) { $autoDetect.AutoDetect } else { $null }
        
        # Registry - DisableWpad
        $disableWpad = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name "DisableWpad" -ErrorAction SilentlyContinue
        $config.WPAD.DisableWpad = if ($disableWpad) { $disableWpad.DisableWpad } else { $null }
    }
    catch {
        $config.WPAD.Error = $_.Exception.Message
    }
    
    # mDNS settings
    try {
        $mdns = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMDNS" -ErrorAction SilentlyContinue
        $config.MDNS.EnableMDNS = if ($mdns) { $mdns.EnableMDNS } else { $null }
        
        # Check for block rule
        $blockRule = Get-NetFirewallRule -DisplayName "Block mDNS (UDP 5353)" -ErrorAction SilentlyContinue
        $config.MDNS.BlockRuleExists = ($null -ne $blockRule)
    }
    catch {
        $config.MDNS.Error = $_.Exception.Message
    }
    
    # LLMNR settings
    try {
        $llmnr = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
        $config.LLMNR.EnableMulticast = if ($llmnr) { $llmnr.EnableMulticast } else { $null }
        
        # Check for block rule
        $blockRule = Get-NetFirewallRule -DisplayName "Block LLMNR (UDP 5355)" -ErrorAction SilentlyContinue
        $config.LLMNR.BlockRuleExists = ($null -ne $blockRule)
    }
    catch {
        $config.LLMNR.Error = $_.Exception.Message
    }
    
    # NTLM settings
    try {
        $lmCompat = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
        $config.NTLM.LmCompatibilityLevel = if ($lmCompat) { $lmCompat.LmCompatibilityLevel } else { $null }
        
        $restrictSend = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -ErrorAction SilentlyContinue
        $config.NTLM.RestrictSendingNTLMTraffic = if ($restrictSend) { $restrictSend.RestrictSendingNTLMTraffic } else { $null }
        
        $restrictReceive = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictReceivingNTLMTraffic" -ErrorAction SilentlyContinue
        $config.NTLM.RestrictReceivingNTLMTraffic = if ($restrictReceive) { $restrictReceive.RestrictReceivingNTLMTraffic } else { $null }
    }
    catch {
        $config.NTLM.Error = $_.Exception.Message
    }
    
    return $config
}

function Save-Configuration {
    param(
        [hashtable]$Config,
        [string]$Path
    )
    
    # Ensure backup folder exists
    if (-not (Test-Path $script:BackupFolder)) {
        New-Item -Path $script:BackupFolder -ItemType Directory -Force | Out-Null
    }
    
    # Save to JSON
    $Config | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -Encoding UTF8
    
    # Also save a timestamped copy
    $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $timestampedPath = Join-Path $script:BackupFolder "backup_$timestamp.json"
    $Config | ConvertTo-Json -Depth 10 | Set-Content -Path $timestampedPath -Encoding UTF8
    
    return $timestampedPath
}

function Restore-Configuration {
    param(
        [System.Windows.Forms.TextBox]$LogBox,
        [string]$BackupPath
    )
    
    function Write-Log {
        param([string]$Message)
        $LogBox.AppendText("$Message`r`n")
        $LogBox.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    }
    
    if (-not (Test-Path $BackupPath)) {
        Write-Log "ERROR: Backup file not found: $BackupPath"
        return $false
    }
    
    try {
        $config = Get-Content -Path $BackupPath -Raw | ConvertFrom-Json
    }
    catch {
        Write-Log "ERROR: Failed to read backup file: $_"
        return $false
    }
    
    Write-Log "Restoring configuration from: $BackupPath"
    Write-Log "Backup timestamp: $($config.Timestamp)"
    Write-Log "========================================"
    
    # Restore Firewall Profiles
    Write-Log "`r`n[1/6] Restoring Firewall settings..."
    try {
        foreach ($profileName in @("Domain", "Private", "Public")) {
            if ($config.Firewall.$profileName) {
                $enabled = $config.Firewall.$profileName.Enabled
                Set-NetFirewallProfile -Profile $profileName -Enabled $enabled -ErrorAction Stop
                Write-Log "  OK: $profileName profile set to Enabled=$enabled"
            }
        }
    }
    catch {
        Write-Log "  ERROR: $_"
    }
    
    # Restore Inbound Rules
    Write-Log "`r`n[2/6] Restoring Inbound Firewall Rules..."
    try {
        $rulesRestored = 0
        foreach ($ruleConfig in $config.InboundRules) {
            if ($ruleConfig.Name) {
                $rule = Get-NetFirewallRule -Name $ruleConfig.Name -ErrorAction SilentlyContinue
                if ($rule) {
                    $shouldBeEnabled = $ruleConfig.Enabled -eq "True"
                    if ($rule.Enabled -ne $shouldBeEnabled) {
                        Set-NetFirewallRule -Name $ruleConfig.Name -Enabled $shouldBeEnabled -ErrorAction SilentlyContinue
                        $rulesRestored++
                    }
                }
            }
        }
        Write-Log "  OK: Restored $rulesRestored firewall rules"
    }
    catch {
        Write-Log "  ERROR: $_"
    }
    
    # Restore NetBIOS
    Write-Log "`r`n[3/6] Restoring NetBIOS settings..."
    try {
        if ($config.NetBIOS.Adapters) {
            foreach ($adapterConfig in $config.NetBIOS.Adapters) {
                $adapter = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "Index=$($adapterConfig.Index)" -ErrorAction SilentlyContinue
                if ($adapter -and $null -ne $adapterConfig.TcpipNetbiosOptions) {
                    $adapter.SetTcpipNetbios($adapterConfig.TcpipNetbiosOptions) | Out-Null
                }
            }
            Write-Log "  OK: NetBIOS adapter settings restored"
        }
        
        # Restore lmhosts service
        if ($config.NetBIOS.LmhostsService) {
            $startType = $config.NetBIOS.LmhostsService.StartType
            if ($startType -eq "Disabled") {
                Set-Service -Name "lmhosts" -StartupType Disabled -ErrorAction SilentlyContinue
            }
            else {
                Set-Service -Name "lmhosts" -StartupType Manual -ErrorAction SilentlyContinue
                if ($config.NetBIOS.LmhostsService.Status -eq "Running") {
                    Start-Service -Name "lmhosts" -ErrorAction SilentlyContinue
                }
            }
            Write-Log "  OK: lmhosts service restored to $startType"
        }
    }
    catch {
        Write-Log "  ERROR: $_"
    }
    
    # Restore WPAD
    Write-Log "`r`n[4/6] Restoring WPAD settings..."
    try {
        # Service
        if ($config.WPAD.Service) {
            $startType = $config.WPAD.Service.StartType
            if ($startType -eq "Disabled") {
                Stop-Service -Name "WinHttpAutoProxySvc" -Force -ErrorAction SilentlyContinue
                Set-Service -Name "WinHttpAutoProxySvc" -StartupType Disabled -ErrorAction SilentlyContinue
            }
            else {
                Set-Service -Name "WinHttpAutoProxySvc" -StartupType Manual -ErrorAction SilentlyContinue
                if ($config.WPAD.Service.Status -eq "Running") {
                    Start-Service -Name "WinHttpAutoProxySvc" -ErrorAction SilentlyContinue
                }
            }
            Write-Log "  OK: WinHttpAutoProxySvc restored to $startType"
        }
        
        # AutoDetect registry
        if ($null -ne $config.WPAD.AutoDetect) {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoDetect" -Value $config.WPAD.AutoDetect -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoDetect" -Value $config.WPAD.AutoDetect -Type DWord -ErrorAction SilentlyContinue
            Write-Log "  OK: AutoDetect restored to $($config.WPAD.AutoDetect)"
        }
        
        # DisableWpad registry
        if ($null -ne $config.WPAD.DisableWpad) {
            $winhttpPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
            if (-not (Test-Path $winhttpPath)) { New-Item -Path $winhttpPath -Force | Out-Null }
            Set-ItemProperty -Path $winhttpPath -Name "DisableWpad" -Value $config.WPAD.DisableWpad -Type DWord
            Write-Log "  OK: DisableWpad restored to $($config.WPAD.DisableWpad)"
        }
        elseif ($config.WPAD.DisableWpad -eq $null) {
            # Remove the key if it didn't exist before
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name "DisableWpad" -ErrorAction SilentlyContinue
            Write-Log "  OK: DisableWpad registry key removed"
        }
    }
    catch {
        Write-Log "  ERROR: $_"
    }
    
    # Restore mDNS
    Write-Log "`r`n[5/6] Restoring mDNS settings..."
    try {
        if ($null -ne $config.MDNS.EnableMDNS) {
            $dnsParams = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
            Set-ItemProperty -Path $dnsParams -Name "EnableMDNS" -Value $config.MDNS.EnableMDNS -Type DWord
            Write-Log "  OK: EnableMDNS restored to $($config.MDNS.EnableMDNS)"
        }
        elseif ($config.MDNS.EnableMDNS -eq $null) {
            Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMDNS" -ErrorAction SilentlyContinue
            Write-Log "  OK: EnableMDNS registry key removed"
        }
        
        # Remove block rules if they didn't exist
        if (-not $config.MDNS.BlockRuleExists) {
            Remove-NetFirewallRule -DisplayName "Block mDNS (UDP 5353)" -ErrorAction SilentlyContinue
            Remove-NetFirewallRule -DisplayName "Block mDNS Outbound (UDP 5353)" -ErrorAction SilentlyContinue
            Write-Log "  OK: mDNS block rules removed"
        }
    }
    catch {
        Write-Log "  ERROR: $_"
    }
    
    # Restore LLMNR
    Write-Log "`r`n[6/7] Restoring LLMNR settings..."
    try {
        $dnsPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        
        if ($null -ne $config.LLMNR.EnableMulticast) {
            if (-not (Test-Path $dnsPolicyPath)) { New-Item -Path $dnsPolicyPath -Force | Out-Null }
            Set-ItemProperty -Path $dnsPolicyPath -Name "EnableMulticast" -Value $config.LLMNR.EnableMulticast -Type DWord
            Write-Log "  OK: EnableMulticast restored to $($config.LLMNR.EnableMulticast)"
        }
        elseif ($config.LLMNR.EnableMulticast -eq $null) {
            Remove-ItemProperty -Path $dnsPolicyPath -Name "EnableMulticast" -ErrorAction SilentlyContinue
            Write-Log "  OK: EnableMulticast registry key removed"
        }
        
        # Remove block rules if they didn't exist
        if (-not $config.LLMNR.BlockRuleExists) {
            Remove-NetFirewallRule -DisplayName "Block LLMNR (UDP 5355)" -ErrorAction SilentlyContinue
            Remove-NetFirewallRule -DisplayName "Block LLMNR Outbound (UDP 5355)" -ErrorAction SilentlyContinue
            Write-Log "  OK: LLMNR block rules removed"
        }
    }
    catch {
        Write-Log "  ERROR: $_"
    }
    
    # Restore NTLM
    Write-Log "`r`n[7/7] Restoring NTLM settings..."
    try {
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $msv1Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        
        if ($null -ne $config.NTLM.LmCompatibilityLevel) {
            Set-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -Value $config.NTLM.LmCompatibilityLevel -Type DWord
            Write-Log "  OK: LmCompatibilityLevel restored to $($config.NTLM.LmCompatibilityLevel)"
        }
        elseif ($config.NTLM.LmCompatibilityLevel -eq $null) {
            Remove-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
            Write-Log "  OK: LmCompatibilityLevel registry key removed"
        }
        
        if ($null -ne $config.NTLM.RestrictSendingNTLMTraffic) {
            Set-ItemProperty -Path $msv1Path -Name "RestrictSendingNTLMTraffic" -Value $config.NTLM.RestrictSendingNTLMTraffic -Type DWord
            Write-Log "  OK: RestrictSendingNTLMTraffic restored to $($config.NTLM.RestrictSendingNTLMTraffic)"
        }
        elseif ($config.NTLM.RestrictSendingNTLMTraffic -eq $null) {
            Remove-ItemProperty -Path $msv1Path -Name "RestrictSendingNTLMTraffic" -ErrorAction SilentlyContinue
            Write-Log "  OK: RestrictSendingNTLMTraffic registry key removed"
        }
        
        if ($null -ne $config.NTLM.RestrictReceivingNTLMTraffic) {
            Set-ItemProperty -Path $msv1Path -Name "RestrictReceivingNTLMTraffic" -Value $config.NTLM.RestrictReceivingNTLMTraffic -Type DWord
            Write-Log "  OK: RestrictReceivingNTLMTraffic restored to $($config.NTLM.RestrictReceivingNTLMTraffic)"
        }
        elseif ($config.NTLM.RestrictReceivingNTLMTraffic -eq $null) {
            Remove-ItemProperty -Path $msv1Path -Name "RestrictReceivingNTLMTraffic" -ErrorAction SilentlyContinue
            Write-Log "  OK: RestrictReceivingNTLMTraffic registry key removed"
        }
    }
    catch {
        Write-Log "  ERROR: $_"
    }
    
    Write-Log "`r`n========================================"
    Write-Log "Rollback complete!"
    Write-Log "A reboot is recommended for full effect."
    
    return $true
}

#endregion

#region Status Check Functions

function Get-FirewallStatus {
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        $allEnabled = ($profiles | Where-Object { $_.Enabled -eq $true }).Count -eq 3
        $enabledProfiles = ($profiles | Where-Object { $_.Enabled -eq $true }).Name -join ", "
        
        if ($allEnabled) {
            return @{ Status = "Secure"; Color = "Green"; Detail = "All profiles enabled" }
        }
        elseif ($enabledProfiles) {
            return @{ Status = "Partial"; Color = "Orange"; Detail = "Enabled: $enabledProfiles" }
        }
        else {
            return @{ Status = "Vulnerable"; Color = "Red"; Detail = "All profiles disabled" }
        }
    }
    catch {
        return @{ Status = "Unknown"; Color = "Gray"; Detail = "Could not query" }
    }
}

function Get-InboundRulesStatus {
    try {
        $rules = Get-NetFirewallRule -Direction Inbound -PolicyStore PersistentStore -ErrorAction Stop
        # Only count Allow rules as potentially vulnerable - Block rules are security measures
        $enabledAllowRules = ($rules | Where-Object { $_.Enabled -eq "True" -and $_.Action -eq "Allow" }).Count
        $enabledBlockRules = ($rules | Where-Object { $_.Enabled -eq "True" -and $_.Action -eq "Block" }).Count
        $totalRules = $rules.Count
        
        if ($enabledAllowRules -eq 0) {
            $detail = "All allow rules disabled"
            if ($enabledBlockRules -gt 0) {
                $detail += " ($enabledBlockRules block rules active)"
            }
            return @{ Status = "Secure"; Color = "Green"; Detail = $detail }
        }
        else {
            return @{ Status = "Vulnerable"; Color = "Red"; Detail = "$enabledAllowRules allow rules enabled" }
        }
    }
    catch {
        return @{ Status = "Unknown"; Color = "Gray"; Detail = "Could not query" }
    }
}

function Get-NetBIOSStatus {
    try {
        $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop
        $netbiosEnabled = $false
        
        foreach ($adapter in $adapters) {
            if ($adapter.TcpipNetbiosOptions -ne 2) {
                $netbiosEnabled = $true
                break
            }
        }
        
        $lmhosts = Get-Service -Name "lmhosts" -ErrorAction SilentlyContinue
        $serviceRunning = $lmhosts -and $lmhosts.Status -eq "Running"
        
        if (-not $netbiosEnabled -and -not $serviceRunning) {
            return @{ Status = "Secure"; Color = "Green"; Detail = "Disabled on all adapters" }
        }
        elseif ($netbiosEnabled) {
            return @{ Status = "Vulnerable"; Color = "Red"; Detail = "Enabled on one or more adapters" }
        }
        else {
            return @{ Status = "Partial"; Color = "Orange"; Detail = "Service still running" }
        }
    }
    catch {
        return @{ Status = "Unknown"; Color = "Gray"; Detail = "Could not query" }
    }
}

function Get-WPADStatus {
    try {
        $vulnerable = $false
        $details = @()
        
        $wpadService = Get-Service -Name "WinHttpAutoProxySvc" -ErrorAction SilentlyContinue
        if ($wpadService -and $wpadService.Status -eq "Running") {
            $vulnerable = $true
            $details += "Service running"
        }
        
        $autoDetect = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoDetect" -ErrorAction SilentlyContinue
        if (-not $autoDetect -or $autoDetect.AutoDetect -ne 0) {
            $vulnerable = $true
            $details += "AutoDetect enabled"
        }
        
        $disableWpad = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name "DisableWpad" -ErrorAction SilentlyContinue
        if (-not $disableWpad -or $disableWpad.DisableWpad -ne 1) {
            $vulnerable = $true
            $details += "WinHttp WPAD enabled"
        }
        
        if (-not $vulnerable) {
            return @{ Status = "Secure"; Color = "Green"; Detail = "WPAD disabled" }
        }
        else {
            return @{ Status = "Vulnerable"; Color = "Red"; Detail = ($details -join ", ") }
        }
    }
    catch {
        return @{ Status = "Unknown"; Color = "Gray"; Detail = "Could not query" }
    }
}

function Get-MDNSStatus {
    try {
        $vulnerable = $false
        $details = @()
        
        $mdns = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMDNS" -ErrorAction SilentlyContinue
        if (-not $mdns -or $mdns.EnableMDNS -ne 0) {
            $vulnerable = $true
            $details += "mDNS enabled"
        }
        
        $blockRule = Get-NetFirewallRule -DisplayName "Block mDNS (UDP 5353)" -ErrorAction SilentlyContinue
        if (-not $blockRule -or $blockRule.Enabled -ne "True") {
            $vulnerable = $true
            $details += "No firewall block"
        }
        
        if (-not $vulnerable) {
            return @{ Status = "Secure"; Color = "Green"; Detail = "mDNS disabled and blocked" }
        }
        else {
            return @{ Status = "Vulnerable"; Color = "Red"; Detail = ($details -join ", ") }
        }
    }
    catch {
        return @{ Status = "Unknown"; Color = "Gray"; Detail = "Could not query" }
    }
}

function Get-LLMNRStatus {
    try {
        $vulnerable = $false
        $details = @()
        
        $llmnr = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
        if (-not $llmnr -or $llmnr.EnableMulticast -ne 0) {
            $vulnerable = $true
            $details += "LLMNR enabled"
        }
        
        $blockRule = Get-NetFirewallRule -DisplayName "Block LLMNR (UDP 5355)" -ErrorAction SilentlyContinue
        if (-not $blockRule -or $blockRule.Enabled -ne "True") {
            $vulnerable = $true
            $details += "No firewall block"
        }
        
        if (-not $vulnerable) {
            return @{ Status = "Secure"; Color = "Green"; Detail = "LLMNR disabled and blocked" }
        }
        else {
            return @{ Status = "Vulnerable"; Color = "Red"; Detail = ($details -join ", ") }
        }
    }
    catch {
        return @{ Status = "Unknown"; Color = "Gray"; Detail = "Could not query" }
    }
}

function Get-NTLMStatus {
    try {
        $vulnerable = $false
        $details = @()
        
        # Check LmCompatibilityLevel (5 = NTLMv2 only, refuse LM & NTLM)
        $lmCompat = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
        if (-not $lmCompat -or $lmCompat.LmCompatibilityLevel -lt 5) {
            $vulnerable = $true
            $level = if ($lmCompat) { $lmCompat.LmCompatibilityLevel } else { "default" }
            $details += "LM level: $level"
        }
        
        # Check if NTLM is restricted for outgoing traffic
        $restrictSend = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -ErrorAction SilentlyContinue
        if (-not $restrictSend -or $restrictSend.RestrictSendingNTLMTraffic -lt 2) {
            $vulnerable = $true
            $details += "Outbound NTLM allowed"
        }
        
        # Check if NTLM is restricted for incoming traffic
        $restrictReceive = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictReceivingNTLMTraffic" -ErrorAction SilentlyContinue
        if (-not $restrictReceive -or $restrictReceive.RestrictReceivingNTLMTraffic -lt 2) {
            $vulnerable = $true
            $details += "Inbound NTLM allowed"
        }
        
        if (-not $vulnerable) {
            return @{ Status = "Secure"; Color = "Green"; Detail = "NTLM restricted (NTLMv2 only)" }
        }
        else {
            return @{ Status = "Vulnerable"; Color = "Red"; Detail = ($details -join ", ") }
        }
    }
    catch {
        return @{ Status = "Unknown"; Color = "Gray"; Detail = "Could not query" }
    }
}

#endregion

#region Hardening Functions

function Invoke-Hardening {
    param(
        [System.Windows.Forms.TextBox]$LogBox,
        [hashtable]$Options
    )
    
    $LogBox.Clear()
    
    function Write-Log {
        param([string]$Message)
        $LogBox.AppendText("$Message`r`n")
        $LogBox.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    }
    
    # Save current configuration before making changes
    Write-Log "Backing up current configuration..."
    try {
        $currentConfig = Get-CurrentConfiguration
        $backupPath = Save-Configuration -Config $currentConfig -Path $script:LatestBackupFile
        Write-Log "  OK: Backup saved to $backupPath"
    }
    catch {
        Write-Log "  WARNING: Could not save backup: $_"
        $result = [System.Windows.Forms.MessageBox]::Show(
            "Failed to create backup. Continue with hardening anyway?",
            "Backup Failed",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($result -ne [System.Windows.Forms.DialogResult]::Yes) {
            Write-Log "Hardening cancelled by user."
            return
        }
    }
    
    Write-Log "`r`nStarting hardening process..."
    Write-Log "========================================"
    
    $stepNum = 0
    $totalSteps = ($Options.Keys | Where-Object { $Options[$_] -eq $true -and $_ -ne "PreserveRDP" }).Count
    
    # 1. Enable Firewall
    if ($Options.Firewall) {
        $stepNum++
        Write-Log "`r`n[$stepNum/$totalSteps] Enabling Windows Defender Firewall..."
        foreach ($profile in @("Domain", "Private", "Public")) {
            try {
                Set-NetFirewallProfile -Profile $profile -Enabled True -ErrorAction Stop
                Write-Log "  OK: $profile profile enabled"
            }
            catch {
                Write-Log "  ERROR: $profile - $_"
            }
        }
    }
    else {
        Write-Log "`r`n[SKIPPED] Windows Defender Firewall (unchecked)"
    }
    
    # 2. Disable Inbound Rules
    if ($Options.InboundRules) {
        $stepNum++
        Write-Log "`r`n[$stepNum/$totalSteps] Disabling local inbound firewall rules..."
        if ($Options.PreserveRDP) {
            Write-Log "  INFO: Preserving RDP rules (TCP 3389)"
        }
        try {
            $rules = Get-NetFirewallRule -Direction Inbound -PolicyStore PersistentStore -ErrorAction Stop
            $count = 0
            $skippedRDP = 0
            
            foreach ($rule in $rules) {
                if ($rule.Enabled -eq "True") {
                    $isRDPRule = $false
                    if ($Options.PreserveRDP) {
                        try {
                            $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                            if ($portFilter -and $portFilter.LocalPort -eq "3389") {
                                $isRDPRule = $true
                            }
                            if ($rule.DisplayName -match "Remote Desktop|RDP") {
                                $isRDPRule = $true
                            }
                        }
                        catch { }
                    }
                    
                    if ($isRDPRule) {
                        Write-Log "  PRESERVED: $($rule.DisplayName) (RDP)"
                        $skippedRDP++
                    }
                    else {
                        $rule | Set-NetFirewallRule -Enabled False -ErrorAction SilentlyContinue
                        $count++
                    }
                }
            }
            Write-Log "  OK: Disabled $count inbound rules"
            if ($skippedRDP -gt 0) {
                Write-Log "  OK: Preserved $skippedRDP RDP rules"
            }
        }
        catch {
            Write-Log "  ERROR: $_"
        }
    }
    else {
        Write-Log "`r`n[SKIPPED] Local Inbound Rules (unchecked)"
    }
    
    # 3. Disable NetBIOS
    if ($Options.NetBIOS) {
        $stepNum++
        Write-Log "`r`n[$stepNum/$totalSteps] Disabling NetBIOS over TCP/IP..."
        try {
            $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
            foreach ($adapter in $adapters) {
                $adapter.SetTcpipNetbios(2) | Out-Null
            }
            Write-Log "  OK: NetBIOS disabled on adapters"
            
            $netbtInterfaces = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -ErrorAction SilentlyContinue
            foreach ($interface in $netbtInterfaces) {
                Set-ItemProperty -Path $interface.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -ErrorAction SilentlyContinue
            }
            Write-Log "  OK: NetBIOS registry updated"
            
            Stop-Service -Name "lmhosts" -Force -ErrorAction SilentlyContinue
            Set-Service -Name "lmhosts" -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Log "  OK: lmhosts service disabled"
        }
        catch {
            Write-Log "  ERROR: $_"
        }
    }
    else {
        Write-Log "`r`n[SKIPPED] NetBIOS over TCP/IP (unchecked)"
    }
    
    # 4. Disable WPAD
    if ($Options.WPAD) {
        $stepNum++
        Write-Log "`r`n[$stepNum/$totalSteps] Disabling WPAD..."
        try {
            Stop-Service -Name "WinHttpAutoProxySvc" -Force -ErrorAction SilentlyContinue
            Set-Service -Name "WinHttpAutoProxySvc" -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Log "  OK: WinHttpAutoProxySvc disabled"
            
            $internetSettingsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
            Set-ItemProperty -Path $internetSettingsPath -Name "AutoDetect" -Value 0 -Type DWord -ErrorAction Stop
            Write-Log "  OK: AutoDetect disabled (HKLM)"
            
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoDetect" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Write-Log "  OK: AutoDetect disabled (HKCU)"
            
            $winhttpPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
            if (-not (Test-Path $winhttpPath)) { New-Item -Path $winhttpPath -Force | Out-Null }
            Set-ItemProperty -Path $winhttpPath -Name "DisableWpad" -Value 1 -Type DWord
            Write-Log "  OK: WinHttp WPAD disabled"
            
            $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
            $hostsContent = Get-Content $hostsFile -Raw -ErrorAction SilentlyContinue
            if ($hostsContent -notmatch "(?m)^\s*[\d\.]+\s+wpad\s*$") {
                Add-Content -Path $hostsFile -Value "`n# Block WPAD`n0.0.0.0 wpad"
                Write-Log "  OK: WPAD blocked in hosts file"
            }
            else {
                Write-Log "  INFO: WPAD already in hosts file"
            }
        }
        catch {
            Write-Log "  ERROR: $_"
        }
    }
    else {
        Write-Log "`r`n[SKIPPED] WPAD (unchecked)"
    }
    
    # 5. Disable mDNS
    if ($Options.MDNS) {
        $stepNum++
        Write-Log "`r`n[$stepNum/$totalSteps] Disabling mDNS..."
        try {
            $dnsParams = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
            if (-not (Test-Path $dnsParams)) { New-Item -Path $dnsParams -Force | Out-Null }
            Set-ItemProperty -Path $dnsParams -Name "EnableMDNS" -Value 0 -Type DWord
            Write-Log "  OK: mDNS disabled in registry"
            
            Remove-NetFirewallRule -DisplayName "Block mDNS (UDP 5353)" -ErrorAction SilentlyContinue
            Remove-NetFirewallRule -DisplayName "Block mDNS Outbound (UDP 5353)" -ErrorAction SilentlyContinue
            
            New-NetFirewallRule -DisplayName "Block mDNS (UDP 5353)" -Direction Inbound -Protocol UDP -LocalPort 5353 -Action Block -Profile Any -Enabled True | Out-Null
            New-NetFirewallRule -DisplayName "Block mDNS Outbound (UDP 5353)" -Direction Outbound -Protocol UDP -LocalPort 5353 -Action Block -Profile Any -Enabled True | Out-Null
            Write-Log "  OK: mDNS firewall block rules created"
        }
        catch {
            Write-Log "  ERROR: $_"
        }
    }
    else {
        Write-Log "`r`n[SKIPPED] mDNS (unchecked)"
    }
    
    # 6. Disable LLMNR
    if ($Options.LLMNR) {
        $stepNum++
        Write-Log "`r`n[$stepNum/$totalSteps] Disabling LLMNR..."
        try {
            $dnsPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
            if (-not (Test-Path $dnsPolicyPath)) { New-Item -Path $dnsPolicyPath -Force | Out-Null }
            Set-ItemProperty -Path $dnsPolicyPath -Name "EnableMulticast" -Value 0 -Type DWord
            Write-Log "  OK: LLMNR disabled in registry"
            
            Remove-NetFirewallRule -DisplayName "Block LLMNR (UDP 5355)" -ErrorAction SilentlyContinue
            Remove-NetFirewallRule -DisplayName "Block LLMNR Outbound (UDP 5355)" -ErrorAction SilentlyContinue
            
            New-NetFirewallRule -DisplayName "Block LLMNR (UDP 5355)" -Direction Inbound -Protocol UDP -LocalPort 5355 -Action Block -Profile Any -Enabled True | Out-Null
            New-NetFirewallRule -DisplayName "Block LLMNR Outbound (UDP 5355)" -Direction Outbound -Protocol UDP -LocalPort 5355 -Action Block -Profile Any -Enabled True | Out-Null
            Write-Log "  OK: LLMNR firewall block rules created"
        }
        catch {
            Write-Log "  ERROR: $_"
        }
    }
    else {
        Write-Log "`r`n[SKIPPED] LLMNR (unchecked)"
    }
    
    # 7. Disable NTLM
    if ($Options.NTLM) {
        $stepNum++
        Write-Log "`r`n[$stepNum/$totalSteps] Restricting NTLM authentication..."
        try {
            $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            $msv1Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
            
            # Set LmCompatibilityLevel to 5 (Send NTLMv2 response only, refuse LM & NTLM)
            Set-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord
            Write-Log "  OK: LmCompatibilityLevel set to 5 (NTLMv2 only)"
            
            # Ensure MSV1_0 path exists
            if (-not (Test-Path $msv1Path)) { New-Item -Path $msv1Path -Force | Out-Null }
            
            # Restrict sending NTLM traffic (2 = Deny all)
            Set-ItemProperty -Path $msv1Path -Name "RestrictSendingNTLMTraffic" -Value 2 -Type DWord
            Write-Log "  OK: Outbound NTLM traffic restricted"
            
            # Restrict receiving NTLM traffic (2 = Deny all)
            Set-ItemProperty -Path $msv1Path -Name "RestrictReceivingNTLMTraffic" -Value 2 -Type DWord
            Write-Log "  OK: Inbound NTLM traffic restricted"
            
            Write-Log "  WARNING: NTLM restriction may break legacy apps/services"
        }
        catch {
            Write-Log "  ERROR: $_"
        }
    }
    else {
        Write-Log "`r`n[SKIPPED] NTLM (unchecked)"
    }
    
    Write-Log "`r`n========================================"
    Write-Log "Hardening complete!"
    Write-Log "A reboot is recommended for full effect."
    Write-Log "`r`nBackup saved - use 'Rollback' to restore previous settings."
}

#endregion

#region Build GUI

$form = New-Object System.Windows.Forms.Form
$form.Text = "Windows Network Hardening Tool"
$form.Size = New-Object System.Drawing.Size(750, 810)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# Title Label
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "Windows Network Hardening Tool"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$titleLabel.Location = New-Object System.Drawing.Point(20, 15)
$titleLabel.Size = New-Object System.Drawing.Size(400, 35)
$form.Controls.Add($titleLabel)

# Admin Status
$adminLabel = New-Object System.Windows.Forms.Label
if ($isAdmin) {
    $adminLabel.Text = "[OK] Running as Administrator"
    $adminLabel.ForeColor = [System.Drawing.Color]::Green
}
else {
    $adminLabel.Text = "[X] Not running as Administrator (hardening will fail)"
    $adminLabel.ForeColor = [System.Drawing.Color]::Red
}
$adminLabel.Location = New-Object System.Drawing.Point(20, 50)
$adminLabel.Size = New-Object System.Drawing.Size(400, 20)
$form.Controls.Add($adminLabel)

# Backup Status Label
$backupStatusLabel = New-Object System.Windows.Forms.Label
$backupStatusLabel.Location = New-Object System.Drawing.Point(430, 50)
$backupStatusLabel.Size = New-Object System.Drawing.Size(300, 20)
$backupStatusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$backupStatusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
$form.Controls.Add($backupStatusLabel)

function Update-BackupStatus {
    if (Test-Path $script:LatestBackupFile) {
        try {
            $backup = Get-Content $script:LatestBackupFile -Raw | ConvertFrom-Json
            $backupStatusLabel.Text = "Last backup: $($backup.Timestamp)"
            $backupStatusLabel.ForeColor = [System.Drawing.Color]::Green
            return $true
        }
        catch {
            $backupStatusLabel.Text = "Backup file corrupted"
            $backupStatusLabel.ForeColor = [System.Drawing.Color]::Red
            return $false
        }
    }
    else {
        $backupStatusLabel.Text = "No backup available"
        $backupStatusLabel.ForeColor = [System.Drawing.Color]::Gray
        return $false
    }
}

# Status Group Box
$statusGroup = New-Object System.Windows.Forms.GroupBox
$statusGroup.Text = "Current Security Status"
$statusGroup.Location = New-Object System.Drawing.Point(20, 80)
$statusGroup.Size = New-Object System.Drawing.Size(695, 310)
$statusGroup.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($statusGroup)

# Column Headers
$headerApply = New-Object System.Windows.Forms.Label
$headerApply.Text = "Apply"
$headerApply.Location = New-Object System.Drawing.Point(15, 22)
$headerApply.Size = New-Object System.Drawing.Size(45, 20)
$headerApply.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
$headerApply.ForeColor = [System.Drawing.Color]::Gray
$statusGroup.Controls.Add($headerApply)

$headerComponent = New-Object System.Windows.Forms.Label
$headerComponent.Text = "Component"
$headerComponent.Location = New-Object System.Drawing.Point(65, 22)
$headerComponent.Size = New-Object System.Drawing.Size(250, 20)
$headerComponent.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
$headerComponent.ForeColor = [System.Drawing.Color]::Gray
$statusGroup.Controls.Add($headerComponent)

$headerStatus = New-Object System.Windows.Forms.Label
$headerStatus.Text = "Status"
$headerStatus.Location = New-Object System.Drawing.Point(340, 22)
$headerStatus.Size = New-Object System.Drawing.Size(90, 20)
$headerStatus.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
$headerStatus.ForeColor = [System.Drawing.Color]::Gray
$statusGroup.Controls.Add($headerStatus)

$headerDetail = New-Object System.Windows.Forms.Label
$headerDetail.Text = "Details"
$headerDetail.Location = New-Object System.Drawing.Point(440, 22)
$headerDetail.Size = New-Object System.Drawing.Size(200, 20)
$headerDetail.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
$headerDetail.ForeColor = [System.Drawing.Color]::Gray
$statusGroup.Controls.Add($headerDetail)

# Status Panel
$statusPanel = New-Object System.Windows.Forms.Panel
$statusPanel.Location = New-Object System.Drawing.Point(10, 45)
$statusPanel.Size = New-Object System.Drawing.Size(675, 255)
$statusPanel.AutoScroll = $false
$statusGroup.Controls.Add($statusPanel)

# Create status rows
$statusItems = @(
    @{ Name = "Windows Firewall"; Key = "Firewall" },
    @{ Name = "Local Inbound Rules"; Key = "InboundRules" },
    @{ Name = "NetBIOS over TCP/IP"; Key = "NetBIOS" },
    @{ Name = "WPAD (Web Proxy Auto-Discovery)"; Key = "WPAD" },
    @{ Name = "mDNS (Multicast DNS)"; Key = "MDNS" },
    @{ Name = "LLMNR (Link-Local Multicast Name Resolution)"; Key = "LLMNR" },
    @{ Name = "NTLM Authentication"; Key = "NTLM" }
)

$script:statusLabels = @{}
$script:detailLabels = @{}
$script:checkBoxes = @{}
$yPos = 5

foreach ($item in $statusItems) {
    $checkBox = New-Object System.Windows.Forms.CheckBox
    $checkBox.Location = New-Object System.Drawing.Point(15, ($yPos + 2))
    $checkBox.Size = New-Object System.Drawing.Size(20, 20)
    # NTLM is unchecked by default due to compatibility concerns
    $checkBox.Checked = ($item.Key -ne "NTLM")
    $checkBox.Tag = $item.Key
    $statusPanel.Controls.Add($checkBox)
    $script:checkBoxes[$item.Key] = $checkBox
    
    $nameLabel = New-Object System.Windows.Forms.Label
    $nameLabel.Text = $item.Name
    $nameLabel.Location = New-Object System.Drawing.Point(55, $yPos)
    $nameLabel.Size = New-Object System.Drawing.Size(280, 25)
    $nameLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $statusPanel.Controls.Add($nameLabel)
    
    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Text = "Checking..."
    $statusLabel.Location = New-Object System.Drawing.Point(330, $yPos)
    $statusLabel.Size = New-Object System.Drawing.Size(90, 25)
    $statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $statusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $statusPanel.Controls.Add($statusLabel)
    $script:statusLabels[$item.Key] = $statusLabel
    
    $detailLabel = New-Object System.Windows.Forms.Label
    $detailLabel.Text = ""
    $detailLabel.Location = New-Object System.Drawing.Point(430, $yPos)
    $detailLabel.Size = New-Object System.Drawing.Size(240, 25)
    $detailLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $detailLabel.ForeColor = [System.Drawing.Color]::Gray
    $statusPanel.Controls.Add($detailLabel)
    $script:detailLabels[$item.Key] = $detailLabel
    
    $yPos += 32
}

# RDP Preservation Option
$rdpCheckBox = New-Object System.Windows.Forms.CheckBox
$rdpCheckBox.Text = "Preserve RDP rules (TCP 3389) when disabling inbound rules"
$rdpCheckBox.Location = New-Object System.Drawing.Point(75, ($yPos + 5))
$rdpCheckBox.Size = New-Object System.Drawing.Size(350, 20)
$rdpCheckBox.Checked = $false
$rdpCheckBox.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
$rdpCheckBox.ForeColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
$statusPanel.Controls.Add($rdpCheckBox)
$script:rdpCheckBox = $rdpCheckBox

$script:checkBoxes["InboundRules"].Add_CheckedChanged({
    $script:rdpCheckBox.Enabled = $script:checkBoxes["InboundRules"].Checked
})

# Refresh Status Function
function Update-AllStatus {
    $script:statusLabels["Firewall"].Text = "Checking..."
    [System.Windows.Forms.Application]::DoEvents()
    
    $checks = @{
        "Firewall" = { Get-FirewallStatus }
        "InboundRules" = { Get-InboundRulesStatus }
        "NetBIOS" = { Get-NetBIOSStatus }
        "WPAD" = { Get-WPADStatus }
        "MDNS" = { Get-MDNSStatus }
        "LLMNR" = { Get-LLMNRStatus }
        "NTLM" = { Get-NTLMStatus }
    }
    
    foreach ($key in $checks.Keys) {
        $result = & $checks[$key]
        $script:statusLabels[$key].Text = $result.Status
        $script:detailLabels[$key].Text = $result.Detail
        
        switch ($result.Color) {
            "Green" { $script:statusLabels[$key].ForeColor = [System.Drawing.Color]::Green }
            "Red" { $script:statusLabels[$key].ForeColor = [System.Drawing.Color]::Red }
            "Orange" { $script:statusLabels[$key].ForeColor = [System.Drawing.Color]::DarkOrange }
            default { $script:statusLabels[$key].ForeColor = [System.Drawing.Color]::Gray }
        }
        [System.Windows.Forms.Application]::DoEvents()
    }
}

# Buttons Panel
$buttonPanel = New-Object System.Windows.Forms.Panel
$buttonPanel.Location = New-Object System.Drawing.Point(20, 400)
$buttonPanel.Size = New-Object System.Drawing.Size(695, 50)
$form.Controls.Add($buttonPanel)

# Select All Button
$selectAllButton = New-Object System.Windows.Forms.Button
$selectAllButton.Text = "[+] All"
$selectAllButton.Location = New-Object System.Drawing.Point(0, 5)
$selectAllButton.Size = New-Object System.Drawing.Size(70, 35)
$selectAllButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$selectAllButton.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 230)
$selectAllButton.FlatStyle = "Flat"
$selectAllButton.Add_Click({
    foreach ($key in $script:checkBoxes.Keys) {
        $script:checkBoxes[$key].Checked = $true
    }
})
$buttonPanel.Controls.Add($selectAllButton)

# Deselect All Button
$deselectAllButton = New-Object System.Windows.Forms.Button
$deselectAllButton.Text = "[-] None"
$deselectAllButton.Location = New-Object System.Drawing.Point(80, 5)
$deselectAllButton.Size = New-Object System.Drawing.Size(70, 35)
$deselectAllButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$deselectAllButton.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 230)
$deselectAllButton.FlatStyle = "Flat"
$deselectAllButton.Add_Click({
    foreach ($key in $script:checkBoxes.Keys) {
        $script:checkBoxes[$key].Checked = $false
    }
})
$buttonPanel.Controls.Add($deselectAllButton)

# Refresh Button
$refreshButton = New-Object System.Windows.Forms.Button
$refreshButton.Text = "Refresh"
$refreshButton.Location = New-Object System.Drawing.Point(165, 5)
$refreshButton.Size = New-Object System.Drawing.Size(90, 35)
$refreshButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$refreshButton.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 230)
$refreshButton.FlatStyle = "Flat"
$refreshButton.Add_Click({
    $refreshButton.Enabled = $false
    $refreshButton.Text = "..."
    Update-AllStatus
    Update-BackupStatus
    $refreshButton.Text = "Refresh"
    $refreshButton.Enabled = $true
})
$buttonPanel.Controls.Add($refreshButton)

# Harden Button
$hardenButton = New-Object System.Windows.Forms.Button
$hardenButton.Text = "Harden System"
$hardenButton.Location = New-Object System.Drawing.Point(270, 5)
$hardenButton.Size = New-Object System.Drawing.Size(140, 35)
$hardenButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$hardenButton.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
$hardenButton.ForeColor = [System.Drawing.Color]::White
$hardenButton.FlatStyle = "Flat"
$hardenButton.Enabled = $isAdmin
$hardenButton.Add_Click({
    $selectedItems = @()
    foreach ($key in $script:checkBoxes.Keys) {
        if ($script:checkBoxes[$key].Checked) {
            $selectedItems += $key
        }
    }
    
    if ($selectedItems.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please select at least one component to harden.",
            "No Selection",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    $confirmMsg = "This will apply hardening to the following components:`n`n"
    foreach ($key in $selectedItems) {
        $confirmMsg += "* $key`n"
    }
    if ($script:rdpCheckBox.Checked -and $script:checkBoxes["InboundRules"].Checked) {
        $confirmMsg += "`n(RDP rules will be preserved)`n"
    }
    $confirmMsg += "`nA backup will be created before changes are made.`n`nContinue?"
    
    $result = [System.Windows.Forms.MessageBox]::Show(
        $confirmMsg,
        "Confirm Hardening",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    
    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        $hardenButton.Enabled = $false
        $refreshButton.Enabled = $false
        $selectAllButton.Enabled = $false
        $deselectAllButton.Enabled = $false
        $rollbackButton.Enabled = $false
        $hardenButton.Text = "Working..."
        
        $options = @{
            Firewall = $script:checkBoxes["Firewall"].Checked
            InboundRules = $script:checkBoxes["InboundRules"].Checked
            NetBIOS = $script:checkBoxes["NetBIOS"].Checked
            WPAD = $script:checkBoxes["WPAD"].Checked
            MDNS = $script:checkBoxes["MDNS"].Checked
            LLMNR = $script:checkBoxes["LLMNR"].Checked
            NTLM = $script:checkBoxes["NTLM"].Checked
            PreserveRDP = $script:rdpCheckBox.Checked
        }
        
        Invoke-Hardening -LogBox $logTextBox -Options $options
        
        Start-Sleep -Seconds 1
        Update-AllStatus
        $hasBackup = Update-BackupStatus
        $rollbackButton.Enabled = $isAdmin -and $hasBackup
        
        $hardenButton.Text = "Harden System"
        $hardenButton.Enabled = $true
        $refreshButton.Enabled = $true
        $selectAllButton.Enabled = $true
        $deselectAllButton.Enabled = $true
        
        [System.Windows.Forms.MessageBox]::Show(
            "Hardening complete!`n`nA backup has been saved. Use 'Rollback' to restore previous settings.`n`nA system reboot is recommended for all changes to take full effect.",
            "Complete",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
})
$buttonPanel.Controls.Add($hardenButton)

# Rollback Button
$rollbackButton = New-Object System.Windows.Forms.Button
$rollbackButton.Text = "<< Rollback"
$rollbackButton.Location = New-Object System.Drawing.Point(420, 5)
$rollbackButton.Size = New-Object System.Drawing.Size(110, 35)
$rollbackButton.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$rollbackButton.BackColor = [System.Drawing.Color]::FromArgb(200, 80, 80)
$rollbackButton.ForeColor = [System.Drawing.Color]::White
$rollbackButton.FlatStyle = "Flat"
$rollbackButton.Enabled = $false
$rollbackButton.Add_Click({
    if (-not (Test-Path $script:LatestBackupFile)) {
        [System.Windows.Forms.MessageBox]::Show(
            "No backup file found. Run hardening first to create a backup.",
            "No Backup",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    try {
        $backup = Get-Content $script:LatestBackupFile -Raw | ConvertFrom-Json
        $backupTime = $backup.Timestamp
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to read backup file: $_",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return
    }
    
    $result = [System.Windows.Forms.MessageBox]::Show(
        "This will restore the system configuration from backup:`n`nBackup created: $backupTime`nComputer: $($backup.ComputerName)`n`nThis will undo all hardening changes. Continue?",
        "Confirm Rollback",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    
    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        $hardenButton.Enabled = $false
        $refreshButton.Enabled = $false
        $selectAllButton.Enabled = $false
        $deselectAllButton.Enabled = $false
        $rollbackButton.Enabled = $false
        $rollbackButton.Text = "Working..."
        
        $logTextBox.Clear()
        $success = Restore-Configuration -LogBox $logTextBox -BackupPath $script:LatestBackupFile
        
        Start-Sleep -Seconds 1
        Update-AllStatus
        
        $rollbackButton.Text = "<< Rollback"
        $hardenButton.Enabled = $true
        $refreshButton.Enabled = $true
        $selectAllButton.Enabled = $true
        $deselectAllButton.Enabled = $true
        $rollbackButton.Enabled = $true
        
        if ($success) {
            [System.Windows.Forms.MessageBox]::Show(
                "Rollback complete!`n`nA system reboot is recommended for all changes to take full effect.",
                "Rollback Complete",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
    }
})
$buttonPanel.Controls.Add($rollbackButton)

# Export Button
$exportButton = New-Object System.Windows.Forms.Button
$exportButton.Text = "Copy Log"
$exportButton.Location = New-Object System.Drawing.Point(545, 5)
$exportButton.Size = New-Object System.Drawing.Size(100, 35)
$exportButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$exportButton.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 230)
$exportButton.FlatStyle = "Flat"
$exportButton.Add_Click({
    if ($logTextBox.Text.Length -gt 0) {
        [System.Windows.Forms.Clipboard]::SetText($logTextBox.Text)
        [System.Windows.Forms.MessageBox]::Show("Log copied to clipboard!", "Copied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})
$buttonPanel.Controls.Add($exportButton)

# Browse Backups Button
$browseBackupsButton = New-Object System.Windows.Forms.Button
$browseBackupsButton.Text = "..."
$browseBackupsButton.Location = New-Object System.Drawing.Point(655, 5)
$browseBackupsButton.Size = New-Object System.Drawing.Size(35, 35)
$browseBackupsButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$browseBackupsButton.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 230)
$browseBackupsButton.FlatStyle = "Flat"
$toolTip = New-Object System.Windows.Forms.ToolTip
$toolTip.SetToolTip($browseBackupsButton, "Select backup file to restore")
$browseBackupsButton.Add_Click({
    # Ensure backup folder exists
    if (-not (Test-Path $script:BackupFolder)) {
        New-Item -Path $script:BackupFolder -ItemType Directory -Force | Out-Null
    }
    
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Title = "Select Backup File to Restore"
    $openFileDialog.InitialDirectory = $script:BackupFolder
    $openFileDialog.Filter = "JSON Backup Files (*.json)|*.json|All Files (*.*)|*.*"
    $openFileDialog.FilterIndex = 1
    
    if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $selectedFile = $openFileDialog.FileName
        
        # Validate the selected file
        try {
            $backup = Get-Content $selectedFile -Raw | ConvertFrom-Json
            $backupTime = $backup.Timestamp
            $backupComputer = $backup.ComputerName
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Invalid backup file. Could not read configuration data.`n`nError: $_",
                "Invalid File",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return
        }
        
        $result = [System.Windows.Forms.MessageBox]::Show(
            "Restore from selected backup?`n`nFile: $(Split-Path $selectedFile -Leaf)`nBackup created: $backupTime`nComputer: $backupComputer`n`nThis will undo hardening changes. Continue?",
            "Confirm Rollback",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            $hardenButton.Enabled = $false
            $refreshButton.Enabled = $false
            $selectAllButton.Enabled = $false
            $deselectAllButton.Enabled = $false
            $rollbackButton.Enabled = $false
            $browseBackupsButton.Enabled = $false
            
            $logTextBox.Clear()
            $success = Restore-Configuration -LogBox $logTextBox -BackupPath $selectedFile
            
            Start-Sleep -Seconds 1
            Update-AllStatus
            $hasBackup = Update-BackupStatus
            $rollbackButton.Enabled = $isAdmin -and $hasBackup
            
            $hardenButton.Enabled = $true
            $refreshButton.Enabled = $true
            $selectAllButton.Enabled = $true
            $deselectAllButton.Enabled = $true
            $browseBackupsButton.Enabled = $true
            
            if ($success) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Rollback complete!`n`nA system reboot is recommended for all changes to take full effect.",
                    "Rollback Complete",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
            }
        }
    }
})
$buttonPanel.Controls.Add($browseBackupsButton)

# Log Group Box
$logGroup = New-Object System.Windows.Forms.GroupBox
$logGroup.Text = "Activity Log"
$logGroup.Location = New-Object System.Drawing.Point(20, 455)
$logGroup.Size = New-Object System.Drawing.Size(695, 300)
$logGroup.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($logGroup)

# Log TextBox
$logTextBox = New-Object System.Windows.Forms.TextBox
$logTextBox.Multiline = $true
$logTextBox.ScrollBars = "Vertical"
$logTextBox.Location = New-Object System.Drawing.Point(10, 25)
$logTextBox.Size = New-Object System.Drawing.Size(675, 265)
$logTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$logTextBox.ReadOnly = $true
$logTextBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$logTextBox.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 200)
$logGroup.Controls.Add($logTextBox)

#endregion

# Initial status check
$form.Add_Shown({
    Update-AllStatus
    $hasBackup = Update-BackupStatus
    $rollbackButton.Enabled = $isAdmin -and $hasBackup
    
    if (-not $isAdmin) {
        $logTextBox.Text = "WARNING: Not running as Administrator.`r`nPlease restart this script with elevated privileges to enable hardening.`r`n`r`nRight-click PowerShell > Run as Administrator"
    }
    else {
        $logTextBox.Text = "Ready. Select components to harden and click 'Harden System'.`r`n`r`nCurrent status shown above. Green = Secure, Red = Vulnerable.`r`n`r`nTip: Uncheck components you want to exclude from hardening.`r`nTip: Check 'Preserve RDP rules' if you need remote desktop access.`r`nTip: NTLM is unchecked by default - enabling may break legacy apps.`r`n`r`nBackups are saved to: $script:BackupFolder`r`nUse 'Rollback' to restore from last backup, or '...' to select a specific backup file."
    }
})

# Show the form
[void]$form.ShowDialog()
