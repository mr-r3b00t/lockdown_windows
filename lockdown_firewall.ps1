#Requires -RunAsAdministrator
#Requires -Version 5.0

<#
.SYNOPSIS
    Hardens Windows networking by enabling firewall and disabling legacy/discovery protocols.
.DESCRIPTION
    This script:
    - Enables Windows Defender Firewall for all profiles
    - Disables all local inbound firewall rules
    - Disables NetBIOS over TCP/IP on all network adapters
    - Disables WPAD (Web Proxy Auto-Discovery)
    - Disables mDNS (Multicast DNS)
.NOTES
    Must be run as Administrator.
    A reboot may be required for some changes to take full effect.
#>

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Windows Network Hardening Script" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

#region Enable Windows Defender Firewall
Write-Host "[1/5] Enabling Windows Defender Firewall for all profiles..." -ForegroundColor Cyan

$profiles = @("Domain", "Private", "Public")

foreach ($profile in $profiles) {
    try {
        Set-NetFirewallProfile -Profile $profile -Enabled True
        Write-Host "  [OK] $profile profile firewall enabled." -ForegroundColor Green
    }
    catch {
        Write-Host "  [ERROR] Failed to enable $profile profile: $_" -ForegroundColor Red
    }
}
#endregion

Write-Host ""

#region Disable Local Inbound Firewall Rules
Write-Host "[2/5] Disabling local inbound firewall rules..." -ForegroundColor Cyan

$inboundRules = Get-NetFirewallRule -Direction Inbound -PolicyStore PersistentStore

if ($inboundRules.Count -eq 0) {
    Write-Host "  No local inbound rules found." -ForegroundColor Yellow
}
else {
    Write-Host "  Found $($inboundRules.Count) local inbound rule(s)." -ForegroundColor White
    
    $disabledCount = 0
    $alreadyDisabledCount = 0
    $errorCount = 0
    
    foreach ($rule in $inboundRules) {
        $ruleName = $rule.DisplayName
        $ruleStatus = $rule.Enabled
        
        if ($ruleStatus -eq "True") {
            try {
                $rule | Set-NetFirewallRule -Enabled False
                Write-Host "    [DISABLED] $ruleName" -ForegroundColor Yellow
                $disabledCount++
            }
            catch {
                Write-Host "    [ERROR] Failed to disable '$ruleName': $_" -ForegroundColor Red
                $errorCount++
            }
        }
        else {
            $alreadyDisabledCount++
        }
    }
    
    Write-Host "  Summary: $disabledCount disabled, $alreadyDisabledCount already disabled, $errorCount errors" -ForegroundColor White
}
#endregion

Write-Host ""

#region Disable NetBIOS over TCP/IP
Write-Host "[3/5] Disabling NetBIOS over TCP/IP on all adapters..." -ForegroundColor Cyan

# Method 1: Using WMI to disable NetBIOS on all adapters
# NetbiosOptions: 0 = Default, 1 = Enable, 2 = Disable
try {
    $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
    
    if ($adapters.Count -eq 0) {
        Write-Host "  No IP-enabled adapters found." -ForegroundColor Yellow
    }
    else {
        foreach ($adapter in $adapters) {
            $adapterName = $adapter.Description
            $result = $adapter.SetTcpipNetbios(2)
            
            if ($result.ReturnValue -eq 0) {
                Write-Host "  [OK] Disabled NetBIOS on: $adapterName" -ForegroundColor Green
            }
            elseif ($result.ReturnValue -eq 1) {
                Write-Host "  [OK] Disabled NetBIOS on: $adapterName (reboot required)" -ForegroundColor Yellow
            }
            else {
                Write-Host "  [WARN] Could not disable NetBIOS on: $adapterName (Return: $($result.ReturnValue))" -ForegroundColor Yellow
            }
        }
    }
}
catch {
    Write-Host "  [ERROR] Failed to disable NetBIOS via WMI: $_" -ForegroundColor Red
}

# Method 2: Also set registry for all interfaces to ensure persistence
try {
    $netbtInterfaces = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -ErrorAction SilentlyContinue
    
    foreach ($interface in $netbtInterfaces) {
        Set-ItemProperty -Path $interface.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -ErrorAction SilentlyContinue
    }
    Write-Host "  [OK] NetBIOS registry settings updated for all interfaces." -ForegroundColor Green
}
catch {
    Write-Host "  [ERROR] Failed to update NetBIOS registry: $_" -ForegroundColor Red
}

# Disable NetBIOS helper service (lmhosts)
try {
    $lmhostsService = Get-Service -Name "lmhosts" -ErrorAction SilentlyContinue
    if ($lmhostsService) {
        Stop-Service -Name "lmhosts" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "lmhosts" -StartupType Disabled
        Write-Host "  [OK] TCP/IP NetBIOS Helper service (lmhosts) disabled." -ForegroundColor Green
    }
}
catch {
    Write-Host "  [WARN] Could not disable lmhosts service: $_" -ForegroundColor Yellow
}
#endregion

Write-Host ""

#region Disable WPAD (Web Proxy Auto-Discovery)
Write-Host "[4/5] Disabling WPAD (Web Proxy Auto-Discovery)..." -ForegroundColor Cyan

# Disable WinHTTP Auto-Proxy Service
try {
    $wpadService = Get-Service -Name "WinHttpAutoProxySvc" -ErrorAction SilentlyContinue
    if ($wpadService) {
        Stop-Service -Name "WinHttpAutoProxySvc" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "WinHttpAutoProxySvc" -StartupType Disabled
        Write-Host "  [OK] WinHTTP Web Proxy Auto-Discovery Service disabled." -ForegroundColor Green
    }
    else {
        Write-Host "  [INFO] WinHttpAutoProxySvc service not found." -ForegroundColor Gray
    }
}
catch {
    Write-Host "  [WARN] Could not disable WinHttpAutoProxySvc: $_" -ForegroundColor Yellow
}

# Disable WPAD via registry (Internet Settings)
try {
    # Machine-wide setting
    $internetSettingsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
    if (-not (Test-Path $internetSettingsPath)) {
        New-Item -Path $internetSettingsPath -Force | Out-Null
    }
    Set-ItemProperty -Path $internetSettingsPath -Name "AutoDetect" -Value 0 -Type DWord
    Write-Host "  [OK] WPAD AutoDetect disabled in registry (HKLM)." -ForegroundColor Green
    
    # Current user setting
    $internetSettingsPathUser = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
    Set-ItemProperty -Path $internetSettingsPathUser -Name "AutoDetect" -Value 0 -Type DWord
    Write-Host "  [OK] WPAD AutoDetect disabled in registry (HKCU)." -ForegroundColor Green
}
catch {
    Write-Host "  [ERROR] Failed to disable WPAD via registry: $_" -ForegroundColor Red
}

# Disable WPAD via WinHTTP registry settings
try {
    $winhttpPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
    if (-not (Test-Path $winhttpPath)) {
        New-Item -Path $winhttpPath -Force | Out-Null
    }
    Set-ItemProperty -Path $winhttpPath -Name "DisableWpad" -Value 1 -Type DWord
    Write-Host "  [OK] WPAD disabled via WinHttp registry key." -ForegroundColor Green
}
catch {
    Write-Host "  [ERROR] Failed to set WinHttp WPAD registry: $_" -ForegroundColor Red
}

# Block WPAD DNS resolution by adding to hosts file (optional but effective)
try {
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    $wpadEntry = "0.0.0.0 wpad"
    $hostsContent = Get-Content $hostsFile -Raw -ErrorAction SilentlyContinue
    
    if ($hostsContent -notmatch "(?m)^\s*[\d\.]+\s+wpad\s*$") {
        Add-Content -Path $hostsFile -Value "`n# Block WPAD`n$wpadEntry" -ErrorAction Stop
        Write-Host "  [OK] Added WPAD block entry to hosts file." -ForegroundColor Green
    }
    else {
        Write-Host "  [INFO] WPAD entry already exists in hosts file." -ForegroundColor Gray
    }
}
catch {
    Write-Host "  [WARN] Could not modify hosts file: $_" -ForegroundColor Yellow
}
#endregion

Write-Host ""

#region Disable mDNS (Multicast DNS)
Write-Host "[5/5] Disabling mDNS (Multicast DNS)..." -ForegroundColor Cyan

# Disable mDNS via DNS Client registry
try {
    $dnsParams = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
    if (-not (Test-Path $dnsParams)) {
        New-Item -Path $dnsParams -Force | Out-Null
    }
    Set-ItemProperty -Path $dnsParams -Name "EnableMDNS" -Value 0 -Type DWord
    Write-Host "  [OK] mDNS disabled via DNS Client registry (EnableMDNS=0)." -ForegroundColor Green
}
catch {
    Write-Host "  [ERROR] Failed to disable mDNS via registry: $_" -ForegroundColor Red
}

# Disable LLMNR (Link-Local Multicast Name Resolution) as well - often grouped with mDNS
try {
    $dnsPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $dnsPolicyPath)) {
        New-Item -Path $dnsPolicyPath -Force | Out-Null
    }
    Set-ItemProperty -Path $dnsPolicyPath -Name "EnableMulticast" -Value 0 -Type DWord
    Write-Host "  [OK] LLMNR disabled via Group Policy registry (EnableMulticast=0)." -ForegroundColor Green
}
catch {
    Write-Host "  [ERROR] Failed to disable LLMNR via registry: $_" -ForegroundColor Red
}

# Block mDNS ports via firewall rules
try {
    # Remove existing rules if present
    Remove-NetFirewallRule -DisplayName "Block mDNS (UDP 5353)" -ErrorAction SilentlyContinue
    
    # Create blocking rule for mDNS port 5353
    New-NetFirewallRule -DisplayName "Block mDNS (UDP 5353)" `
        -Direction Inbound `
        -Protocol UDP `
        -LocalPort 5353 `
        -Action Block `
        -Profile Any `
        -Enabled True | Out-Null
    
    New-NetFirewallRule -DisplayName "Block mDNS Outbound (UDP 5353)" `
        -Direction Outbound `
        -Protocol UDP `
        -LocalPort 5353 `
        -Action Block `
        -Profile Any `
        -Enabled True -ErrorAction SilentlyContinue | Out-Null
    
    Write-Host "  [OK] Firewall rules created to block mDNS (UDP 5353)." -ForegroundColor Green
}
catch {
    Write-Host "  [WARN] Could not create mDNS blocking firewall rules: $_" -ForegroundColor Yellow
}

# Block LLMNR port as well
try {
    Remove-NetFirewallRule -DisplayName "Block LLMNR (UDP 5355)" -ErrorAction SilentlyContinue
    
    New-NetFirewallRule -DisplayName "Block LLMNR (UDP 5355)" `
        -Direction Inbound `
        -Protocol UDP `
        -LocalPort 5355 `
        -Action Block `
        -Profile Any `
        -Enabled True | Out-Null
    
    New-NetFirewallRule -DisplayName "Block LLMNR Outbound (UDP 5355)" `
        -Direction Outbound `
        -Protocol UDP `
        -LocalPort 5355 `
        -Action Block `
        -Profile Any `
        -Enabled True -ErrorAction SilentlyContinue | Out-Null
    
    Write-Host "  [OK] Firewall rules created to block LLMNR (UDP 5355)." -ForegroundColor Green
}
catch {
    Write-Host "  [WARN] Could not create LLMNR blocking firewall rules: $_" -ForegroundColor Yellow
}
#endregion

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Hardening Complete!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary of changes:" -ForegroundColor White
Write-Host "  - Windows Firewall enabled on all profiles" -ForegroundColor Gray
Write-Host "  - Local inbound firewall rules disabled" -ForegroundColor Gray
Write-Host "  - NetBIOS over TCP/IP disabled" -ForegroundColor Gray
Write-Host "  - WPAD (Web Proxy Auto-Discovery) disabled" -ForegroundColor Gray
Write-Host "  - mDNS (Multicast DNS) disabled" -ForegroundColor Gray
Write-Host "  - LLMNR (Link-Local Multicast Name Resolution) disabled" -ForegroundColor Gray
Write-Host ""
Write-Host "NOTE: A system REBOOT is recommended for all changes to take full effect." -ForegroundColor Yellow
Write-Host ""
