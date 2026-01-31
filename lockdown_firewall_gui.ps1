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
.NOTES
    Must be run as Administrator for hardening to work.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

#region Check Admin Status
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
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
        $enabledRules = ($rules | Where-Object { $_.Enabled -eq "True" }).Count
        $totalRules = $rules.Count
        
        if ($enabledRules -eq 0) {
            return @{ Status = "Secure"; Color = "Green"; Detail = "All $totalRules rules disabled" }
        }
        else {
            return @{ Status = "Vulnerable"; Color = "Red"; Detail = "$enabledRules of $totalRules rules enabled" }
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
            # TcpipNetbiosOptions: 0 = Default (usually enabled), 1 = Enabled, 2 = Disabled
            if ($adapter.TcpipNetbiosOptions -ne 2) {
                $netbiosEnabled = $true
                break
            }
        }
        
        # Also check lmhosts service
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
        
        # Check WinHttpAutoProxySvc service
        $wpadService = Get-Service -Name "WinHttpAutoProxySvc" -ErrorAction SilentlyContinue
        if ($wpadService -and $wpadService.Status -eq "Running") {
            $vulnerable = $true
            $details += "Service running"
        }
        
        # Check registry AutoDetect
        $autoDetect = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoDetect" -ErrorAction SilentlyContinue
        if (-not $autoDetect -or $autoDetect.AutoDetect -ne 0) {
            $vulnerable = $true
            $details += "AutoDetect enabled"
        }
        
        # Check WinHttp DisableWpad
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
        
        # Check EnableMDNS registry
        $mdns = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMDNS" -ErrorAction SilentlyContinue
        if (-not $mdns -or $mdns.EnableMDNS -ne 0) {
            $vulnerable = $true
            $details += "mDNS enabled"
        }
        
        # Check firewall block rule
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
        
        # Check EnableMulticast registry
        $llmnr = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
        if (-not $llmnr -or $llmnr.EnableMulticast -ne 0) {
            $vulnerable = $true
            $details += "LLMNR enabled"
        }
        
        # Check firewall block rule
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

#endregion

#region Hardening Functions

function Invoke-Hardening {
    param([System.Windows.Forms.TextBox]$LogBox)
    
    $LogBox.Clear()
    
    function Write-Log {
        param([string]$Message, [string]$Color = "Black")
        $LogBox.AppendText("$Message`r`n")
        $LogBox.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    }
    
    Write-Log "Starting hardening process..."
    Write-Log "========================================"
    
    # 1. Enable Firewall
    Write-Log "`r`n[1/6] Enabling Windows Defender Firewall..."
    foreach ($profile in @("Domain", "Private", "Public")) {
        try {
            Set-NetFirewallProfile -Profile $profile -Enabled True -ErrorAction Stop
            Write-Log "  OK: $profile profile enabled"
        }
        catch {
            Write-Log "  ERROR: $profile - $_"
        }
    }
    
    # 2. Disable Inbound Rules
    Write-Log "`r`n[2/6] Disabling local inbound firewall rules..."
    try {
        $rules = Get-NetFirewallRule -Direction Inbound -PolicyStore PersistentStore -ErrorAction Stop
        $count = 0
        foreach ($rule in $rules) {
            if ($rule.Enabled -eq "True") {
                $rule | Set-NetFirewallRule -Enabled False -ErrorAction SilentlyContinue
                $count++
            }
        }
        Write-Log "  OK: Disabled $count inbound rules"
    }
    catch {
        Write-Log "  ERROR: $_"
    }
    
    # 3. Disable NetBIOS
    Write-Log "`r`n[3/6] Disabling NetBIOS over TCP/IP..."
    try {
        $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
        foreach ($adapter in $adapters) {
            $adapter.SetTcpipNetbios(2) | Out-Null
        }
        Write-Log "  OK: NetBIOS disabled on adapters"
        
        # Registry
        $netbtInterfaces = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -ErrorAction SilentlyContinue
        foreach ($interface in $netbtInterfaces) {
            Set-ItemProperty -Path $interface.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -ErrorAction SilentlyContinue
        }
        Write-Log "  OK: NetBIOS registry updated"
        
        # Service
        Stop-Service -Name "lmhosts" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "lmhosts" -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Log "  OK: lmhosts service disabled"
    }
    catch {
        Write-Log "  ERROR: $_"
    }
    
    # 4. Disable WPAD
    Write-Log "`r`n[4/6] Disabling WPAD..."
    try {
        # Service
        Stop-Service -Name "WinHttpAutoProxySvc" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "WinHttpAutoProxySvc" -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Log "  OK: WinHttpAutoProxySvc disabled"
        
        # Registry - HKLM
        $internetSettingsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
        Set-ItemProperty -Path $internetSettingsPath -Name "AutoDetect" -Value 0 -Type DWord -ErrorAction Stop
        Write-Log "  OK: AutoDetect disabled (HKLM)"
        
        # Registry - HKCU
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoDetect" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Write-Log "  OK: AutoDetect disabled (HKCU)"
        
        # WinHttp
        $winhttpPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
        if (-not (Test-Path $winhttpPath)) { New-Item -Path $winhttpPath -Force | Out-Null }
        Set-ItemProperty -Path $winhttpPath -Name "DisableWpad" -Value 1 -Type DWord
        Write-Log "  OK: WinHttp WPAD disabled"
        
        # Hosts file
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
    
    # 5. Disable mDNS
    Write-Log "`r`n[5/6] Disabling mDNS..."
    try {
        $dnsParams = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
        if (-not (Test-Path $dnsParams)) { New-Item -Path $dnsParams -Force | Out-Null }
        Set-ItemProperty -Path $dnsParams -Name "EnableMDNS" -Value 0 -Type DWord
        Write-Log "  OK: mDNS disabled in registry"
        
        # Firewall rules
        Remove-NetFirewallRule -DisplayName "Block mDNS (UDP 5353)" -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName "Block mDNS Outbound (UDP 5353)" -ErrorAction SilentlyContinue
        
        New-NetFirewallRule -DisplayName "Block mDNS (UDP 5353)" -Direction Inbound -Protocol UDP -LocalPort 5353 -Action Block -Profile Any -Enabled True | Out-Null
        New-NetFirewallRule -DisplayName "Block mDNS Outbound (UDP 5353)" -Direction Outbound -Protocol UDP -LocalPort 5353 -Action Block -Profile Any -Enabled True | Out-Null
        Write-Log "  OK: mDNS firewall block rules created"
    }
    catch {
        Write-Log "  ERROR: $_"
    }
    
    # 6. Disable LLMNR
    Write-Log "`r`n[6/6] Disabling LLMNR..."
    try {
        $dnsPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        if (-not (Test-Path $dnsPolicyPath)) { New-Item -Path $dnsPolicyPath -Force | Out-Null }
        Set-ItemProperty -Path $dnsPolicyPath -Name "EnableMulticast" -Value 0 -Type DWord
        Write-Log "  OK: LLMNR disabled in registry"
        
        # Firewall rules
        Remove-NetFirewallRule -DisplayName "Block LLMNR (UDP 5355)" -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName "Block LLMNR Outbound (UDP 5355)" -ErrorAction SilentlyContinue
        
        New-NetFirewallRule -DisplayName "Block LLMNR (UDP 5355)" -Direction Inbound -Protocol UDP -LocalPort 5355 -Action Block -Profile Any -Enabled True | Out-Null
        New-NetFirewallRule -DisplayName "Block LLMNR Outbound (UDP 5355)" -Direction Outbound -Protocol UDP -LocalPort 5355 -Action Block -Profile Any -Enabled True | Out-Null
        Write-Log "  OK: LLMNR firewall block rules created"
    }
    catch {
        Write-Log "  ERROR: $_"
    }
    
    Write-Log "`r`n========================================"
    Write-Log "Hardening complete!"
    Write-Log "A reboot is recommended for full effect."
}

#endregion

#region Build GUI

$form = New-Object System.Windows.Forms.Form
$form.Text = "Windows Network Hardening Tool"
$form.Size = New-Object System.Drawing.Size(700, 680)
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
    $adminLabel.Text = "✓ Running as Administrator"
    $adminLabel.ForeColor = [System.Drawing.Color]::Green
}
else {
    $adminLabel.Text = "✗ Not running as Administrator (hardening will fail)"
    $adminLabel.ForeColor = [System.Drawing.Color]::Red
}
$adminLabel.Location = New-Object System.Drawing.Point(20, 50)
$adminLabel.Size = New-Object System.Drawing.Size(400, 20)
$form.Controls.Add($adminLabel)

# Status Group Box
$statusGroup = New-Object System.Windows.Forms.GroupBox
$statusGroup.Text = "Current Security Status"
$statusGroup.Location = New-Object System.Drawing.Point(20, 80)
$statusGroup.Size = New-Object System.Drawing.Size(645, 250)
$statusGroup.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($statusGroup)

# Status Panel (inside group)
$statusPanel = New-Object System.Windows.Forms.Panel
$statusPanel.Location = New-Object System.Drawing.Point(10, 25)
$statusPanel.Size = New-Object System.Drawing.Size(625, 215)
$statusPanel.AutoScroll = $false
$statusGroup.Controls.Add($statusPanel)

# Create status rows
$statusItems = @(
    @{ Name = "Windows Firewall"; Key = "Firewall" },
    @{ Name = "Local Inbound Rules"; Key = "InboundRules" },
    @{ Name = "NetBIOS over TCP/IP"; Key = "NetBIOS" },
    @{ Name = "WPAD (Web Proxy Auto-Discovery)"; Key = "WPAD" },
    @{ Name = "mDNS (Multicast DNS)"; Key = "MDNS" },
    @{ Name = "LLMNR (Link-Local Multicast Name Resolution)"; Key = "LLMNR" }
)

$script:statusLabels = @{}
$script:detailLabels = @{}
$yPos = 5

foreach ($item in $statusItems) {
    # Item name label
    $nameLabel = New-Object System.Windows.Forms.Label
    $nameLabel.Text = $item.Name
    $nameLabel.Location = New-Object System.Drawing.Point(10, $yPos)
    $nameLabel.Size = New-Object System.Drawing.Size(280, 25)
    $nameLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $statusPanel.Controls.Add($nameLabel)
    
    # Status indicator label
    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Text = "Checking..."
    $statusLabel.Location = New-Object System.Drawing.Point(300, $yPos)
    $statusLabel.Size = New-Object System.Drawing.Size(90, 25)
    $statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $statusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $statusPanel.Controls.Add($statusLabel)
    $script:statusLabels[$item.Key] = $statusLabel
    
    # Detail label
    $detailLabel = New-Object System.Windows.Forms.Label
    $detailLabel.Text = ""
    $detailLabel.Location = New-Object System.Drawing.Point(400, $yPos)
    $detailLabel.Size = New-Object System.Drawing.Size(220, 25)
    $detailLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $detailLabel.ForeColor = [System.Drawing.Color]::Gray
    $statusPanel.Controls.Add($detailLabel)
    $script:detailLabels[$item.Key] = $detailLabel
    
    $yPos += 35
}

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
$buttonPanel.Location = New-Object System.Drawing.Point(20, 340)
$buttonPanel.Size = New-Object System.Drawing.Size(645, 45)
$form.Controls.Add($buttonPanel)

# Refresh Button
$refreshButton = New-Object System.Windows.Forms.Button
$refreshButton.Text = "🔄 Refresh Status"
$refreshButton.Location = New-Object System.Drawing.Point(0, 0)
$refreshButton.Size = New-Object System.Drawing.Size(150, 40)
$refreshButton.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$refreshButton.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 230)
$refreshButton.FlatStyle = "Flat"
$refreshButton.Add_Click({
    $refreshButton.Enabled = $false
    $refreshButton.Text = "Checking..."
    Update-AllStatus
    $refreshButton.Text = "🔄 Refresh Status"
    $refreshButton.Enabled = $true
})
$buttonPanel.Controls.Add($refreshButton)

# Harden Button
$hardenButton = New-Object System.Windows.Forms.Button
$hardenButton.Text = "🛡️ Harden System"
$hardenButton.Location = New-Object System.Drawing.Point(170, 0)
$hardenButton.Size = New-Object System.Drawing.Size(180, 40)
$hardenButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$hardenButton.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
$hardenButton.ForeColor = [System.Drawing.Color]::White
$hardenButton.FlatStyle = "Flat"
$hardenButton.Enabled = $isAdmin
$hardenButton.Add_Click({
    $result = [System.Windows.Forms.MessageBox]::Show(
        "This will:`n`n• Enable Windows Firewall on all profiles`n• Disable all local inbound firewall rules`n• Disable NetBIOS over TCP/IP`n• Disable WPAD`n• Disable mDNS`n• Disable LLMNR`n`nContinue?",
        "Confirm Hardening",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    
    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        $hardenButton.Enabled = $false
        $refreshButton.Enabled = $false
        $hardenButton.Text = "Working..."
        
        Invoke-Hardening -LogBox $logTextBox
        
        Start-Sleep -Seconds 1
        Update-AllStatus
        
        $hardenButton.Text = "🛡️ Harden System"
        $hardenButton.Enabled = $true
        $refreshButton.Enabled = $true
        
        [System.Windows.Forms.MessageBox]::Show(
            "Hardening complete!`n`nA system reboot is recommended for all changes to take full effect.",
            "Complete",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
})
$buttonPanel.Controls.Add($hardenButton)

# Export Button
$exportButton = New-Object System.Windows.Forms.Button
$exportButton.Text = "📋 Copy Log"
$exportButton.Location = New-Object System.Drawing.Point(495, 0)
$exportButton.Size = New-Object System.Drawing.Size(150, 40)
$exportButton.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$exportButton.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 230)
$exportButton.FlatStyle = "Flat"
$exportButton.Add_Click({
    if ($logTextBox.Text.Length -gt 0) {
        [System.Windows.Forms.Clipboard]::SetText($logTextBox.Text)
        [System.Windows.Forms.MessageBox]::Show("Log copied to clipboard!", "Copied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})
$buttonPanel.Controls.Add($exportButton)

# Log Group Box
$logGroup = New-Object System.Windows.Forms.GroupBox
$logGroup.Text = "Activity Log"
$logGroup.Location = New-Object System.Drawing.Point(20, 395)
$logGroup.Size = New-Object System.Drawing.Size(645, 230)
$logGroup.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($logGroup)

# Log TextBox
$logTextBox = New-Object System.Windows.Forms.TextBox
$logTextBox.Multiline = $true
$logTextBox.ScrollBars = "Vertical"
$logTextBox.Location = New-Object System.Drawing.Point(10, 25)
$logTextBox.Size = New-Object System.Drawing.Size(625, 195)
$logTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$logTextBox.ReadOnly = $true
$logTextBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$logTextBox.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 200)
$logGroup.Controls.Add($logTextBox)

#endregion

# Initial status check
$form.Add_Shown({
    Update-AllStatus
    if (-not $isAdmin) {
        $logTextBox.Text = "WARNING: Not running as Administrator.`r`nPlease restart this script with elevated privileges to enable hardening.`r`n`r`nRight-click PowerShell > Run as Administrator"
    }
    else {
        $logTextBox.Text = "Ready. Click 'Harden System' to apply security hardening.`r`n`r`nCurrent status shown above. Green = Secure, Red = Vulnerable."
    }
})

# Show the form
[void]$form.ShowDialog()
