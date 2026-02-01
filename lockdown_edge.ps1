<#
.SYNOPSIS
    Microsoft Edge Customization Tool
.DESCRIPTION
    GUI tool to configure Microsoft Edge settings via registry policies and profile config.
    Disables startup wizard, Copilot, translations, writing assistance, and privacy-risking features.
.NOTES
    Requires Administrator privileges to modify HKLM policies.
    Compatible with PowerShell 5.1
#>

# Check for Admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Registry paths
$EdgePolicyPathHKLM = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
$EdgePolicyPathHKCU = "HKCU:\SOFTWARE\Policies\Microsoft\Edge"

# Edge user data path
$EdgeUserDataPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, "Microsoft", "Edge", "User Data")

# Function to get Edge profiles
function Get-EdgeProfiles {
    $profiles = @()
    
    if (Test-Path $EdgeUserDataPath) {
        # Check Local State file for profile info
        $localStatePath = Join-Path $EdgeUserDataPath "Local State"
        if (Test-Path $localStatePath) {
            try {
                $localState = Get-Content $localStatePath -Raw | ConvertFrom-Json
                $profileInfo = $localState.profile.info_cache
                
                if ($profileInfo) {
                    foreach ($prop in $profileInfo.PSObject.Properties) {
                        $profiles += [PSCustomObject]@{
                            Name = $prop.Name
                            DisplayName = $prop.Value.name
                            Path = Join-Path $EdgeUserDataPath $prop.Name
                        }
                    }
                }
            } catch {
                # Fallback: scan for profile directories
            }
        }
        
        # Fallback: Check for Default and Profile folders
        if ($profiles.Count -eq 0) {
            $defaultPath = Join-Path $EdgeUserDataPath "Default"
            if (Test-Path $defaultPath) {
                $profiles += [PSCustomObject]@{
                    Name = "Default"
                    DisplayName = "Default"
                    Path = $defaultPath
                }
            }
            
            # Check for Profile 1, Profile 2, etc.
            Get-ChildItem -Path $EdgeUserDataPath -Directory -Filter "Profile *" -ErrorAction SilentlyContinue | ForEach-Object {
                $profiles += [PSCustomObject]@{
                    Name = $_.Name
                    DisplayName = $_.Name
                    Path = $_.FullName
                }
            }
        }
    }
    
    return $profiles
}

# Function to get default profile
function Get-DefaultEdgeProfile {
    $localStatePath = Join-Path $EdgeUserDataPath "Local State"
    if (Test-Path $localStatePath) {
        try {
            $localState = Get-Content $localStatePath -Raw | ConvertFrom-Json
            $lastUsed = $localState.profile.last_used
            if ($lastUsed) {
                return $lastUsed
            }
        } catch { }
    }
    return "Default"
}

# Function to ensure registry path exists with full path creation
function Ensure-RegistryPath {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        try {
            $parts = $Path -replace '^(HKLM:|HKCU:)\\?', '' -split '\\'
            $root = if ($Path -match '^HKLM:') { 'HKLM:' } else { 'HKCU:' }
            $currentPath = $root
            
            foreach ($part in $parts) {
                if ([string]::IsNullOrWhiteSpace($part)) { continue }
                $currentPath = Join-Path $currentPath $part
                if (-not (Test-Path $currentPath)) {
                    $null = New-Item -Path $currentPath -Force -ErrorAction Stop
                }
            }
            return $true
        } catch {
            return $false
        }
    }
    return $true
}

# Function to set registry value
function Set-EdgePolicy {
    param(
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord",
        [bool]$UseHKLM = $true
    )
    
    $basePath = if ($UseHKLM -and $isAdmin) { $EdgePolicyPathHKLM } else { $EdgePolicyPathHKCU }
    
    if (-not (Ensure-RegistryPath -Path $basePath)) {
        if ($basePath -eq $EdgePolicyPathHKCU) {
            return $false
        }
        $basePath = $EdgePolicyPathHKCU
        if (-not (Ensure-RegistryPath -Path $basePath)) {
            return $false
        }
    }
    
    try {
        Set-ItemProperty -Path $basePath -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
        return $true
    } catch {
        if ($basePath -eq $EdgePolicyPathHKLM) {
            $basePath = $EdgePolicyPathHKCU
            if (Ensure-RegistryPath -Path $basePath) {
                try {
                    Set-ItemProperty -Path $basePath -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
                    return $true
                } catch {
                    return $false
                }
            }
        }
        return $false
    }
}

# Function to get current registry value
function Get-EdgePolicy {
    param([string]$Name)
    
    foreach ($path in @($EdgePolicyPathHKLM, $EdgePolicyPathHKCU)) {
        if (Test-Path $path) {
            try {
                $value = Get-ItemProperty -Path $path -Name $Name -ErrorAction SilentlyContinue
                if ($null -ne $value.$Name) {
                    return $value.$Name
                }
            } catch { }
        }
    }
    return $null
}

# Function to modify Edge profile preferences
function Set-EdgeProfilePreference {
    param(
        [string]$ProfilePath,
        [string]$SettingPath,
        [object]$Value
    )
    
    $prefsPath = Join-Path $ProfilePath "Preferences"
    
    if (-not (Test-Path $prefsPath)) {
        return $false
    }
    
    try {
        $prefs = Get-Content $prefsPath -Raw -ErrorAction Stop | ConvertFrom-Json
        
        # Navigate/create the path
        $pathParts = $SettingPath -split '\.'
        $current = $prefs
        
        for ($i = 0; $i -lt $pathParts.Count - 1; $i++) {
            $part = $pathParts[$i]
            if (-not $current.PSObject.Properties[$part]) {
                $current | Add-Member -NotePropertyName $part -NotePropertyValue ([PSCustomObject]@{}) -Force
            }
            $current = $current.$part
        }
        
        $lastPart = $pathParts[-1]
        if ($current.PSObject.Properties[$lastPart]) {
            $current.$lastPart = $Value
        } else {
            $current | Add-Member -NotePropertyName $lastPart -NotePropertyValue $Value -Force
        }
        
        $prefs | ConvertTo-Json -Depth 100 -Compress | Set-Content $prefsPath -Encoding UTF8 -Force
        return $true
    } catch {
        return $false
    }
}

# Function to apply profile settings
function Apply-ProfileSettings {
    param(
        [string]$ProfilePath,
        [hashtable]$Settings
    )
    
    $prefsPath = Join-Path $ProfilePath "Preferences"
    
    if (-not (Test-Path $prefsPath)) {
        return 0
    }
    
    $successCount = 0
    
    try {
        # Read existing preferences
        $prefsContent = Get-Content $prefsPath -Raw -ErrorAction Stop
        $prefs = $prefsContent | ConvertFrom-Json
        
        foreach ($settingPath in $Settings.Keys) {
            $value = $Settings[$settingPath]
            $pathParts = $settingPath -split '\.'
            $current = $prefs
            
            # Navigate/create the path
            for ($i = 0; $i -lt $pathParts.Count - 1; $i++) {
                $part = $pathParts[$i]
                if (-not $current.PSObject.Properties[$part]) {
                    $current | Add-Member -NotePropertyName $part -NotePropertyValue ([PSCustomObject]@{}) -Force
                }
                $current = $current.$part
            }
            
            $lastPart = $pathParts[-1]
            if ($current.PSObject.Properties[$lastPart]) {
                $current.$lastPart = $value
            } else {
                $current | Add-Member -NotePropertyName $lastPart -NotePropertyValue $value -Force
            }
            $successCount++
        }
        
        # Write back
        $prefs | ConvertTo-Json -Depth 100 | Set-Content $prefsPath -Encoding UTF8 -Force
        
    } catch {
        return 0
    }
    
    return $successCount
}

# Create main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Microsoft Edge Customization Tool"
$form.Size = New-Object System.Drawing.Size(700, 780)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$form.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)

# Title label
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Location = New-Object System.Drawing.Point(20, 10)
$titleLabel.Size = New-Object System.Drawing.Size(660, 28)
$titleLabel.Text = "Microsoft Edge Privacy and Customization Settings"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$titleLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 102, 153)
$form.Controls.Add($titleLabel)

# Admin status label
$adminLabel = New-Object System.Windows.Forms.Label
$adminLabel.Location = New-Object System.Drawing.Point(20, 38)
$adminLabel.Size = New-Object System.Drawing.Size(660, 18)
if ($isAdmin) {
    $adminLabel.Text = "[OK] Running as Administrator - Machine-wide policies available"
    $adminLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 128, 0)
} else {
    $adminLabel.Text = "[!] Running as User - Only user-level policies available (Run as Admin for full control)"
    $adminLabel.ForeColor = [System.Drawing.Color]::FromArgb(200, 100, 0)
}
$form.Controls.Add($adminLabel)

# Profile selection
$lblProfile = New-Object System.Windows.Forms.Label
$lblProfile.Location = New-Object System.Drawing.Point(20, 60)
$lblProfile.Size = New-Object System.Drawing.Size(100, 22)
$lblProfile.Text = "Edge Profile:"
$form.Controls.Add($lblProfile)

$cboProfile = New-Object System.Windows.Forms.ComboBox
$cboProfile.Location = New-Object System.Drawing.Point(120, 58)
$cboProfile.Size = New-Object System.Drawing.Size(250, 24)
$cboProfile.DropDownStyle = "DropDownList"
$form.Controls.Add($cboProfile)

# Populate profiles
$profiles = Get-EdgeProfiles
$defaultProfile = Get-DefaultEdgeProfile
foreach ($profile in $profiles) {
    $idx = $cboProfile.Items.Add("$($profile.DisplayName) ($($profile.Name))")
    if ($profile.Name -eq $defaultProfile) {
        $cboProfile.SelectedIndex = $idx
    }
}
if ($cboProfile.SelectedIndex -lt 0 -and $cboProfile.Items.Count -gt 0) {
    $cboProfile.SelectedIndex = 0
}

$chkApplyToAllProfiles = New-Object System.Windows.Forms.CheckBox
$chkApplyToAllProfiles.Location = New-Object System.Drawing.Point(380, 60)
$chkApplyToAllProfiles.Size = New-Object System.Drawing.Size(180, 22)
$chkApplyToAllProfiles.Text = "Apply to all profiles"
$form.Controls.Add($chkApplyToAllProfiles)

# Create TabControl
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Location = New-Object System.Drawing.Point(20, 88)
$tabControl.Size = New-Object System.Drawing.Size(645, 555)
$form.Controls.Add($tabControl)

# Tab 1: Startup and First Run
$tabStartup = New-Object System.Windows.Forms.TabPage
$tabStartup.Text = "Startup"
$tabStartup.BackColor = [System.Drawing.Color]::White
$tabControl.Controls.Add($tabStartup)

# Tab 2: Copilot and AI
$tabCopilot = New-Object System.Windows.Forms.TabPage
$tabCopilot.Text = "Copilot / AI"
$tabCopilot.BackColor = [System.Drawing.Color]::White
$tabControl.Controls.Add($tabCopilot)

# Tab 3: Privacy and Telemetry
$tabPrivacy = New-Object System.Windows.Forms.TabPage
$tabPrivacy.Text = "Privacy"
$tabPrivacy.BackColor = [System.Drawing.Color]::White
$tabControl.Controls.Add($tabPrivacy)

# Tab 4: Features and Integrations
$tabFeatures = New-Object System.Windows.Forms.TabPage
$tabFeatures.Text = "Features"
$tabFeatures.BackColor = [System.Drawing.Color]::White
$tabControl.Controls.Add($tabFeatures)

# Tab 5: Search and New Tab
$tabSearch = New-Object System.Windows.Forms.TabPage
$tabSearch.Text = "Search / New Tab"
$tabSearch.BackColor = [System.Drawing.Color]::White
$tabControl.Controls.Add($tabSearch)

# Tab 6: Language and Writing
$tabLanguage = New-Object System.Windows.Forms.TabPage
$tabLanguage.Text = "Language / Writing"
$tabLanguage.BackColor = [System.Drawing.Color]::White
$tabControl.Controls.Add($tabLanguage)

# Helper function to create checkboxes
function New-SettingCheckbox {
    param(
        [System.Windows.Forms.Control]$Parent,
        [string]$Text,
        [string]$Description,
        [int]$Y,
        [string]$Tag
    )
    
    $cb = New-Object System.Windows.Forms.CheckBox
    $cb.Location = New-Object System.Drawing.Point(15, $Y)
    $cb.Size = New-Object System.Drawing.Size(600, 22)
    $cb.Text = $Text
    $cb.Tag = $Tag
    $cb.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $Parent.Controls.Add($cb)
    
    $descLabel = New-Object System.Windows.Forms.Label
    $descLabel.Location = New-Object System.Drawing.Point(32, ($Y + 22))
    $descLabel.Size = New-Object System.Drawing.Size(590, 18)
    $descLabel.Text = $Description
    $descLabel.ForeColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
    $descLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $Parent.Controls.Add($descLabel)
    
    return $cb
}

# ===== TAB 1: STARTUP AND FIRST RUN =====
$y = 15

$chkHideFirstRun = New-SettingCheckbox -Parent $tabStartup -Y $y -Tag "HideFirstRunExperience" `
    -Text "Disable First Run Experience / Welcome Wizard" `
    -Description "Prevents the initial setup wizard and welcome screens from appearing"
$y += 48

$chkDisableImportOnLaunch = New-SettingCheckbox -Parent $tabStartup -Y $y -Tag "ImportOnEachLaunch" `
    -Text "Disable Import Prompt on Each Launch" `
    -Description "Stops Edge from prompting to import data from other browsers"
$y += 48

$chkRestoreOnStartup = New-SettingCheckbox -Parent $tabStartup -Y $y -Tag "RestoreOnStartup" `
    -Text "Open Blank Page on Startup (instead of previous session)" `
    -Description "Starts Edge with a blank page rather than restoring previous tabs"
$y += 48

$chkDisableProfilePicker = New-SettingCheckbox -Parent $tabStartup -Y $y -Tag "BrowserGuestModeEnabled" `
    -Text "Disable Profile Picker on Startup" `
    -Description "Skips the profile selection screen when launching Edge"
$y += 48

$chkDisableSigninPrompt = New-SettingCheckbox -Parent $tabStartup -Y $y -Tag "BrowserSignin" `
    -Text "Disable Sign-in Prompt" `
    -Description "Prevents Edge from prompting you to sign in with a Microsoft account"
$y += 48

$chkDisableDefaultBrowserPrompt = New-SettingCheckbox -Parent $tabStartup -Y $y -Tag "DefaultBrowserSettingEnabled" `
    -Text "Disable Set as Default Browser Prompt" `
    -Description "Stops Edge from asking to be set as the default browser"
$y += 48

$chkDisableAutoImport = New-SettingCheckbox -Parent $tabStartup -Y $y -Tag "AutoImportAtFirstRun" `
    -Text "Disable Automatic Data Import from Other Browsers" `
    -Description "Prevents automatic import of bookmarks, history, etc. from other browsers"
$y += 48

$chkDisableEdgeUpdate = New-SettingCheckbox -Parent $tabStartup -Y $y -Tag "EdgeUpdateDisabled" `
    -Text "Disable Edge Auto-Update Prompts" `
    -Description "Stops update notifications and prompts"

# ===== TAB 2: COPILOT AND AI =====
$y = 15

$chkDisableCopilot = New-SettingCheckbox -Parent $tabCopilot -Y $y -Tag "CopilotEnabled" `
    -Text "Disable Copilot Completely" `
    -Description "Disables Microsoft Copilot integration entirely"
$y += 48

$chkDisableCopilotSidebar = New-SettingCheckbox -Parent $tabCopilot -Y $y -Tag "CopilotSidebar" `
    -Text "Disable Copilot Sidebar" `
    -Description "Removes the Copilot button and sidebar panel"
$y += 48

$chkDisableCopilotPageContext = New-SettingCheckbox -Parent $tabCopilot -Y $y -Tag "CopilotPageContext" `
    -Text "Disable Copilot Page Context Access" `
    -Description "Prevents Copilot from reading your current page content"
$y += 48

$chkDisableCopilotCompose = New-SettingCheckbox -Parent $tabCopilot -Y $y -Tag "CopilotCompose" `
    -Text "Disable Copilot Compose (Text Generation)" `
    -Description "Disables AI text generation and rewriting features"
$y += 48

$chkDisableDesignerAI = New-SettingCheckbox -Parent $tabCopilot -Y $y -Tag "DesignerAI" `
    -Text "Disable Designer / Image Creator AI" `
    -Description "Disables AI image generation features"
$y += 48

$chkDisableBingChat = New-SettingCheckbox -Parent $tabCopilot -Y $y -Tag "BingChat" `
    -Text "Disable Bing Chat / Discover" `
    -Description "Disables Bing Chat integration and Discover feature"
$y += 48

$chkDisableAIThemes = New-SettingCheckbox -Parent $tabCopilot -Y $y -Tag "AIThemes" `
    -Text "Disable AI-Generated Themes" `
    -Description "Disables AI theme suggestions and generation"
$y += 48

$chkDisableImageEnhance = New-SettingCheckbox -Parent $tabCopilot -Y $y -Tag "ImageEnhance" `
    -Text "Disable AI Image Enhancement" `
    -Description "Disables automatic AI image enhancement features"
$y += 48

$chkDisableMathSolver = New-SettingCheckbox -Parent $tabCopilot -Y $y -Tag "MathSolver" `
    -Text "Disable Math Solver AI" `
    -Description "Disables the AI-powered math solver feature"
$y += 48

$chkDisableDropAI = New-SettingCheckbox -Parent $tabCopilot -Y $y -Tag "DropAI" `
    -Text "Disable Drop (AI File Sharing)" `
    -Description "Disables the Drop feature with AI capabilities"

# ===== TAB 3: PRIVACY AND TELEMETRY =====
$y = 15

$chkDisableTelemetry = New-SettingCheckbox -Parent $tabPrivacy -Y $y -Tag "MetricsReportingEnabled" `
    -Text "Disable Telemetry and Usage Data Collection" `
    -Description "Prevents Edge from sending usage statistics and crash reports to Microsoft"
$y += 48

$chkDisableDiagnostics = New-SettingCheckbox -Parent $tabPrivacy -Y $y -Tag "DiagnosticData" `
    -Text "Disable Diagnostic Data Collection" `
    -Description "Minimizes diagnostic data sent to Microsoft"
$y += 48

$chkDisablePersonalization = New-SettingCheckbox -Parent $tabPrivacy -Y $y -Tag "PersonalizationReportingEnabled" `
    -Text "Disable Personalization and Ad Tracking" `
    -Description "Prevents browsing data from being used for personalized ads"
$y += 48

$chkEnableTrackingPrevention = New-SettingCheckbox -Parent $tabPrivacy -Y $y -Tag "TrackingPrevention" `
    -Text "Enable Strict Tracking Prevention" `
    -Description "Sets tracking prevention to the strictest level"
$y += 48

$chkEnableDNT = New-SettingCheckbox -Parent $tabPrivacy -Y $y -Tag "ConfigureDoNotTrack" `
    -Text "Enable Do Not Track Requests" `
    -Description "Sends Do Not Track header with browsing requests"
$y += 48

$chkDisableSendSiteInfo = New-SettingCheckbox -Parent $tabPrivacy -Y $y -Tag "SendSiteInfoToImproveServices" `
    -Text "Disable Send Site Info to Improve Services" `
    -Description "Stops sending browsing data to improve Microsoft services"
$y += 48

$chkDisableNetworkPrediction = New-SettingCheckbox -Parent $tabPrivacy -Y $y -Tag "NetworkPredictionOptions" `
    -Text "Disable Network Prediction / Preloading" `
    -Description "Prevents Edge from pre-fetching pages, which can leak browsing intent"
$y += 48

$chkDisableTypingInsights = New-SettingCheckbox -Parent $tabPrivacy -Y $y -Tag "TypingInsights" `
    -Text "Disable Typing Insights" `
    -Description "Prevents collection of typing patterns and behavior"
$y += 48

$chkDisableResolveNav = New-SettingCheckbox -Parent $tabPrivacy -Y $y -Tag "ResolveNavigationErrors" `
    -Text "Disable Navigation Error Resolution" `
    -Description "Prevents sending failed URLs to Microsoft for suggestions"

# ===== TAB 4: FEATURES AND INTEGRATIONS =====
$y = 15

$chkDisableSidebar = New-SettingCheckbox -Parent $tabFeatures -Y $y -Tag "HubsSidebarEnabled" `
    -Text "Disable Sidebar / Edge Bar" `
    -Description "Removes the sidebar panel from Edge"
$y += 48

$chkDisableCollections = New-SettingCheckbox -Parent $tabFeatures -Y $y -Tag "EdgeCollectionsEnabled" `
    -Text "Disable Collections Feature" `
    -Description "Disables the Collections feature for saving content"
$y += 48

$chkDisableShopping = New-SettingCheckbox -Parent $tabFeatures -Y $y -Tag "EdgeShoppingAssistantEnabled" `
    -Text "Disable Shopping Assistant" `
    -Description "Disables price comparison and coupon features"
$y += 48

$chkDisableSync = New-SettingCheckbox -Parent $tabFeatures -Y $y -Tag "SyncDisabled" `
    -Text "Disable Sync Functionality" `
    -Description "Prevents syncing of bookmarks, history, and settings across devices"
$y += 48

$chkDisableWallet = New-SettingCheckbox -Parent $tabFeatures -Y $y -Tag "EdgeWalletCheckoutEnabled" `
    -Text "Disable Edge Wallet / Payment Features" `
    -Description "Disables the built-in wallet and payment autofill"
$y += 48

$chkDisableFeedback = New-SettingCheckbox -Parent $tabFeatures -Y $y -Tag "UserFeedbackAllowed" `
    -Text "Disable Feedback Prompts" `
    -Description "Stops Edge from asking for feedback"
$y += 48

$chkDisableMiniMenu = New-SettingCheckbox -Parent $tabFeatures -Y $y -Tag "QuickSearchShowMiniMenu" `
    -Text "Disable Quick Search Mini Menu (on text selection)" `
    -Description "Disables the popup menu when selecting text"
$y += 48

$chkDisableWorkspaces = New-SettingCheckbox -Parent $tabFeatures -Y $y -Tag "Workspaces" `
    -Text "Disable Workspaces" `
    -Description "Disables the Workspaces collaborative feature"
$y += 48

$chkDisableGames = New-SettingCheckbox -Parent $tabFeatures -Y $y -Tag "Games" `
    -Text "Disable Built-in Games" `
    -Description "Disables Edge's built-in games feature"
$y += 48

$chkDisableRewards = New-SettingCheckbox -Parent $tabFeatures -Y $y -Tag "Rewards" `
    -Text "Disable Microsoft Rewards Integration" `
    -Description "Disables Microsoft Rewards prompts and integration"

# ===== TAB 5: SEARCH AND NEW TAB =====
$y = 15

$chkBlankHomepage = New-SettingCheckbox -Parent $tabSearch -Y $y -Tag "HomepageLocation" `
    -Text "Set Homepage to Blank (about:blank)" `
    -Description "Sets the homepage to a blank page instead of MSN"
$y += 48

$chkBlankNewTab = New-SettingCheckbox -Parent $tabSearch -Y $y -Tag "NewTabPageLocation" `
    -Text "Set New Tab Page to Blank" `
    -Description "Opens a blank page for new tabs instead of the news feed"
$y += 48

$chkDisableNewsFeed = New-SettingCheckbox -Parent $tabSearch -Y $y -Tag "NewTabPageContentEnabled" `
    -Text "Disable News Feed on New Tab Page" `
    -Description "Removes the news content from the new tab page"
$y += 48

$chkDisableQuickLinks = New-SettingCheckbox -Parent $tabSearch -Y $y -Tag "NewTabPageQuickLinksEnabled" `
    -Text "Disable Quick Links on New Tab Page" `
    -Description "Removes suggested sites from the new tab page"
$y += 48

$chkDisableSearchSuggestions = New-SettingCheckbox -Parent $tabSearch -Y $y -Tag "SearchSuggestEnabled" `
    -Text "Disable Search Suggestions" `
    -Description "Prevents sending keystrokes to search engine for suggestions"
$y += 48

$chkDisableAddressBarSuggestions = New-SettingCheckbox -Parent $tabSearch -Y $y -Tag "AddressBarMicrosoftSearchInBingProviderEnabled" `
    -Text "Disable Microsoft Search in Bing Suggestions" `
    -Description "Removes Microsoft Search suggestions from address bar"
$y += 48

$chkDisableSpotlight = New-SettingCheckbox -Parent $tabSearch -Y $y -Tag "Spotlight" `
    -Text "Disable Spotlight (Background Images with Info)" `
    -Description "Disables background images and related content on new tab"

# Custom homepage textbox
$lblCustomHomepage = New-Object System.Windows.Forms.Label
$lblCustomHomepage.Location = New-Object System.Drawing.Point(15, ($y + 55))
$lblCustomHomepage.Size = New-Object System.Drawing.Size(150, 22)
$lblCustomHomepage.Text = "Custom Homepage URL:"
$lblCustomHomepage.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$tabSearch.Controls.Add($lblCustomHomepage)

$txtCustomHomepage = New-Object System.Windows.Forms.TextBox
$txtCustomHomepage.Location = New-Object System.Drawing.Point(170, ($y + 53))
$txtCustomHomepage.Size = New-Object System.Drawing.Size(400, 24)
$txtCustomHomepage.Text = "about:blank"
$tabSearch.Controls.Add($txtCustomHomepage)

# ===== TAB 6: LANGUAGE AND WRITING =====
$y = 15

$chkDisableTranslate = New-SettingCheckbox -Parent $tabLanguage -Y $y -Tag "TranslateEnabled" `
    -Text "Disable Translation Features" `
    -Description "Disables automatic translation prompts and features"
$y += 48

$chkDisableTranslatePrompt = New-SettingCheckbox -Parent $tabLanguage -Y $y -Tag "TranslatePrompt" `
    -Text "Disable Translation Prompt/Popup" `
    -Description "Stops the translate this page popup from appearing"
$y += 48

$chkDisableWritingAssist = New-SettingCheckbox -Parent $tabLanguage -Y $y -Tag "WritingAssistant" `
    -Text "Disable Writing Assistant (Rewrite/Compose)" `
    -Description "Disables AI-powered writing assistance features"
$y += 48

$chkDisableEditorService = New-SettingCheckbox -Parent $tabLanguage -Y $y -Tag "EditorService" `
    -Text "Disable Microsoft Editor (Grammar/Spelling Service)" `
    -Description "Disables cloud-based grammar and spelling suggestions"
$y += 48

$chkDisableSpellcheck = New-SettingCheckbox -Parent $tabLanguage -Y $y -Tag "SpellcheckEnabled" `
    -Text "Disable Cloud Spellcheck Service" `
    -Description "Disables cloud-based spellchecking that sends typed text to Microsoft"
$y += 48

$chkDisableTextPrediction = New-SettingCheckbox -Parent $tabLanguage -Y $y -Tag "TextPrediction" `
    -Text "Disable Text Prediction" `
    -Description "Disables predictive text suggestions while typing"
$y += 48

$chkDisableAutoCorrect = New-SettingCheckbox -Parent $tabLanguage -Y $y -Tag "AutoCorrect" `
    -Text "Disable Auto-Correct" `
    -Description "Disables automatic correction of typos"
$y += 48

$chkDisableReadAloud = New-SettingCheckbox -Parent $tabLanguage -Y $y -Tag "ReadAloud" `
    -Text "Disable Read Aloud Feature" `
    -Description "Disables the text-to-speech read aloud feature"
$y += 48

$chkDisablePDFAnnotate = New-SettingCheckbox -Parent $tabLanguage -Y $y -Tag "PDFAnnotate" `
    -Text "Disable PDF AI Features" `
    -Description "Disables AI summarization and chat for PDFs"
$y += 48

$chkDisableImmersiveReader = New-SettingCheckbox -Parent $tabLanguage -Y $y -Tag "ImmersiveReader" `
    -Text "Disable Immersive Reader Enhancements" `
    -Description "Disables AI-powered reading mode enhancements"

# ===== BUTTONS =====
$buttonY = 653

$btnApply = New-Object System.Windows.Forms.Button
$btnApply.Location = New-Object System.Drawing.Point(20, $buttonY)
$btnApply.Size = New-Object System.Drawing.Size(130, 35)
$btnApply.Text = "Apply Settings"
$btnApply.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
$btnApply.ForeColor = [System.Drawing.Color]::White
$btnApply.FlatStyle = "Flat"
$btnApply.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($btnApply)

$btnSelectAll = New-Object System.Windows.Forms.Button
$btnSelectAll.Location = New-Object System.Drawing.Point(160, $buttonY)
$btnSelectAll.Size = New-Object System.Drawing.Size(100, 35)
$btnSelectAll.Text = "Select All"
$btnSelectAll.FlatStyle = "Flat"
$form.Controls.Add($btnSelectAll)

$btnDeselectAll = New-Object System.Windows.Forms.Button
$btnDeselectAll.Location = New-Object System.Drawing.Point(270, $buttonY)
$btnDeselectAll.Size = New-Object System.Drawing.Size(100, 35)
$btnDeselectAll.Text = "Deselect All"
$btnDeselectAll.FlatStyle = "Flat"
$form.Controls.Add($btnDeselectAll)

$btnReset = New-Object System.Windows.Forms.Button
$btnReset.Location = New-Object System.Drawing.Point(380, $buttonY)
$btnReset.Size = New-Object System.Drawing.Size(100, 35)
$btnReset.Text = "Reset All"
$btnReset.BackColor = [System.Drawing.Color]::FromArgb(200, 80, 80)
$btnReset.ForeColor = [System.Drawing.Color]::White
$btnReset.FlatStyle = "Flat"
$form.Controls.Add($btnReset)

$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Location = New-Object System.Drawing.Point(490, $buttonY)
$btnExport.Size = New-Object System.Drawing.Size(80, 35)
$btnExport.Text = "Export"
$btnExport.FlatStyle = "Flat"
$form.Controls.Add($btnExport)

$btnExit = New-Object System.Windows.Forms.Button
$btnExit.Location = New-Object System.Drawing.Point(580, $buttonY)
$btnExit.Size = New-Object System.Drawing.Size(80, 35)
$btnExit.Text = "Exit"
$btnExit.FlatStyle = "Flat"
$form.Controls.Add($btnExit)

# Status label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Location = New-Object System.Drawing.Point(20, 695)
$statusLabel.Size = New-Object System.Drawing.Size(640, 40)
$statusLabel.Text = "Ready. Select options and click Apply Settings. Close Edge before applying."
$statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
$form.Controls.Add($statusLabel)

# ===== EVENT HANDLERS =====

function Get-AllCheckboxes {
    $checkboxes = @()
    foreach ($tab in $tabControl.TabPages) {
        foreach ($control in $tab.Controls) {
            if ($control -is [System.Windows.Forms.CheckBox]) {
                $checkboxes += $control
            }
        }
    }
    return $checkboxes
}

$btnSelectAll.Add_Click({
    foreach ($cb in (Get-AllCheckboxes)) {
        $cb.Checked = $true
    }
})

$btnDeselectAll.Add_Click({
    foreach ($cb in (Get-AllCheckboxes)) {
        $cb.Checked = $false
    }
})

# Apply Settings
$btnApply.Add_Click({
    $successCount = 0
    $errorCount = 0
    
    $statusLabel.Text = "Applying settings... Please ensure Edge is closed."
    $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 100, 200)
    $form.Refresh()
    
    # Registry policy mappings
    $policySettings = @{
        # Startup
        "HideFirstRunExperience" = @{ Checkbox = $chkHideFirstRun; Value = 1 }
        "ImportOnEachLaunch" = @{ Checkbox = $chkDisableImportOnLaunch; Value = 0 }
        "RestoreOnStartup" = @{ Checkbox = $chkRestoreOnStartup; Value = 5 }
        "BrowserSignin" = @{ Checkbox = $chkDisableSigninPrompt; Value = 0 }
        "DefaultBrowserSettingEnabled" = @{ Checkbox = $chkDisableDefaultBrowserPrompt; Value = 0 }
        "AutoImportAtFirstRun" = @{ Checkbox = $chkDisableAutoImport; Value = 4 }
        "PromotionalTabsEnabled" = @{ Checkbox = $chkDisableEdgeUpdate; Value = 0 }
        
        # Copilot and AI
        "HubsSidebarEnabled" = @{ Checkbox = $chkDisableCopilotSidebar; Value = 0 }
        "CopilotCDPPageContext" = @{ Checkbox = $chkDisableCopilotPageContext; Value = 0 }
        "DiscoverPageContextEnabled" = @{ Checkbox = $chkDisableBingChat; Value = 0 }
        "EdgeAssetDeliveryServiceEnabled" = @{ Checkbox = $chkDisableAIThemes; Value = 0 }
        "ShowAcrobatSubscriptionButton" = @{ Checkbox = $chkDisablePDFAnnotate; Value = 0 }
        
        # Privacy
        "MetricsReportingEnabled" = @{ Checkbox = $chkDisableTelemetry; Value = 0 }
        "DiagnosticData" = @{ Checkbox = $chkDisableDiagnostics; Value = 0 }
        "PersonalizationReportingEnabled" = @{ Checkbox = $chkDisablePersonalization; Value = 0 }
        "TrackingPrevention" = @{ Checkbox = $chkEnableTrackingPrevention; Value = 3 }
        "ConfigureDoNotTrack" = @{ Checkbox = $chkEnableDNT; Value = 1 }
        "SendSiteInfoToImproveServices" = @{ Checkbox = $chkDisableSendSiteInfo; Value = 0 }
        "NetworkPredictionOptions" = @{ Checkbox = $chkDisableNetworkPrediction; Value = 2 }
        "TypingInsightsEnabled" = @{ Checkbox = $chkDisableTypingInsights; Value = 0 }
        "ResolveNavigationErrorsUseWebService" = @{ Checkbox = $chkDisableResolveNav; Value = 0 }
        
        # Features
        "EdgeCollectionsEnabled" = @{ Checkbox = $chkDisableCollections; Value = 0 }
        "EdgeShoppingAssistantEnabled" = @{ Checkbox = $chkDisableShopping; Value = 0 }
        "SyncDisabled" = @{ Checkbox = $chkDisableSync; Value = 1 }
        "EdgeWalletCheckoutEnabled" = @{ Checkbox = $chkDisableWallet; Value = 0 }
        "UserFeedbackAllowed" = @{ Checkbox = $chkDisableFeedback; Value = 0 }
        "ConfigureSharePreviewType" = @{ Checkbox = $chkDisableMiniMenu; Value = 0 }
        "EdgeWorkspacesEnabled" = @{ Checkbox = $chkDisableWorkspaces; Value = 0 }
        "AllowGamesMenu" = @{ Checkbox = $chkDisableGames; Value = 0 }
        "ShowMicrosoftRewards" = @{ Checkbox = $chkDisableRewards; Value = 0 }
        
        # Search and New Tab
        "NewTabPageContentEnabled" = @{ Checkbox = $chkDisableNewsFeed; Value = 0 }
        "NewTabPageQuickLinksEnabled" = @{ Checkbox = $chkDisableQuickLinks; Value = 0 }
        "SearchSuggestEnabled" = @{ Checkbox = $chkDisableSearchSuggestions; Value = 0 }
        "AddressBarMicrosoftSearchInBingProviderEnabled" = @{ Checkbox = $chkDisableAddressBarSuggestions; Value = 0 }
        "NewTabPageAllowedBackgroundTypes" = @{ Checkbox = $chkDisableSpotlight; Value = 3 }
        
        # Language and Writing
        "TranslateEnabled" = @{ Checkbox = $chkDisableTranslate; Value = 0 }
        "ShowRecommendationsForTranslationsEnabled" = @{ Checkbox = $chkDisableTranslatePrompt; Value = 0 }
        "SpellcheckEnabled" = @{ Checkbox = $chkDisableSpellcheck; Value = 0 }
        "TextPredictionEnabled" = @{ Checkbox = $chkDisableTextPrediction; Value = 0 }
        "ImmersiveReaderGrammarToolsEnabled" = @{ Checkbox = $chkDisableImmersiveReader; Value = 0 }
    }
    
    # Apply registry policies
    foreach ($key in $policySettings.Keys) {
        $setting = $policySettings[$key]
        if ($setting.Checkbox.Checked) {
            if (Set-EdgePolicy -Name $key -Value $setting.Value) {
                $successCount++
            } else {
                $errorCount++
            }
        }
    }
    
    # Handle Copilot master disable (multiple keys)
    if ($chkDisableCopilot.Checked) {
        $copilotKeys = @(
            @{ Name = "CopilotPageContext"; Value = 0 },
            @{ Name = "CopilotCDPPageContext"; Value = 0 },
            @{ Name = "HubsSidebarEnabled"; Value = 0 },
            @{ Name = "DiscoverPageContextEnabled"; Value = 0 }
        )
        foreach ($ck in $copilotKeys) {
            if (Set-EdgePolicy -Name $ck.Name -Value $ck.Value) { $successCount++ } else { $errorCount++ }
        }
    }
    
    # Handle Compose/Writing Assistant
    if ($chkDisableCopilotCompose.Checked -or $chkDisableWritingAssist.Checked) {
        Set-EdgePolicy -Name "ComposeInlineEnabled" -Value 0 | Out-Null
        Set-EdgePolicy -Name "QuickSearchShowMiniMenu" -Value 0 | Out-Null
        $successCount++
    }
    
    # Handle Editor service
    if ($chkDisableEditorService.Checked) {
        Set-EdgePolicy -Name "SpellcheckEnabled" -Value 0 | Out-Null
        Set-EdgePolicy -Name "SpellcheckLanguage" -Value "" -Type "String" | Out-Null
        $successCount++
    }
    
    # Handle Homepage
    if ($chkBlankHomepage.Checked) {
        $homepage = if ($txtCustomHomepage.Text) { $txtCustomHomepage.Text } else { "about:blank" }
        if (Set-EdgePolicy -Name "HomepageLocation" -Value $homepage -Type "String") { $successCount++ } else { $errorCount++ }
        Set-EdgePolicy -Name "HomepageIsNewTabPage" -Value 0 | Out-Null
        Set-EdgePolicy -Name "ShowHomeButton" -Value 1 | Out-Null
    }
    
    # Handle New Tab Page
    if ($chkBlankNewTab.Checked) {
        if (Set-EdgePolicy -Name "NewTabPageLocation" -Value "about:blank" -Type "String") { $successCount++ } else { $errorCount++ }
    }
    
    # Handle RestoreOnStartup with URL
    if ($chkRestoreOnStartup.Checked) {
        $basePath = if ($isAdmin) { $EdgePolicyPathHKLM } else { $EdgePolicyPathHKCU }
        $startupPath = "$basePath\RestoreOnStartupURLs"
        if (Ensure-RegistryPath -Path $startupPath) {
            try {
                Set-ItemProperty -Path $startupPath -Name "1" -Value "about:blank" -Type "String" -Force
            } catch { }
        }
    }
    
    # Handle sidebar disable
    if ($chkDisableSidebar.Checked) {
        Set-EdgePolicy -Name "HubsSidebarEnabled" -Value 0 | Out-Null
        Set-EdgePolicy -Name "StandaloneHubsSidebarEnabled" -Value 0 | Out-Null
    }
    
    # ===== PROFILE SETTINGS =====
    $profileCount = 0
    $profilesToApply = @()
    
    if ($chkApplyToAllProfiles.Checked) {
        $profilesToApply = $profiles
    } elseif ($cboProfile.SelectedIndex -ge 0 -and $profiles.Count -gt 0) {
        $profilesToApply = @($profiles[$cboProfile.SelectedIndex])
    }
    
    foreach ($profile in $profilesToApply) {
        $profileSettings = @{}
        
        # Copilot/AI profile settings
        if ($chkDisableCopilot.Checked) {
            $profileSettings["browser.copilot_enabled"] = $false
            $profileSettings["edge_copilot.visible"] = $false
        }
        if ($chkDisableCopilotSidebar.Checked) {
            $profileSettings["browser.show_hub_apps_tower"] = $false
            $profileSettings["sidebar.show_on_startup"] = $false
        }
        if ($chkDisableCopilotPageContext.Checked) {
            $profileSettings["edge_copilot.page_context_enabled"] = $false
        }
        if ($chkDisableDesignerAI.Checked) {
            $profileSettings["edge_creator.enabled"] = $false
        }
        if ($chkDisableBingChat.Checked) {
            $profileSettings["edge_discover.visible"] = $false
        }
        if ($chkDisableMathSolver.Checked) {
            $profileSettings["math_solver.enabled"] = $false
        }
        if ($chkDisableDropAI.Checked) {
            $profileSettings["edge_drop.enabled"] = $false
        }
        
        # Translation settings
        if ($chkDisableTranslate.Checked -or $chkDisableTranslatePrompt.Checked) {
            $profileSettings["translate.enabled"] = $false
            $profileSettings["translate_page.enabled"] = $false
        }
        
        # Writing/Editor settings
        if ($chkDisableWritingAssist.Checked -or $chkDisableCopilotCompose.Checked) {
            $profileSettings["browser.enable_spellchecking"] = $false
            $profileSettings["edge_write.enabled"] = $false
        }
        if ($chkDisableEditorService.Checked -or $chkDisableSpellcheck.Checked) {
            $profileSettings["browser.enable_spellchecking"] = $false
            $profileSettings["spellcheck.use_spelling_service"] = $false
        }
        if ($chkDisableTextPrediction.Checked) {
            $profileSettings["browser.text_prediction_enabled"] = $false
        }
        if ($chkDisableAutoCorrect.Checked) {
            $profileSettings["browser.auto_correct_enabled"] = $false
        }
        if ($chkDisableReadAloud.Checked) {
            $profileSettings["edge_read_aloud.enabled"] = $false
        }
        
        # Privacy settings
        if ($chkDisableTelemetry.Checked) {
            $profileSettings["user_experience_metrics.reporting_enabled"] = $false
        }
        if ($chkDisablePersonalization.Checked) {
            $profileSettings["personalization.enabled"] = $false
        }
        
        # Features settings
        if ($chkDisableCollections.Checked) {
            $profileSettings["edge_collections.enabled"] = $false
        }
        if ($chkDisableShopping.Checked) {
            $profileSettings["edge_shopping.enabled"] = $false
        }
        if ($chkDisableWallet.Checked) {
            $profileSettings["edge_wallet.enabled"] = $false
        }
        
        # Search settings
        if ($chkDisableSearchSuggestions.Checked) {
            $profileSettings["search.suggest_enabled"] = $false
        }
        
        # Apply profile settings
        if ($profileSettings.Count -gt 0) {
            $applied = Apply-ProfileSettings -ProfilePath $profile.Path -Settings $profileSettings
            $profileCount += $applied
        }
    }
    
    # Update status
    $totalSuccess = $successCount + $profileCount
    if ($errorCount -eq 0 -and $totalSuccess -gt 0) {
        $statusLabel.Text = "Success! Applied $successCount policies + $profileCount profile settings. Restart Edge."
        $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 128, 0)
    } elseif ($totalSuccess -gt 0) {
        $statusLabel.Text = "Applied $totalSuccess settings with $errorCount errors. Run as Admin for full access."
        $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(200, 100, 0)
    } else {
        $statusLabel.Text = "No settings selected or all operations failed."
        $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(200, 0, 0)
    }
})

# Reset All Settings
$btnReset.Add_Click({
    $result = [System.Windows.Forms.MessageBox]::Show(
        "This will remove all Edge policy customizations.`n`nAre you sure?",
        "Confirm Reset",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    
    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        $statusLabel.Text = "Removing policies..."
        $form.Refresh()
        
        try {
            if ($isAdmin -and (Test-Path $EdgePolicyPathHKLM)) {
                Remove-Item -Path $EdgePolicyPathHKLM -Recurse -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path $EdgePolicyPathHKCU) {
                Remove-Item -Path $EdgePolicyPathHKCU -Recurse -Force -ErrorAction SilentlyContinue
            }
            
            foreach ($cb in (Get-AllCheckboxes)) {
                $cb.Checked = $false
            }
            
            $statusLabel.Text = "All policies removed. Restart Edge to restore default behavior."
            $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 128, 0)
        } catch {
            $statusLabel.Text = "Error resetting policies: " + $_.Exception.Message
            $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(200, 0, 0)
        }
    }
})

# Export button
$btnExport.Add_Click({
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "Registry File (*.reg)|*.reg"
    $saveDialog.FileName = "EdgePolicies.reg"
    
    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $regContent = "Windows Registry Editor Version 5.00`r`n`r`n"
            $regContent += "[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge]`r`n"
            
            if (Test-Path $EdgePolicyPathHKCU) {
                $props = Get-ItemProperty -Path $EdgePolicyPathHKCU
                foreach ($prop in $props.PSObject.Properties) {
                    if ($prop.Name -notmatch '^PS') {
                        if ($prop.Value -is [int]) {
                            $regContent += "`"$($prop.Name)`"=dword:$($prop.Value.ToString('x8'))`r`n"
                        } elseif ($prop.Value -is [string]) {
                            $escaped = $prop.Value -replace '\\', '\\' -replace '"', '\"'
                            $regContent += "`"$($prop.Name)`"=`"$escaped`"`r`n"
                        }
                    }
                }
            }
            
            [System.IO.File]::WriteAllText($saveDialog.FileName, $regContent, [System.Text.Encoding]::Unicode)
            $statusLabel.Text = "Exported to: $($saveDialog.FileName)"
            $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 128, 0)
        } catch {
            $statusLabel.Text = "Export failed: " + $_.Exception.Message
            $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(200, 0, 0)
        }
    }
})

$btnExit.Add_Click({
    $form.Close()
})

# Load current settings on startup
function Load-CurrentSettings {
    $checkStates = @{
        $chkHideFirstRun = (Get-EdgePolicy "HideFirstRunExperience") -eq 1
        $chkDisableTelemetry = (Get-EdgePolicy "MetricsReportingEnabled") -eq 0
        $chkDisablePersonalization = (Get-EdgePolicy "PersonalizationReportingEnabled") -eq 0
        $chkDisableSync = (Get-EdgePolicy "SyncDisabled") -eq 1
        $chkDisableShopping = (Get-EdgePolicy "EdgeShoppingAssistantEnabled") -eq 0
        $chkBlankHomepage = (Get-EdgePolicy "HomepageLocation") -eq "about:blank"
        $chkBlankNewTab = (Get-EdgePolicy "NewTabPageLocation") -eq "about:blank"
        $chkDisableSidebar = (Get-EdgePolicy "HubsSidebarEnabled") -eq 0
        $chkDisableTranslate = (Get-EdgePolicy "TranslateEnabled") -eq 0
    }
    
    foreach ($cb in $checkStates.Keys) {
        if ($checkStates[$cb]) {
            $cb.Checked = $true
        }
    }
}

Load-CurrentSettings

[void]$form.ShowDialog()
