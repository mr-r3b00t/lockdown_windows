# 🔒 Lockdown Windows

A collection of PowerShell scripts designed to harden Windows devices by configuring security features such as Windows Defender, Windows Firewall, network settings, and Windows Defender Application Control (WDAC).

## 📋 Overview

This repository provides security hardening scripts for Windows environments. Each script focuses on a specific security domain, allowing administrators to apply targeted hardening measures based on their needs.

## 📁 Scripts

| Script | Description |
|--------|-------------|
| `lockdown_defender.ps1` | Configures and hardens Windows Defender settings for enhanced protection |
| `lockdown_firewall.ps1` | Applies restrictive Windows Firewall rules and policies |
| `lockdown_firewall_gui.ps1` | GUI-based version for configuring Windows Firewall settings |
| `lockdown_network.ps1` | Hardens network configuration and disables insecure protocols |
| `lockdown_wdac.ps1` | Implements Windows Defender Application Control policies |

## 🚀 Usage

### Prerequisites

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or later
- Administrator privileges

### Running the Scripts

1. **Open PowerShell as Administrator**

2. **Set Execution Policy** (if needed):
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
   ```

3. **Navigate to the script directory**:
   ```powershell
   cd path\to\lockdown_windows
   ```

4. **Run the desired script**:
   ```powershell
   .\lockdown_defender.ps1
   .\lockdown_firewall.ps1
   .\lockdown_network.ps1
   .\lockdown_wdac.ps1
   ```

   Or use the GUI version for firewall configuration:
   ```powershell
   .\lockdown_firewall_gui.ps1
   ```

## 🛡️ Script Details

### lockdown_defender.ps1
Enhances Windows Defender configuration by enabling advanced protection features such as:
- Real-time protection
- Cloud-delivered protection
- Automatic sample submission settings
- Attack Surface Reduction (ASR) rules
- Controlled folder access
- Network protection

### lockdown_firewall.ps1
Configures Windows Firewall with restrictive policies:
- Enables firewall for all profiles (Domain, Private, Public)
- Blocks inbound connections by default
- Configures logging for dropped packets
- Creates rules for essential services only

### lockdown_firewall_gui.ps1
Provides a graphical interface for firewall configuration, making it easier to:
- View and modify firewall rules
- Enable/disable specific profiles
- Configure exceptions interactively

### lockdown_network.ps1
Applies network-level hardening:
- Disables legacy protocols (SMBv1, NetBIOS, LLMNR)
- Configures secure DNS settings
- Hardens TCP/IP stack settings
- Disables unnecessary network services

### lockdown_wdac.ps1
Implements Windows Defender Application Control:
- Creates and deploys WDAC policies
- Restricts application execution to trusted software
- Configures code integrity policies

## ⚠️ Important Warnings

1. **Test in a Lab Environment First**: Always test these scripts in a non-production environment before deploying to production systems.

2. **Create System Restore Points**: Before running any hardening script, create a system restore point:
   ```powershell
   Checkpoint-Computer -Description "Before Lockdown Scripts" -RestorePointType "MODIFY_SETTINGS"
   ```

3. **Review Script Contents**: Review each script's contents and understand the changes being made before execution.

4. **Backup Current Configuration**: Export your current settings before applying changes.

5. **Potential Application Impact**: Security hardening may break functionality for some applications. Ensure critical applications are tested after applying changes.

## 🔄 Reverting Changes

If you need to undo changes made by these scripts:

1. Use System Restore to revert to a previous restore point
2. Manually reverse specific settings through Group Policy or PowerShell
3. Use the Windows Security app to reset settings to defaults

## 📖 References

- [Microsoft Windows Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines)
- [Windows Defender Application Control](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control)
- [Windows Firewall with Advanced Security](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/windows-firewall-with-advanced-security)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## 📄 License

This project is provided as-is for educational and security hardening purposes.

## ⚡ Disclaimer

These scripts modify system security settings. The author is not responsible for any issues that may arise from using these scripts. Always test thoroughly and use at your own risk.

---

**Author:** [mr-r3b00t](https://github.com/mr-r3b00t)
