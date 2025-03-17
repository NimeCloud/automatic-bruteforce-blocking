# Automatic Firewall Whitelisting and Blacklisting Script

This PowerShell script automatically manages firewall rules to whitelist or blacklist IP addresses based on successful and failed login attempts. It scans Windows Security and Application logs for specific events and updates firewall rules accordingly.

## Features

- **Whitelisting**: Automatically adds IP addresses with successful login attempts to a whitelist.
- **Blacklisting**: Automatically blocks IP addresses with multiple failed login attempts.
- **Log Scanning**: Scans Windows Security and Application logs for failed and successful login attempts.
- **Log Management**: Clears old logs based on configurable settings.
- **Customizable Settings**: Allows configuration of thresholds, log file paths, and time ranges.

## Prerequisites

- **PowerShell**: The script requires PowerShell 5.1 or later.
- **Administrator Privileges**: The script must be run with administrator privileges to manage firewall rules and access event logs.
- **Windows Firewall**: The script uses the Windows Firewall to manage rules.

## Installation

1. **Download the Script**:
   - Clone this repository or download the `automatic-whitelisting-blacklisting.ps1` script.

2. **Run the Script**:
   - Open PowerShell as an administrator.
   - Navigate to the directory where the script is located.
   - Run the script:
     ```powershell
     .\automatic-whitelisting-blacklisting.ps1
     ```

## Configuration

The script uses a settings hashtable (`$settings`) to configure its behavior. You can modify the following settings:

```powershell
$settings = @{
    # Rule names
    WhitelistRuleName = "_WhitelistIPs"
    BlockRuleName = "_BlacklistIPs"

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
```

---
## 🔑 Key Settings

- **WhitelistRuleName**: Name of the firewall rule for whitelisted IPs.  
- **BlockRuleName**: Name of the firewall rule for blacklisted IPs.  
- **BlockedIPLogFile**: Log file for blacklisted IPs.  
- **WhitelistRemovalLogFile**: Log file for IPs removed from the whitelist.  
- **WhitelistAdditionLogFile**: Log file for IPs added to the whitelist.  
- **LogScanRangeHours**: Time range (in hours) for scanning logs.  
- **NonWhitelistFailedAttempts**: Number of failed attempts to block non-whitelisted IPs.  
- **WhitelistFailedAttempts**: Number of failed attempts to block whitelisted IPs.  
- **ClearOldLogs**: Time range (in hours) for clearing old logs.  

---

## ⚙️ How It Works

### 🔍 Log Scanning
- The script scans Windows Security logs:
  - **Event ID 4625** for failed logins  
  - **Event ID 4624** for successful logins  
- It also scans Application logs:
  - **Event ID 17836** for failed SQL logins  
- It collects IP addresses from these logs and processes them based on the configured thresholds.  

### ✅ Whitelisting
- IP addresses with successful login attempts are added to the **whitelist**.  
- The whitelist is managed by a firewall rule that **allows** traffic from these IPs.  

### ⛔ Blacklisting
- IP addresses with multiple failed login attempts are added to the **blacklist**.  
- The blacklist is managed by a firewall rule that **blocks** traffic from these IPs.  

### 📝 Log Management
- The script can clear old logs based on the configured settings.  

---

## 📂 Log Files

- **Blacklisted IPs**: Logs IP addresses added to the blacklist (`_log-blacklist-added.txt`).  
- **Whitelist Additions**: Logs IP addresses added to the whitelist (`_log-whitelist-added.txt`).  
- **Whitelist Removals**: Logs IP addresses removed from the whitelist (`_log-whitelist-removed.txt`).  

---

## 🛠 Troubleshooting

- **No Events Found**: Ensure that the event logs (Security and Application) contain the relevant events (**4624, 4625, 17836**).  
- **Firewall Rule Not Applied**: Ensure the script is run **with administrator privileges** and that the firewall rules are correctly configured.  
- **Invalid IP Addresses**: The script skips invalid IP addresses. Ensure the logs contain valid IP addresses.  

---

## 🤝 Contributing

Contributions are welcome! Please open an **issue** or submit a **pull request** for any improvements or bug fixes.  

---

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
