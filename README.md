<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/brittaparks/Threat-Hunting-Scenario/blob/main/Threat-Hunting-Scenario-Tor-Event-Creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for any string with the word “tor” and discovered what appears to be the user employee having downloaded a tor installer, which resulted in many tor related files being copied to the desktop and the creation of a file called `tor-shopping-list` to the desktop.  These events began at `Apr 8, 2025 1:32:23 PM`.  The shopping list was created at `2:00:43 PM`.  

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "britt-windows10"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "cyber"
| where Timestamp >= datetime(2025-04-08T17:32:23.9568599Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, SHA256, AccountName=InitiatingProcessAccountName, FileName, FolderPath
```

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any process command line containing the string `tor-browser-windows-x86_64-portable-14.0.9.exe`.  Based on the results returned, at `Apr 8, 2025 1:34:59 PM`, the employee ran a command to silently install a tor browser.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "britt-windows10"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.9.exe"
| project Timestamp, DeviceName, AccountName,ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication the user actually opened the tor browser.  There was evidence the employee did open the browser at `Apr 8, 2025 1:35:46 PM`.  There were several other instances of firefox as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "britt-windows10"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName,ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network ConnectionsSearched the DeviceNetworkEvents table for any indication the Tor browser was used to establish a connection using any of the known Tor ports.  At `Apr 8, 2025 1:37:50 PM`, an employee on the device successfully established a connection to the Remote IP address `192.121.44.26` on port `9001`.  The connection was initiated by the process `tor.exe`, located in the folder `c:\users\cyber\desktop\tor browser\browser\torbrowser\tor\tor.exe`.  There were a few other connections to sites over the Tor browser made around this timeframe.  

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "britt-windows10"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("firefox.exe", "tor.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
```

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp** - `Apr 8, 2025 1:32:23 PM`
- **Event** - User “cyber” downloaded file named “tor-browser-windows-x86_64-portable-14.0.9.exe” to “downloads” folder.
- **Action** - File download detected
- **File Path** - `C:\Users\Cyber\Downloads\tor-browser-windows-x86_64-portable-14.0.9.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp** - `Apr 8, 2025 1:34:59 PM`
- **Event**  - User “cyber” executed the file `tor-browser-windows-x86_64-portable-14.0.9.exe` in Silent Mode
- **Action** - Process creation detected
- **Command** - `tor-browser-windows-x86_64-portable-14.0.9.exe  /S`
- **File Path** - `C:\Users\Cyber\Downloads\tor-browser-windows-x86_64-portable-14.0.9.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp** - `Apr 8, 2025 1:35:52 PM`
- **Event** - User “cyber” opened the Tor browser.  Subsequent processes associated with the Tor browser, such as `firefox.exe` and `tor.exe` were also created, indicating that the browser launched successfully.
- **Action** - Process creation of Tor-browser related executables detected.
- **File Path** - `C:\Users\Cyber\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp** - `Apr 8, 2025 1:38:02 PM`
- **Event** - A network connection to IP `192.121.44.26` on Port `9001` was established using `tor.exe`, confirming Tor browser network activity. 
- **Action** - Connection success
- **Process** - tor.exe
- **File Path** - `C:\Users\Cyber\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps** - 
`Apr 8, 2025 1:37:52 PM` Connected to `88.198.87.37` on Port `443`
`Apr 8, 2025 1:37:52 PM` Connected to `104.244.79.75` on Port `443`
`Apr 8, 2025 1:38:14 PM` Local Connection to `127.0.0.1` on Port `9150`
- **Event** - Additional network connections to the Tor network were established, indicating ongoing activity through the Tor browser.
- **Action** - Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp** - `Apr 8, 2025 2:00:43 PM`
- **Event** - User “cyber” created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes of their Tor browsing activity. 
- **Action** - File creation detected.
- **File Path** - `C:\Users\Cyber\Documents\tor-shopping-list.txt`

---

## Summary

The user “cyber” on the endpoint device “britt-windows10” initiated and completed the installation of the Tor browser.  They proceeded to launch the browser, establish connections within the Tor network and created various files related to Tor on their desktop including a file named `tor-shopping-list`.  This sequence of activities indicates the user actively installed, configured and used the Tor browser, likely for anonymous browsing purposes with possible documentation in the form of the shopping list document.  

---

## Response Taken

TOR usage was confirmed on endpoint `britt-windows10`. The device was isolated and the user's direct manager was notified.

---
