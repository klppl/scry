# SCRY 1.0

SCRY is a PowerShell tool for network discovery. The tool scans local subnets. It identifies connected devices. It queries public network routing data.

### Collected Device Data

- IPv4 address
- MAC address
- Hardware manufacturer
- Hostname
- Open TCP ports
- Device category

### Collected External Network Data

- Public WAN IP address
- ISP name and ASN
- Geolocation and timezone

---

## Interactive Menu Interface

Run `.\scry.ps1` or `scan.bat` without parameters to start the menu interface:

```text
=================================================================
 [SCRY]
=================================================================
 Target Interface : Ethernet
 Target Subnet    : 192.168.86.0/24 (254 Hosts)
 Default Gateway  : 192.168.86.1
 This PC Local IP : 192.168.86.249
 Public / WAN IP  : 95.196.109.76 (Telia Company AB - Sweden)
-----------------------------------------------------------------
 [1] Start Scan  (Standard: Devices, Hostnames, Top Ports) [Default]
 [2] Deep Scan   (Extended: 25+ Ports & Web Banners)
 [3] Quick Scan  (Fast Discovery: ARP + Ping + DNS)
 [4] Switch Adapter / Custom Subnet
 [0] Exit
=================================================================
 Select an option [0-4] (Press ENTER for [1]):
```

### Verified Header & Menu Options

- **Header Check**: The header check reads the active network adapter, local IP address, gateway IP address, and internet connection. It prompts for a DHCP renewal if no valid IP address exists.
- **`[1]` Start Scan (Default)**: This option scans the subnet with ARP, ICMP, DNS, NetBIOS, diagnostic ports, and HTTP headers. It saves output to a new report folder. Press ENTER to run this scan.
- **`[2]` Deep Scan**: This option scans 25 service ports. It captures SSL and HTTP banners.
- **`[3]` Quick Scan**: This option scans the subnet with ARP, ICMP ping, and DNS only.
- **`[4]` Switch Adapter / Custom Subnet**: This option selects a different network adapter. You can specify a target IP range or CIDR subnet. You can also trigger a DHCP renewal.
- **`[0]` Exit**: This option closes the script.

---

## Key Features

- **Public IP and Geolocation**:
  - The tool queries `ip-api.com`, `ipinfo.io`, and `api.ipify.org`.
  - It resolves the public IP address, hostname, ISP, ASN, country, city, and coordinates.
  - The scan continues if external lookups fail or when the system is offline.
- **Link and DHCP Verification**:
  - The tool checks for a valid local IPv4 address and default gateway before scanning.
  - It flushes DNS and requests a new DHCP lease when Windows lacks a valid IP address.
- **Report Generation**:
  - The tool writes scan results to `Reports/YYYY-MM-DD_HH-mm-ss/`.
  - It creates five output files:
    - `report.html` (Interactive dashboard with search filter and WAN data)
    - `devices.csv` (Device list in CSV format)
    - `devices.json` (Device list in JSON format)
    - `network_info.json` (Network and WAN metadata in JSON format)
    - `summary.txt` (Scan summary in plain text format)
- **Interface and Subnet Detection**:
  - The tool detects the active network adapter, local IP address, default gateway, and subnet mask.
- **Asynchronous Scanner Engine**:
  - The engine uses Win32 `SendARP` API calls and .NET socket tasks for concurrent scanning.
- **Layer 2 ARP Discovery**:
  - The tool finds active devices through ARP when firewalls drop ICMP ping packets.
- **Vendor Identification**:
  - The tool resolves device manufacturers with an embedded IEEE MAC OUI database.
- **Randomized MAC Detection**:
  - The tool flags private and randomized MAC addresses from mobile and desktop operating systems.
- **Host Fingerprinting**:
  - **Reverse DNS**: The tool resolves hostnames through local DNS servers.
  - **NetBIOS (UDP 137)**: The tool reads Windows computer names and workgroups without authentication.
  - **Diagnostic Port Probing**: The tool tests common management ports such as SSH, Telnet, HTTP, HTTPS, SMB, and RDP.
  - **Web Title Grabber**: The tool captures web server headers and HTML `<title>` tags.
- **Device Classification**:
  - The tool assigns device categories such as Gateway, Windows PC, Printer, NAS, IoT, Smart TV, or Virtual Machine.

---

## Quick Start

### 1. Launch Interactive Menu

Run this command in PowerShell:
```powershell
.\scry.ps1
```

Or run the batch file:
```cmd
scan.bat
```

### 2. Command Line Examples (Direct / Batch Mode)

Pass command-line arguments to run scans without the interactive menu:

#### Run a deep scan and open the HTML report:
```powershell
.\scry.ps1 -DeepScan -OpenReport
```

#### Flush DNS and renew the DHCP lease before scanning:
```powershell
.\scry.ps1 -RenewDhcp
```

#### Run a quick scan with ARP, ping, and DNS only:
```powershell
.\scry.ps1 -QuickScan
```

#### Scan an offline network and skip the WAN lookup:
```powershell
.\scry.ps1 -SkipWanCheck
```

#### Scan a specific subnet or IP range:
```powershell
# CIDR Subnet
.\scry.ps1 -Subnet "192.168.1.0/24"

# IP Range
.\scry.ps1 -Subnet "192.168.1.1-50"
```

#### Filter scan objects in a PowerShell pipeline:
```powershell
$devices = .\scry.ps1 -NoReport -Quiet
$devices | Where-Object DeviceType -match 'Printer' | Format-Table IP, MAC, Vendor, HostName
```

---

## Parameters Reference

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-Menu` | Switch | `False` | Opens the interactive menu when other parameters are present. |
| `-NonInteractive` | Switch | `False` | Runs the scan directly without displaying the menu. |
| `-SkipWanCheck` | Switch | `False` | Skips the public IP and geolocation lookup. |
| `-WanTimeoutSec` | Int | `3` | Sets the timeout in seconds for the WAN lookup. |
| `-RenewDhcp` | Switch | `False` | Flushes DNS and requests a new DHCP lease before scanning. |
| `-SkipDhcpCheck` | Switch | `False` | Skips the network link and DHCP verification step. |
| `-DhcpTimeoutSec` | Int | `12` | Sets the timeout in seconds for DHCP lease assignment. |
| `-ReportDir` | String | `Reports` | Sets the parent directory for report folders. |
| `-NoReport` | Switch | `False` | Disables generation of report files. |
| `-OpenReport` | Switch | `False` | Opens report.html in the default web browser after scanning. |
| `-Subnet` | String | Auto-detected | Specifies a target CIDR subnet, IP range, or single IP address. |
| `-InterfaceAlias` | String | Auto-detected | Specifies the name of the network interface to scan. |
| `-AllInterfaces` | Switch | `False` | Scans all active network interfaces in sequence. |
| `-QuickScan` | Switch | `False` | Skips port scans and HTTP banner collection. |
| `-DeepScan` | Switch | `False` | Scans 25 service ports, HTTP titles, and SSL certificates. |
| `-ShowGrid` | Switch | `False` | Shows scan results in a PowerShell Out-GridView window. |
| `-Quiet` | Switch | `False` | Suppresses console output and returns raw objects to the pipeline. |

---

## Report Folder Structure

Each scan creates a timestamped folder with report files:

```text
Reports/
├── 2026-08-19_08-22-54/
│   ├── report.html       (Interactive dashboard with search filter and WAN data)
│   ├── devices.csv       (Device list in CSV format)
│   ├── devices.json      (Device list in JSON format)
│   ├── network_info.json (Network and WAN metadata in JSON format)
│   └── summary.txt       (Scan summary in plain text format)
└── 2026-08-19_08-23-03/
    ├── report.html
    ├── devices.csv
    ├── devices.json
    ├── network_info.json
    └── summary.txt
```
