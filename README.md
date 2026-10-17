# SCRY 1.0

[![License: Lagom](https://img.shields.io/badge/license-lagom-9E2B25)](https://klppl.github.io/lagom-license/)

SCRY is a PowerShell tool for network discovery and wireless reconnaissance. The tool scans local subnets, surveys nearby Wi-Fi networks and access points, identifies connected devices, and queries public network routing data.

### Collected Device Data

- IPv4 address
- MAC address
- Hardware manufacturer
- Hostname
- Open TCP ports
- Device category

### Collected Wi-Fi & Wireless Data

- Connected Wi-Fi adapter state, SSID, BSSID, and link speeds (Rx / Tx Mbps)
- Nearby visible SSIDs (including hidden networks)
- Access point BSSID (MAC address) and hardware vendor
- Signal quality percentage and ASCII signal strength bars
- Radio standard (802.11ax, 802.11ac, 802.11n, etc.)
- Channel frequency and band (2.4 GHz, 5 GHz, 6 GHz)
- Security authentication (WPA3-Personal, WPA2-Personal, Open) and cipher

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
 Target Interface : Wi-Fi (Connected: "5G_Router_B517AF" | 78% Signal)
 Target Subnet    : 192.168.32.0/24 (254 Hosts)
 Default Gateway  : 192.168.32.1
 This PC Local IP : 192.168.32.44
 Public / WAN IP  : 95.196.109.76 (Telia Company AB - Sweden)
-----------------------------------------------------------------
 [1] Start Scan   (Standard: Devices, Hostnames, Top Ports) [Default]
 [2] Deep Scan    (Comprehensive: 25+ Ports & Web Banners)
 [3] Quick Scan   (Fast Discovery: ARP + Ping + DNS)
 [4] Switch Adapter / Custom Subnet
 [5] Wi-Fi Survey (Nearby SSIDs, Channels & Signal Strengths)
 [0] Exit
=================================================================
 Select an option [0-5] (Press ENTER for [1]):
```

### Verified Header & Menu Options

- **Header Check**: The header check reads the active network adapter (including connected SSID and signal strength), local IP address, gateway IP address, and internet connection. It prompts for a DHCP renewal if no valid IP address exists.
- **`[1]` Start Scan (Default)**: Scans the subnet with ARP, ICMP, DNS, NetBIOS, diagnostic ports, and HTTP headers. Automatically includes a Wi-Fi snapshot and nearby SSIDs in the reports. Press ENTER to run this scan.
- **`[2]` Deep Scan**: Scans 25 service ports and captures SSL and HTTP banners across the subnet.
- **`[3]` Quick Scan**: Scans the subnet with ARP, ICMP ping, and DNS only.
- **`[4]` Switch Adapter / Custom Subnet**: Selects a different network adapter, specifies a target IP range or CIDR subnet, or triggers DHCP renewal.
- **`[5]` Wi-Fi Survey**: Performs an instant wireless survey of all nearby SSIDs and access points around the host without scanning IP subnets. Displays a formatted console table with live options to Rescan (`[R]`), Export to CSV/JSON (`[E]`), or return to Menu (`[M]`).
- **`[0]` Exit**: Closes the script.

---

## Key Features

- **Wi-Fi & Wireless Environment Survey**:
  - Automatically captures the connected Wi-Fi interface details (SSID, BSSID, AP vendor, link rates, channel, band, security) and nearby access points during subnet scans.
  - Interactive standalone Wi-Fi survey menu `[5]` for instant wireless spectrum reconnaissance without IP scanning.
  - Computes exact channels, frequency bands (2.4 GHz, 5 GHz, 6 GHz), and resolves access point hardware manufacturers.
  - Generates HTML interactive tables with signal meters and dedicated CSV / JSON export files (`wifi_survey.json`).
- **Public IP and Geolocation**:
  - The tool queries `ip-api.com`, `ipinfo.io`, and `api.ipify.org`.
  - Resolves the public IP address, hostname, ISP, ASN, country, city, and coordinates.
  - The scan continues seamlessly if external lookups fail or when the system is offline.
- **Link and DHCP Verification**:
  - Checks for a valid local IPv4 address and default gateway before scanning.
  - Flushes DNS and requests a new DHCP lease when Windows lacks a valid IP address.
- **Report Generation**:
  - Writes scan results to `Reports/YYYY-MM-DD_HH-mm-ss/`.
  - Creates comprehensive output files:
    - `report.html` (Interactive dashboard with search filter, WAN intelligence, and Wi-Fi survey table)
    - `devices.csv` (Device list in CSV format)
    - `devices.json` (Device list in JSON format)
    - `wifi_survey.json` (Nearby Wi-Fi networks and access points in JSON format)
    - `network_info.json` (Subnet, Wi-Fi context, and WAN metadata in JSON format)
    - `summary.txt` (Scan summary in plain text format)
- **Interface and Subnet Detection**:
  - Automatically detects the active network adapter, local IP address, default gateway, and subnet mask.
- **Asynchronous Scanner Engine**:
  - The engine uses Win32 `SendARP` API calls and .NET socket tasks for concurrent scanning.
- **Layer 2 ARP Discovery**:
  - Finds active devices through ARP when firewalls drop ICMP ping packets.
- **Vendor Identification & Extensible OUI Database (`oui.txt`)**:
  - Resolves device manufacturers through an external, customizable IEEE MAC OUI database file ([`oui.txt`](file:///C:/dropbox/_github/scry/oui.txt)) containing 1,100+ hardware vendors (routers, PCs, IoT, printers, gaming consoles, smart TVs, and access points).
  - Easily extend the database by adding new lines to `oui.txt` (supports `OUI\tVendor`, `00:11:22 = Vendor`, `00-11-22,Vendor`, or comments `#`).
  - Includes a built-in core fallback table if `oui.txt` is missing.
  - Optional `-OnlineLookup` parameter queries the maclookup API for unlisted vendor prefixes.
- **Randomized MAC Detection**:
  - Flags private and randomized MAC addresses from mobile and desktop operating systems.
- **Host Fingerprinting**:
  - **Reverse DNS**: Resolves hostnames through local DNS servers.
  - **NetBIOS (UDP 137)**: Reads Windows computer names and workgroups without authentication.
  - **Diagnostic Port Probing**: Tests common management ports such as SSH, Telnet, HTTP, HTTPS, SMB, and RDP.
  - **Web Title Grabber**: Captures web server headers and HTML `<title>` tags.
- **Device Classification**:
  - Assigns device categories such as Gateway, Windows PC, Printer, NAS, IoT, Smart TV, or Virtual Machine.

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

#### Run Wi-Fi survey only (without IP scan):
```powershell
.\scry.ps1 -WifiOnly
```

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

#### Scan an offline network and skip WAN & Wi-Fi lookups:
```powershell
.\scry.ps1 -SkipWanCheck -SkipWifi
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
| `-WifiOnly` | Switch | `False` | Surveys nearby Wi-Fi networks (SSIDs, BSSIDs, signal, channels) without scanning IP subnets. |
| `-SkipWifi` | Switch | `False` | Skips Wi-Fi discovery and nearby SSID survey during subnet scans. |
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
├── 2026-08-24_13-33-17/
│   ├── report.html       (Interactive dashboard with search filter, WAN intelligence, and Wi-Fi survey table)
│   ├── devices.csv       (Device list in CSV format)
│   ├── devices.json      (Device list in JSON format)
│   ├── wifi_survey.json  (Nearby Wi-Fi networks and access points in JSON format)
│   ├── network_info.json (Subnet, Wi-Fi context, and WAN metadata in JSON format)
│   └── summary.txt       (Scan summary in plain text format)
└── Surveys/
    └── 2026-08-24_11-25-30/
        ├── wifi_survey.csv
        └── wifi_survey.json
```
