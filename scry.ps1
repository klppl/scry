<#
.SYNOPSIS
    SCRY - Network Discovery and Device Identification Tool.

.DESCRIPTION
    SCRY is a PowerShell tool for local network discovery and device mapping.
    The tool discovers connected devices and collects network configuration data.

    Functions:
    - Queries public WAN IP address, ISP, ASN, and geographic location.
    - Provides an interactive console menu to inspect network state and run scans.
    - Detects active network adapters, local IP addresses, default gateways, and subnets.
    - Verifies network link status and requests DHCP lease renewals.
    - Scans hosts concurrently using Win32 SendARP and .NET asynchronous sockets.
    - Resolves IP addresses, MAC addresses, and ping latency.
    - Identifies hardware vendors using an embedded IEEE MAC OUI database.
    - Flags randomized and private MAC addresses.
    - Resolves hostnames with reverse DNS and NetBIOS UDP port 137 queries.
    - Probes standard management ports: SSH, Telnet, DNS, HTTP, HTTPS, SMB, and RDP.
    - Captures HTTP server banners and web page titles.
    - Classifies devices: Router, PC, Printer, NAS, IoT, Smart TV, or Virtual Machine.
    - Surveys nearby Wi-Fi SSIDs, BSSIDs, signal strengths, channels, bands, and security encryption.
    - Saves scan output in HTML, CSV, JSON, and plain text formats.

.PARAMETER Subnet
    Target subnet in CIDR notation (e.g. "192.168.1.0/24"), IP range ("192.168.1.1-50"),
    or single IP ("192.168.1.1"). If omitted, the tool detects the active subnet.

.PARAMETER InterfaceAlias
    Name of the network interface to scan (e.g. "Wi-Fi", "Ethernet").

.PARAMETER AllInterfaces
    Scans all active network interfaces sequentially.

.PARAMETER ReportDir
    Root directory for report output folders. Default: "Reports".

.PARAMETER NoReport
    Disables creation of report files.

.PARAMETER OpenReport
    Opens the generated HTML report in the default web browser after scanning.

.PARAMETER RenewDhcp
    Flushes DNS and requests a new DHCP lease before scanning.

.PARAMETER SkipDhcpCheck
    Skips the network link and DHCP verification step.

.PARAMETER DhcpTimeoutSec
    Maximum seconds to wait for DHCP IP assignment. Default: 12.

.PARAMETER SkipWanCheck
    Skips the external public IP and geolocation lookup.

.PARAMETER WanTimeoutSec
    Maximum seconds to wait for the WAN IP lookup. Default: 3.

.PARAMETER QuickScan
    Runs ARP, ICMP ping, and reverse DNS only. Skips port scans and HTTP title grabs.

.PARAMETER DeepScan
    Scans 25 service ports, HTTP titles, and SSL certificates.

.PARAMETER WifiOnly
    Scans nearby Wi-Fi SSIDs and wireless environment only. Skips IP subnet scanning.

.PARAMETER SkipWifi
    Disables nearby Wi-Fi network discovery during network scans.

.PARAMETER OnlineLookup
    Enables online API lookups for unlisted MAC vendor OUIs.

.PARAMETER TimeoutMs
    Timeout in milliseconds for individual probes. Default: 350.

.PARAMETER ThrottleLimit
    Maximum number of concurrent scan tasks. Default: 64.

.PARAMETER ExportHtml
    File path to export an HTML report.

.PARAMETER ExportCsv
    File path to export a CSV spreadsheet.

.PARAMETER ExportJson
    File path to export JSON data.

.PARAMETER ShowGrid
    Displays results in a PowerShell Out-GridView window.

.PARAMETER Quiet
    Suppresses console table output and returns raw objects to the pipeline.

.PARAMETER Menu
    Opens the interactive menu.

.PARAMETER NonInteractive
    Runs the scan directly without displaying the menu.

.EXAMPLE
    .\scry.ps1
    Opens the interactive menu.

.EXAMPLE
    .\scry.ps1 -DeepScan -OpenReport
    Runs a deep scan and opens the HTML report in the browser.

.EXAMPLE
    .\scry.ps1 -WifiOnly
    Surveys all nearby Wi-Fi SSIDs, channels, signal strengths, and AP vendors.

.EXAMPLE
    .\scry.ps1 -Subnet "192.168.1.0/24" -ExportCsv "devices.csv"
    Scans a specific subnet and exports results to CSV.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0, HelpMessage = "Subnet CIDR (e.g. 192.168.1.0/24), Range (192.168.1.1-50), or single IP")]
    [string]$Subnet,

    [Parameter(HelpMessage = "Network interface alias (e.g. 'Wi-Fi', 'Ethernet')")]
    [string]$InterfaceAlias,

    [Parameter(HelpMessage = "Scan all active connected network adapters/subnets")]
    [switch]$AllInterfaces,

    [Parameter(HelpMessage = "Root folder to store timestamped scan reports")]
    [string]$ReportDir = "Reports",

    [Parameter(HelpMessage = "Disable automatic timestamped report generation")]
    [switch]$NoReport,

    [Parameter(HelpMessage = "Automatically open generated HTML report in browser")]
    [switch]$OpenReport,

    [Parameter(HelpMessage = "Force flush DNS and renew DHCP lease before scanning")]
    [switch]$RenewDhcp,

    [Parameter(HelpMessage = "Skip initial DHCP lease / router IP verification")]
    [switch]$SkipDhcpCheck,

    [Parameter(HelpMessage = "Maximum seconds to wait for DHCP IP assignment")]
    [int]$DhcpTimeoutSec = 12,

    [Parameter(HelpMessage = "Skip external WAN IP / Geolocation lookup")]
    [switch]$SkipWanCheck,

    [Parameter(HelpMessage = "Timeout in seconds for external WAN IP lookup")]
    [int]$WanTimeoutSec = 3,

    [Parameter(HelpMessage = "Quick mode: Ping + ARP + DNS only")]
    [switch]$QuickScan,

    [Parameter(HelpMessage = "Deep mode: Extended port probing & banner grabbing")]
    [switch]$DeepScan,

    [Parameter(HelpMessage = "Scan nearby Wi-Fi SSIDs and wireless environment only")]
    [switch]$WifiOnly,

    [Parameter(HelpMessage = "Skip nearby Wi-Fi network survey")]
    [switch]$SkipWifi,

    [Parameter(HelpMessage = "Query online MAC vendor APIs for unknown OUIs")]
    [switch]$OnlineLookup,

    [Parameter(HelpMessage = "Probe timeout in milliseconds")]
    [int]$TimeoutMs = 350,

    [Parameter(HelpMessage = "Max concurrent async tasks")]
    [int]$ThrottleLimit = 64,

    [Parameter(HelpMessage = "Custom additional path to export interactive HTML report")]
    [string]$ExportHtml,

    [Parameter(HelpMessage = "Custom additional path to export CSV file")]
    [string]$ExportCsv,

    [Parameter(HelpMessage = "Custom additional path to export JSON file")]
    [string]$ExportJson,

    [Parameter(HelpMessage = "Open results in Out-GridView")]
    [switch]$ShowGrid,

    [Parameter(HelpMessage = "Suppress console output and return raw objects")]
    [switch]$Quiet,

    [Parameter(HelpMessage = "Launch interactive menu")]
    [switch]$Menu,

    [Parameter(HelpMessage = "Run non-interactively without menu")]
    [switch]$NonInteractive
)

Set-StrictMode -Off

# ====================================================================
# 1. C# ASYNCHRONOUS SCAN ENGINE
# ====================================================================
if (-not ([System.Management.Automation.PSTypeName]'FastNetScanner.Core').Type) {
    $cSharpCode = @'
#pragma warning disable 0618, 0612
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace FastNetScanner
{
    public class NetBiosResult
    {
        public string ComputerName = "";
        public string Workgroup = "";
    }

    public class HttpResult
    {
        public string Title = "";
        public string Server = "";
    }

    public class HostInfo
    {
        public string IP;
        public string MAC;
        public bool IsAlive;
        public long PingLatencyMs;
        public string HostName;
        public string NetBiosName;
        public string Workgroup;
        public string OpenPorts;
        public string HttpTitle;
        public string HttpServer;
        public bool IsLocalHost;
        public bool IsGateway;
    }

    public static class Core
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int SendARP(uint DestIP, uint SrcIP, byte[] pMacAddr, ref uint PhysAddrLen);

        public static string ResolveMac(string ipStr)
        {
            try
            {
                IPAddress ip;
                if (!IPAddress.TryParse(ipStr, out ip)) return null;
                byte[] mac = new byte[6];
                uint macLen = (uint)mac.Length;
                uint destIp = BitConverter.ToUInt32(ip.GetAddressBytes(), 0);
                int res = SendARP(destIp, 0, mac, ref macLen);
                if (res == 0 && macLen == 6)
                {
                    return string.Format("{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                }
            }
            catch { }
            return null;
        }

        public static async Task<long> PingAsync(string ipStr, int timeoutMs)
        {
            try
            {
                using (var ping = new System.Net.NetworkInformation.Ping())
                {
                    var reply = await ping.SendPingAsync(ipStr, timeoutMs);
                    if (reply.Status == System.Net.NetworkInformation.IPStatus.Success)
                    {
                        return reply.RoundtripTime;
                    }
                }
            }
            catch { }
            return -1;
        }

        public static async Task<string> ResolveDnsAsync(string ipStr, int timeoutMs)
        {
            try
            {
                var task = Dns.GetHostEntryAsync(ipStr);
                if (await Task.WhenAny(task, Task.Delay(timeoutMs)) == task)
                {
                    var entry = await task;
                    if (!string.IsNullOrEmpty(entry.HostName))
                        return entry.HostName;
                }
            }
            catch { }
            return null;
        }

        public static async Task<NetBiosResult> QueryNetBiosAsync(string ipStr, int timeoutMs)
        {
            var resObj = new NetBiosResult();
            try
            {
                using (var udpClient = new UdpClient())
                {
                    udpClient.Client.ReceiveTimeout = timeoutMs;
                    udpClient.Client.SendTimeout = timeoutMs;
                    byte[] query = new byte[] {
                        0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
                        0x00, 0x01
                    };
                    IPAddress ip;
                    if (IPAddress.TryParse(ipStr, out ip))
                    {
                        var endpoint = new IPEndPoint(ip, 137);
                        await udpClient.SendAsync(query, query.Length, endpoint);

                        var receiveTask = udpClient.ReceiveAsync();
                        var delayTask = Task.Delay(timeoutMs);
                        if (await Task.WhenAny(receiveTask, delayTask) == receiveTask)
                        {
                            var res = await receiveTask;
                            byte[] data = res.Buffer;
                            if (data != null && data.Length > 57)
                            {
                                int numNames = data[56];
                                for (int i = 0; i < numNames; i++)
                                {
                                    int offset = 57 + (i * 18);
                                    if (data.Length >= offset + 18)
                                    {
                                        string n = Encoding.ASCII.GetString(data, offset, 15).Trim();
                                        byte type = data[offset + 15];
                                        byte flags = data[offset + 16];
                                        bool isGroup = (flags & 0x80) != 0;

                                        if (!isGroup && type == 0x00 && string.IsNullOrEmpty(resObj.ComputerName))
                                        {
                                            resObj.ComputerName = n;
                                        }
                                        else if (isGroup && type == 0x00 && string.IsNullOrEmpty(resObj.Workgroup))
                                        {
                                            resObj.Workgroup = n;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }
            return resObj;
        }

        public static async Task<bool> TestPortAsync(string ipStr, int port, int timeoutMs)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var connectTask = client.ConnectAsync(ipStr, port);
                    var delayTask = Task.Delay(timeoutMs);
                    if (await Task.WhenAny(connectTask, delayTask) == connectTask)
                    {
                        if (client.Connected) return true;
                    }
                }
            }
            catch { }
            return false;
        }

        public static HttpResult GrabHttpInfo(string ipStr, int port, int timeoutMs)
        {
            var res = new HttpResult();
            try
            {
                string scheme = (port == 443 || port == 8443 || port == 5001 || port == 8006 || port == 9443) ? "https" : "http";
                string url = scheme + "://" + ipStr + ":" + port + "/";

                ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | (SecurityProtocolType)768 | (SecurityProtocolType)3072;

                var req = (HttpWebRequest)WebRequest.Create(url);
                req.Timeout = timeoutMs;
                req.ReadWriteTimeout = timeoutMs;
                req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetworkMapper/1.0";
                req.AllowAutoRedirect = true;
                req.MaximumAutomaticRedirections = 2;

                using (var resp = (HttpWebResponse)req.GetResponse())
                {
                    if (resp.Headers["Server"] != null)
                    {
                        res.Server = resp.Headers["Server"];
                    }
                    using (var reader = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                    {
                        char[] buffer = new char[8192];
                        int read = reader.Read(buffer, 0, buffer.Length);
                        string html = new string(buffer, 0, read);
                        var match = Regex.Match(html, @"<title[^>]*>(.*?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
                        if (match.Success)
                        {
                            res.Title = Regex.Replace(WebUtility.HtmlDecode(match.Groups[1].Value).Trim(), @"\s+", " ");
                        }
                    }
                }
            }
            catch { }
            return res;
        }

        public static async Task<HostInfo> ScanSingleHostAsync(string ip, string localIp, string gatewayIp, int[] portsToScan, int timeoutMs, bool quickScan, bool deepScan)
        {
            bool isLocal = (ip == localIp);
            bool isGw = (ip == gatewayIp);
            string mac = ResolveMac(ip);
            long pingMs = await PingAsync(ip, timeoutMs);

            bool alive = isLocal || isGw || (mac != null) || (pingMs >= 0);

            // Fast Discovery Fallback: If host didn't respond to ICMP/ARP, probe top TCP discovery ports
            if (!alive)
            {
                int[] discPorts = new int[] { 80, 443, 445, 139, 8080, 22 };
                var discTasks = new List<Task<bool>>();
                foreach (int dp in discPorts)
                {
                    discTasks.Add(TestPortAsync(ip, dp, Math.Min(timeoutMs, 250)));
                }
                var whenAny = await Task.WhenAny(discTasks);
                if (await whenAny)
                {
                    alive = true;
                    if (mac == null) mac = ResolveMac(ip);
                }
                else
                {
                    await Task.WhenAll(discTasks);
                    foreach (var dt in discTasks)
                    {
                        if (await dt) { alive = true; break; }
                    }
                    if (alive && mac == null) mac = ResolveMac(ip);
                }
            }

            if (!alive) return null;

            var host = new HostInfo();
            host.IP = ip;
            host.MAC = (mac != null) ? mac : ResolveMac(ip);
            host.IsAlive = true;
            host.PingLatencyMs = pingMs;
            host.IsLocalHost = isLocal;
            host.IsGateway = isGw;

            var dnsTask = ResolveDnsAsync(ip, timeoutMs);
            Task<NetBiosResult> netbiosTask = null;
            if (!quickScan)
            {
                netbiosTask = QueryNetBiosAsync(ip, timeoutMs);
            }

            var openPortsList = new List<int>();
            var portTasks = new List<Tuple<int, Task<bool>>>();
            if (!quickScan && portsToScan != null && portsToScan.Length > 0)
            {
                foreach (int p in portsToScan)
                {
                    portTasks.Add(new Tuple<int, Task<bool>>(p, TestPortAsync(ip, p, timeoutMs)));
                }
            }

            if (netbiosTask != null)
            {
                await Task.WhenAll(dnsTask, netbiosTask);
                var nbRes = await netbiosTask;
                host.NetBiosName = nbRes.ComputerName;
                host.Workgroup = nbRes.Workgroup;
            }
            else
            {
                await dnsTask;
            }
            host.HostName = await dnsTask;

            foreach (var pt in portTasks)
            {
                if (await pt.Item2)
                {
                    openPortsList.Add(pt.Item1);
                }
            }
            host.OpenPorts = string.Join(", ", openPortsList);

            if (!quickScan && (deepScan || openPortsList.Contains(80) || openPortsList.Contains(443) || openPortsList.Contains(8080) || openPortsList.Contains(8443) || openPortsList.Contains(5000) || openPortsList.Contains(8006)))
            {
                int[] webPorts = new int[] { 80, 443, 8080, 8443, 5000, 8006, 9443, 8123 };
                foreach (int wp in webPorts)
                {
                    if (openPortsList.Contains(wp))
                    {
                        var httpRes = GrabHttpInfo(ip, wp, Math.Max(timeoutMs, 800));
                        if (!string.IsNullOrEmpty(httpRes.Title))
                        {
                            host.HttpTitle = httpRes.Title;
                        }
                        if (!string.IsNullOrEmpty(httpRes.Server))
                        {
                            host.HttpServer = httpRes.Server;
                        }
                        if (!string.IsNullOrEmpty(host.HttpTitle)) break;
                    }
                }
            }

            return host;
        }

        public static string GetNetworkCidr(string ipStr, int prefix)
        {
            try
            {
                IPAddress ip;
                if (IPAddress.TryParse(ipStr, out ip))
                {
                    if (prefix < 8 || prefix > 30) prefix = 24;
                    byte[] bytes = ip.GetAddressBytes();
                    Array.Reverse(bytes);
                    uint ipUint = BitConverter.ToUInt32(bytes, 0);
                    uint mask = prefix == 0 ? 0 : 0xFFFFFFFF << (32 - prefix);
                    uint net = ipUint & mask;
                    byte[] netBytes = BitConverter.GetBytes(net);
                    Array.Reverse(netBytes);
                    return (new IPAddress(netBytes)).ToString() + "/" + prefix;
                }
            }
            catch { }
            return ipStr + "/" + prefix;
        }

        public static List<string> ParseIpRange(string input)
        {
            var list = new List<string>();
            if (string.IsNullOrEmpty(input)) return list;
            input = input.Trim();

            if (input.Contains("/"))
            {
                string[] parts = input.Split('/');
                IPAddress baseIp;
                int prefix;
                if (IPAddress.TryParse(parts[0], out baseIp) && int.TryParse(parts[1], out prefix))
                {
                    if (prefix >= 8 && prefix <= 30)
                    {
                        byte[] bytes = baseIp.GetAddressBytes();
                        Array.Reverse(bytes);
                        uint ipUint = BitConverter.ToUInt32(bytes, 0);
                        uint mask = prefix == 0 ? 0 : 0xFFFFFFFF << (32 - prefix);
                        uint net = ipUint & mask;
                        uint bcast = net | ~mask;

                        for (uint u = net + 1; u < bcast; u++)
                        {
                            byte[] b = BitConverter.GetBytes(u);
                            Array.Reverse(b);
                            list.Add(new IPAddress(b).ToString());
                        }
                        return list;
                    }
                }
            }

            if (input.Contains("-"))
            {
                string[] parts = input.Split('-');
                string startStr = parts[0].Trim();
                string endStr = parts[1].Trim();

                IPAddress startIp;
                if (IPAddress.TryParse(startStr, out startIp))
                {
                    IPAddress endIp;
                    int lastOctet;
                    if (!endStr.Contains(".") && int.TryParse(endStr, out lastOctet))
                    {
                        string[] sb = startStr.Split('.');
                        if (sb.Length == 4)
                        {
                            endStr = sb[0] + "." + sb[1] + "." + sb[2] + "." + lastOctet;
                        }
                    }
                    if (IPAddress.TryParse(endStr, out endIp))
                    {
                        byte[] bStart = startIp.GetAddressBytes();
                        Array.Reverse(bStart);
                        uint uStart = BitConverter.ToUInt32(bStart, 0);

                        byte[] bEnd = endIp.GetAddressBytes();
                        Array.Reverse(bEnd);
                        uint uEnd = BitConverter.ToUInt32(bEnd, 0);

                        if (uStart <= uEnd)
                        {
                            for (uint u = uStart; u <= uEnd; u++)
                            {
                                byte[] b = BitConverter.GetBytes(u);
                                Array.Reverse(b);
                                list.Add(new IPAddress(b).ToString());
                            }
                            return list;
                        }
                    }
                }
            }

            IPAddress singleIp;
            if (IPAddress.TryParse(input, out singleIp))
            {
                list.Add(singleIp.ToString());
            }

            return list;
        }

        public static List<HostInfo> ScanIpList(string[] ipList, string localIp, string gatewayIp, int[] portsToScan, int timeoutMs, int throttle, bool quickScan, bool deepScan)
        {
            var results = new List<HostInfo>();
            var semaphore = new SemaphoreSlim(throttle, throttle);
            var tasks = new List<Task>();

            foreach (var ip in ipList)
            {
                tasks.Add(Task.Run(async () =>
                {
                    await semaphore.WaitAsync();
                    try
                    {
                        var res = await ScanSingleHostAsync(ip, localIp, gatewayIp, portsToScan, timeoutMs, quickScan, deepScan);
                        if (res != null)
                        {
                            lock (results)
                            {
                                results.Add(res);
                            }
                        }
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            Task.WaitAll(tasks.ToArray());
            return results;
        }

        [DllImport("wlanapi.dll")]
        public static extern int WlanOpenHandle(uint dwClientVersion, IntPtr pReserved, out uint pdwNegotiatedVersion, out IntPtr phClientHandle);

        [DllImport("wlanapi.dll")]
        public static extern int WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);

        [DllImport("wlanapi.dll")]
        public static extern int WlanEnumInterfaces(IntPtr hClientHandle, IntPtr pReserved, out IntPtr ppInterfaceList);

        [DllImport("wlanapi.dll")]
        public static extern int WlanScan(IntPtr hClientHandle, ref Guid pInterfaceGuid, IntPtr pDot11Ssid, IntPtr pIeData, IntPtr pReserved);

        [DllImport("wlanapi.dll")]
        public static extern void WlanFreeMemory(IntPtr pMemory);

        public static bool TriggerWlanScan(int waitMs = 2000)
        {
            IntPtr hClient = IntPtr.Zero;
            try
            {
                uint negotiatedVer;
                if (WlanOpenHandle(2, IntPtr.Zero, out negotiatedVer, out hClient) != 0) return false;
                IntPtr pList = IntPtr.Zero;
                if (WlanEnumInterfaces(hClient, IntPtr.Zero, out pList) == 0 && pList != IntPtr.Zero)
                {
                    try
                    {
                        uint count = (uint)Marshal.ReadInt32(pList);
                        for (int i = 0; i < count; i++)
                        {
                            IntPtr pGuid = new IntPtr(pList.ToInt64() + 8 + (i * 532));
                            byte[] guidBytes = new byte[16];
                            Marshal.Copy(pGuid, guidBytes, 0, 16);
                            Guid guid = new Guid(guidBytes);
                            WlanScan(hClient, ref guid, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                        }
                    }
                    finally
                    {
                        WlanFreeMemory(pList);
                    }
                }
            }
            catch { return false; }
            finally
            {
                if (hClient != IntPtr.Zero) WlanCloseHandle(hClient, IntPtr.Zero);
            }

            if (waitMs > 0)
            {
                Thread.Sleep(waitMs);
            }
            return true;
        }
    }
}
'@
    Add-Type -TypeDefinition $cSharpCode -Language CSharp -IgnoreWarnings -WarningAction SilentlyContinue
}

# ====================================================================
# 2. IEEE MAC OUI VENDOR LOOKUP (External Database & Dynamic Loader)
# ====================================================================
$script:MacOuiDatabase = $null

function Get-MacOuiDatabase {
    if ($script:MacOuiDatabase -ne $null -and $script:MacOuiDatabase.Count -gt 0) {
        return $script:MacOuiDatabase
    }

    $db = @{}

    # Locate external OUI database file
    $searchPaths = @(
        (Join-Path $PSScriptRoot "oui.txt"),
        (Join-Path (Get-Location).Path "oui.txt"),
        (Join-Path $PSScriptRoot "mac_oui.txt"),
        (Join-Path (Get-Location).Path "mac_oui.txt")
    )

    $dbFile = $null
    foreach ($p in $searchPaths) {
        if ($p -and (Test-Path -Path $p -PathType Leaf)) {
            $dbFile = $p
            break
        }
    }

    if ($dbFile) {
        try {
            $lines = [System.IO.File]::ReadAllLines($dbFile, [System.Text.Encoding]::UTF8)
            foreach ($line in $lines) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                $t = $line.Trim()
                if ($t.StartsWith('#') -or $t.StartsWith('//')) { continue }

                $sepMatch = [regex]::Match($t, '^([0-9A-Fa-f]{2}[:\-\.]?[0-9A-Fa-f]{2}[:\-\.]?[0-9A-Fa-f]{2})[\s\t=,|:]+(.+)$')
                if ($sepMatch.Success) {
                    $prefix = ($sepMatch.Groups[1].Value -replace '[:\-\.]', '').ToUpper()
                    $vendor = $sepMatch.Groups[2].Value.Trim()
                    if ($prefix.Length -ge 6 -and -not [string]::IsNullOrEmpty($vendor)) {
                        $db[$prefix.Substring(0, 6)] = $vendor
                    }
                }
            }
        } catch { }
    }

    # Embedded fallback entries in case external file is not present
    if ($db.Count -eq 0) {
        $fallbacks = @{
            'B827EB' = 'Raspberry Pi Foundation'; 'DCA632' = 'Raspberry Pi Foundation'; 'E45F01' = 'Raspberry Pi Foundation'
            '18FE34' = 'Espressif Inc (IoT/ESP)'; '240AC4' = 'Espressif Inc (IoT/ESP)'; '3C71BF' = 'Espressif Inc (IoT/ESP)'
            '000393' = 'Apple'; '000502' = 'Apple'; '0010FA' = 'Apple'; '183451' = 'Apple'; '3C22FB' = 'Apple'; 'B8E856' = 'Apple'
            '001D0F' = 'TP-Link'; '50C7BF' = 'TP-Link'; '7403BD' = 'TP-Link'; '98DAC4' = 'TP-Link'; 'C006C3' = 'TP-Link'
            '00156D' = 'Ubiquiti (UniFi)'; '245A4C' = 'Ubiquiti (UniFi)'; '7483C2' = 'Ubiquiti (UniFi)'; 'AC8BA9' = 'Ubiquiti (UniFi)'
            '00095B' = 'Netgear'; '200CC8' = 'Netgear'; 'A00460' = 'Netgear'; 'C0FFD4' = 'Netgear'
            '00000C' = 'Cisco'; '001A30' = 'Cisco'; '080002' = 'Cisco'; '58971E' = 'Cisco'
            '000C6E' = 'ASUS'; '04D9F5' = 'ASUS'; '14DDA9' = 'ASUS'; 'AC220B' = 'ASUS'
            '000C42' = 'MikroTik'; '488F5A' = 'MikroTik'; '744D28' = 'MikroTik'
            '00040E' = 'AVM (FRITZ!Box)'; '3431C4' = 'AVM (FRITZ!Box)'
            '001132' = 'Synology'; '00089B' = 'QNAP'
            '00FC8B' = 'Amazon (Echo/Ring/Fire)'; '44650D' = 'Amazon (Echo/Ring/Fire)'; '84D6D0' = 'Amazon (Echo/Ring/Fire)'
            '001A11' = 'Google'; '1097BD' = 'Google (Nest/Home)'; '3C3174' = 'Google (Nest Wifi)'; '546009' = 'Google'
            '0007AB' = 'Samsung'; '001247' = 'Samsung'; '380A94' = 'Samsung'; 'BC4486' = 'Samsung'
            '105AF7' = 'Tuya (Smart Life IoT)'; '20F41B' = 'Tuya (Smart Life IoT)'; '708976' = 'Tuya (Smart Life IoT)'
            '009EC8' = 'Xiaomi'; '185936' = 'Xiaomi'; '742344' = 'Xiaomi'
            '000E58' = 'Sonos'; '347E5C' = 'Sonos'; '5CAAFD' = 'Sonos'
            '000D4B' = 'Roku'; '20EFBD' = 'Roku'; 'B0A737' = 'Roku'
            '001788' = 'Philips Hue (Signify)'; 'ECB5FA' = 'Philips Hue (Signify)'
            '0001E6' = 'HP'; '0017A4' = 'HP'; '082E5F' = 'HP'; '308D99' = 'HP'; '705A0F' = 'HP'
            '000085' = 'Canon'; '001BA9' = 'Brother'; '000048' = 'Epson'; '000074' = 'Ricoh'
            '00065B' = 'Dell'; '180373' = 'Dell'; '3417EB' = 'Dell'; '74867A' = 'Dell'
            '0012FE' = 'Lenovo'; '207693' = 'Lenovo'; '6099D1' = 'Lenovo'
            '0002B3' = 'Intel'; '001E67' = 'Intel'; '84A93E' = 'Intel'; 'F8633F' = 'Intel'
            '000732' = 'Realtek'; '5404A6' = 'Realtek'; 'FC3497' = 'Realtek'
            '0003FF' = 'Microsoft'; '00155D' = 'Microsoft (Hyper-V)'; '281878' = 'Microsoft'; '706655' = 'Microsoft'
            '00014A' = 'Sony'; '0009BF' = 'Nintendo'; '0019A1' = 'LG'
            '0024D4' = 'Sagemcom'; '103C59' = 'Sagemcom'; '541F8D' = 'Sagemcom'
            '00055D' = 'D-Link'; '0002CF' = 'Zyxel'; '000B86' = 'Aruba (HPE)'; '0015CE' = 'Arris/Motorola'
            '001E10' = 'Huawei'; '001E73' = 'ZTE'; '50FF20' = 'Keenetic'
            '000569' = 'VMware'; '000C29' = 'VMware'; '080027' = 'Oracle VirtualBox'; '525400' = 'QEMU / KVM / Proxmox VM'
        }
        foreach ($k in $fallbacks.Keys) { $db[$k] = $fallbacks[$k] }
    }

    $script:MacOuiDatabase = $db
    return $script:MacOuiDatabase
}

function Resolve-MacVendor {
    param([string]$MacAddress, [switch]$QueryOnline)
    if ([string]::IsNullOrWhiteSpace($MacAddress)) { return "Unknown (No ARP/MAC)" }

    $cleanMac = ($MacAddress -replace '[:-]', '').ToUpper()
    if ($cleanMac.Length -lt 6) { return "Unknown" }

    $firstByte = [Convert]::ToByte($cleanMac.Substring(0,2), 16)
    $isPrivate = ($firstByte -band 0x02) -ne 0

    $ouiDb = Get-MacOuiDatabase
    $prefix = $cleanMac.Substring(0, 6)
    if ($ouiDb.ContainsKey($prefix)) {
        $vendor = $ouiDb[$prefix]
        if ($isPrivate) { return "$vendor (Private MAC)" }
        return $vendor
    }

    if ($isPrivate) {
        return "Private / Randomized MAC (iOS/Android/Win Privacy)"
    }

    if ($QueryOnline) {
        try {
            $apiUrl = "https://api.maclookup.app/v2/macs/$MacAddress"
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("User-Agent", "NetworkScanner/1.0")
            $resp = $wc.DownloadString($apiUrl) | ConvertFrom-Json
            if ($resp.success -and $resp.found -and $resp.company) {
                $ouiDb[$prefix] = $resp.company
                return $resp.company
            }
        } catch { }
    }

    return "Unknown Vendor"
}

# ====================================================================
# 3. DEVICE CLASSIFICATION AND FINGERPRINTING
# ====================================================================
function Get-DeviceClassification {
    param($HostObj, [string]$Vendor)

    $ip = $HostObj.IP
    $hostName = [string]$HostObj.HostName
    $netbios = [string]$HostObj.NetBiosName
    $title = [string]$HostObj.HttpTitle
    $server = [string]$HostObj.HttpServer
    $openPorts = [string]$HostObj.OpenPorts
    $portsList = if ($openPorts) { $openPorts.Split(', ') | ForEach-Object { [int]$_ } } else { @() }
    $combinedText = "$hostName $netbios $title $server $Vendor".ToLower()

    # Rule 0: This Host PC
    if ($HostObj.IsLocalHost) {
        return @{
            Type = "This PC (Local Host)"
            Icon = "[THIS-PC]"
            HtmlIcon = "&#128187;"
            Confidence = "High"
            Category = "Computer"
        }
    }

    # Rule 1: Gateway / Router
    if ($HostObj.IsGateway -or
        ($Vendor -match 'Cisco|MikroTik|AVM|Ubiquiti|TP-Link|Netgear|ASUS|Linksys|D-Link|Aruba|DrayTek|Fortinet|SonicWall|Huawei|ZTE' -and ($portsList -contains 53 -or $portsList -contains 80 -or $portsList -contains 443 -or $portsList -contains 22)) -or
        ($combinedText -match 'router|gateway|openwrt|pfsense|opnsense|dd-wrt|mikrotik|edgerouter|fritz!box|unifi|deco|amplifi|speedport|nest wifi')) {
        return @{
            Type = "Router / Gateway"
            Icon = "[ROUTER]"
            HtmlIcon = "&#127760;"
            Confidence = "High"
            Category = "Network Infrastructure"
        }
    }

    # Rule 2: Network Printer / MFP
    if ($portsList -contains 9100 -or $portsList -contains 515 -or $portsList -contains 631 -or
        ($Vendor -match 'Canon|Brother|Epson|Ricoh|Xerox|Kyocera|Lexmark|Konica' -and $combinedText -match 'printer|laserjet|deskjet|officejet|page-wide|centreware|jetadmin|mfp|print') -or
        ($combinedText -match 'printer|laserjet|deskjet|officejet|page-wide|centreware|jetadmin|mfp')) {
        return @{
            Type = "Network Printer"
            Icon = "[PRINTER]"
            HtmlIcon = "&#128424;"
            Confidence = "High"
            Category = "Office Hardware"
        }
    }

    # Rule 3: NAS / Network Storage
    if (($Vendor -match 'Synology|QNAP') -or $portsList -contains 5000 -or $portsList -contains 5001 -or
        ($combinedText -match 'synology|diskstation|rackstation|qnap|truenas|freenas|unraid|openmediavault|nas|mycloud|readynas')) {
        return @{
            Type = "NAS / Storage Server"
            Icon = "[STORAGE]"
            HtmlIcon = "&#128190;"
            Confidence = "High"
            Category = "Storage"
        }
    }

    # Rule 4: Windows PC / Workstation / Server
    if ($portsList -contains 445 -or $portsList -contains 3389 -or $portsList -contains 139 -or
        (-not [string]::IsNullOrEmpty($netbios)) -or ($Vendor -match 'Microsoft') -or
        (($Vendor -match 'Dell|Lenovo|Intel|HP') -and ($combinedText -match 'pc-|desktop|laptop|workstation|windows|server|srv|corp|dom'))) {
        return @{
            Type = "Windows PC / Workstation"
            Icon = "[WIN-PC]"
            HtmlIcon = "&#128187;"
            Confidence = "High"
            Category = "Computer"
        }
    }

    # Rule 5: Smart Home & IoT
    if (($Vendor -match 'Espressif|Tuya|Philips Hue|Sonos|Sonoff|Shelly|Xiaomi|IKEA') -or
        ($portsList -contains 1883 -or ($portsList -contains 8123 -and $Vendor -notmatch 'Dell|Lenovo|Intel|Microsoft')) -or
        ($combinedText -match 'esphome|tasmota|wled|sonoff|shelly|homeassistant|hue-bridge|smart-plug|iot|tuya|sonos|octopi|nest|google home')) {
        return @{
            Type = "Smart Home / IoT"
            Icon = "[IOT]"
            HtmlIcon = "&#128161;"
            Confidence = "High"
            Category = "Smart Home"
        }
    }

    # Rule 6: Smart TV / Media Player / Game Console
    if (($Vendor -match 'Roku|LG|Samsung|Sony|Nintendo' -and ($portsList -contains 8008 -or $portsList -contains 8009 -or $portsList -contains 32400 -or $portsList.Count -le 2)) -or
        ($combinedText -match 'tv|roku|chromecast|appletv|bravia|webos|tizen|playstation|ps4|ps5|xbox|nintendo|shield|firetv|kodi|plex')) {
        return @{
            Type = "Smart TV / Media Player"
            Icon = "[TV/MEDIA]"
            HtmlIcon = "&#128250;"
            Confidence = "Medium"
            Category = "Entertainment"
        }
    }

    # Rule 7: Raspberry Pi / Single Board Computer
    if (($Vendor -match 'Raspberry Pi') -or ($combinedText -match 'raspberrypi|raspbian|dietpi|octoprint')) {
        return @{
            Type = "Raspberry Pi (SBC)"
            Icon = "[RASP-PI]"
            HtmlIcon = "&#127827;"
            Confidence = "High"
            Category = "Single Board Computer"
        }
    }

    # Rule 8: Virtual Machine / Hypervisor
    if (($Vendor -match 'VMware|VirtualBox|QEMU|KVM') -or $portsList -contains 8006 -or ($combinedText -match 'proxmox|vmware|esxi|hyper-v|xen|vbox')) {
        return @{
            Type = "Virtual Machine / Hypervisor"
            Icon = "[VM/HYPERV]"
            HtmlIcon = "&#128421;"
            Confidence = "High"
            Category = "Virtualization"
        }
    }

    # Rule 9: Linux / Unix Server
    if (($portsList -contains 22 -and ($portsList -notcontains 445)) -or
        ($combinedText -match 'ubuntu|debian|centos|redhat|alpine|linux|apache|nginx|node|docker|k8s')) {
        return @{
            Type = "Linux / Unix Server"
            Icon = "[LINUX]"
            HtmlIcon = "&#128039;"
            Confidence = "Medium"
            Category = "Server"
        }
    }

    # Rule 10: Apple Device (iPhone, iPad, Mac)
    if ($Vendor -match 'Apple') {
        return @{
            Type = "Apple Device (Mac/iOS)"
            Icon = "[APPLE]"
            HtmlIcon = "&#127823;"
            Confidence = "Medium"
            Category = "Mobile / Computer"
        }
    }

    # Rule 11: Mobile Phone / Tablet
    if ($Vendor -match 'Samsung|Google|Xiaomi|OnePlus|Huawei|Private / Randomized') {
        return @{
            Type = "Mobile / Wireless Device"
            Icon = "[MOBILE]"
            HtmlIcon = "&#128241;"
            Confidence = "Medium"
            Category = "Mobile"
        }
    }

    # Fallback
    return @{
        Type = "Network Host"
        Icon = "[DEVICE]"
        HtmlIcon = "&#128225;"
        Confidence = "Low"
        Category = "General"
    }
}

# ====================================================================
# 4. NETWORK ADAPTER ENUMERATION & ROUTE DETECTION HELPERS
# ====================================================================
function Get-AllActiveNetworkInterfaces {
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $routes = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
    $ipAddresses = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '169.254*' -and $_.IPAddress -ne '127.0.0.1' -and $_.AddressState -ne 'Tentative' }

    foreach ($ad in $adapters) {
        $ip = $ipAddresses | Where-Object { $_.InterfaceIndex -eq $ad.InterfaceIndex } | Select-Object -First 1
        if (-not $ip) { continue }

        $gwRoute = $routes | Where-Object { $_.InterfaceIndex -eq $ad.InterfaceIndex } |
            Sort-Object @{ Expression = { $_.RouteMetric + $_.InterfaceMetric } } | Select-Object -First 1

        $gwIp = if ($gwRoute) { $gwRoute.NextHop } else { $null }
        $totalMetric = if ($gwRoute) { $gwRoute.RouteMetric + $gwRoute.InterfaceMetric } else { 9999 }

        $prefix = $ip.PrefixLength
        if ($prefix -lt 8 -or $prefix -gt 30) { $prefix = 24 }
        $subnetCidr = [FastNetScanner.Core]::GetNetworkCidr($ip.IPAddress, $prefix)

        $hostCount = [Math]::Pow(2, 32 - $prefix) - 2
        if ($hostCount -lt 1) { $hostCount = 1 }

        $isVirtual = ($ad.InterfaceDescription -match 'Hyper-V|Virtual|Loopback|WSL|VMware|VirtualBox|vEthernet')

        $results.Add([PSCustomObject]@{
            InterfaceAlias = $ad.Name
            Description    = $ad.InterfaceDescription
            InterfaceIndex = $ad.InterfaceIndex
            LocalIP        = $ip.IPAddress
            PrefixLength   = $prefix
            SubnetCidr     = $subnetCidr
            HostCount      = [int]$hostCount
            GatewayIP      = $gwIp
            TotalMetric    = $totalMetric
            IsVirtual      = $isVirtual
            LinkSpeed      = $ad.LinkSpeed
            MacAddress     = $ad.MacAddress
            Status         = $ad.Status
        })
    }

    # Sort priority: Physical first, Gateway present first, lowest route metric, larger subnet host count
    $sorted = $results | Sort-Object @{ Expression = { if ($_.IsVirtual) { 1 } else { 0 } } },
                                     @{ Expression = { if ($_.GatewayIP) { 0 } else { 1 } } },
                                     @{ Expression = { $_.TotalMetric } },
                                     @{ Expression = { -$_.HostCount } }

    return ,$sorted
}

# ====================================================================
# 4b. EXTERNAL WAN & GEOLOCATION DISCOVERY
# ====================================================================
$script:CachedWanInfo = $null
$script:LastWanCheck = [DateTime]::MinValue

function Get-ExternalNetworkInfo {
    param(
        [int]$TimeoutMs = 3000
    )

    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor 768 -bor 3072 -bor [System.Net.SecurityProtocolType]::Tls
    } catch { }

    # Source 1: ip-api.com (Geolocation, ISP, ASN, reverse DNS)
    try {
        $req = [System.Net.HttpWebRequest]::Create("http://ip-api.com/json/?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse")
        $req.Timeout = $TimeoutMs
        $req.ReadWriteTimeout = $TimeoutMs
        $req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SCRY/1.0"
        $resp = $req.GetResponse()
        if ($resp) {
            $stream = $resp.GetResponseStream()
            $sr = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
            $rawJson = $sr.ReadToEnd()
            $sr.Close()
            $resp.Close()

            $d = $rawJson | ConvertFrom-Json
            if ($d.status -eq 'success' -and $d.query) {
                $coords = if ($d.lat -and $d.lon) { "$($d.lat), $($d.lon)" } else { "" }
                $rDns = if ($d.reverse) { [string]$d.reverse } else { "" }
                if ([string]::IsNullOrEmpty($rDns)) {
                    try {
                        $dnsEntry = [System.Net.Dns]::GetHostEntry([string]$d.query)
                        if ($dnsEntry -and $dnsEntry.HostName) { $rDns = $dnsEntry.HostName }
                    } catch { }
                }
                $resObj = [PSCustomObject]@{
                    IsConnected   = $true
                    IP            = [string]$d.query
                    Hostname      = $rDns
                    ISP           = if ($d.isp) { [string]$d.isp } else { "" }
                    Org           = if ($d.org) { [string]$d.org } else { "" }
                    ASN           = if ($d.as) { [string]$d.as } else { "" }
                    City          = if ($d.city) { [string]$d.city } else { "" }
                    Region        = if ($d.regionName) { [string]$d.regionName } elseif ($d.region) { [string]$d.region } else { "" }
                    Country       = if ($d.country) { [string]$d.country } else { "" }
                    CountryCode   = if ($d.countryCode) { [string]$d.countryCode } else { "" }
                    PostalCode    = if ($d.zip) { [string]$d.zip } else { "" }
                    Coordinates   = $coords
                    Timezone      = if ($d.timezone) { [string]$d.timezone } else { "" }
                    SourceService = "ip-api.com"
                    FetchTime     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                }
                $script:CachedWanInfo = $resObj
                $script:LastWanCheck = Get-Date
                return $resObj
            }
        }
    } catch { }

    # Source 2: ipinfo.io (Fallback)
    try {
        $req = [System.Net.HttpWebRequest]::Create("https://ipinfo.io/json")
        $req.Timeout = $TimeoutMs
        $req.ReadWriteTimeout = $TimeoutMs
        $req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SCRY/1.0"
        $resp = $req.GetResponse()
        if ($resp) {
            $stream = $resp.GetResponseStream()
            $sr = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
            $rawJson = $sr.ReadToEnd()
            $sr.Close()
            $resp.Close()

            $d = $rawJson | ConvertFrom-Json
            if ($d.ip) {
                $extIp = [string]$d.ip
                $rDns = if ($d.hostname) { [string]$d.hostname } else { "" }
                if ([string]::IsNullOrEmpty($rDns)) {
                    try {
                        $dnsEntry = [System.Net.Dns]::GetHostEntry($extIp)
                        if ($dnsEntry -and $dnsEntry.HostName) { $rDns = $dnsEntry.HostName }
                    } catch { }
                }
                $resObj = [PSCustomObject]@{
                    IsConnected   = $true
                    IP            = $extIp
                    Hostname      = $rDns
                    ISP           = if ($d.org) { [string]$d.org } else { "" }
                    Org           = if ($d.org) { [string]$d.org } else { "" }
                    ASN           = if ($d.org) { [string]$d.org } else { "" }
                    City          = if ($d.city) { [string]$d.city } else { "" }
                    Region        = if ($d.region) { [string]$d.region } else { "" }
                    Country       = if ($d.country) { [string]$d.country } else { "" }
                    CountryCode   = if ($d.countryCode) { [string]$d.countryCode } else { "" }
                    PostalCode    = if ($d.postal) { [string]$d.postal } else { "" }
                    Coordinates   = if ($d.loc) { [string]$d.loc } else { "" }
                    Timezone      = if ($d.timezone) { [string]$d.timezone } else { "" }
                    SourceService = "ipinfo.io"
                    FetchTime     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                }
                $script:CachedWanInfo = $resObj
                $script:LastWanCheck = Get-Date
                return $resObj
            }
        }
    } catch { }

    # Source 3: api.ipify.org (Fallback IP + rDNS)
    try {
        $req = [System.Net.HttpWebRequest]::Create("https://api.ipify.org?format=json")
        $req.Timeout = $TimeoutMs
        $req.ReadWriteTimeout = $TimeoutMs
        $req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SCRY/1.0"
        $resp = $req.GetResponse()
        if ($resp) {
            $stream = $resp.GetResponseStream()
            $sr = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
            $rawJson = $sr.ReadToEnd()
            $sr.Close()
            $resp.Close()

            $d = $rawJson | ConvertFrom-Json
            if ($d.ip) {
                $extIp = [string]$d.ip
                $rDns = ""
                try {
                    $dnsEntry = [System.Net.Dns]::GetHostEntry($extIp)
                    if ($dnsEntry -and $dnsEntry.HostName) { $rDns = $dnsEntry.HostName }
                } catch { }
                $resObj = [PSCustomObject]@{
                    IsConnected   = $true
                    IP            = $extIp
                    Hostname      = $rDns
                    ISP           = "Unknown ISP"
                    Org           = ""
                    ASN           = ""
                    City          = ""
                    Region        = ""
                    Country       = ""
                    CountryCode   = ""
                    PostalCode    = ""
                    Coordinates   = ""
                    Timezone      = ""
                    SourceService = "api.ipify.org"
                    FetchTime     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                }
                $script:CachedWanInfo = $resObj
                $script:LastWanCheck = Get-Date
                return $resObj
            }
        }
    } catch { }

    # Offline / Unreachable
    $offlineObj = [PSCustomObject]@{
        IsConnected   = $false
        IP            = "Offline / Unreachable"
        Hostname      = ""
        ISP           = "No Internet Connection"
        Org           = ""
        ASN           = ""
        City          = ""
        Region        = ""
        Country       = ""
        CountryCode   = ""
        PostalCode    = ""
        Coordinates   = ""
        Timezone      = ""
        SourceService = "None (Offline / Isolated Network)"
        FetchTime     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    }
    $script:CachedWanInfo = $offlineObj
    $script:LastWanCheck = Get-Date
    return $offlineObj
}

function Show-NetworkStatus {
    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host " [STATUS] LOCAL NETWORK INTERFACES & ROUTE CONFIGURATION" -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan

    $activeInterfaces = Get-AllActiveNetworkInterfaces

    if (-not $activeInterfaces -or $activeInterfaces.Count -eq 0) {
        Write-Host " [!] No connected active IPv4 network adapters found." -ForegroundColor Red
        Write-Host "     Please connect an Ethernet cable or connect to a Wi-Fi network." -ForegroundColor Yellow
        Write-Host "=================================================================" -ForegroundColor Cyan
        return
    }

    $primary = $activeInterfaces | Select-Object -First 1

    foreach ($ad in $activeInterfaces) {
        $isPrimary = ($ad.InterfaceIndex -eq $primary.InterfaceIndex)
        $primaryTag = if ($isPrimary) { " [PRIMARY TARGET]" } else { "" }
        $aliasColor = if ($isPrimary) { "Green" } else { "Yellow" }

        $dhcp = Get-NetIPInterface -InterfaceIndex $ad.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        $dnsArr = (Get-DnsClientServerAddress -InterfaceIndex $ad.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
        $dns = if ($dnsArr) { $dnsArr -join ', ' } else { 'None' }

        Write-Host " Adapter Name   : " -NoNewline
        Write-Host "$($ad.InterfaceAlias) ($($ad.Description))$primaryTag" -ForegroundColor $aliasColor
        Write-Host " Link Status    : " -NoNewline; Write-Host "$($ad.Status) ($($ad.LinkSpeed))" -ForegroundColor Green
        Write-Host " MAC Address    : " -NoNewline; Write-Host "$($ad.MacAddress)" -ForegroundColor White
        Write-Host " IPv4 Address   : " -NoNewline; Write-Host "$($ad.LocalIP) /$($ad.PrefixLength) (Subnet: $($ad.SubnetCidr) - $($ad.HostCount) Hosts)" -ForegroundColor White

        if ($ad.GatewayIP) {
            $pingGw = [FastNetScanner.Core]::PingAsync($ad.GatewayIP, 500).Result
            $gwStatus = if ($pingGw -ge 0) { "Reachable ($($pingGw) ms)" } else { "Unreachable / Filtered" }
            $gwColor = if ($pingGw -ge 0) { "Green" } else { "Yellow" }
            Write-Host " Default Gateway: " -NoNewline; Write-Host "$($ad.GatewayIP) ($gwStatus)" -ForegroundColor $gwColor
        } else {
            Write-Host " Default Gateway: " -NoNewline; Write-Host "None configured (Local only / Virtual switch)" -ForegroundColor DarkGray
        }

        $dhcpStatus = if ($dhcp -and $dhcp.Dhcp -eq 1) { "Enabled (DHCP Client Active)" } elseif ($dhcp) { "Disabled (Static IP)" } else { "Unknown" }
        $dhcpColor = if ($dhcp -and $dhcp.Dhcp -eq 1) { "Green" } else { "DarkCyan" }
        Write-Host " DHCP Mode      : " -NoNewline; Write-Host "$dhcpStatus" -ForegroundColor $dhcpColor
        Write-Host " DNS Servers    : " -NoNewline; Write-Host "$dns" -ForegroundColor DarkCyan
        Write-Host "-----------------------------------------------------------------" -ForegroundColor DarkGray
    }

    # External WAN Discovery
    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host " [STATUS] EXTERNAL WAN & INTERNET CONNECTIVITY" -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host " Checking external IP address and ISP origin..." -ForegroundColor Gray

    $wan = Get-ExternalNetworkInfo -TimeoutMs 3000
    if ($wan.IsConnected) {
        Write-Host " Internet Status: " -NoNewline; Write-Host "ONLINE (Connected)" -ForegroundColor Green
        Write-Host " Public IPv4    : " -NoNewline; Write-Host "$($wan.IP)" -ForegroundColor Yellow
        if ($wan.Hostname) {
            Write-Host " External Host  : " -NoNewline; Write-Host "$($wan.Hostname)" -ForegroundColor DarkCyan
        }
        Write-Host " ISP / Provider : " -NoNewline; Write-Host "$($wan.ISP)" -ForegroundColor White
        if ($wan.Org -and $wan.Org -ne $wan.ISP) {
            Write-Host " Organization   : " -NoNewline; Write-Host "$($wan.Org)" -ForegroundColor DarkCyan
        }
        if ($wan.ASN) {
            Write-Host " ASN            : " -NoNewline; Write-Host "$($wan.ASN)" -ForegroundColor DarkCyan
        }
        $locParts = @()
        if ($wan.City) { $locParts += $wan.City }
        if ($wan.Region) { $locParts += $wan.Region }
        if ($wan.Country) { $locParts += "$($wan.Country) ($($wan.CountryCode))" }
        if ($wan.PostalCode) { $locParts += "[Zip: $($wan.PostalCode)]" }
        if ($locParts.Count -gt 0) {
            Write-Host " Geo Location   : " -NoNewline; Write-Host ($locParts -join ", ") -ForegroundColor White
        }
        if ($wan.Coordinates -or $wan.Timezone) {
            $geoExtra = @()
            if ($wan.Coordinates) { $geoExtra += "Coordinates: $($wan.Coordinates)" }
            if ($wan.Timezone) { $geoExtra += "Timezone: $($wan.Timezone)" }
            Write-Host " Location Info  : " -NoNewline; Write-Host ($geoExtra -join " | ") -ForegroundColor DarkGray
        }
        Write-Host " Lookup Provider: " -NoNewline; Write-Host "$($wan.SourceService) (at $($wan.FetchTime))" -ForegroundColor DarkGray
    } else {
        Write-Host " Internet Status: " -NoNewline; Write-Host "OFFLINE / LOCAL LAN ONLY" -ForegroundColor Yellow
        Write-Host " Details        : " -NoNewline; Write-Host "Unable to reach external IP service (Isolated network or no WAN gateway)" -ForegroundColor DarkGray
    }
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Ensure-NetworkConnection {
    param(
        [string]$PreferredInterface,
        [switch]$ForceRenew,
        [int]$WaitTimeoutSec = 12
    )

    Write-Host " [*] Checking router link and IPv4 lease..." -ForegroundColor Cyan

    $activeInterfaces = Get-AllActiveNetworkInterfaces
    $targetAdapter = $null

    if ($PreferredInterface) {
        $targetAdapter = $activeInterfaces | Where-Object { $_.InterfaceAlias -like "*$PreferredInterface*" -or $_.Description -like "*$PreferredInterface*" } | Select-Object -First 1
    }
    if (-not $targetAdapter) {
        $targetAdapter = $activeInterfaces | Select-Object -First 1
    }

    $needsRenew = $ForceRenew.IsPresent -or (-not $targetAdapter) -or (-not $targetAdapter.GatewayIP)

    if ($needsRenew) {
        if ($ForceRenew.IsPresent) {
            Write-Host " [*] Manual DHCP lease renewal requested." -ForegroundColor Yellow
        } else {
            Write-Host " [!] No valid IPv4 lease or gateway found on active adapter." -ForegroundColor Yellow
        }

        Write-Host " [*] Flushing DNS cache and requesting DHCP lease from router..." -ForegroundColor Yellow
        try {
            & ipconfig.exe /flushdns 2>&1 | Out-Null
            if ($targetAdapter) {
                & ipconfig.exe /renew "$($targetAdapter.InterfaceAlias)" 2>&1 | Out-Null
            } else {
                & ipconfig.exe /renew 2>&1 | Out-Null
            }
        } catch { }

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $acquired = $false

        while ($sw.Elapsed.TotalSeconds -lt $WaitTimeoutSec) {
            Start-Sleep -Milliseconds 1500
            $activeInterfaces = Get-AllActiveNetworkInterfaces
            if ($PreferredInterface) {
                $targetAdapter = $activeInterfaces | Where-Object { $_.InterfaceAlias -like "*$PreferredInterface*" } | Select-Object -First 1
            } else {
                $targetAdapter = $activeInterfaces | Select-Object -First 1
            }

            if ($targetAdapter -and $targetAdapter.GatewayIP) {
                $acquired = $true
                break
            }

            $elapsedRound = [Math]::Round($sw.Elapsed.TotalSeconds, 0)
            Write-Host " [*] Waiting for router DHCP response... ($elapsedRound s / $WaitTimeoutSec s)" -ForegroundColor DarkGray
        }

        if ($acquired) {
            Write-Host " [+] DHCP lease successfully acquired on [$($targetAdapter.InterfaceAlias)]: IP = $($targetAdapter.LocalIP) | Gateway = $($targetAdapter.GatewayIP)" -ForegroundColor Green
        } else {
            Write-Host " [-] Warning: DHCP lease renewal timed out without a gateway assignment." -ForegroundColor Yellow
        }
    } else {
        Write-Host " [+] Verified active link on [$($targetAdapter.InterfaceAlias)]: IP = $($targetAdapter.LocalIP) | Gateway = $($targetAdapter.GatewayIP)" -ForegroundColor Green
    }
}

function Get-ActiveNetworkConfig {
    param([string]$PreferredInterface)

    $activeInterfaces = Get-AllActiveNetworkInterfaces

    $target = $null
    if ($PreferredInterface) {
        $target = $activeInterfaces | Where-Object { $_.InterfaceAlias -like "*$PreferredInterface*" -or $_.Description -like "*$PreferredInterface*" } | Select-Object -First 1
    }
    if (-not $target) {
        $target = $activeInterfaces | Select-Object -First 1
    }

    if (-not $target) {
        throw "Could not automatically detect an active IPv4 network interface. Please specify -Subnet (e.g. -Subnet '192.168.1.0/24')."
    }

    return @{
        InterfaceAlias = $target.InterfaceAlias
        Description    = $target.Description
        LocalIP        = $target.LocalIP
        PrefixLength   = $target.PrefixLength
        GatewayIP      = $target.GatewayIP
        SubnetCidr     = $target.SubnetCidr
        HostCount      = $target.HostCount
    }
}

# ====================================================================
# 4c. WI-FI & WIRELESS ENVIRONMENT DISCOVERY
# ====================================================================
function Get-ConnectedWifiInfo {
    try {
        $raw = & netsh.exe wlan show interfaces 2>$null
        if (-not $raw) { return $null }

        $info = [ordered]@{}
        foreach ($line in $raw) {
            if ($line -match '^\s*([^:]+?)\s*:\s*(.*)$') {
                $key = $Matches[1].Trim()
                $val = $Matches[2].Trim()
                $info[$key] = $val
            }
        }

        if (-not $info.Contains('State') -or $info['State'] -ne 'connected') {
            return [PSCustomObject]@{
                IsConnected      = $false
                Name             = if ($info['Name']) { $info['Name'] } else { 'Wi-Fi' }
                Description      = if ($info['Description']) { $info['Description'] } else { 'Wireless Adapter' }
                State            = if ($info['State']) { $info['State'] } else { 'Disconnected / No WLAN' }
                SSID             = ""
                BSSID            = ""
                Vendor           = ""
                Band             = ""
                Channel          = ""
                RadioType        = ""
                Authentication   = ""
                Cipher           = ""
                ReceiveRateMbps  = ""
                TransmitRateMbps = ""
                SignalPercent    = 0
                Rssi             = ""
                Profile          = ""
            }
        }

        $bssid = if ($info['AP BSSID']) { $info['AP BSSID'] } elseif ($info['BSSID']) { $info['BSSID'] } else { "" }
        $vendor = if ($bssid) { Resolve-MacVendor -MacAddress $bssid } else { "Unknown" }

        $sigInt = 0
        if ($info['Signal'] -match '(\d+)') { $sigInt = [int]$Matches[1] }

        return [PSCustomObject]@{
            IsConnected      = $true
            Name             = if ($info['Name']) { $info['Name'] } else { 'Wi-Fi' }
            Description      = if ($info['Description']) { $info['Description'] } else { 'Wireless Adapter' }
            State            = $info['State']
            SSID             = if ($info['SSID']) { $info['SSID'] } else { "" }
            BSSID            = $bssid
            Vendor           = $vendor
            Band             = if ($info['Band']) { $info['Band'] } else { "" }
            Channel          = if ($info['Channel']) { $info['Channel'] } else { "" }
            RadioType        = if ($info['Radio type']) { $info['Radio type'] } else { "" }
            Authentication   = if ($info['Authentication']) { $info['Authentication'] } else { "" }
            Cipher           = if ($info['Cipher']) { $info['Cipher'] } else { "" }
            ReceiveRateMbps  = if ($info['Receive rate (Mbps)']) { $info['Receive rate (Mbps)'] } else { "" }
            TransmitRateMbps = if ($info['Transmit rate (Mbps)']) { $info['Transmit rate (Mbps)'] } else { "" }
            SignalPercent    = $sigInt
            Rssi             = if ($info['Rssi']) { $info['Rssi'] } else { "" }
            Profile          = if ($info['Profile']) { $info['Profile'] } else { "" }
        }
    } catch {
        return $null
    }
}

function Get-NearbyWifiNetworks {
    param(
        [string]$ConnectedBssid = "",
        [switch]$DoOnlineLookup,
        [switch]$ForceScan = $true,
        [int]$ScanWaitMs = 3000
    )

    try {
        # Helper to parse netsh output
        $parseNetsh = {
            $raw = & netsh.exe wlan show networks mode=bssid 2>$null
            if (-not $raw) { return @() }

            $nets = [System.Collections.Generic.List[PSCustomObject]]::new()
            $curSsid = $null
            $curNetType = ""
            $curAuth = ""
            $curEnc = ""
            $curBssidObj = $null

            foreach ($line in $raw) {
                $trimmed = $line.Trim()
                if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

                if ($trimmed -match '^SSID\s+\d+\s*:\s*(.*)$') {
                    if ($curBssidObj) {
                        $nets.Add([PSCustomObject]$curBssidObj)
                        $curBssidObj = $null
                    }
                    $ssidName = $Matches[1].Trim()
                    $curSsid = if ($ssidName) { $ssidName } else { "[Hidden SSID]" }
                    $curNetType = ""
                    $curAuth = ""
                    $curEnc = ""
                    continue
                }

                if ($trimmed -match '^Network type\s*:\s*(.*)$') {
                    $curNetType = $Matches[1].Trim()
                    continue
                }
                if ($trimmed -match '^Authentication\s*:\s*(.*)$') {
                    $curAuth = $Matches[1].Trim()
                    continue
                }
                if ($trimmed -match '^Encryption\s*:\s*(.*)$') {
                    $curEnc = $Matches[1].Trim()
                    continue
                }

                if ($trimmed -match '^BSSID\s+\d+\s*:\s*([0-9a-fA-F:-]{17})') {
                    if ($curBssidObj) {
                        $nets.Add([PSCustomObject]$curBssidObj)
                    }
                    $bssidMac = $Matches[1].Trim()
                    $isConn = ($ConnectedBssid -and ($bssidMac.ToLower() -eq $ConnectedBssid.ToLower()))
                    $vendor = Resolve-MacVendor -MacAddress $bssidMac -QueryOnline:$DoOnlineLookup

                    $curBssidObj = [ordered]@{
                        Status         = if ($isConn) { "CONNECTED" } else { "NEARBY" }
                        SSID           = $curSsid
                        BSSID          = $bssidMac
                        Vendor         = $vendor
                        NetworkType    = $curNetType
                        Authentication = $curAuth
                        Encryption     = $curEnc
                        SignalPercent  = 0
                        SignalBars     = "[....]   0%"
                        RadioType      = ""
                        Band           = ""
                        Channel        = ""
                        IsConnected    = $isConn
                    }
                    continue
                }

                if ($curBssidObj) {
                    if ($trimmed -match '^Signal\s*:\s*(\d+)%') {
                        $sigVal = [int]$Matches[1]
                        $curBssidObj['SignalPercent'] = $sigVal
                        $bars = if ($sigVal -ge 80) { "[####]" }
                                elseif ($sigVal -ge 60) { "[###.]" }
                                elseif ($sigVal -ge 40) { "[##..]" }
                                elseif ($sigVal -ge 20) { "[#...]" }
                                elseif ($sigVal -gt 0)  { "[#...]" }
                                else { "[....]" }
                        $curBssidObj['SignalBars'] = "$bars $('{0,3}' -f $sigVal)%"
                    } elseif ($trimmed -match '^Radio type\s*:\s*(.*)$') {
                        $curBssidObj['RadioType'] = $Matches[1].Trim()
                    } elseif ($trimmed -match '^Band\s*:\s*(.*)$') {
                        $curBssidObj['Band'] = $Matches[1].Trim()
                    } elseif ($trimmed -match '^Channel\s*:\s*(\d+)') {
                        $curBssidObj['Channel'] = $Matches[1].Trim()
                    }
                }
            }

            if ($curBssidObj) {
                $nets.Add([PSCustomObject]$curBssidObj)
            }
            return $nets
        }

        # Actively trigger 802.11 channel sweep across all Wi-Fi cards if requested
        if ($ForceScan) {
            try {
                [FastNetScanner.Core]::TriggerWlanScan($ScanWaitMs) | Out-Null
            } catch { }
        }

        $results = & $parseNetsh

        # If only 0 or 1 AP is found, force an active 3-second hardware sweep and re-query
        if ($results.Count -le 1) {
            try {
                [FastNetScanner.Core]::TriggerWlanScan(3000) | Out-Null
                $results = & $parseNetsh
            } catch { }
        }

        # Sort: Connected AP first, then signal strength descending
        $sortedNets = @($results | Sort-Object @{ Expression = { if ($_.IsConnected) { 0 } else { 1 } } },
                                               @{ Expression = { -$_.SignalPercent } })

        return ,$sortedNets
    } catch {
        return @()
    }
}

function Export-WifiSurvey {
    param(
        $Networks,
        $ConnectedWifi,
        [string]$ReportFolder = "Reports"
    )

    if (-not $Networks -or $Networks.Count -eq 0) {
        Write-Host " [!] No Wi-Fi networks available to export." -ForegroundColor Yellow
        return
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $baseDir = if ([System.IO.Path]::IsPathRooted($ReportFolder)) { $ReportFolder } else { Join-Path (Get-Location).Path $ReportFolder }
    $surveyFolder = Join-Path $baseDir "WifiSurvey_$timestamp"

    if (-not (Test-Path -Path $surveyFolder)) {
        [System.IO.Directory]::CreateDirectory($surveyFolder) | Out-Null
    }

    $csvFile = Join-Path $surveyFolder "wifi_survey.csv"
    $jsonFile = Join-Path $surveyFolder "wifi_survey.json"

    $Networks | Select-Object Status, SSID, BSSID, Vendor, SignalPercent, Channel, Band, RadioType, Authentication, Encryption, IsConnected |
        Export-Csv -Path $csvFile -NoTypeInformation -Encoding utf8

    $surveySummaryObj = [PSCustomObject]@{
        ScanTimestamp  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        ConnectedWifi  = if ($ConnectedWifi) { $ConnectedWifi } else { $null }
        DiscoveredAPs  = $Networks.Count
        Networks       = $Networks
    }
    $surveySummaryObj | ConvertTo-Json -Depth 4 | Out-File -FilePath $jsonFile -Encoding utf8

    Write-Host ""
    Write-Host " [+] Wi-Fi Survey successfully exported to: $surveyFolder" -ForegroundColor Green
    Write-Host "    |-- wifi_survey.csv  (CSV Spreadsheet)" -ForegroundColor DarkCyan
    Write-Host "    |-- wifi_survey.json (JSON Structured Dataset)" -ForegroundColor DarkCyan
    Write-Host ""
}

function Show-WifiSurvey {
    param(
        [switch]$DoOnlineLookup,
        [string]$BaseReportFolder = "Reports"
    )

    $loopSurvey = $true
    while ($loopSurvey) {
        $connWifi = Get-ConnectedWifiInfo
        $connBssid = if ($connWifi -and $connWifi.IsConnected) { $connWifi.BSSID } else { "" }

        Write-Host ""
        Write-Host "=========================================================================================================" -ForegroundColor Cyan
        Write-Host " [SCRY] WI-FI ENVIRONMENT & NEARBY ACCESS POINTS SURVEY" -ForegroundColor Cyan
        Write-Host "=========================================================================================================" -ForegroundColor Cyan

        if ($connWifi -and $connWifi.IsConnected) {
            Write-Host " Connected Network : " -NoNewline; Write-Host "$($connWifi.SSID)" -ForegroundColor Green -NoNewline
            Write-Host " (BSSID: $($connWifi.BSSID) - $($connWifi.Vendor))" -ForegroundColor DarkCyan
            Write-Host " Radio & Channel   : " -NoNewline; Write-Host "$($connWifi.RadioType) | Band: $($connWifi.Band) | Channel: $($connWifi.Channel)" -ForegroundColor Yellow
            $linkSpeedStr = if ($connWifi.ReceiveRateMbps -and $connWifi.TransmitRateMbps) { " | Link: Rx $($connWifi.ReceiveRateMbps) Mbps / Tx $($connWifi.TransmitRateMbps) Mbps" } else { "" }
            $rssiStr = if ($connWifi.Rssi) { " ($($connWifi.Rssi) dBm)" } else { "" }
            Write-Host " Signal & Link     : " -NoNewline; Write-Host "$($connWifi.SignalPercent)%$rssiStr$linkSpeedStr" -ForegroundColor Green
            Write-Host " Security / Cipher : " -NoNewline; Write-Host "$($connWifi.Authentication) ($($connWifi.Cipher))" -ForegroundColor White
            Write-Host " Interface Adapter : " -NoNewline; Write-Host "$($connWifi.Name) ($($connWifi.Description))" -ForegroundColor Gray
            Write-Host "---------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGray
        } elseif ($connWifi -and $connWifi.State) {
            Write-Host " Wi-Fi Interface   : $($connWifi.Name) ($($connWifi.Description)) - Status: $($connWifi.State)" -ForegroundColor Yellow
            Write-Host "---------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGray
        } else {
            Write-Host " [!] No active Wi-Fi interface detected on this machine (or WLAN AutoConfig service is stopped)." -ForegroundColor Yellow
            Write-Host "---------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGray
        }

        Write-Host " Sweeping wireless spectrum (2.4 GHz / 5 GHz / 6 GHz) for nearby access points..." -ForegroundColor Gray
        $nearby = Get-NearbyWifiNetworks -ConnectedBssid $connBssid -DoOnlineLookup:$DoOnlineLookup -ForceScan

        if (-not $nearby -or $nearby.Count -eq 0) {
            Write-Host " [-] No nearby wireless networks detected or Wi-Fi adapter is disabled." -ForegroundColor Yellow
            Write-Host "=========================================================================================================" -ForegroundColor Cyan
            return @()
        }

        Write-Host ""
        Write-Host (" {0,-3} {1,-24} {2,-18} {3,-12} {4,-12} {5,-10} {6,-17} {7}" -f "#", "SSID NAME", "BSSID (AP MAC)", "SIGNAL", "CHAN (BAND)", "RADIO", "SECURITY", "AP VENDOR") -ForegroundColor Cyan
        Write-Host "---------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGray

        $count = 1
        foreach ($net in $nearby) {
            $statusTag = if ($net.IsConnected) { "*" } else { " " }
            $ssidDisp = if ($net.SSID.Length -gt 22) { $net.SSID.Substring(0, 21) + "…" } else { $net.SSID }
            $vendorDisp = if ($net.Vendor.Length -gt 20) { $net.Vendor.Substring(0, 19) + "…" } else { $net.Vendor }
            $chanBand = if ($net.Band -match '5') { "$($net.Channel) (5G)" } elseif ($net.Band -match '6') { "$($net.Channel) (6G)" } elseif ($net.Band) { "$($net.Channel) (2.4G)" } else { "$($net.Channel)" }
            $secDisp = if ($net.Authentication.Length -gt 15) { $net.Authentication.Substring(0, 14) + "…" } else { $net.Authentication }

            Write-Host ("{0,2}{1,-1} " -f $count, $statusTag) -ForegroundColor $(if ($net.IsConnected) { "Green" } else { "DarkGray" }) -NoNewline
            Write-Host ("{0,-24} " -f $ssidDisp) -ForegroundColor $(if ($net.IsConnected) { "Green" } else { "Yellow" }) -NoNewline
            Write-Host ("{0,-18} " -f $net.BSSID) -ForegroundColor Gray -NoNewline
            
            $sigColor = if ($net.SignalPercent -ge 70) { "Green" } elseif ($net.SignalPercent -ge 40) { "Yellow" } else { "Red" }
            Write-Host ("{0,-12} " -f $net.SignalBars) -ForegroundColor $sigColor -NoNewline
            Write-Host ("{0,-12} " -f $chanBand) -ForegroundColor Cyan -NoNewline
            Write-Host ("{0,-10} " -f $net.RadioType) -ForegroundColor Gray -NoNewline
            Write-Host ("{0,-17} " -f $secDisp) -ForegroundColor DarkCyan -NoNewline
            Write-Host ("{0}" -f $vendorDisp) -ForegroundColor White

            $count++
        }

        Write-Host "=========================================================================================================" -ForegroundColor Cyan
        Write-Host " Found $($nearby.Count) visible access point(s). [*] indicates currently connected network." -ForegroundColor Green
        Write-Host ""
        Write-Host "Options: [R] Rescan / Refresh | [E] Export Survey (CSV/JSON) | [M] Return to Menu" -ForegroundColor DarkCyan
        Write-Host -NoNewline "Choice [M]: "
        $subChoice = Read-Host

        if ($subChoice -match '^[eE]') {
            Export-WifiSurvey -Networks $nearby -ConnectedWifi $connWifi -ReportFolder $BaseReportFolder
            Write-Host " Press ENTER to return to Wi-Fi view..." -ForegroundColor Gray
            $null = Read-Host
        } elseif ($subChoice -match '^[rR]') {
            # Loop again to rescan
            continue
        } else {
            $loopSurvey = $false
        }
    }

    return $nearby
}

# ====================================================================
# 5. HTML REPORT GENERATOR
# ====================================================================
function Generate-HtmlReport {
    param($Devices, $NetworkConfig, [string]$FilePath, [double]$ScanDurationSec, $WanInfo = $null, $WifiInfo = $null, $NearbyWifi = @())

    $fullReportPath = if ($FilePath) {
        try { [System.IO.Path]::GetFullPath($FilePath) } catch { $FilePath }
    } else { "" }

    $rowsHtml = New-Object System.Text.StringBuilder
    foreach ($d in $Devices) {
        $badgeClass = if ($d.IsGateway) { "badge-gateway" } elseif ($d.IsLocalHost) { "badge-local" } else { "badge-active" }
        $badgeText  = if ($d.IsGateway) { "Gateway" } elseif ($d.IsLocalHost) { "This PC" } else { "Active" }

        $portsBadge = ""
        if ($d.OpenPorts) {
            foreach ($p in ($d.OpenPorts -split ', ')) {
                $portsBadge += "<span class='port-chip'>$p</span>"
            }
        } else {
            $portsBadge = "<span class='text-muted'>-</span>"
        }

        $linkIp = $d.IP
        if ($d.OpenPorts -match '\b(80|8080|5000|8006|8123)\b') {
            $linkIp = "<a href='http://$($d.IP)' target='_blank' class='ip-link'>$($d.IP)</a>"
        } elseif ($d.OpenPorts -match '\b(443|8443|5001|9443)\b') {
            $linkIp = "<a href='https://$($d.IP)' target='_blank' class='ip-link'>$($d.IP)</a>"
        }

        $infoDetail = ""
        if ($d.HttpTitle) { $infoDetail += "<div class='detail-text'><strong>Title:</strong> " + [System.Net.WebUtility]::HtmlEncode($d.HttpTitle) + "</div>" }
        if ($d.HttpServer) { $infoDetail += "<div class='detail-text'><strong>Server:</strong> " + [System.Net.WebUtility]::HtmlEncode($d.HttpServer) + "</div>" }
        if ($d.Workgroup) { $infoDetail += "<div class='detail-text'><strong>Workgroup:</strong> " + [System.Net.WebUtility]::HtmlEncode($d.Workgroup) + "</div>" }
        if (-not $infoDetail) { $infoDetail = "<span class='text-muted'>-</span>" }

        $latencyStr = if ($d.LatencyMs -gt 0) { "$($d.LatencyMs) ms" } else { "&lt;1 ms" }

        $row = @"
        <tr>
            <td><span class='badge $badgeClass'>$badgeText</span></td>
            <td class='ip-cell'>$linkIp</td>
            <td class='mac-cell'>$($d.MAC)</td>
            <td class='type-cell'>$([System.Net.WebUtility]::HtmlEncode($d.DeviceType))</td>
            <td>$([System.Net.WebUtility]::HtmlEncode($d.HostName))</td>
            <td class='vendor-cell'>$([System.Net.WebUtility]::HtmlEncode($d.Vendor))</td>
            <td>$portsBadge</td>
            <td class='latency-cell'>$latencyStr</td>
            <td>$infoDetail</td>
        </tr>
"@
        [void]$rowsHtml.AppendLine($row)
    }

    $totalDevices = @($Devices).Count
    $gwCount = @($Devices | Where-Object { $_.IsGateway -or $_.DeviceType -match 'Router|Gateway' }).Count
    $pcCount = @($Devices | Where-Object { $_.DeviceType -match 'PC|Windows|Computer|Workstation' }).Count
    $printerCount = @($Devices | Where-Object { $_.DeviceType -match 'Printer' }).Count
    $iotCount = @($Devices | Where-Object { $_.DeviceType -match 'IoT|Smart Home' }).Count
    $storageCount = @($Devices | Where-Object { $_.DeviceType -match 'Storage|NAS' }).Count

    # Build Network Context Cards (Local Subnet, Wi-Fi Environment, External WAN)
    $wifiCardHtml = ""
    if ($WifiInfo -and $WifiInfo.IsConnected) {
        $wifiBandCh = if ($WifiInfo.Band -and $WifiInfo.Channel) { "$($WifiInfo.Band) &bull; Ch $($WifiInfo.Channel)" } elseif ($WifiInfo.Band) { $WifiInfo.Band } else { "" }
        $wifiSec = if ($WifiInfo.Authentication) { [System.Net.WebUtility]::HtmlEncode($WifiInfo.Authentication) } else { "Open" }
        $wifiVen = if ($WifiInfo.Vendor) { [System.Net.WebUtility]::HtmlEncode($WifiInfo.Vendor) } else { "Unknown" }
        $wifiSpeed = if ($WifiInfo.ReceiveRateMbps -and $WifiInfo.TransmitRateMbps) { " &bull; Rx $($WifiInfo.ReceiveRateMbps) / Tx $($WifiInfo.TransmitRateMbps) Mbps" } else { "" }

        $wifiCardHtml = @"
            <div class="card">
                <div class="card-header">
                    <span class="card-heading">Wi-Fi Environment</span>
                    <span class="badge badge-wifi">Connected</span>
                </div>
                <table class="kv-table">
                    <tr><td class="kv-key">SSID / Band</td><td class="kv-val mono font-bold">$([System.Net.WebUtility]::HtmlEncode($WifiInfo.SSID)) <span class="text-muted">($wifiBandCh)</span></td></tr>
                    <tr><td class="kv-key">AP BSSID / Vendor</td><td class="kv-val mono">$($WifiInfo.BSSID) <span class="text-muted">($wifiVen)</span></td></tr>
                    <tr><td class="kv-key">Signal &amp; Link</td><td class="kv-val mono" style="color: var(--success-fg); font-weight: 600;">$($WifiInfo.SignalPercent)% <span class="text-muted" style="font-weight: 400; color: var(--text-secondary);">($($WifiInfo.RadioType)$wifiSpeed)</span></td></tr>
                </table>
            </div>
"@
    } elseif ($WifiInfo -and $WifiInfo.State -and $WifiInfo.State -ne 'Disconnected / No WLAN') {
        $wifiCardHtml = @"
            <div class="card">
                <div class="card-header">
                    <span class="card-heading">Wi-Fi Environment</span>
                    <span class="badge badge-active">$([System.Net.WebUtility]::HtmlEncode($WifiInfo.State))</span>
                </div>
                <table class="kv-table">
                    <tr><td class="kv-key">Adapter</td><td class="kv-val">$([System.Net.WebUtility]::HtmlEncode($WifiInfo.Name))</td></tr>
                    <tr><td class="kv-key">Description</td><td class="kv-val text-muted">$([System.Net.WebUtility]::HtmlEncode($WifiInfo.Description))</td></tr>
                    <tr><td class="kv-key">Nearby APs</td><td class="kv-val">$(@($NearbyWifi).Count) visible access points</td></tr>
                </table>
            </div>
"@
    }

    $wanCardHtml = ""
    if ($WanInfo -and $WanInfo.IsConnected) {
        $locParts = @()
        if ($WanInfo.City) { $locParts += $WanInfo.City }
        if ($WanInfo.Country) { $locParts += $WanInfo.Country }
        $locStr = if ($locParts.Count -gt 0) { $locParts -join ", " } else { "Unknown" }

        $ispBrief = if ($WanInfo.ISP) { [System.Net.WebUtility]::HtmlEncode($WanInfo.ISP) } else { "Unknown ISP" }
        $hostBrief = if ($WanInfo.Hostname) { [System.Net.WebUtility]::HtmlEncode($WanInfo.Hostname) } else { "-" }
        $asnBrief = if ($WanInfo.ASN) { [System.Net.WebUtility]::HtmlEncode($WanInfo.ASN) } else { "-" }

        $wanCardHtml = @"
            <div class="card">
                <div class="card-header">
                    <span class="card-heading">External Uplink</span>
                    <span class="badge badge-gateway">Online</span>
                </div>
                <table class="kv-table">
                    <tr><td class="kv-key">Public IPv4</td><td class="kv-val mono" style="color: var(--accent); font-weight: 600;">$($WanInfo.IP)</td></tr>
                    <tr><td class="kv-key">ISP / Origin</td><td class="kv-val">$ispBrief &bull; $([System.Net.WebUtility]::HtmlEncode($locStr))</td></tr>
                    <tr><td class="kv-key">Hostname &amp; ASN</td><td class="kv-val mono" style="font-size: 11.5px; color: var(--text-secondary);">$hostBrief <span class="text-muted">($asnBrief)</span></td></tr>
                </table>
            </div>
"@
    } elseif ($WanInfo) {
        $wanCardHtml = @"
            <div class="card">
                <div class="card-header">
                    <span class="card-heading">External Uplink</span>
                    <span class="badge badge-offline">Offline</span>
                </div>
                <table class="kv-table">
                    <tr><td class="kv-key">Public IPv4</td><td class="kv-val text-muted">Offline / None</td></tr>
                    <tr><td class="kv-key">Internet Route</td><td class="kv-val text-muted">No external route detected</td></tr>
                    <tr><td class="kv-key">Environment</td><td class="kv-val text-muted">Isolated / Air-Gapped Network</td></tr>
                </table>
            </div>
"@
    }

    # Build Wi-Fi Nearby Access Points Table HTML
    $wifiSectionHtml = ""
    if ($NearbyWifi -and @($NearbyWifi).Count -gt 0) {
        $wifiRowsHtml = New-Object System.Text.StringBuilder
        foreach ($w in $NearbyWifi) {
            $wBadgeClass = if ($w.IsConnected) { "badge-gateway" } else { "badge-active" }
            $wBadgeText  = if ($w.IsConnected) { "Connected" } else { "Nearby" }

            $sigColor = if ($w.SignalPercent -ge 70) { "var(--success-fg)" }
                        elseif ($w.SignalPercent -ge 40) { "var(--warning-fg)" }
                        else { "#f85149" }

            $chanDisp = if ($w.Band -match '5') { "$($w.Channel) <span class='text-muted'>(5 GHz)</span>" }
                        elseif ($w.Band -match '6') { "$($w.Channel) <span class='text-muted'>(6 GHz)</span>" }
                        elseif ($w.Band) { "$($w.Channel) <span class='text-muted'>(2.4 GHz)</span>" }
                        else { "$($w.Channel)" }

            $encDisp = if ($w.Encryption) { "<span class='text-muted'>($($w.Encryption))</span>" } else { "" }

            $wRow = @"
            <tr>
                <td><span class='badge $wBadgeClass'>$wBadgeText</span></td>
                <td class='type-cell'><strong>$([System.Net.WebUtility]::HtmlEncode($w.SSID))</strong></td>
                <td class='mac-cell'>$($w.BSSID)</td>
                <td class='vendor-cell'>$([System.Net.WebUtility]::HtmlEncode($w.Vendor))</td>
                <td>
                    <div style='display: flex; align-items: center; gap: 8px;'>
                        <div class='sig-track'><div class='sig-fill' style='width: $($w.SignalPercent)%; background: $sigColor;'></div></div>
                        <span class='mono' style='font-size: 11.5px; font-weight: 600;'>$($w.SignalPercent)%</span>
                    </div>
                </td>
                <td class='latency-cell'>$chanDisp</td>
                <td><span class='port-chip'>$([System.Net.WebUtility]::HtmlEncode($w.RadioType))</span></td>
                <td>$([System.Net.WebUtility]::HtmlEncode($w.Authentication)) $encDisp</td>
            </tr>
"@
            [void]$wifiRowsHtml.AppendLine($wRow)
        }

        $wifiSectionHtml = @"
        <div style="margin-top: 28px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <div>
                <div style="font-size: 15px; font-weight: 600; color: var(--text-primary);">Nearby Wi-Fi Networks &amp; Access Points</div>
                <div style="font-size: 12px; color: var(--text-secondary);">Wireless environment survey &bull; $(@($NearbyWifi).Count) access point(s) detected</div>
            </div>
            <button class="btn" onclick="exportWifiTableToCSV('scry_wifi_survey.csv')">Export Wi-Fi CSV</button>
        </div>
        <div class="table-wrap" style="margin-bottom: 20px;">
            <table id="wifiTable">
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>SSID</th>
                        <th>BSSID (AP MAC)</th>
                        <th>Hardware Vendor</th>
                        <th>Signal</th>
                        <th>Channel / Band</th>
                        <th>Radio Type</th>
                        <th>Security</th>
                    </tr>
                </thead>
                <tbody>
                    $($wifiRowsHtml.ToString())
                </tbody>
            </table>
        </div>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SCRY &mdash; $($NetworkConfig.SubnetCidr)</title>
    <style>
        :root {
            --bg: #0d1117;
            --surface: #161b22;
            --surface-subtle: #21262d;
            --border: #30363d;
            --border-subtle: #21262d;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --text-muted: #6e7681;
            --accent: #58a6ff;
            --success-fg: #3fb950;
            --success-bg: rgba(46, 160, 67, 0.15);
            --success-border: rgba(46, 160, 67, 0.4);
            --warning-fg: #d29922;
            --warning-bg: rgba(187, 128, 9, 0.15);
            --warning-border: rgba(187, 128, 9, 0.4);
            --info-fg: #58a6ff;
            --info-bg: rgba(56, 139, 253, 0.15);
            --info-border: rgba(56, 139, 253, 0.4);
            --wifi-fg: #a371f7;
            --wifi-bg: rgba(163, 113, 247, 0.15);
            --wifi-border: rgba(163, 113, 247, 0.4);
            --row-hover: #1c2128;
            --mono-font: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
            --sans-font: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: var(--bg); color: var(--text-primary); font-family: var(--sans-font); font-size: 13px; line-height: 1.5; padding: 24px; }
        .wrapper { max-width: 1360px; margin: 0 auto; }
        
        /* Header */
        .page-header { display: flex; justify-content: space-between; align-items: flex-start; padding-bottom: 16px; border-bottom: 1px solid var(--border); margin-bottom: 20px; flex-wrap: wrap; gap: 12px; }
        .page-title { font-size: 18px; font-weight: 600; color: var(--text-primary); letter-spacing: -0.01em; }
        .page-subtitle { color: var(--text-secondary); font-size: 12px; margin-top: 2px; }
        .meta-group { display: flex; gap: 8px; flex-wrap: wrap; }
        .meta-pill { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 4px 10px; font-size: 12px; color: var(--text-secondary); }
        .meta-pill strong { color: var(--text-primary); font-weight: 600; }

        /* Stats Bar */
        .stats-bar { display: flex; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 20px; overflow-x: auto; }
        .stat-item { flex: 1; min-width: 110px; padding: 12px 16px; border-right: 1px solid var(--border); }
        .stat-item:last-child { border-right: none; }
        .stat-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); font-weight: 600; }
        .stat-number { font-size: 20px; font-weight: 600; color: var(--text-primary); margin-top: 2px; font-family: var(--mono-font); }
        
        /* Context Grid */
        .context-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 14px; margin-bottom: 20px; }
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 14px 16px; }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid var(--border-subtle); }
        .card-heading { font-size: 13px; font-weight: 600; color: var(--text-primary); }
        .kv-table { width: 100%; font-size: 12px; border-collapse: collapse; }
        .kv-table td { padding: 4px 0; vertical-align: top; }
        .kv-key { color: var(--text-muted); width: 130px; }
        .kv-val { color: var(--text-primary); font-weight: 500; word-break: break-all; }
        .kv-val.mono { font-family: var(--mono-font); }
        .font-bold { font-weight: 600; }
        
        /* Badges & Chips */
        .badge { display: inline-flex; align-items: center; padding: 2px 7px; border-radius: 12px; font-size: 11px; font-weight: 600; line-height: 1.2; text-transform: uppercase; letter-spacing: 0.03em; }
        .badge-gateway { background: var(--success-bg); color: var(--success-fg); border: 1px solid var(--success-border); }
        .badge-local { background: var(--info-bg); color: var(--info-fg); border: 1px solid var(--info-border); }
        .badge-active { background: var(--surface-subtle); color: var(--text-secondary); border: 1px solid var(--border); }
        .badge-offline { background: var(--warning-bg); color: var(--warning-fg); border: 1px solid var(--warning-border); }
        .badge-wifi { background: var(--wifi-bg); color: var(--wifi-fg); border: 1px solid var(--wifi-border); }
        
        .port-chip { display: inline-block; background: var(--surface-subtle); border: 1px solid var(--border); color: var(--text-secondary); padding: 1px 6px; border-radius: 3px; font-family: var(--mono-font); font-size: 11px; margin: 1px 2px 1px 0; }
        .sig-track { width: 56px; height: 6px; background: var(--surface-subtle); border-radius: 3px; overflow: hidden; border: 1px solid var(--border); }
        .sig-fill { height: 100%; border-radius: 2px; }

        /* Toolbar */
        .toolbar { display: flex; justify-content: space-between; gap: 12px; margin-bottom: 14px; flex-wrap: wrap; }
        .search-input { flex: 1; min-width: 260px; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 7px 12px; font-size: 13px; color: var(--text-primary); outline: none; transition: border-color 0.15s ease; }
        .search-input:focus { border-color: var(--accent); }
        .btn { background: var(--surface); border: 1px solid var(--border); color: var(--text-primary); padding: 7px 14px; border-radius: 6px; font-size: 12px; font-weight: 500; cursor: pointer; transition: background 0.15s ease; }
        .btn:hover { background: var(--surface-subtle); border-color: #8b949e; }

        /* Table */
        .table-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th { background: #161b22; color: var(--text-muted); font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; padding: 10px 14px; border-bottom: 1px solid var(--border); white-space: nowrap; }
        td { padding: 9px 14px; border-bottom: 1px solid var(--border-subtle); vertical-align: middle; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: var(--row-hover); }
        
        .ip-cell { font-family: var(--mono-font); font-weight: 600; font-size: 12.5px; }
        .ip-link { color: var(--accent); text-decoration: none; }
        .ip-link:hover { text-decoration: underline; }
        .mac-cell { font-family: var(--mono-font); color: var(--text-secondary); font-size: 12px; }
        .type-cell { font-weight: 500; }
        .vendor-cell { color: var(--text-secondary); }
        .latency-cell { font-family: var(--mono-font); color: var(--text-muted); font-size: 12px; }
        .detail-text { font-size: 11.5px; color: var(--text-secondary); margin-top: 2px; }
        .text-muted { color: var(--text-muted); }

        /* Footer */
        .page-footer { margin-top: 24px; text-align: center; color: var(--text-muted); font-size: 11.5px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <header class="page-header">
            <div>
                <div class="page-title">SCRY</div>
                <div class="page-subtitle">Subnet: <strong>$($NetworkConfig.SubnetCidr)</strong> &bull; Interface: <strong>$($NetworkConfig.InterfaceAlias)</strong> &bull; Gateway: <strong>$($NetworkConfig.GatewayIP)</strong></div>
            </div>
            <div class="meta-group">
                <div class="meta-pill">Scan Time: <strong>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</strong></div>
                <div class="meta-pill">Duration: <strong>$($ScanDurationSec)s</strong></div>
            </div>
        </header>

        <div class="stats-bar">
            <div class="stat-item"><div class="stat-label">Discovered</div><div class="stat-number">$totalDevices</div></div>
            <div class="stat-item"><div class="stat-label">Gateways</div><div class="stat-number" style="color: var(--success-fg);">$gwCount</div></div>
            <div class="stat-item"><div class="stat-label">Workstations</div><div class="stat-number">$pcCount</div></div>
            <div class="stat-item"><div class="stat-label">Storage / NAS</div><div class="stat-number">$storageCount</div></div>
            <div class="stat-item"><div class="stat-label">Printers</div><div class="stat-number">$printerCount</div></div>
            <div class="stat-item"><div class="stat-label">IoT / Smart</div><div class="stat-number">$iotCount</div></div>
        </div>

        <div class="context-grid">
            <div class="card">
                <div class="card-header">
                    <span class="card-heading">Local Network</span>
                    <span class="badge badge-local">Local</span>
                </div>
                <table class="kv-table">
                    <tr><td class="kv-key">Subnet CIDR</td><td class="kv-val mono">$($NetworkConfig.SubnetCidr)</td></tr>
                    <tr><td class="kv-key">Router Gateway</td><td class="kv-val mono">$($NetworkConfig.GatewayIP)</td></tr>
                    <tr><td class="kv-key">Scanner Host</td><td class="kv-val mono">$($NetworkConfig.LocalIP) <span class="text-muted">($($NetworkConfig.InterfaceAlias))</span></td></tr>
                </table>
            </div>

            $wifiCardHtml
            $wanCardHtml
        </div>

        <div class="toolbar">
            <input type="text" id="searchInput" class="search-input" placeholder="Filter by IP, MAC, Hostname, Vendor, or Device Type..." onkeyup="filterTable()">
            <button class="btn" onclick="exportTableToCSV('scry_devices.csv')">Export CSV</button>
        </div>

        <div class="table-wrap">
            <table id="deviceTable">
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>IP Address</th>
                        <th>MAC Address</th>
                        <th>Device Type</th>
                        <th>Hostname / NetBIOS</th>
                        <th>Hardware Vendor</th>
                        <th>Open Ports</th>
                        <th>Latency</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    $($rowsHtml.ToString())
                </tbody>
            </table>
        </div>

        $wifiSectionHtml

        <footer class="page-footer">
            Generated by SCRY &bull; $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')$(if ($fullReportPath) { " &bull; <code style='font-family: var(--mono-font); font-size: 11px; color: var(--text-secondary);'>$([System.Net.WebUtility]::HtmlEncode($fullReportPath))</code>" } else { "" })
        </footer>
    </div>

    <script>
        function filterTable() {
            var input = document.getElementById("searchInput");
            var filter = input.value.toLowerCase();
            var table = document.getElementById("deviceTable");
            var tr = table.getElementsByTagName("tr");
            for (var i = 1; i < tr.length; i++) {
                var text = tr[i].textContent || tr[i].innerText;
                tr[i].style.display = text.toLowerCase().indexOf(filter) > -1 ? "" : "none";
            }
        }

        function exportTableToCSV(filename) {
            var csv = [];
            var rows = document.querySelectorAll("#deviceTable tr");
            for (var i = 0; i < rows.length; i++) {
                var row = [], cols = rows[i].querySelectorAll("td, th");
                for (var j = 0; j < cols.length; j++) {
                    var data = cols[j].innerText.replace(/(\r\n|\n|\r)/gm, " ").replace(/"/g, '""');
                    row.push('"' + data + '"');
                }
                csv.push(row.join(","));
            }
            var csvFile = new Blob([csv.join("\n")], { type: "text/csv" });
            var downloadLink = document.createElement("a");
            downloadLink.download = filename;
            downloadLink.href = window.URL.createObjectURL(csvFile);
            downloadLink.style.display = "none";
            document.body.appendChild(downloadLink);
            downloadLink.click();
        }

        function exportWifiTableToCSV(filename) {
            var csv = [];
            var rows = document.querySelectorAll("#wifiTable tr");
            for (var i = 0; i < rows.length; i++) {
                var row = [], cols = rows[i].querySelectorAll("td, th");
                for (var j = 0; j < cols.length; j++) {
                    var data = cols[j].innerText.replace(/(\r\n|\n|\r)/gm, " ").replace(/"/g, '""');
                    row.push('"' + data + '"');
                }
                csv.push(row.join(","));
            }
            var csvFile = new Blob([csv.join("\n")], { type: "text/csv" });
            var downloadLink = document.createElement("a");
            downloadLink.download = filename;
            downloadLink.href = window.URL.createObjectURL(csvFile);
            downloadLink.style.display = "none";
            document.body.appendChild(downloadLink);
            downloadLink.click();
        }
    </script>
</body>
</html>
"@

    $html | Out-File -FilePath $FilePath -Encoding utf8 -Force
}

# ====================================================================
# 6. SCANNER EXECUTION PIPELINE
# ====================================================================
function Invoke-NetworkScanner {
    param(
        [string]$TargetSubnet,
        [string]$TargetInterface,
        [switch]$IsQuickScan,
        [switch]$IsDeepScan,
        [switch]$DoOnlineLookup,
        [int]$ProbeTimeoutMs = 350,
        [int]$TasksThrottle = 64,
        [string]$BaseReportFolder = "Reports",
        [switch]$DisableReport,
        [switch]$AutoOpenReport,
        [string]$CustomHtmlPath,
        [string]$CustomCsvPath,
        [string]$CustomJsonPath,
        [switch]$DisplayGrid,
        [switch]$SilentMode,
        [switch]$DoRenewDhcp,
        [switch]$BypassDhcpCheck,
        [int]$DhcpWaitSec = 12,
        [switch]$SkipWanLookup,
        [int]$WanTimeout = 3,
        [switch]$SkipWifiScan
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    # Step A: Verify Network Link / DHCP
    if (-not $BypassDhcpCheck -and (-not $SilentMode)) {
        Ensure-NetworkConnection -PreferredInterface $TargetInterface -ForceRenew:$DoRenewDhcp -WaitTimeoutSec $DhcpWaitSec
    }

    # Step A.1: External WAN Discovery
    $wanInfo = $null
    if (-not $SkipWanLookup) {
        if (-not $SilentMode) {
            Write-Host " [*] Checking Internet connectivity & External WAN IP..." -ForegroundColor DarkGray
        }
        $wanInfo = Get-ExternalNetworkInfo -TimeoutMs ($WanTimeout * 1000)
    }

    # Step A.2: Wi-Fi Environment Discovery
    $wifiInfo = Get-ConnectedWifiInfo
    $nearbyWifi = @()
    if (-not $SkipWifiScan) {
        if (-not $SilentMode) {
            Write-Host " [*] Sweeping wireless spectrum (2.4 GHz / 5 GHz / 6 GHz) for nearby access points..." -ForegroundColor DarkGray
        }
        $connBssid = if ($wifiInfo -and $wifiInfo.IsConnected) { $wifiInfo.BSSID } else { "" }
        $nearbyWifi = Get-NearbyWifiNetworks -ConnectedBssid $connBssid -DoOnlineLookup:$DoOnlineLookup -ForceScan:$true -ScanWaitMs 3000
    }

    $netConfig = $null
    $ipsToScan = [System.Collections.Generic.List[string]]::new()

    if ($TargetSubnet) {
        $parsed = [FastNetScanner.Core]::ParseIpRange($TargetSubnet)
        if ($parsed.Count -eq 0) {
            Write-Error "Invalid subnet or IP range specified: '$TargetSubnet'."
            return $null
        }
        foreach ($p in $parsed) { $ipsToScan.Add($p) }
        $activeIfs = Get-AllActiveNetworkInterfaces
        $matchingIf = if ($activeIfs) { $activeIfs | Select-Object -First 1 } else { $null }

        $netConfig = @{
            SubnetCidr     = $TargetSubnet
            InterfaceAlias = if ($matchingIf) { $matchingIf.InterfaceAlias } else { "Custom Subnet" }
            LocalIP        = if ($matchingIf) { $matchingIf.LocalIP } else { "127.0.0.1" }
            GatewayIP      = if ($matchingIf) { $matchingIf.GatewayIP } else { $null }
            HostCount      = $ipsToScan.Count
        }
    } else {
        try {
            $netConfig = Get-ActiveNetworkConfig -PreferredInterface $TargetInterface
            $parsed = [FastNetScanner.Core]::ParseIpRange($netConfig.SubnetCidr)
            foreach ($p in $parsed) { $ipsToScan.Add($p) }
        } catch {
            Write-Error $_.Exception.Message
            return $null
        }
    }

    if (-not $SilentMode) {
        Write-Host ""
        Write-Host "=================================================================" -ForegroundColor Cyan
        Write-Host " [SCRY]" -ForegroundColor Cyan
        Write-Host "=================================================================" -ForegroundColor Cyan
        Write-Host " Target Subnet     : " -NoNewline; Write-Host "$($netConfig.SubnetCidr)" -ForegroundColor Yellow

        $ifDisp = "$($netConfig.InterfaceAlias)"
        if ($wifiInfo -and $wifiInfo.IsConnected -and ($netConfig.InterfaceAlias -match 'Wi-Fi|Wireless|WLAN' -or $wifiInfo.Name -eq $netConfig.InterfaceAlias)) {
            $ifDisp += " (Connected: `"$($wifiInfo.SSID)`" | $($wifiInfo.SignalPercent)% Signal | $($wifiInfo.Band) Ch $($wifiInfo.Channel))"
        }
        Write-Host " Active Interface  : " -NoNewline; Write-Host "$ifDisp" -ForegroundColor Yellow
        Write-Host " Default Gateway   : " -NoNewline; Write-Host "$($netConfig.GatewayIP)" -ForegroundColor Yellow
        Write-Host " Local Computer IP : " -NoNewline; Write-Host "$($netConfig.LocalIP)" -ForegroundColor Yellow
        if ($wanInfo -and $wanInfo.IsConnected) {
            $wanLoc = if ($wanInfo.City -and $wanInfo.Country) { "$($wanInfo.City), $($wanInfo.Country)" } elseif ($wanInfo.Country) { $wanInfo.Country } else { "" }
            $wanTag = "$($wanInfo.IP)"
            if ($wanInfo.ISP) {
                if ($wanLoc) {
                    $wanTag += " ($($wanInfo.ISP) - $wanLoc)"
                } else {
                    $wanTag += " ($($wanInfo.ISP))"
                }
            }
            Write-Host " Public / WAN IP   : " -NoNewline; Write-Host "$wanTag" -ForegroundColor Green
        } elseif ($wanInfo) {
            Write-Host " Public / WAN IP   : " -NoNewline; Write-Host "Offline / Isolated Local LAN" -ForegroundColor DarkGray
        }
        Write-Host " Scan Mode         : " -NoNewline
        if ($IsQuickScan) {
            Write-Host "Quick (ARP + Ping + DNS)" -ForegroundColor Green
        } elseif ($IsDeepScan) {
            Write-Host "Deep (Extended 25+ Ports & Web Title Grab)" -ForegroundColor Magenta
        } else {
            Write-Host "Standard (ARP + Ping + DNS + Top Ports & Web Titles)" -ForegroundColor Green
        }
        Write-Host " Total Hosts       : " -NoNewline; Write-Host "$($ipsToScan.Count) IP addresses" -ForegroundColor White
        Write-Host "=================================================================" -ForegroundColor Cyan
        Write-Host "Scanning network in parallel, please wait..." -ForegroundColor Gray
    }

    # Step B: Determine Port List
    $ports = if ($IsQuickScan) {
        [int[]]@()
    } elseif ($IsDeepScan) {
        [int[]]@(21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 515, 631, 1883, 1900, 3000, 3389, 5000, 5001, 5353, 8006, 8080, 8123, 8443, 9000, 9100, 9443, 32400)
    } else {
        [int[]]@(22, 23, 53, 80, 443, 445, 515, 631, 1883, 3389, 5000, 8006, 8080, 8123, 8443, 9100)
    }

    # Step C: Perform Parallel Scan
    $rawResults = [FastNetScanner.Core]::ScanIpList(
        $ipsToScan.ToArray(),
        $netConfig.LocalIP,
        $netConfig.GatewayIP,
        $ports,
        $ProbeTimeoutMs,
        $TasksThrottle,
        [bool]$IsQuickScan,
        [bool]$IsDeepScan
    )

    # Step D: Process & Classify Results
    $finalResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($r in $rawResults) {
        $vendor = Resolve-MacVendor -MacAddress $r.MAC -QueryOnline:$DoOnlineLookup
        $classInfo = Get-DeviceClassification -HostObj $r -Vendor $vendor

        $dispName = if (-not [string]::IsNullOrEmpty($r.NetBiosName)) {
            if (-not [string]::IsNullOrEmpty($r.HostName) -and $r.HostName -ne $r.NetBiosName) {
                "$($r.NetBiosName) ($($r.HostName))"
            } else {
                $r.NetBiosName
            }
        } elseif (-not [string]::IsNullOrEmpty($r.HostName)) {
            $r.HostName
        } else {
            "-"
        }

        $statusBadge = if ($r.IsGateway) { "GATEWAY" } elseif ($r.IsLocalHost) { "THIS PC" } else { "ONLINE" }

        $obj = [PSCustomObject]@{
            Status      = $statusBadge
            IP          = $r.IP
            MAC         = if ($r.MAC) { $r.MAC } else { "N/A" }
            DeviceType  = $classInfo.Type
            TypeIcon    = $classInfo.Icon
            HtmlIcon    = $classInfo.HtmlIcon
            Category    = $classInfo.Category
            HostName    = $dispName
            Vendor      = $vendor
            OpenPorts   = $r.OpenPorts
            HttpTitle   = $r.HttpTitle
            HttpServer  = $r.HttpServer
            Workgroup   = $r.Workgroup
            LatencyMs   = if ($r.PingLatencyMs -ge 0) { $r.PingLatencyMs } else { 0 }
            IsGateway   = $r.IsGateway
            IsLocalHost = $r.IsLocalHost
        }

        $finalResults.Add($obj)
    }

    # Sort logically: Gateway first, LocalHost second, then by numeric IPv4 address
    $sortedResults = @($finalResults | Sort-Object -Property @{
        Expression = {
            if ($_.IsGateway) { 0 }
            elseif ($_.IsLocalHost) { 1 }
            else { 2 }
        }
    }, @{
        Expression = {
            $octets = $_.IP.Split('.')
            if ($octets.Length -eq 4) {
                ([uint32]$octets[0] -shl 24) -bor ([uint32]$octets[1] -shl 16) -bor ([uint32]$octets[2] -shl 8) -bor [uint32]$octets[3]
            } else { 0 }
        }
    })

    $stopwatch.Stop()
    $scanDuration = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 2)
    $devCount = $sortedResults.Count

    # Step E: Display Formatted Console Output
    if (-not $SilentMode) {
        Write-Host ""
        Write-Host "=========================================================================================================" -ForegroundColor DarkGray
        Write-Host (" {0,-9} {1,-15} {2,-18} {3,-26} {4,-24} {5,-18}" -f "STATUS", "IP ADDRESS", "MAC ADDRESS", "IDENTIFIED DEVICE", "HOSTNAME / NETBIOS", "VENDOR") -ForegroundColor Cyan
        Write-Host "=========================================================================================================" -ForegroundColor DarkGray

        foreach ($dev in $sortedResults) {
            $statusColor = if ($dev.IsGateway) { "Yellow" } elseif ($dev.IsLocalHost) { "Cyan" } else { "Green" }
            $typeWithIcon = "$($dev.TypeIcon) $($dev.DeviceType)"

            Write-Host (" {0,-9} " -f "[$($dev.Status)]") -ForegroundColor $statusColor -NoNewline
            Write-Host ("{0,-15} " -f $dev.IP) -ForegroundColor White -NoNewline
            Write-Host ("{0,-18} " -f $dev.MAC) -ForegroundColor Yellow -NoNewline
            Write-Host ("{0,-26} " -f $typeWithIcon) -ForegroundColor Green -NoNewline
            Write-Host ("{0,-24} " -f ($dev.HostName.Substring(0, [Math]::Min(23, $dev.HostName.Length)))) -ForegroundColor Gray -NoNewline
            Write-Host ("{0,-18}" -f ($dev.Vendor.Substring(0, [Math]::Min(18, $dev.Vendor.Length)))) -ForegroundColor DarkCyan

            $extraInfo = @()
            if ($dev.OpenPorts) { $extraInfo += "Open Ports: [$($dev.OpenPorts)]" }
            if ($dev.HttpTitle) { $extraInfo += "Web: '$($dev.HttpTitle)'" }
            if ($dev.LatencyMs -gt 0) { $extraInfo += "Ping: $($dev.LatencyMs)ms" }

            if ($extraInfo.Count -gt 0) {
                Write-Host ("            |-- " + ($extraInfo -join " | ")) -ForegroundColor DarkGray
            }
        }

        Write-Host "=========================================================================================================" -ForegroundColor DarkGray
        Write-Host " Scan completed in $scanDuration seconds. Found $devCount active device(s)." -ForegroundColor Green
        if ($wanInfo -and $wanInfo.IsConnected) {
            $wanSummaryLoc = if ($wanInfo.City -and $wanInfo.Country) { "$($wanInfo.City), $($wanInfo.Country)" } elseif ($wanInfo.Country) { $wanInfo.Country } else { "" }
            Write-Host " WAN Context: Public IP $($wanInfo.IP) | ISP: $($wanInfo.ISP) | Location: $wanSummaryLoc ($($wanInfo.ASN))" -ForegroundColor Cyan
        }
        Write-Host ""
    }

    # Step E.1: Refresh Wi-Fi Survey right before report generation (capturing full background sweep)
    if (-not $SkipWifiScan -and (@($nearbyWifi).Count -le 1)) {
        $connBssid = if ($wifiInfo -and $wifiInfo.IsConnected) { $wifiInfo.BSSID } else { "" }
        $refreshedWifi = Get-NearbyWifiNetworks -ConnectedBssid $connBssid -DoOnlineLookup:$DoOnlineLookup -ForceScan:$true -ScanWaitMs 3000
        if ($refreshedWifi -and @($refreshedWifi).Count -gt @($nearbyWifi).Count) {
            $nearbyWifi = $refreshedWifi
        }
    }

    # Step F: Export Files & Timestamped Report Folder
    $generatedHtmlPath = $null

    if (-not $DisableReport) {
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $baseDir = if ([System.IO.Path]::IsPathRooted($BaseReportFolder)) { $BaseReportFolder } else { Join-Path (Get-Location).Path $BaseReportFolder }
        $scanFolder = Join-Path $baseDir $timestamp

        if (-not (Test-Path -Path $scanFolder)) {
            [System.IO.Directory]::CreateDirectory($scanFolder) | Out-Null
        }

        $autoHtml = Join-Path $scanFolder "report.html"
        $autoCsv  = Join-Path $scanFolder "devices.csv"
        $autoJson = Join-Path $scanFolder "devices.json"
        $autoWifiJson = Join-Path $scanFolder "wifi_survey.json"
        $autoNetJson = Join-Path $scanFolder "network_info.json"
        $autoTxt  = Join-Path $scanFolder "summary.txt"

        # 1. HTML Report
        Generate-HtmlReport -Devices $sortedResults -NetworkConfig $netConfig -FilePath $autoHtml -ScanDurationSec $scanDuration -WanInfo $wanInfo -WifiInfo $wifiInfo -NearbyWifi $nearbyWifi
        $generatedHtmlPath = $autoHtml

        # 2. CSV Report
        $sortedResults | Select-Object Status, IP, MAC, DeviceType, HostName, Vendor, OpenPorts, HttpTitle, HttpServer, Workgroup, LatencyMs |
            Export-Csv -Path $autoCsv -NoTypeInformation -Encoding utf8

        # 3. JSON Device Report
        $sortedResults | ConvertTo-Json -Depth 4 | Out-File -FilePath $autoJson -Encoding utf8

        # 3b. JSON Wi-Fi Survey Report (if wireless networks discovered)
        if ($nearbyWifi -and @($nearbyWifi).Count -gt 0) {
            $nearbyWifi | ConvertTo-Json -Depth 4 | Out-File -FilePath $autoWifiJson -Encoding utf8
        }

        # 3c. JSON Network & WAN Metadata Report
        $netSummaryObj = [PSCustomObject]@{
            ScanTimestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            ScanDurationSec = $scanDuration
            TargetSubnet    = $netConfig.SubnetCidr
            InterfaceAlias  = $netConfig.InterfaceAlias
            GatewayIP       = $netConfig.GatewayIP
            LocalIP         = $netConfig.LocalIP
            DiscoveredCount = $sortedResults.Count
            ExternalWAN     = if ($wanInfo) { $wanInfo } else { $null }
            WifiContext     = [PSCustomObject]@{
                Connected      = if ($wifiInfo) { $wifiInfo } else { $null }
                NearbyCount    = @($nearbyWifi).Count
                NearbyNetworks = $nearbyWifi
            }
        }
        $netSummaryObj | ConvertTo-Json -Depth 4 | Out-File -FilePath $autoNetJson -Encoding utf8

        # 4. Text Summary
        $txtSummary = New-Object System.Text.StringBuilder
        [void]$txtSummary.AppendLine("=================================================================")
        [void]$txtSummary.AppendLine(" SCRY - SUMMARY - $timestamp")
        [void]$txtSummary.AppendLine("=================================================================")
        [void]$txtSummary.AppendLine("Subnet     : $($netConfig.SubnetCidr)")
        [void]$txtSummary.AppendLine("Interface  : $($netConfig.InterfaceAlias)")
        [void]$txtSummary.AppendLine("Gateway IP : $($netConfig.GatewayIP)")
        [void]$txtSummary.AppendLine("This PC IP : $($netConfig.LocalIP)")
        if ($wifiInfo -and $wifiInfo.IsConnected) {
            [void]$txtSummary.AppendLine("-----------------------------------------------------------------")
            [void]$txtSummary.AppendLine("WI-FI ENVIRONMENT & NEARBY ACCESS POINTS")
            [void]$txtSummary.AppendLine("-----------------------------------------------------------------")
            [void]$txtSummary.AppendLine("Connected  : $($wifiInfo.SSID) (BSSID: $($wifiInfo.BSSID) - $($wifiInfo.Vendor))")
            $txtLink = if ($wifiInfo.ReceiveRateMbps -and $wifiInfo.TransmitRateMbps) { " | Link: Rx $($wifiInfo.ReceiveRateMbps) Mbps / Tx $($wifiInfo.TransmitRateMbps) Mbps" } else { "" }
            $txtRssi = if ($wifiInfo.Rssi) { " ($($wifiInfo.Rssi) dBm)" } else { "" }
            [void]$txtSummary.AppendLine("Signal     : $($wifiInfo.SignalPercent)%$txtRssi$txtLink")
            [void]$txtSummary.AppendLine("Radio/Chan : $($wifiInfo.RadioType) | Band: $($wifiInfo.Band) | Channel: $($wifiInfo.Channel)")
            [void]$txtSummary.AppendLine("Security   : $($wifiInfo.Authentication) ($($wifiInfo.Cipher))")
        }
        if ($nearbyWifi -and @($nearbyWifi).Count -gt 0) {
            [void]$txtSummary.AppendLine("Visible Access Points ($(@($nearbyWifi).Count) APs):")
            $idx = 1
            foreach ($nw in $nearbyWifi) {
                $star = if ($nw.IsConnected) { "*" } else { " " }
                $ssidN = if ($nw.SSID.Length -gt 20) { $nw.SSID.Substring(0,19) + "…" } else { $nw.SSID }
                $venN = if ($nw.Vendor.Length -gt 16) { $nw.Vendor.Substring(0,15) + "…" } else { $nw.Vendor }
                [void]$txtSummary.AppendLine(("{0,2}{1,-1} {2,-20} {3,-18} {4,-12} {5,-8} {6,-10} {7,-14} {8}" -f $idx, $star, $ssidN, $nw.BSSID, $nw.SignalBars, $nw.Channel, $nw.RadioType, $nw.Authentication, $venN))
                $idx++
            }
        }
        if ($wanInfo -and $wanInfo.IsConnected) {
            [void]$txtSummary.AppendLine("-----------------------------------------------------------------")
            [void]$txtSummary.AppendLine("Public IP  : $($wanInfo.IP)")
            if ($wanInfo.Hostname) { [void]$txtSummary.AppendLine("Hostname   : $($wanInfo.Hostname)") }
            $ispLine = if ($wanInfo.Org -and $wanInfo.Org -ne $wanInfo.ISP) { "$($wanInfo.ISP) / $($wanInfo.Org)" } else { "$($wanInfo.ISP)" }
            [void]$txtSummary.AppendLine("ISP / Org  : $ispLine")
            if ($wanInfo.ASN) { [void]$txtSummary.AppendLine("ASN        : $($wanInfo.ASN)") }
            $locParts = @()
            if ($wanInfo.City) { $locParts += $wanInfo.City }
            if ($wanInfo.Region) { $locParts += $wanInfo.Region }
            if ($wanInfo.Country) { $locParts += "$($wanInfo.Country) ($($wanInfo.CountryCode))" }
            if ($wanInfo.PostalCode) { $locParts += "[Zip: $($wanInfo.PostalCode)]" }
            if ($locParts.Count -gt 0) { [void]$txtSummary.AppendLine("Location   : " + ($locParts -join ", ")) }
            if ($wanInfo.Coordinates -or $wanInfo.Timezone) {
                $gParts = @()
                if ($wanInfo.Coordinates) { $gParts += "Coords: $($wanInfo.Coordinates)" }
                if ($wanInfo.Timezone) { $gParts += "TZ: $($wanInfo.Timezone)" }
                [void]$txtSummary.AppendLine("Geo Info   : " + ($gParts -join " | "))
            }
            [void]$txtSummary.AppendLine("Source     : $($wanInfo.SourceService)")
            [void]$txtSummary.AppendLine("Status     : ONLINE (Internet Connected)")
        } elseif ($wanInfo) {
            [void]$txtSummary.AppendLine("-----------------------------------------------------------------")
            [void]$txtSummary.AppendLine("Public IP  : Offline / Isolated LAN")
            [void]$txtSummary.AppendLine("Status     : OFFLINE (No Internet Connection)")
        }
        [void]$txtSummary.AppendLine("-----------------------------------------------------------------")
        [void]$txtSummary.AppendLine("Scanned in $scanDuration seconds. Found $devCount active device(s).")
        [void]$txtSummary.AppendLine("=================================================================")
        foreach ($d in $sortedResults) {
            [void]$txtSummary.AppendLine(("{0,-9} {1,-15} {2,-18} {3,-26} {4,-24} {5}" -f "[$($d.Status)]", $d.IP, $d.MAC, $d.DeviceType, $d.HostName, $d.Vendor))
            if ($d.OpenPorts -or $d.HttpTitle) {
                $extra = @()
                if ($d.OpenPorts) { $extra += "Ports: [$($d.OpenPorts)]" }
                if ($d.HttpTitle) { $extra += "Web: '$($d.HttpTitle)'" }
                [void]$txtSummary.AppendLine("            |-- " + ($extra -join " | "))
            }
        }
        $txtSummary.ToString() | Out-File -FilePath $autoTxt -Encoding utf8

        if (-not $SilentMode) {
            Write-Host " [REPORTS] Saved unique scan to: $scanFolder" -ForegroundColor Cyan
            Write-Host "    |-- report.html       (Interactive HTML Dashboard with WAN & Wi-Fi Intelligence)" -ForegroundColor DarkCyan
            Write-Host "    |-- devices.csv       (CSV Spreadsheet)" -ForegroundColor DarkCyan
            Write-Host "    |-- devices.json      (JSON Device Dataset)" -ForegroundColor DarkCyan
            if ($nearbyWifi -and @($nearbyWifi).Count -gt 0) {
                Write-Host "    |-- wifi_survey.json  (Nearby Wi-Fi Environment & SSIDs)" -ForegroundColor DarkCyan
            }
            Write-Host "    |-- network_info.json (Network, Wi-Fi & WAN Metadata)" -ForegroundColor DarkCyan
            Write-Host "    |-- summary.txt       (Text Summary Log)" -ForegroundColor DarkCyan
            Write-Host ""
        }
    }

    # Custom Additional File Exports
    if ($CustomHtmlPath) {
        Generate-HtmlReport -Devices $sortedResults -NetworkConfig $netConfig -FilePath $CustomHtmlPath -ScanDurationSec $scanDuration -WanInfo $wanInfo -WifiInfo $wifiInfo -NearbyWifi $nearbyWifi
        if (-not $SilentMode) { Write-Host " Additional HTML saved to: $CustomHtmlPath" -ForegroundColor Cyan }
    }

    if ($CustomCsvPath) {
        $sortedResults | Select-Object Status, IP, MAC, DeviceType, HostName, Vendor, OpenPorts, HttpTitle, HttpServer, Workgroup, LatencyMs |
            Export-Csv -Path $CustomCsvPath -NoTypeInformation -Encoding utf8
        if (-not $SilentMode) { Write-Host " Additional CSV saved to: $CustomCsvPath" -ForegroundColor Cyan }
    }

    if ($CustomJsonPath) {
        $sortedResults | ConvertTo-Json -Depth 4 | Out-File -FilePath $CustomJsonPath -Encoding utf8
        if (-not $SilentMode) { Write-Host " Additional JSON saved to: $CustomJsonPath" -ForegroundColor Cyan }
    }

    if ($AutoOpenReport -and $generatedHtmlPath -and (Test-Path $generatedHtmlPath)) {
        try { Start-Process $generatedHtmlPath } catch { }
    }

    if ($DisplayGrid) {
        $sortedResults | Select-Object Status, IP, MAC, DeviceType, HostName, Vendor, OpenPorts, HttpTitle, LatencyMs |
            Out-GridView -Title "Network Devices ($($netConfig.SubnetCidr))"
    }

    return $sortedResults
}

# ====================================================================
# 7. INTERACTIVE MENU LOOP & ADAPTER SELECTION
# ====================================================================
function Pause-MenuPrompt {
    Write-Host ""
    Write-Host " Press ENTER or any key to return to menu..." -ForegroundColor Gray
    try {
        if ([Console]::IsInputRedirected) {
            $null = [Console]::ReadLine()
        } else {
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    } catch {
        $null = Read-Host
    }
}

function Start-InteractiveMenu {
    param(
        [string]$DefaultReportDir = "Reports",
        [string]$TargetInterface,
        [string]$TargetSubnet
    )

    $selectedInterface = $TargetInterface
    $selectedSubnet = $TargetSubnet
    $continueMenu = $true

    # Startup link check: If no valid IP or router gateway is detected, offer to renew DHCP automatically
    $startupIfs = Get-AllActiveNetworkInterfaces
    if ((-not $startupIfs -or $startupIfs.Count -eq 0 -or (-not $startupIfs[0].GatewayIP)) -and (-not $selectedSubnet)) {
        Write-Host ""
        Write-Host "=================================================================" -ForegroundColor Yellow
        Write-Host " [!] Notice: No active IPv4 address or default gateway detected." -ForegroundColor Yellow
        Write-Host "=================================================================" -ForegroundColor Yellow
        Write-Host -NoNewline " Would you like to request a fresh DHCP lease from the router now? [Y/n]: "
        $renewAns = Read-Host
        if ([string]::IsNullOrWhiteSpace($renewAns) -or $renewAns -match '^[yY]') {
            Ensure-NetworkConnection -PreferredInterface $selectedInterface -ForceRenew
            $script:CachedWanInfo = $null
            $script:LastWanCheck = [DateTime]::MinValue
        }
    }

    while ($continueMenu) {
        $activeIfs = Get-AllActiveNetworkInterfaces
        $currentCfg = $null

        if ($selectedSubnet) {
            $currentCfg = @{
                InterfaceAlias = "Custom Subnet"
                SubnetCidr     = $selectedSubnet
                GatewayIP      = "-"
                LocalIP        = "Custom"
            }
        } elseif ($selectedInterface) {
            $matched = $activeIfs | Where-Object { $_.InterfaceAlias -like "*$selectedInterface*" } | Select-Object -First 1
            if ($matched) {
                $currentCfg = @{
                    InterfaceAlias = $matched.InterfaceAlias
                    SubnetCidr     = $matched.SubnetCidr
                    GatewayIP      = if ($matched.GatewayIP) { $matched.GatewayIP } else { "None" }
                    LocalIP        = $matched.LocalIP
                    HostCount      = $matched.HostCount
                }
            }
        }

        if (-not $currentCfg -and $activeIfs.Count -gt 0) {
            $matched = $activeIfs | Select-Object -First 1
            $selectedInterface = $matched.InterfaceAlias
            $currentCfg = @{
                InterfaceAlias = $matched.InterfaceAlias
                SubnetCidr     = $matched.SubnetCidr
                GatewayIP      = if ($matched.GatewayIP) { $matched.GatewayIP } else { "None" }
                LocalIP        = $matched.LocalIP
                HostCount      = $matched.HostCount
            }
        }

        # Quick cached WAN info check (refreshed every 60s or if empty)
        if (-not $script:CachedWanInfo -or ((Get-Date) - $script:LastWanCheck).TotalSeconds -gt 60) {
            $script:CachedWanInfo = Get-ExternalNetworkInfo -TimeoutMs 1500
            $script:LastWanCheck = Get-Date
        }

        # Quick Wi-Fi link check
        $menuWifi = Get-ConnectedWifiInfo

        Write-Host ""
        Write-Host "=================================================================" -ForegroundColor Cyan
        Write-Host " [SCRY]" -ForegroundColor Cyan
        Write-Host "=================================================================" -ForegroundColor Cyan
        if ($currentCfg) {
            $ifDisplay = "$($currentCfg.InterfaceAlias)"
            if ($menuWifi -and $menuWifi.IsConnected -and ($currentCfg.InterfaceAlias -match 'Wi-Fi|Wireless|WLAN' -or $menuWifi.Name -eq $currentCfg.InterfaceAlias)) {
                $ifDisplay += " (Connected: `"$($menuWifi.SSID)`" | $($menuWifi.SignalPercent)% Signal)"
            }
            Write-Host " Target Interface : " -NoNewline; Write-Host "$ifDisplay" -ForegroundColor Yellow
            Write-Host " Target Subnet    : " -NoNewline; Write-Host "$($currentCfg.SubnetCidr)" -ForegroundColor Yellow -NoNewline
            if ($currentCfg.HostCount) { Write-Host " ($($currentCfg.HostCount) Hosts)" -ForegroundColor DarkGray } else { Write-Host "" }
            Write-Host " Default Gateway  : " -NoNewline; Write-Host "$($currentCfg.GatewayIP)" -ForegroundColor Yellow
            Write-Host " This PC Local IP : " -NoNewline; Write-Host "$($currentCfg.LocalIP)" -ForegroundColor Yellow
            if ($script:CachedWanInfo -and $script:CachedWanInfo.IsConnected) {
                $wanBrief = "$($script:CachedWanInfo.IP)"
                if ($script:CachedWanInfo.ISP) {
                    $wanBrief += " ($($script:CachedWanInfo.ISP)"
                    if ($script:CachedWanInfo.Country) { $wanBrief += " - $($script:CachedWanInfo.Country)" }
                    $wanBrief += ")"
                }
                Write-Host " Public / WAN IP  : " -NoNewline; Write-Host "$wanBrief" -ForegroundColor Green
            } elseif ($script:CachedWanInfo) {
                Write-Host " Public / WAN IP  : " -NoNewline; Write-Host "Offline / Isolated LAN" -ForegroundColor DarkGray
            }
            Write-Host "-----------------------------------------------------------------" -ForegroundColor DarkGray
        }
        Write-Host " [1] Start Scan   (Standard: Devices, Hostnames, Top Ports) [Default]" -ForegroundColor Green
        Write-Host " [2] Deep Scan    (Comprehensive: 25+ Ports & Web Banners)" -ForegroundColor Magenta
        Write-Host " [3] Quick Scan   (Fast Discovery: ARP + Ping + DNS)" -ForegroundColor Yellow
        Write-Host " [4] Switch Adapter / Custom Subnet" -ForegroundColor White
        Write-Host " [5] Wi-Fi Survey (Nearby SSIDs, Channels & Signal Strengths)" -ForegroundColor Cyan
        Write-Host " [0] Exit" -ForegroundColor DarkGray
        Write-Host "=================================================================" -ForegroundColor Cyan
        Write-Host -NoNewline " Select an option [0-5] (Press ENTER for [1]): "

        $choice = Read-Host

        if ([string]::IsNullOrWhiteSpace($choice)) {
            $choice = "1"
        }

        switch ($choice.Trim()) {
            "1" {
                Write-Host ""
                $results = Invoke-NetworkScanner -TargetSubnet $selectedSubnet -TargetInterface $selectedInterface -BaseReportFolder $DefaultReportDir
                Write-Host "Options: [O] Open HTML Report | [M] Back to Menu" -ForegroundColor DarkCyan
                Write-Host -NoNewline "Choice [M]: "
                $subChoice = Read-Host
                if ($subChoice -match '^[oO]') {
                    $latestDir = Get-ChildItem -Path $DefaultReportDir -Directory -ErrorAction SilentlyContinue | Sort-Object CreationTime -Descending | Select-Object -First 1
                    if ($latestDir) {
                        $html = Join-Path $latestDir.FullName "report.html"
                        if (Test-Path $html) { Start-Process $html }
                    }
                }
            }

            "2" {
                Write-Host ""
                $results = Invoke-NetworkScanner -TargetSubnet $selectedSubnet -TargetInterface $selectedInterface -IsDeepScan -BaseReportFolder $DefaultReportDir
                Write-Host "Options: [O] Open HTML Report | [M] Back to Menu" -ForegroundColor DarkCyan
                Write-Host -NoNewline "Choice [M]: "
                $subChoice = Read-Host
                if ($subChoice -match '^[oO]') {
                    $latestDir = Get-ChildItem -Path $DefaultReportDir -Directory -ErrorAction SilentlyContinue | Sort-Object CreationTime -Descending | Select-Object -First 1
                    if ($latestDir) {
                        $html = Join-Path $latestDir.FullName "report.html"
                        if (Test-Path $html) { Start-Process $html }
                    }
                }
            }

            "3" {
                Write-Host ""
                $results = Invoke-NetworkScanner -TargetSubnet $selectedSubnet -TargetInterface $selectedInterface -IsQuickScan -BaseReportFolder $DefaultReportDir
                Pause-MenuPrompt
            }

            "4" {
                Write-Host ""
                Write-Host "=================================================================" -ForegroundColor Cyan
                Write-Host " AVAILABLE NETWORK INTERFACES" -ForegroundColor Cyan
                Write-Host "=================================================================" -ForegroundColor Cyan
                $allIfs = Get-AllActiveNetworkInterfaces
                for ($i = 0; $i -lt $allIfs.Count; $i++) {
                    $item = $allIfs[$i]
                    $isCur = ($item.InterfaceAlias -eq $selectedInterface)
                    $curTag = if ($isCur) { " (Current)" } else { "" }
                    Write-Host " [$($i+1)] $($item.InterfaceAlias)$curTag" -ForegroundColor Yellow
                    Write-Host "     Subnet: $($item.SubnetCidr) ($($item.HostCount) hosts) | IP: $($item.LocalIP) | Gateway: $($item.GatewayIP)" -ForegroundColor Gray
                }
                Write-Host "-----------------------------------------------------------------" -ForegroundColor DarkGray
                Write-Host " [A] Scan ALL Active Adapters Sequentially" -ForegroundColor Cyan
                Write-Host " [C] Custom Subnet (e.g. 192.168.1.0/24 or 10.0.0.1-50)" -ForegroundColor White
                Write-Host " [W] Wi-Fi Survey (Nearby SSIDs & Access Points)" -ForegroundColor Cyan
                Write-Host " [R] Renew DHCP Lease & Flush DNS" -ForegroundColor Yellow
                Write-Host " [D] Detailed Network Diagnostic & Route Status" -ForegroundColor Gray
                Write-Host " [M] Back to Main Menu" -ForegroundColor DarkGray
                Write-Host "=================================================================" -ForegroundColor Cyan
                Write-Host -NoNewline " Choose an option [1-$($allIfs.Count)], [A], [C], [W], [R], [D], or [M]: "
                $ifChoice = Read-Host

                if ($ifChoice -match '^[0-9]+$') {
                    $idx = [int]$ifChoice - 1
                    if ($idx -ge 0 -and $idx -lt $allIfs.Count) {
                        $selectedInterface = $allIfs[$idx].InterfaceAlias
                        $selectedSubnet = $null
                        Write-Host " [+] Switched target to: $($selectedInterface) ($($allIfs[$idx].SubnetCidr))" -ForegroundColor Green
                    }
                } elseif ($ifChoice -match '^[aA]') {
                    Write-Host ""
                    Write-Host " [*] Scanning all $($allIfs.Count) active network interfaces..." -ForegroundColor Cyan
                    foreach ($ad in $allIfs) {
                        Write-Host ""
                        Write-Host " >>> Scanning [$($ad.InterfaceAlias)] Subnet: $($ad.SubnetCidr) <<<" -ForegroundColor Yellow
                        $null = Invoke-NetworkScanner -TargetInterface $ad.InterfaceAlias -BaseReportFolder $DefaultReportDir
                    }
                    Pause-MenuPrompt
                } elseif ($ifChoice -match '^[cC]') {
                    Write-Host -NoNewline " Enter Subnet CIDR (e.g. 192.168.1.0/24) or IP Range (e.g. 192.168.1.1-254): "
                    $customSub = Read-Host
                    if (-not [string]::IsNullOrWhiteSpace($customSub)) {
                        $selectedSubnet = $customSub.Trim()
                        $selectedInterface = $null
                        Write-Host " [+] Target subnet set to: $selectedSubnet" -ForegroundColor Green
                    }
                } elseif ($ifChoice -match '^[wW]') {
                    $null = Show-WifiSurvey -BaseReportFolder $DefaultReportDir
                    Pause-MenuPrompt
                } elseif ($ifChoice -match '^[rR]') {
                    Write-Host ""
                    Ensure-NetworkConnection -PreferredInterface $selectedInterface -ForceRenew
                    $script:CachedWanInfo = $null
                    $script:LastWanCheck = [DateTime]::MinValue
                    Write-Host " [+] DHCP lease renewed and network link refreshed." -ForegroundColor Green
                    Pause-MenuPrompt
                } elseif ($ifChoice -match '^[dD]') {
                    Show-NetworkStatus
                    Pause-MenuPrompt
                }
            }

            { $_ -in "5", "w", "wifi", "survey" } {
                $null = Show-WifiSurvey -BaseReportFolder $DefaultReportDir
                Pause-MenuPrompt
            }

            { $_ -in "r", "renew", "dhcp" } {
                Write-Host ""
                Ensure-NetworkConnection -PreferredInterface $selectedInterface -ForceRenew
                $script:CachedWanInfo = $null
                $script:LastWanCheck = [DateTime]::MinValue
                Write-Host " [+] DHCP lease renewed and network link refreshed." -ForegroundColor Green
                Pause-MenuPrompt
            }

            { $_ -in "6", "8", "reports", "report" } {
                $baseDir = if ([System.IO.Path]::IsPathRooted($DefaultReportDir)) { $DefaultReportDir } else { Join-Path (Get-Location).Path $DefaultReportDir }
                if (-not (Test-Path $baseDir)) {
                    [System.IO.Directory]::CreateDirectory($baseDir) | Out-Null
                }
                Write-Host "Opening $baseDir in Explorer..." -ForegroundColor Cyan
                Start-Process "explorer.exe" $baseDir
            }

            { $_ -in "7", "a", "all" } {
                Write-Host ""
                $allIfs = Get-AllActiveNetworkInterfaces
                Write-Host " [*] Scanning all $($allIfs.Count) active network interfaces..." -ForegroundColor Cyan
                foreach ($ad in $allIfs) {
                    Write-Host ""
                    Write-Host " >>> Scanning [$($ad.InterfaceAlias)] Subnet: $($ad.SubnetCidr) <<<" -ForegroundColor Yellow
                    $null = Invoke-NetworkScanner -TargetInterface $ad.InterfaceAlias -BaseReportFolder $DefaultReportDir
                }
                Pause-MenuPrompt
            }

            { $_ -in "d", "status" } {
                Show-NetworkStatus
                Pause-MenuPrompt
            }

            { $_ -in "0", "q", "exit" } {
                Write-Host "Exiting. Happy hunting!" -ForegroundColor Green
                $continueMenu = $false
            }

            default {
                Write-Host "Invalid option. Please choose [0-5]." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    }
}

# ====================================================================
# 8. MAIN SCRIPT ENTRY POINT
# ====================================================================
$isDirectCli = ($PSBoundParameters.Count -gt 0) -and (-not $Menu)

if ($WifiOnly) {
    if ($Quiet) {
        $connW = Get-ConnectedWifiInfo
        $connB = if ($connW -and $connW.IsConnected) { $connW.BSSID } else { "" }
        return Get-NearbyWifiNetworks -ConnectedBssid $connB -DoOnlineLookup:$OnlineLookup
    } else {
        $res = Show-WifiSurvey -DoOnlineLookup:$OnlineLookup -BaseReportFolder $ReportDir
        if ($ExportCsv) {
            $res | Select-Object Status, SSID, BSSID, Vendor, SignalPercent, Channel, Band, RadioType, Authentication, Encryption, IsConnected |
                Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8
            Write-Host " [+] Wi-Fi Survey CSV saved to: $ExportCsv" -ForegroundColor Cyan
        }
        if ($ExportJson) {
            $res | ConvertTo-Json -Depth 4 | Out-File -FilePath $ExportJson -Encoding utf8
            Write-Host " [+] Wi-Fi Survey JSON saved to: $ExportJson" -ForegroundColor Cyan
        }
        if ($ShowGrid) {
            $res | Out-GridView -Title "Nearby Wi-Fi Networks"
        }
        return $res
    }
}

if ($isDirectCli -or $NonInteractive) {
    if ($AllInterfaces) {
        $allIfs = Get-AllActiveNetworkInterfaces
        $allRes = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($ad in $allIfs) {
            $r = Invoke-NetworkScanner `
                -TargetInterface $ad.InterfaceAlias `
                -IsQuickScan:$QuickScan `
                -IsDeepScan:$DeepScan `
                -DoOnlineLookup:$OnlineLookup `
                -ProbeTimeoutMs $TimeoutMs `
                -TasksThrottle $ThrottleLimit `
                -BaseReportFolder $ReportDir `
                -DisableReport:$NoReport `
                -AutoOpenReport:$OpenReport `
                -CustomHtmlPath $ExportHtml `
                -CustomCsvPath $ExportCsv `
                -CustomJsonPath $ExportJson `
                -DisplayGrid:$ShowGrid `
                -SilentMode:$Quiet `
                -DoRenewDhcp:$RenewDhcp `
                -BypassDhcpCheck:$SkipDhcpCheck `
                -DhcpWaitSec $DhcpTimeoutSec `
                -SkipWanLookup:$SkipWanCheck `
                -WanTimeout $WanTimeoutSec `
                -SkipWifiScan:$SkipWifi
            if ($r) { foreach ($item in $r) { $allRes.Add($item) } }
        }
        return $allRes
    } else {
        # Non-interactive CLI run with passed parameters
        return Invoke-NetworkScanner `
            -TargetSubnet $Subnet `
            -TargetInterface $InterfaceAlias `
            -IsQuickScan:$QuickScan `
            -IsDeepScan:$DeepScan `
            -DoOnlineLookup:$OnlineLookup `
            -ProbeTimeoutMs $TimeoutMs `
            -TasksThrottle $ThrottleLimit `
            -BaseReportFolder $ReportDir `
            -DisableReport:$NoReport `
            -AutoOpenReport:$OpenReport `
            -CustomHtmlPath $ExportHtml `
            -CustomCsvPath $ExportCsv `
            -CustomJsonPath $ExportJson `
            -DisplayGrid:$ShowGrid `
            -SilentMode:$Quiet `
            -DoRenewDhcp:$RenewDhcp `
            -BypassDhcpCheck:$SkipDhcpCheck `
            -DhcpWaitSec $DhcpTimeoutSec `
            -SkipWanLookup:$SkipWanCheck `
            -WanTimeout $WanTimeoutSec `
            -SkipWifiScan:$SkipWifi
    }
} else {
    # Launch interactive menu loop
    Start-InteractiveMenu -DefaultReportDir $ReportDir -TargetInterface $InterfaceAlias -TargetSubnet $Subnet
}
