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
    }
}
'@
    Add-Type -TypeDefinition $cSharpCode -Language CSharp
}

# ====================================================================
# 2. EMBEDDED OUI VENDOR LOOKUP DATABASE (500+ Top Vendors)
# ====================================================================
$script:MacOuiDatabase = @{
    # Raspberry Pi Foundation
    'B827EB' = 'Raspberry Pi Foundation'; 'DCA632' = 'Raspberry Pi Foundation'; 'E45F01' = 'Raspberry Pi Foundation'
    '28CDC1' = 'Raspberry Pi Foundation'; 'D83ADD' = 'Raspberry Pi Foundation'; '2CCF67' = 'Raspberry Pi Foundation'

    # Espressif IoT (ESP8266, ESP32, Smart Plugs, WLED, Tasmota)
    '18FE34' = 'Espressif Inc (IoT/ESP)'; '240AC4' = 'Espressif Inc (IoT/ESP)'; '2462AB' = 'Espressif Inc (IoT/ESP)'
    '246F28' = 'Espressif Inc (IoT/ESP)'; '24B2DE' = 'Espressif Inc (IoT/ESP)'; '2C3AE8' = 'Espressif Inc (IoT/ESP)'
    '2CF432' = 'Espressif Inc (IoT/ESP)'; '30AEA4' = 'Espressif Inc (IoT/ESP)'; '3C6105' = 'Espressif Inc (IoT/ESP)'
    '3C71BF' = 'Espressif Inc (IoT/ESP)'; '4022D8' = 'Espressif Inc (IoT/ESP)'; '40F520' = 'Espressif Inc (IoT/ESP)'
    '441793' = 'Espressif Inc (IoT/ESP)'; '483FDA' = 'Espressif Inc (IoT/ESP)'; '485519' = 'Espressif Inc (IoT/ESP)'
    '4C11AE' = 'Espressif Inc (IoT/ESP)'; '4C7525' = 'Espressif Inc (IoT/ESP)'; '500291' = 'Espressif Inc (IoT/ESP)'
    '5443B2' = 'Espressif Inc (IoT/ESP)'; '545AA6' = 'Espressif Inc (IoT/ESP)'; '5CCF7F' = 'Espressif Inc (IoT/ESP)'
    '600194' = 'Espressif Inc (IoT/ESP)'; '68C63A' = 'Espressif Inc (IoT/ESP)'; '70039F' = 'Espressif Inc (IoT/ESP)'
    '7CDFA1' = 'Espressif Inc (IoT/ESP)'; '807D3A' = 'Espressif Inc (IoT/ESP)'; '840D8E' = 'Espressif Inc (IoT/ESP)'
    '84F3EB' = 'Espressif Inc (IoT/ESP)'; '8CAAB5' = 'Espressif Inc (IoT/ESP)'; '9097D5' = 'Espressif Inc (IoT/ESP)'
    '94B97E' = 'Espressif Inc (IoT/ESP)'; '98CDAC' = 'Espressif Inc (IoT/ESP)'; 'A020A6' = 'Espressif Inc (IoT/ESP)'
    'A4CF12' = 'Espressif Inc (IoT/ESP)'; 'A4E57C' = 'Espressif Inc (IoT/ESP)'; 'AC67B2' = 'Espressif Inc (IoT/ESP)'
    'B4E62D' = 'Espressif Inc (IoT/ESP)'; 'BCDDD2' = 'Espressif Inc (IoT/ESP)'; 'C44F33' = 'Espressif Inc (IoT/ESP)'
    'C82B96' = 'Espressif Inc (IoT/ESP)'; 'CC50E3' = 'Espressif Inc (IoT/ESP)'; 'D8A01D' = 'Espressif Inc (IoT/ESP)'
    'DC4F22' = 'Espressif Inc (IoT/ESP)'; 'EC6260' = 'Espressif Inc (IoT/ESP)'; 'ECFABC' = 'Espressif Inc (IoT/ESP)'

    # Apple
    '000393' = 'Apple'; '000502' = 'Apple'; '000A27' = 'Apple'; '000A95' = 'Apple'; '000D93' = 'Apple'
    '0010FA' = 'Apple'; '001124' = 'Apple'; '001451' = 'Apple'; '0016CB' = 'Apple'; '0017F2' = 'Apple'
    '0019E3' = 'Apple'; '001B63' = 'Apple'; '001CB3' = 'Apple'; '001D4F' = 'Apple'; '001E52' = 'Apple'
    '001EC2' = 'Apple'; '001F5B' = 'Apple'; '001FF3' = 'Apple'; '0021E9' = 'Apple'; '002241' = 'Apple'
    '002312' = 'Apple'; '002332' = 'Apple'; '00236C' = 'Apple'; '0023DF' = 'Apple'; '002436' = 'Apple'
    '002500' = 'Apple'; '00254B' = 'Apple'; '0025BC' = 'Apple'; '002608' = 'Apple'; '00264A' = 'Apple'
    '040CCE' = 'Apple'; '041552' = 'Apple'; '042665' = 'Apple'; '04489A' = 'Apple'; '044BED' = 'Apple'
    '080007' = 'Apple'; '086698' = 'Apple'; '087045' = 'Apple'; '087402' = 'Apple'; '08E689' = 'Apple'
    '0C1539' = 'Apple'; '0C3021' = 'Apple'; '0C4DE9' = 'Apple'; '0C5101' = 'Apple'; '0C74C2' = 'Apple'
    '101C0C' = 'Apple'; '1040F3' = 'Apple'; '1093E9' = 'Apple'; '1094BB' = 'Apple'; '109ADD' = 'Apple'
    '14109F' = 'Apple'; '14205E' = 'Apple'; '145A05' = 'Apple'; '147DC5' = 'Apple'; '1499E2' = 'Apple'
    '183451' = 'Apple'; '186590' = 'Apple'; '18AF61' = 'Apple'; '18E728' = 'Apple'; '18EE69' = 'Apple'
    '207D74' = 'Apple'; '20A2E4' = 'Apple'; '20AB37' = 'Apple'; '20EE28' = 'Apple'; '24240E' = 'Apple'
    '280B5C' = 'Apple'; '286ABA' = 'Apple'; '28CFDA' = 'Apple'; '28CFE9' = 'Apple'; '28E02C' = 'Apple'
    '30074D' = 'Apple'; '3090AB' = 'Apple'; '3408BC' = 'Apple'; '34159E' = 'Apple'; '34363B' = 'Apple'
    '38484C' = 'Apple'; '38CA7D' = 'Apple'; '3C0754' = 'Apple'; '3C15C2' = 'Apple'; '3C22FB' = 'Apple'
    '406C8F' = 'Apple'; '4098AD' = 'Apple'; '40A6D9' = 'Apple'; '440010' = 'Apple'; '442A60' = 'Apple'
    '48437C' = 'Apple'; '48605F' = 'Apple'; '48D705' = 'Apple'; '4C3275' = 'Apple'; '4C57CA' = 'Apple'
    '50BC96' = 'Apple'; '50EAD6' = 'Apple'; '542696' = 'Apple'; '544E90' = 'Apple'; '54724F' = 'Apple'
    '600308' = 'Apple'; '60334B' = 'Apple'; '606720' = 'Apple'; '608B0E' = 'Apple'; '60A37D' = 'Apple'
    '685B35' = 'Apple'; '68967B' = 'Apple'; '68A86D' = 'Apple'; '6C4008' = 'Apple'; '6C709F' = 'Apple'
    '701124' = 'Apple'; '703EAC' = 'Apple'; '70708B' = 'Apple'; '70EF00' = 'Apple'; '748D08' = 'Apple'
    '784F43' = 'Apple'; '787B8A' = 'Apple'; '7C04D0' = 'Apple'; '7C6D62' = 'Apple'; '7CF05F' = 'Apple'
    '804971' = 'Apple'; '80E650' = 'Apple'; '843835' = 'Apple'; '84FCAC' = 'Apple'; '88665A' = 'Apple'
    '8C2DAA' = 'Apple'; '8C8590' = 'Apple'; '9027E4' = 'Apple'; '907240' = 'Apple'; '90FD61' = 'Apple'
    '9801A7' = 'Apple'; '985AEB' = 'Apple'; '98E0D9' = 'Apple'; '9C207B' = 'Apple'; '9C35EB' = 'Apple'
    'A45E60' = 'Apple'; 'A4C361' = 'Apple'; 'A82066' = 'Apple'; 'A85B78' = 'Apple'; 'A8667F' = 'Apple'
    'B065BD' = 'Apple'; 'B418D1' = 'Apple'; 'B8098A' = 'Apple'; 'B8782E' = 'Apple'; 'B8E856' = 'Apple'
    'C0847A' = 'Apple'; 'C4B301' = 'Apple'; 'C82A14' = 'Apple'; 'C83C85' = 'Apple'; 'C869CD' = 'Apple'
    'CC088D' = 'Apple'; 'CC29F5' = 'Apple'; 'D0034B' = 'Apple'; 'D023DB' = 'Apple'; 'D0817A' = 'Apple'
    'DC2B61' = 'Apple'; 'DC56E7' = 'Apple'; 'E06678' = 'Apple'; 'E0B6F5' = 'Apple'; 'E4CE8F' = 'Apple'
    'F01898' = 'Apple'; 'F07960' = 'Apple'; 'F0C1F1' = 'Apple'; 'F40F24' = 'Apple'; 'F437B7' = 'Apple'
    'F81EDF' = 'Apple'; 'F83880' = 'Apple'; 'FC183C' = 'Apple'; 'FC257F' = 'Apple'; 'FCE998' = 'Apple'

    # TP-Link
    '001D0F' = 'TP-Link'; '002719' = 'TP-Link'; '1027F5' = 'TP-Link'; '14CC20' = 'TP-Link'; '1C3BF3' = 'TP-Link'
    '30DE4B' = 'TP-Link'; '50C7BF' = 'TP-Link'; '54AF97' = 'TP-Link'; '60A44C' = 'TP-Link'; '704F57' = 'TP-Link'
    '7403BD' = 'TP-Link'; '788A20' = 'TP-Link'; '8416F9' = 'TP-Link'; '90F652' = 'TP-Link'; '98DAC4' = 'TP-Link'
    'A0F3C1' = 'TP-Link'; 'AC84C6' = 'TP-Link'; 'B04E26' = 'TP-Link'; 'B09575' = 'TP-Link'; 'C006C3' = 'TP-Link'
    'C025E9' = 'TP-Link'; 'C46E1F' = 'TP-Link'; 'C4E984' = 'TP-Link'; 'D80D17' = 'TP-Link'; 'E4C32A' = 'TP-Link'
    'EC086B' = 'TP-Link'; 'EC172F' = 'TP-Link'; 'F4F26D' = 'TP-Link'; 'F81A67' = 'TP-Link'

    # Ubiquiti Networks (UniFi)
    '00156D' = 'Ubiquiti (UniFi)'; '002722' = 'Ubiquiti (UniFi)'; '0418D6' = 'Ubiquiti (UniFi)'; '18E829' = 'Ubiquiti (UniFi)'
    '245A4C' = 'Ubiquiti (UniFi)'; '44D9E7' = 'Ubiquiti (UniFi)'; '687251' = 'Ubiquiti (UniFi)'; '68D79A' = 'Ubiquiti (UniFi)'
    '708BCD' = 'Ubiquiti (UniFi)'; '7483C2' = 'Ubiquiti (UniFi)'; '784558' = 'Ubiquiti (UniFi)'; '802AA8' = 'Ubiquiti (UniFi)'
    '9C05D6' = 'Ubiquiti (UniFi)'; 'AC8BA9' = 'Ubiquiti (UniFi)'; 'B4FBE4' = 'Ubiquiti (UniFi)'; 'DC9FDB' = 'Ubiquiti (UniFi)'
    'E063DA' = 'Ubiquiti (UniFi)'; 'F09FC2' = 'Ubiquiti (UniFi)'; 'FCECDA' = 'Ubiquiti (UniFi)'

    # Netgear
    '00095B' = 'Netgear'; '000FB5' = 'Netgear'; '00146C' = 'Netgear'; '00184D' = 'Netgear'; '001F33' = 'Netgear'
    '0024B2' = 'Netgear'; '0026F2' = 'Netgear'; '04A151' = 'Netgear'; '08028E' = 'Netgear'; '10DA43' = 'Netgear'
    '1459C0' = 'Netgear'; '200CC8' = 'Netgear'; '20E52A' = 'Netgear'; '288088' = 'Netgear'; '2C3033' = 'Netgear'
    '4494FC' = 'Netgear'; '4C60DE' = 'Netgear'; '6CB0CE' = 'Netgear'; '841B5E' = 'Netgear'; '9C3DCF' = 'Netgear'
    'A00460' = 'Netgear'; 'A42BB0' = 'Netgear'; 'B03956' = 'Netgear'; 'B07FB9' = 'Netgear'; 'C0FFD4' = 'Netgear'
    'CC40D0' = 'Netgear'; 'E0469A' = 'Netgear'; 'E091F5' = 'Netgear'; 'E4F4C6' = 'Netgear'

    # Cisco / Linksys
    '00000C' = 'Cisco'; '000142' = 'Cisco'; '0001C7' = 'Cisco'; '0001C9' = 'Cisco'; '000216' = 'Cisco'
    '000217' = 'Cisco'; '00024B' = 'Cisco'; '00027D' = 'Cisco'; '0002B9' = 'Cisco'; '0002FC' = 'Cisco'
    '00036B' = 'Cisco'; '00044D' = 'Cisco'; '00049B' = 'Cisco'; '000653' = 'Cisco'; '000C85' = 'Cisco'
    '001121' = 'Cisco'; '001201' = 'Cisco'; '00141B' = 'Cisco'; '0015C7' = 'Cisco'; '001759' = 'Cisco'
    '001A30' = 'Cisco'; '001BD4' = 'Cisco'; '001C0E' = 'Cisco'; '002155' = 'Cisco'; '002414' = 'Cisco'
    '00260B' = 'Cisco'; '080002' = 'Cisco'; '18EF63' = 'Cisco'; '203A07' = 'Cisco'; '58971E' = 'Cisco'
    '68BDAB' = 'Cisco'; '708105' = 'Cisco'; '8843E1' = 'Cisco'; 'ACF2C5' = 'Cisco'; 'C47295' = 'Cisco'
    'CCD539' = 'Cisco'; 'F4ACC1' = 'Cisco'

    # ASUS
    '000C6E' = 'ASUS'; '000EA6' = 'ASUS'; '0011D8' = 'ASUS'; '0013D4' = 'ASUS'; '0015F2' = 'ASUS'
    '0018F3' = 'ASUS'; '001A92' = 'ASUS'; '001BFC' = 'ASUS'; '001D60' = 'ASUS'; '001E8C' = 'ASUS'
    '002215' = 'ASUS'; '00248C' = 'ASUS'; '002618' = 'ASUS'; '04D9F5' = 'ASUS'; '08606E' = 'ASUS'
    '086266' = 'ASUS'; '107B44' = 'ASUS'; '10BF48' = 'ASUS'; '14DDA9' = 'ASUS'; '1831BF' = 'ASUS'
    '20CF30' = 'ASUS'; '244BFE' = 'ASUS'; '2C4D54' = 'ASUS'; '305A3A' = 'ASUS'; '38D547' = 'ASUS'
    '40167E' = 'ASUS'; '50465D' = 'ASUS'; '54A050' = 'ASUS'; '704D7B' = 'ASUS'; '74D02B' = 'ASUS'
    '88D7F6' = 'ASUS'; '90E6BA' = 'ASUS'; 'AC220B' = 'ASUS'; 'B06EBF' = 'ASUS'; 'BCEE7B' = 'ASUS'
    'C87F54' = 'ASUS'; 'D850E6' = 'ASUS'; 'E03F49' = 'ASUS'; 'F02F74' = 'ASUS'; 'F07959' = 'ASUS'

    # MikroTik
    '000C42' = 'MikroTik'; '2CC81B' = 'MikroTik'; '488F5A' = 'MikroTik'; '64D154' = 'MikroTik'; '6C3B6B' = 'MikroTik'
    '744D28' = 'MikroTik'; '789A18' = 'MikroTik'; 'B869F4' = 'MikroTik'; 'C4AD34' = 'MikroTik'; 'D401C3' = 'MikroTik'; 'E48D8C' = 'MikroTik'

    # AVM FRITZ!Box
    '00040E' = 'AVM (FRITZ!Box)'; '00150C' = 'AVM (FRITZ!Box)'; '001A4F' = 'AVM (FRITZ!Box)'; '001C4A' = 'AVM (FRITZ!Box)'
    '0024FE' = 'AVM (FRITZ!Box)'; '2C3996' = 'AVM (FRITZ!Box)'; '3431C4' = 'AVM (FRITZ!Box)'; '3810D5' = 'AVM (FRITZ!Box)'
    '444E6D' = 'AVM (FRITZ!Box)'; '70C922' = 'AVM (FRITZ!Box)'; '9CC7A6' = 'AVM (FRITZ!Box)'; 'C02506' = 'AVM (FRITZ!Box)'; 'DC396F' = 'AVM (FRITZ!Box)'

    # Synology & QNAP
    '001132' = 'Synology'; '245EBE' = 'Synology / QNAP'; '001395' = 'Synology'; '00089B' = 'QNAP'

    # Amazon (Echo, Ring, Blink, Fire TV)
    '00FC8B' = 'Amazon (Echo/Ring/Fire)'; '0C47C9' = 'Amazon (Echo/Ring/Fire)'; '18742E' = 'Amazon (Echo/Ring/Fire)'
    '244CE3' = 'Amazon (Echo/Ring/Fire)'; '34D270' = 'Amazon (Echo/Ring/Fire)'; '38F73D' = 'Amazon (Echo/Ring/Fire)'
    '40B4CD' = 'Amazon (Echo/Ring/Fire)'; '44650D' = 'Amazon (Echo/Ring/Fire)'; '4844F7' = 'Amazon (Echo/Ring/Fire)'
    '50DCE7' = 'Amazon (Echo/Ring/Fire)'; '6837E9' = 'Amazon (Echo/Ring/Fire)'; '68545A' = 'Amazon (Echo/Ring/Fire)'
    '747548' = 'Amazon (Echo/Ring/Fire)'; '74C246' = 'Amazon (Echo/Ring/Fire)'; '84D6D0' = 'Amazon (Echo/Ring/Fire)'
    '8871B1' = 'Amazon (Echo/Ring/Fire)'; 'AC63BE' = 'Amazon (Echo/Ring/Fire)'; 'B47C9C' = 'Amazon (Echo/Ring/Fire)'
    'CC9E00' = 'Amazon (Echo/Ring/Fire)'; 'F0272D' = 'Amazon (Echo/Ring/Fire)'; 'FC65DE' = 'Amazon (Echo/Ring/Fire)'; 'FCA667' = 'Amazon (Echo/Ring/Fire)'

    # Google (Nest, Chromecast, Home)
    '001A11' = 'Google'; '1097BD' = 'Google (Nest/Home)'; '1C56FE' = 'Google'; '20DFB9' = 'Google'; '3C3174' = 'Google (Nest Wifi)'; '3C5A37' = 'Google'; '48D6D5' = 'Google'
    '546009' = 'Google'; '6CADF8' = 'Google'; '70EE50' = 'Google'; '94EBCD' = 'Google'; 'A47733' = 'Google'
    'D86C63' = 'Google'; 'E4F042' = 'Google'; 'F40304' = 'Google'; 'F4F5D8' = 'Google'; 'F80FF9' = 'Google'; 'F88FC2' = 'Google'

    # Samsung
    '0007AB' = 'Samsung'; '001247' = 'Samsung'; '001599' = 'Samsung'; '001632' = 'Samsung'; '0017C9' = 'Samsung'
    '001A8A' = 'Samsung'; '001C43' = 'Samsung'; '001D25' = 'Samsung'; '0021D1' = 'Samsung'; '0023D6' = 'Samsung'
    '002637' = 'Samsung'; '0808C2' = 'Samsung'; '14F42A' = 'Samsung'; '1C66AA' = 'Samsung'; '244B03' = 'Samsung'
    '289A4B' = 'Samsung'; '30CDA7' = 'Samsung'; '34BE00' = 'Samsung'; '380A94' = 'Samsung'; '400E85' = 'Samsung'
    '44F459' = 'Samsung'; '4849C7' = 'Samsung'; '508569' = 'Samsung'; '5492BE' = 'Samsung'; '5CE8EB' = 'Samsung'
    '606BBD' = 'Samsung'; '641CAE' = 'Samsung'; '78471D' = 'Samsung'; '8425DB' = 'Samsung'; '88329B' = 'Samsung'
    '94350A' = 'Samsung'; 'A0821F' = 'Samsung'; 'A80600' = 'Samsung'; 'AC5F3E' = 'Samsung'; 'B0C4E7' = 'Samsung'
    'BC4486' = 'Samsung'; 'C0BDD1' = 'Samsung'; 'C81479' = 'Samsung'; 'CCF9E8' = 'Samsung'; 'D059E4' = 'Samsung'
    'E47CF9' = 'Samsung'; 'F0EE10' = 'Samsung'; 'F47B5E' = 'Samsung'; 'F8042E' = 'Samsung'

    # Tuya (Smart Life / Smart Home)
    '105AF7' = 'Tuya (Smart Life IoT)'; '20F41B' = 'Tuya (Smart Life IoT)'; '403F8C' = 'Tuya (Smart Life IoT)'
    '508A06' = 'Tuya (Smart Life IoT)'; '68572D' = 'Tuya (Smart Life IoT)'; '708976' = 'Tuya (Smart Life IoT)'
    '7C87CE' = 'Tuya (Smart Life IoT)'; 'A09208' = 'Tuya (Smart Life IoT)'; 'D81F12' = 'Tuya (Smart Life IoT)'

    # Xiaomi / Yeelight
    '009EC8' = 'Xiaomi'; '04CF8C' = 'Xiaomi'; '14F65A' = 'Xiaomi'; '185936' = 'Xiaomi'; '286C07' = 'Xiaomi'
    '34800D' = 'Xiaomi'; '38A4ED' = 'Xiaomi'; '50642B' = 'Xiaomi'; '584498' = 'Xiaomi'; '640980' = 'Xiaomi'
    '742344' = 'Xiaomi'; '7802F8' = 'Xiaomi'; '7C49EB' = 'Xiaomi'; '8CBEBE' = 'Xiaomi'; '98FAE3' = 'Xiaomi'
    'ACC1EE' = 'Xiaomi'; 'C40BCB' = 'Xiaomi'; 'F0B429' = 'Xiaomi'

    # Sonos
    '000E58' = 'Sonos'; '347E5C' = 'Sonos'; '48A6B8' = 'Sonos'; '5CAAFD' = 'Sonos'; '7828CA' = 'Sonos'; '949F3E' = 'Sonos'; 'B8E937' = 'Sonos'

    # Roku
    '000D4B' = 'Roku'; '080581' = 'Roku'; '20EFBD' = 'Roku'; '2AEFBD' = 'Roku'; '7CA81C' = 'Roku'
    '84EAED' = 'Roku'; 'AC3A7A' = 'Roku'; 'B0A737' = 'Roku'; 'C83A6B' = 'Roku'; 'CC6DA0' = 'Roku'; 'D83134' = 'Roku'

    # Philips / Signify (Hue)
    '001788' = 'Philips Hue (Signify)'; 'ECB5FA' = 'Philips Hue (Signify)'

    # HP (Hewlett-Packard Printers & PCs)
    '0001E6' = 'HP'; '0002A5' = 'HP'; '000802' = 'HP'; '000BCD' = 'HP'; '000E7F' = 'HP'; '000F20' = 'HP'
    '00110A' = 'HP'; '001279' = 'HP'; '001321' = 'HP'; '0014C2' = 'HP'; '001560' = 'HP'; '001635' = 'HP'
    '0017A4' = 'HP'; '001871' = 'HP'; '0018FE' = 'HP'; '0019BB' = 'HP'; '001A4B' = 'HP'; '001B78' = 'HP'
    '001CC4' = 'HP'; '001E0B' = 'HP'; '001F29' = 'HP'; '00215A' = 'HP'; '002264' = 'HP'; '00237D' = 'HP'
    '002481' = 'HP'; '0025B3' = 'HP'; '002655' = 'HP'; '082E5F' = 'HP'; '101F74' = 'HP'; '10604B' = 'HP'
    '1458D0' = 'HP'; '18A958' = 'HP'; '288023' = 'HP'; '2C4138' = 'HP'; '308D99' = 'HP'; '3464A9' = 'HP'
    '3C5282' = 'HP'; '40B034' = 'HP'; '480FCF' = 'HP'; '645106' = 'HP'; '705A0F' = 'HP'; '843497' = 'HP'
    '9457A5' = 'HP'; '9C8E99' = 'HP'; 'A0D3C1' = 'HP'; 'AC162D' = 'HP'; 'B05ADA' = 'HP'; 'BCEAFA' = 'HP'
    'C8D3FF' = 'HP'; 'D48564' = 'HP'; 'E4115B' = 'HP'; 'F80DAC' = 'HP'

    # Canon, Brother, Epson, Ricoh, Xerox, Kyocera
    '000085' = 'Canon'; '001E8F' = 'Canon'; '0021E1' = 'Canon'; '180CAC' = 'Canon'; '381A52' = 'Canon'
    '84BA20' = 'Canon'; 'A4EE57' = 'Canon'; 'B4148F' = 'Canon'; 'D46AA8' = 'Canon'
    '001BA9' = 'Brother'; '008077' = 'Brother'; '30055C' = 'Brother'; '446D57' = 'Brother'; '541379' = 'Brother'; '8056F2' = 'Brother'; 'B499BA' = 'Brother'; 'C47EAB' = 'Brother'
    '000048' = 'Epson'; '002164' = 'Epson'; '0026AB' = 'Epson'; '44D244' = 'Epson'; '64EB8C' = 'Epson'; 'AC140F' = 'Epson'; 'D84732' = 'Epson'
    '000074' = 'Ricoh'; '002673' = 'Ricoh'; '000000' = 'Xerox'; '0000AA' = 'Xerox'; '0000F8' = 'Digital/Xerox'

    # Dell, Lenovo, Intel, Realtek
    '00065B' = 'Dell'; '000874' = 'Dell'; '000BDB' = 'Dell'; '000F1F' = 'Dell'; '001143' = 'Dell'; '00123F' = 'Dell'
    '001372' = 'Dell'; '001422' = 'Dell'; '0015C5' = 'Dell'; '0016F0' = 'Dell'; '00188B' = 'Dell'; '0019B9' = 'Dell'
    '001AA0' = 'Dell'; '001C23' = 'Dell'; '001D09' = 'Dell'; '001E4F' = 'Dell'; '002170' = 'Dell'; '002219' = 'Dell'
    '0023AE' = 'Dell'; '0024E8' = 'Dell'; '002564' = 'Dell'; '0026B9' = 'Dell'; '180373' = 'Dell'; '1866DA' = 'Dell'
    '20040F' = 'Dell'; '2453ED' = 'Dell'; '24B6FD' = 'Dell'; '3417EB' = 'Dell'; '44A842' = 'Dell'; '544810' = 'Dell'; '74867A' = 'Dell'
    '847BEB' = 'Dell'; '90B11C' = 'Dell'; 'A4BADB' = 'Dell'; 'B8AC6F' = 'Dell'; 'BC305B' = 'Dell'; 'D494A9' = 'Dell'
    'D4BED9' = 'Dell'; 'E4F004' = 'Dell'; 'F01FAF' = 'Dell'; 'F8BC12' = 'Dell'
    '0012FE' = 'Lenovo'; '005907' = 'Lenovo'; '04CF4B' = 'Lenovo'; '083E8E' = 'Lenovo'; '085DDD' = 'Lenovo'; '207693' = 'Lenovo'
    '28D244' = 'Lenovo'; '3052CB' = 'Lenovo'; '38BAF8' = 'Lenovo'; '4439C4' = 'Lenovo'; '54EE75' = 'Lenovo'; '6099D1' = 'Lenovo'
    '70720D' = 'Lenovo'; '80006E' = 'Lenovo'; '88708C' = 'Lenovo'; '940853' = 'Lenovo'; '98FA9B' = 'Lenovo'; 'A0C589' = 'Lenovo'
    'A48CDB' = 'Lenovo'; 'B49691' = 'Lenovo'; 'CC4463' = 'Lenovo'; 'E0D55E' = 'Lenovo'; 'EC70F3' = 'Lenovo'; 'F0761C' = 'Lenovo'
    '0002B3' = 'Intel'; '000347' = 'Intel'; '000423' = 'Intel'; '000E0C' = 'Intel'; '001302' = 'Intel'; '0013E8' = 'Intel'
    '001500' = 'Intel'; '001676' = 'Intel'; '0019D1' = 'Intel'; '001B21' = 'Intel'; '001CC0' = 'Intel'; '001DE0' = 'Intel'
    '001E67' = 'Intel'; '001F3B' = 'Intel'; '00215C' = 'Intel'; '0022FA' = 'Intel'; '002314' = 'Intel'; '0024D7' = 'Intel'
    '00270E' = 'Intel'; '3413E8' = 'Intel'; '3CFDFE' = 'Intel'; '4851B7' = 'Intel'; '4C79BA' = 'Intel'; '6805CA' = 'Intel'
    '7C5758' = 'Intel'; '84A93E' = 'Intel'; '88AEDD' = 'Intel'; '8C705A' = 'Intel'; '94659C' = 'Intel'; 'A036BC' = 'Intel'
    'A44CC8' = 'Intel'; 'ACFDCE' = 'Intel'; 'C85B76' = 'Intel'; 'D0ABD5' = 'Intel'; 'E4A471' = 'Intel'; 'E82AEA' = 'Intel'
    'ECF4BB' = 'Intel'; 'F8633F' = 'Intel'
    '000732' = 'Realtek'; '000E2E' = 'Realtek'; '001AEF' = 'Realtek'; '00265A' = 'Realtek'; '00E04C' = 'Realtek'
    '5404A6' = 'Realtek'; '7085C2' = 'Realtek'; '9C5322' = 'Realtek'; 'B8AEED' = 'Realtek'; 'D85ED3' = 'Realtek'; 'FC3497' = 'Realtek'

    # Microsoft / Xbox / Surface
    '0003FF' = 'Microsoft'; '000D3A' = 'Microsoft'; '00125A' = 'Microsoft'; '00155D' = 'Microsoft (Hyper-V)'; '0017FA' = 'Microsoft'
    '001DD8' = 'Microsoft'; '002248' = 'Microsoft'; '0025AE' = 'Microsoft'; '0050F2' = 'Microsoft'; '28167F' = 'Microsoft'
    '281878' = 'Microsoft'; '3059B7' = 'Microsoft'; '485073' = 'Microsoft'; '501AC5' = 'Microsoft'; '5882A8' = 'Microsoft'
    '6045BD' = 'Microsoft'; '706655' = 'Microsoft'; '7C1E52' = 'Microsoft'; '985FD3' = 'Microsoft'; 'A085FC' = 'Microsoft'
    'B4AE2B' = 'Microsoft'; 'C49DED' = 'Microsoft'; 'DC9840' = 'Microsoft'; 'E0D4E8' = 'Microsoft'; 'F43909' = 'Microsoft'

    # Sony / PlayStation & Nintendo & LG
    '00014A' = 'Sony'; '00041F' = 'Sony'; '000AD9' = 'Sony'; '000E07' = 'Sony'; '0013A9' = 'Sony'; '0015C1' = 'Sony'
    '0019C5' = 'Sony'; '001DBA' = 'Sony'; '00248D' = 'Sony'; '0498F3' = 'Sony'; '280DFC' = 'Sony'; '300ED5' = 'Sony'
    '709E29' = 'Sony'; '78C881' = 'Sony'; 'A8E3EE' = 'Sony'; 'BC60A7' = 'Sony'; 'CC9EA2' = 'Sony'; 'F8461C' = 'Sony'
    '0009BF' = 'Nintendo'; '001656' = 'Nintendo'; '0017AB' = 'Nintendo'; '00191D' = 'Nintendo'; '001B7A' = 'Nintendo'
    '001E35' = 'Nintendo'; '001F32' = 'Nintendo'; '002147' = 'Nintendo'; '00224C' = 'Nintendo'; '0022AA' = 'Nintendo'
    '002331' = 'Nintendo'; '0023CC' = 'Nintendo'; '00241E' = 'Nintendo'; '002444' = 'Nintendo'; '0025A0' = 'Nintendo'
    '002659' = 'Nintendo'; '78A2A0' = 'Nintendo'; '98B6E9' = 'Nintendo'; 'B87826' = 'Nintendo'; 'D86BF7' = 'Nintendo'; 'E84E06' = 'Nintendo'
    '0019A1' = 'LG'; '001C62' = 'LG'; '001E75' = 'LG'; '0022A9' = 'LG'; '002483' = 'LG'; '10F96F' = 'LG'
    '14C913' = 'LG'; '203D66' = 'LG'; '34FCEF' = 'LG'; '58A2B5' = 'LG'; '64995D' = 'LG'; '785DC7' = 'LG'
    '88366C' = 'LG'; 'A823FE' = 'LG'; 'B81DAA' = 'LG'; 'CC2D83' = 'LG'; 'E85B5B' = 'LG'; 'F80CF3' = 'LG'

    # Virtualization (VMware, VirtualBox, QEMU, Proxmox)
    '000569' = 'VMware'; '000C29' = 'VMware'; '001C14' = 'VMware'; '005056' = 'VMware'
    '080027' = 'Oracle VirtualBox'; '525400' = 'QEMU / KVM / Proxmox VM'
}

function Resolve-MacVendor {
    param([string]$MacAddress, [switch]$QueryOnline)
    if ([string]::IsNullOrWhiteSpace($MacAddress)) { return "Unknown (No ARP/MAC)" }

    $cleanMac = ($MacAddress -replace '[:-]', '').ToUpper()
    if ($cleanMac.Length -lt 6) { return "Unknown" }

    $firstByte = [Convert]::ToByte($cleanMac.Substring(0,2), 16)
    $isPrivate = ($firstByte -band 0x02) -ne 0

    $prefix = $cleanMac.Substring(0, 6)
    if ($script:MacOuiDatabase.ContainsKey($prefix)) {
        $vendor = $script:MacOuiDatabase[$prefix]
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
                $script:MacOuiDatabase[$prefix] = $resp.company
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
# 5. HTML REPORT GENERATOR
# ====================================================================
function Generate-HtmlReport {
    param($Devices, $NetworkConfig, [string]$FilePath, [double]$ScanDurationSec, $WanInfo = $null)

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

    # Build Split Network Context Cards (LOCAL and ONLINE / OFFLINE)
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
        </div>
"@
    } elseif ($WanInfo) {
        $wanCardHtml = @"
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
        
        /* Dual Context Cards */
        .context-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 14px; margin-bottom: 20px; }
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 14px 16px; }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid var(--border-subtle); }
        .card-heading { font-size: 13px; font-weight: 600; color: var(--text-primary); }
        .kv-table { width: 100%; font-size: 12px; border-collapse: collapse; }
        .kv-table td { padding: 4px 0; vertical-align: top; }
        .kv-key { color: var(--text-muted); width: 130px; }
        .kv-val { color: var(--text-primary); font-weight: 500; word-break: break-all; }
        .kv-val.mono { font-family: var(--mono-font); }
        
        /* Badges & Chips */
        .badge { display: inline-flex; align-items: center; padding: 2px 7px; border-radius: 12px; font-size: 11px; font-weight: 600; line-height: 1.2; text-transform: uppercase; letter-spacing: 0.03em; }
        .badge-gateway { background: var(--success-bg); color: var(--success-fg); border: 1px solid var(--success-border); }
        .badge-local { background: var(--info-bg); color: var(--info-fg); border: 1px solid var(--info-border); }
        .badge-active { background: var(--surface-subtle); color: var(--text-secondary); border: 1px solid var(--border); }
        .badge-offline { background: var(--warning-bg); color: var(--warning-fg); border: 1px solid var(--warning-border); }
        
        .port-chip { display: inline-block; background: var(--surface-subtle); border: 1px solid var(--border); color: var(--text-secondary); padding: 1px 6px; border-radius: 3px; font-family: var(--mono-font); font-size: 11px; margin: 1px 2px 1px 0; }

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

        $wanCardHtml

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
        [int]$WanTimeout = 3
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
        Write-Host " Active Interface  : " -NoNewline; Write-Host "$($netConfig.InterfaceAlias)" -ForegroundColor Yellow
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
        $autoNetJson = Join-Path $scanFolder "network_info.json"
        $autoTxt  = Join-Path $scanFolder "summary.txt"

        # 1. HTML Report
        Generate-HtmlReport -Devices $sortedResults -NetworkConfig $netConfig -FilePath $autoHtml -ScanDurationSec $scanDuration -WanInfo $wanInfo
        $generatedHtmlPath = $autoHtml

        # 2. CSV Report
        $sortedResults | Select-Object Status, IP, MAC, DeviceType, HostName, Vendor, OpenPorts, HttpTitle, HttpServer, Workgroup, LatencyMs |
            Export-Csv -Path $autoCsv -NoTypeInformation -Encoding utf8

        # 3. JSON Device Report
        $sortedResults | ConvertTo-Json -Depth 4 | Out-File -FilePath $autoJson -Encoding utf8

        # 3b. JSON Network & WAN Metadata Report
        $netSummaryObj = [PSCustomObject]@{
            ScanTimestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            ScanDurationSec = $scanDuration
            TargetSubnet    = $netConfig.SubnetCidr
            InterfaceAlias  = $netConfig.InterfaceAlias
            GatewayIP       = $netConfig.GatewayIP
            LocalIP         = $netConfig.LocalIP
            DiscoveredCount = $sortedResults.Count
            ExternalWAN     = if ($wanInfo) { $wanInfo } else { $null }
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
            Write-Host "    |-- report.html       (Interactive HTML Dashboard with WAN Intelligence)" -ForegroundColor DarkCyan
            Write-Host "    |-- devices.csv       (CSV Spreadsheet)" -ForegroundColor DarkCyan
            Write-Host "    |-- devices.json      (JSON Device Dataset)" -ForegroundColor DarkCyan
            Write-Host "    |-- network_info.json (Network & WAN Metadata)" -ForegroundColor DarkCyan
            Write-Host "    |-- summary.txt       (Text Summary Log)" -ForegroundColor DarkCyan
            Write-Host ""
        }
    }

    # Custom Additional File Exports
    if ($CustomHtmlPath) {
        Generate-HtmlReport -Devices $sortedResults -NetworkConfig $netConfig -FilePath $CustomHtmlPath -ScanDurationSec $scanDuration -WanInfo $wanInfo
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

        Write-Host ""
        Write-Host "=================================================================" -ForegroundColor Cyan
        Write-Host " [SCRY]" -ForegroundColor Cyan
        Write-Host "=================================================================" -ForegroundColor Cyan
        if ($currentCfg) {
            Write-Host " Target Interface : " -NoNewline; Write-Host "$($currentCfg.InterfaceAlias)" -ForegroundColor Yellow
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
        Write-Host " [1] Start Scan  (Standard: Devices, Hostnames, Top Ports) [Default]" -ForegroundColor Green
        Write-Host " [2] Deep Scan   (Comprehensive: 25+ Ports & Web Banners)" -ForegroundColor Magenta
        Write-Host " [3] Quick Scan  (Fast Discovery: ARP + Ping + DNS)" -ForegroundColor Yellow
        Write-Host " [4] Switch Adapter / Custom Subnet" -ForegroundColor White
        Write-Host " [0] Exit" -ForegroundColor DarkGray
        Write-Host "=================================================================" -ForegroundColor Cyan
        Write-Host -NoNewline " Select an option [0-4] (Press ENTER for [1]): "

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
                Write-Host " [R] Renew DHCP Lease & Flush DNS" -ForegroundColor Yellow
                Write-Host " [D] Detailed Network Diagnostic & Route Status" -ForegroundColor Gray
                Write-Host " [M] Back to Main Menu" -ForegroundColor DarkGray
                Write-Host "=================================================================" -ForegroundColor Cyan
                Write-Host -NoNewline " Choose an option [1-$($allIfs.Count)], [A], [C], [R], [D], or [M]: "
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

            { $_ -in "5", "r", "renew", "dhcp" } {
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
                Write-Host "Invalid option. Please choose [0-4]." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    }
}

# ====================================================================
# 8. MAIN SCRIPT ENTRY POINT
# ====================================================================
$isDirectCli = ($PSBoundParameters.Count -gt 0) -and (-not $Menu)

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
                -WanTimeout $WanTimeoutSec
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
            -WanTimeout $WanTimeoutSec
    }
} else {
    # Launch interactive menu loop
    Start-InteractiveMenu -DefaultReportDir $ReportDir -TargetInterface $InterfaceAlias -TargetSubnet $Subnet
}
