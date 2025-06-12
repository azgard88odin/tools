function Connect-WiFiNetwork {
    param (
        [string]$SSID
    )
    netsh wlan connect name=$SSID
}

function Get-WiFiGeneration {
    param (
        [string]$RadioType
    )
    switch -Wildcard ($RadioType) {
        "*802.11b" { return "Wi-Fi 1" }
        "*802.11a" { return "Wi-Fi 2" }
        "*802.11g" { return "Wi-Fi 3" }
        "*802.11n" { return "Wi-Fi 4" }
        "*802.11ac" { return "Wi-Fi 5" }
        "*802.11ax" { return "Wi-Fi 6/6E" }
        "*802.11be" { return "Wi-Fi 7" }
        default { return "Unknown" }
    }
}

function Get-WirelessAccessPoints {
    $raw = netsh wlan show networks mode=bssid

    $networks = @()
    $current = @{}

    foreach ($line in $raw) {
        switch -Regex ($line) {
            "^SSID\s+\d+\s+:\s*(.*)" {
                if ($current.SSID) {
                    $networks += [PSCustomObject]$current
                    $current = @{}
                }
                $current.SSID = if ($matches[1].Trim()) { $matches[1].Trim() } else { "[Hidden Network]" }
            }
            "^\s*Authentication\s+:\s+(.*)" {
                $current.Authentication = $matches[1].Trim()
            }
            "^\s*Encryption\s+:\s+(.*)" {
                $current.Encryption = $matches[1].Trim()
            }
            "^\s*BSSID\s+\d+\s+:\s+(.*)" {
                $current.BSSID = $matches[1].Trim()
            }
            "^\s*Signal\s+:\s+(.*)" {
                $current.Signal = $matches[1].Trim()
            }
            "^\s*Radio type\s+:\s+(.*)" {
                $current.Radio = $matches[1].Trim()
                $current.Generation = Get-WiFiGeneration -RadioType $matches[1].Trim()
            }
            "^\s*Band\s+:\s+(.*)" {
                $current.Band = $matches[1].Trim()
            }
            "^\s*Channel\s+:\s+(.*)" {
                $current.Channel = $matches[1].Trim()
            }
            "^\s*Basic rates.*:\s+(.*)" {
                $current.Rates = $matches[1].Trim()
            }
            "^\s*Other rates.*:\s+(.*)" {
                $current.Rates += " " + $matches[1].Trim()
            }
        }
    }

    # Add the final network if it wasn't already added
    if ($current.SSID) {
        $networks += [PSCustomObject]$current
    }

    # Display as a table
    return ($networks | Format-Table SSID, BSSID, Signal, Channel, Authentication, Encryption, Band, Radio, Generation)
}

function Get-CurrentSSID {
    return (netsh wlan show interfaces) -match '^\s*SSID\s*:(.+)' | ForEach-Object { ($_ -split ':')[1].Trim() }
}

function Show-WirelessAccessPoints {

    $currentSSID = Get-CurrentSSID
    Grant-LocationAccess

    Disable-NetAdapter -Name "Wi-Fi" -Confirm:$false
    Start-Sleep -Seconds 3
    Enable-NetAdapter -Name "Wi-Fi" -Confirm:$false

    Connect-WiFiNetwork -SSID $currentSSID
    Get-WirelessAccessPoints

    Revoke-LocationAccess
}

# Credit for this function goes to: xkln.net (mdjx)
# Create a quick subnet list with the following:
# $IPs = 1..254 | ForEach-Object { "192.168.1.$_" } OR
# $IPs = 1..254 | % { "10.0.0.$_" }
function Start-ARPScan {
    [Cmdletbinding()]

    Param (
        [Parameter(Mandatory, Position=1)]
        [string[]]$IP,

        [Parameter(Mandatory=$false, Position=2)]
        [ValidateRange(0,15000)]
        [int]$DelayMS = 2,

        [Parameter(Mandatory=$false, Position=3)]
        [boolean]$ReturnArray = $false,
        
        [ValidateScript({
            $IsAdmin = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
            if ($IsAdmin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                $True
            } 
            else {
                Throw "Must be running an elevated prompt to use ClearARPCache"
            }
        })]
        [switch]$ClearARPCache
    )

    $ASCIIEncoding = New-Object System.Text.ASCIIEncoding
    $Bytes = $ASCIIEncoding.GetBytes("a")
    $UDP = New-Object System.Net.Sockets.Udpclient

    if ($ClearARPCache) {
        arp -d
    }

    $Timer = [System.Diagnostics.Stopwatch]::StartNew()

    $IP | ForEach-Object {
        $UDP.Connect($_,1)
        [void]$UDP.Send($Bytes,$Bytes.length)
        if ($DelayMS) {
            [System.Threading.Thread]::Sleep($DelayMS)
        }
    }

    $Hosts = arp -a

    $Timer.Stop()
    if ($Timer.Elapsed.TotalSeconds -gt 15) {
        Write-Warning "Scan took longer than 15 seconds, ARP entries may have been flushed. Recommend lowering DelayMS parameter"
    }

    $Hosts = $Hosts | Where-Object {$_ -match "dynamic"} | % {($_.Trim() -replace " {1,}",",") | ConvertFrom-Csv -Header "IP","MACAddress"} | Select-Object IP, @{Name='MACAddress'; Expression={ $_.MACAddress -replace '-',':' }}
    $hostCount = $Hosts.Count
    $Hosts = $Hosts | Where-Object {$_.IP -in $IP}

    if ($ReturnArray) {
        return $Hosts | ForEach-Object { $_.IP }
    } else {
        Write-Output $Hosts
        Write-Output "Total Hosts: $hostCount"
    }
}

# A simple function to check if a port is open on a target host
# I want to expand this in the future to test for multiple ports
function Confirm-OpenPort {
    param([string]$TargetHost, [int]$Port, [int]$TimeOut = 100)
    try {
        $tcp = New-Object Net.Sockets.TcpClient
        $conn = $tcp.BeginConnect($TargetHost, $Port, $null, $null)
        $wait = $conn.AsyncWaitHandle.WaitOne($TimeOut,$false)
        if($wait) {
            $tcp.EndConnect($conn)
            return $true
        }
        $tcp.Close()
    } catch {
        return $false
    }
}

# Perform a port scan on a host
function Start-PortScanSequential {
    param([string]$TargetHost, [int]$StartPort = 1, [int]$EndPort = 1024, [int]$Timeout = 300)
    $StartPort..$EndPort | ForEach-Object { 
        try {
            $tcp = New-Object Net.Sockets.TcpClient
            $conn = $tcp.BeginConnect($TargetHost, $_, $null, $null)
            $wait = $conn.AsyncWaitHandle.WaitOne($TimeOut,$false)
            if($wait) {
                $tcp.EndConnect($conn)
                "Port $_ is open!"
            }
            $tcp.Close()
        } catch {}
    }
}

# This function performs a port scan on a target host
# this uses an array of ports so that you can specify individual ports
function Start-PortScanSelected {
    param([string]$TargetHost, [int[]]$Ports, [int]$TimeOut = 300)
    $Ports | ForEach-Object { 
        try {
            $tcp = New-Object Net.Sockets.TcpClient
            $conn = $tcp.BeginConnect($TargetHost, $_, $null, $null)
            $wait = $conn.AsyncWaitHandle.WaitOne($TimeOut,$false)
            if($wait) {
                $tcp.EndConnect($conn)
                results += [PSCustomObject]@{
                    Host = $TargetHost
                    Port = $_
                    Open = $true
                }
            }
            $tcp.Close()
        } catch {}
    }
}

# Basic function for pinging a range of IP addresses
# This is still much slower than the ARP scan, but it is a good alternative
# An idea is also to use a combination of the two to get a more accurate list of hosts
function Start-PingSweep {
    param([string]$Subnet)
    $addressList = @()
    1..255 | ForEach-Object {
        $address = "$Subnet.$_" 
        $result = ping -n 1 -w 100 $address | Select-String ttl
        if ($result) {
            $addressList += $address
        }
    }
    $count = $addressList.Length
    Write-Host "Ping Sweep Complete. Total Hosts: $count"
    return $addressList
}

# This function sets a static IP address on a network interface
# It requires the interface name, IP address, gateway, and DNS servers
function Set-StaticIP {
    param(
        [string]$InterfaceName,
        [string]$IPAddress,
        [string]$Gateway,
        [string[]]$NameServers
    )
    New-NetIPAddress -InterfaceAlias $InterfaceName -IPAddress $IPAddress -PrefixLength 24 -DefaultGateway $Gateway
    Set-DnsClientServerAddress -InterfaceAlias $InterfaceName -ServerAddresses ($NameServers)
}

# This function sets a dynamic IP address on a network interface
# It requires the interface name
# It will remove any existing static routes and reset the DNS server addresses
function Set-DynamicIP {
    param(
        [string]$InterfaceName
    )
    $interface = Get-NetAdapter -Name $InterfaceName | Get-NetIPInterface -AddressFamily IPv4
    $interface | Remove-NetRoute -Confirm:$false
    $interface | Set-NetIPInterface -Dhcp Enabled
    $interface | Set-DnsClientServerAddress -ResetServerAddresses
}

function Get-ActiveNetworkInterface {
    $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Where-Object { $_.NextHop -ne "::" } | Sort-Object RouteMetric | Select-Object -First 1
    return Get-NetAdapter | Where-Object { $_.InterfaceIndex -eq $defaultRoute.InterfaceIndex -and $_.HardwareInterface -eq "True" }
}

Export-ModuleMember -Function Connect-WiFiNetwork, Get-WiFiGeneration, Get-WirelessAccessPoints, Get-CurrentSSID, Show-WirelessAccessPoints, 
    Start-ARPScan, Confirm-OpenPort, Start-PingSweep, Start-PortScanSequential, Start-PortScanSelected, Set-StaticIP, Set-DynamicIP, Get-ActiveNetworkInterface