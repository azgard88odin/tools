#===========================================================================
# POWERSHELL COMMAND LIBRARY
# A comprehensive collection of useful PowerShell commands and functions
# Organized by category for easy reference
#===========================================================================

#===========================================================================
# SYSTEM INFORMATION
#===========================================================================

# Get PowerShell version info
$PSVersionTable

# Get computer name
$env:COMPUTERNAME

# Get PowerShell version information (build specific)
$PSVersionTable.BuildVersion

# Get time zone information
Get-TimeZone

# Get computer system domain
(Get-CimInstance Win32_ComputerSystem).Domain

# Get registered owner of Windows
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").RegisteredOwner

# Get Motherboard information
Get-WmiObject -Class Win32_BaseBoard

# Get list of hot fixes
Get-HotFix

# Get list of all account types on system, this can reveal different kinds of software installed on a system
(Get-WmiObject -Class Win32_Account).Name | Sort-Object

# Get Environment Variables
Get-ChildItem Env:

# Set Environment Variable for Current User (Temporarily)
$env:MY_ENV_VAR = "MyValue"
# Set Environment Variable for Current User (Permanently)
# This will create a variable called $env:MY_ENV_VAR with the value "MyValue"
# The 'User' is not to be replaced with the username, it is a keyword
[System.Environment]::SetEnvironmentVariable("MY_ENV_VAR", "MyValue", "User")

# Remove Environment Variable for Current User
[System.Environment]::SetEnvironmentVariable("MY_ENV_VAR", $null, "User")

# Set Environment Variable for System (Permanently)
# This will create a variable called $env:MY_ENV_VAR with the value "MyValue"
# The 'Machine' is not to be replaced with the username, it is a keyword
[System.Environment]::SetEnvironmentVariable("MY_ENV_VAR", "MyValue", "Machine")

# Remove Environment Variable for System
[System.Environment]::SetEnvironmentVariable("MY_ENV_VAR", $null, "Machine")

# Confirm new environment variable
[System.Environment]::GetEnvironmentVariable("MY_ENV_VAR", "User")
[System.Environment]::GetEnvironmentVariable("MY_ENV_VAR", "Machine")

# Append to the PATH variable (Temporarily)
$env:Path += ";C:\MyNewPath"

# Append to the PATH variable (Permanently)
[System.Environment]::SetEnvironmentVariable("Path", ([System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";C:\MyNewPath"), "Machine")

# Get local user accounts
Get-LocalUser

# Get local groups
Get-LocalGroup

#===========================================================================
# HARDWARE & DEVICE MANAGEMENT
#===========================================================================

# Get all COM ports
Get-WmiObject Win32_SerialPort | Select-Object Name, DeviceID, Description

# Get all connected USB devices
Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match '^USB' }

# Get all the installed printers on the PC
Get-Printer

# Get all the printer jobs (if any)
(Get-Printer).Name | ForEach-Object { Get-PrintJob -PrinterName $_ }

# Remove printer jobs
(Get-Printer).Name | ForEach-Object { Get-PrintJob -PrinterName $_ | Remove-PrintJob }

#===========================================================================
# FILE OPERATIONS
#===========================================================================

# Show directory listing
Get-ChildItem

# Copy items
Copy-Item sourceFile.doc destinationFile.doc

# Move items
Move-Item source.doc destination.doc

# Find string of text within a file
Select-String -Path C:\Users \*.txt -Pattern password

# Get content of files
Get-Content passwords.txt

# Show pwd
Get-Location

# Count files in the current directory
(Get-ChildItem).Count

# Count directories in the current directory
(Get-ChildItem -Directory).Count

# Get file with specific filter
Get-ChildItem -Path "Can You Open Me"

# List files in specific user directories
foreach ($name in @("Contacts","Desktop","Documents","Downloads","Favorites","Music","Videos")) { 
    Get-ChildItem -Path "C:\Users\username\$name" -File 
}

# List hidden files in specific user directories
foreach ($name in @("Contacts","Desktop","Documents","Downloads","Favorites","Music","Videos")) { 
    Get-ChildItem -Path "C:\Users\username\$name" -File -Hidden 
}

# Sort file content and get unique items count
(Get-Content -Path .\unique.txt | Sort-Object -Unique).Count

# Split content by whitespace and get specific word
((Get-Content -Path .\Word_File.txt) -split '\s')[160]

# Count specific words in a file
((Get-Content -Path .\countpolos) -split '\s' -match '^polo$').Count

# Count total words in a file
((Get-Content -Path .\countmywords) -split '\s').Count

# Get file hash using specific algorithm
Get-FileHash -Path "C:\Windows\System32\drivers\etc\hosts" -Algorithm MD5
(Get-FileHash -Path "C:\Windows\System32\drivers\etc\hosts" -Algorithm MD5).Hash[-5..-1] -join ''

# Group files by hash to find duplicates
Get-FileHash -Path * -Algorithm MD5 | Group-Object -Property Hash | Where-Object { $_.Count -gt 1 }

# Read binary data from files
[System.Text.Encoding]::UTF8.GetString(([System.IO.File]::ReadAllBytes(".\elements.txt")[1481109..1481116]))
[System.BitConverter]::ToString((Get-Content -Path .\file.pdf -Encoding Byte -TotalCount 8)) -replace("-","")
([System.IO.File]::ReadAllBytes(".\file.pdf")[0..7]) -join ""

# Work with alternate data streams
Get-Item -Path .\file.png -Stream *
Get-Content -Path .\file.png -Stream Zone.Identifier
Get-Content -Path .\TPS_Reports04.pdf -Stream secret

# Compare files
Compare-Object -ReferenceObject (Get-Content -Path .\old.txt) -DifferenceObject (Get-Content -Path .\new.txt)

# Get file owner
(Get-Acl -Path '.\Nine Realms').Owner

# Get file ACL (Access Control List)
(Get-Acl -Path '.\Nine Realms').Access | Select-Object IdentityReference, FileSystemRights, AccessControlType

# Get File ACL in a formatted table
(Get-ACL -Path ".\TestFile.txt").Access | Format-Table IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -AutoSize

# List prefetch files
Get-ChildItem -Path "C:\Windows\Prefetch" -Filter "*access*"

# Recursively search for files with specific extension
(Get-ChildItem -Path "C:\Program Files\Adobe\" -Recurse -Filter "*.dll" -File).Count

# Format dates from file properties
(Get-ChildItem -Path "C:\Windows\Prefetch" -Filter "*access*" | Select-Object *).LastAccessTime.ToString('MM/dd/yyyy')

# Compress files into a zip archive
Compress-Archive -Path "C:\Path\To\Directory" -DestinationPath "C:\Path\To\Archive.zip"

# This function was created to use in Powershell 4.0 where there is no Compress-Archive cmdlet
#TODO edit this so that it works with arguments
function Compress-Files {
    param(
        [string]$SourcePath,
        [string]$DestinationPath,
        [string]$ArchiveFileName,

        [Parameter(Mandatory=$true)]
        [ValidateSet("cmd", "bat", "jpg", "txt", "png", "pdf", "doc", "docx", "xlsx", "pptx", "zip", "rar", "7z", "csv")]
        [string]$FileExtension
    )
    $tempDirectoryPath = "$env:TEMP\zip_temp"
    New-Item -ItemType Directory -Force -Path $tempDirectoryPath | Out-Null

    Get-ChildItem -Path $SourcePath -Filter "*.$FileExtension" | ForEach-Object {
        Copy-Item $_.FullName -Destination $tempDirectoryPath
    }
    $zipFile = Join-Path -Path $DestinationPath -ChildPath "$ArchiveFileName.zip"
    
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($tempDirectoryPath, $zipFile)

    Remove-Item -Recurse -Force $tempDirectoryPath   
    Write-Host "Files compressed to $zipFile"
}


#===========================================================================
# CLIPBOARD OPERATIONS
#===========================================================================

# Get value in clipboard
Get-Clipboard

# Clear value in clipboard
Set-Clipboard -Value $null

# Get the path of a file that has been copied (ready to be pasted)
# This only works when a file is COPIED and not CUT
function Get-CopiedFilePath {
    Add-Type -AssemblyName System.Windows.Forms
    $clipboardData = [System.Windows.Forms.Clipboard]::GetDataObject()

    if ($clipboardData.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
        $files = $clipboardData.GetData([System.Windows.Forms.DataFormats]::FileDrop)
        Write-Host "Copied files in clipboard:"
        $files | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "No file paths in clipboard (or clipboard contains other data)."
    }
}

# Monitor clipboard and clear after 5 minutes of inactivity
function Start-ClipboardMonitor {
    $lastClipboardChange = Get-Date
    $clearDelayMinutes = 5

    while ($true) {
        $timeSinceLastChange = (Get-Date) - $lastClipboardChange
        if ($timeSinceLastChange.TotalMinutes -ge $clearDelayMinutes) {
            Set-Clipboard -Value $null
            Write-Host "Clipboard cleared: $(Get-Date -Format 'HH:mm:ss')"
            $lastClipboardChange = Get-Date 
        }
        Start-Sleep -Seconds 5
    }
}

# Create scheduled task for clipboard monitoring
function Register-ClipboardMonitorTask {
    $taskName = "Monitor and Clear Clipboard"
    $scriptPath = "C:\Users\dexte\Documents\UsefulScripts\Powershell\security\Clear-ClipboardContents.ps1"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -WindowStyle Hidden
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive

    Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -Settings $settings -Principal $principal -Force
}

#===========================================================================
# NETWORKING
#===========================================================================

# Show processes
Get-Process
Get-Process | Export-Csv processes.csv

# Show Services
Get-Service

# Show routing table
Get-NetRoute

# Show all active TCP Connections
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table -AutoSize

# Show all active UDP Connections
Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort | Format-Table

# Show all network interfaces
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed | Format-Table -AutoSize

# Get IP configuration information
Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, PrefixLength

# Show recently resolved domain names
Get-DnsClientCache | Format-Table -AutoSize

# Disable Wi-Fi interface
Disable-NetAdapter -Name Wi-Fi -Confirm:$false

# Get network interfaces
Get-NetAdapter

# Get basic web request information
Invoke-WebRequest

# Resolve DNS names
Resolve-DnsName COMPUTERNAME

# Get DNS server zone aging information
Get-DnsServerZoneAging -Name domainname.tech

# Get DNS server resource records
Get-DnsServerResourceRecord -ZoneName 'domainname.tech' | Where-Object { $_.RecordType -eq 'MX' }

# Get network shares
Get-SmbShare
Get-SmbShare -Name sharename$ | Select-Object *

# Get network connection settings
(Get-ItemProperty -Path "HKCU:\Network\*").PSChildName

# Get Terminal Server Client connections
(Get-ItemProperty -Path "HKCU:\Software\Microsoft\Terminal Server Client\*").PSChildName

# Get network firewall rules
(Get-NetFirewallRule -All | Where-Object { $_.DisplayName -like "MySQL" }).Description
Get-NetFirewallRulle -All

# Modify Windows firewall rules
Net-NetFirewallRule -Action Allow -DisplayName LetMeIn -RemoteAddress 10.0.0.1

# Disable Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Enable Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

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

# Perform a ping sweep on the 192.168.0.1/24 subnet
function Start-PingSweep {
    param([string]$Subnet = "192.168.0")
    1..255 | ForEach-Object { ping -n 1 -w 100 "$Subnet.$_" | Select-String ttl }
}

# This function also performs a ping sweep but can return a list of active hosts
# This is handy if you want to combine it with another utility or function
function Start-PingSweepV2 {
    param([string]$Subnet = "10.0.0")
    $addressList = @()
    1..255 | ForEach-Object {
        $address = "$Subnet.$_" 
        $result = ping -n 1 -w 100 $address | Select-String ttl
        if ($result) {
            $addressList += $address
            Write-Host $address
        }
    }
    $count = $addressList.Length
    Write-Host "Host Count: $count"
    #return $addressList
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

# This function checks if a port is open on a target host
# A slight modification of the Start-PortScan function
# Be sure to set your timeout (milliseconds) if you think some connections are slow and you may not be getting the correct results
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
    return
}

# This loop goes through all the IP addresses in the subnet and checks if port 80 is open
# If it is open, it makes a web request to that IP address and analyzes the body content
# I use this to find devices and services on my network
# Example: Login pages
function Find-LocalDevices {
    $subnet = "10.0.0."
    1..254 | ForEach-Object {
        $address = $subnet + $_
        try {
            if (Confirm-OpenPort -TargetHost $address -Port 80) {
                $response = Invoke-WebRequest $address -ErrorAction SilentlyContinue
                if ($response.Content -match "SomethingDistinctiveInContentBody") {
                    Write-Host "Something Distinctive at $address"
                }
                if ($response.Content -match "[Ll]ogin|[Uu]sername|[Pp]assword") {
                    Write-Host "Possible Login Page at $address"
                }
            }
        } catch {
            # Do nothing
        }
    }
}

# This is a variant of the Find-LocalDevices function
# This has more of a 'live' update feel to it so you don't have to wait for the results but see it as it happens
# I felt that the table output reads better than just a print statement
# The server header addition also helps to enumerate other web services in the network
function Find-LocalDevicesV2 {
    $subnet = "10.0.0."
    $tableSpacer = "{0,-15} {1,-15} {2,-15} {3}"

    # Create table header
    $tableSpacer -f "IPAddress", "Type", "PageTitle", "Server"
    $tableSpacer -f "----------", "----", "---------", "------"

    1..254 | ForEach-Object {
        $address = $subnet + $_
        try {
            if (Confirm-OpenPort -TargetHost $address -Port 80) {
                $response = Invoke-WebRequest $address -ErrorAction SilentlyContinue
                $server = $response.Headers["Server"]
                $title = $response.ParsedHtml.title
                $found = $false

                # You can use a switch statement here if you want to expand this
                if ($response.Content -match "AccessPointName") { $found = $true; $tableSpacer -f $address, "AP", $title, $server }
                if ($response.Content -match "[Ll]ogin|[Uu]sername|[Pp]assword") { $found = $true; $tableSpacer -f $address, "Login Page", $title, $server }

                if (-not $found) {
                    $tableSpacer -f $address, "Unknown", $server
                }

            }
        } catch {
            # Do nothing
        }
    }
}

# Here is version 3 of Find-LocalDevices
# This combines the Start-PingSweepV2 to return an array of addresses which is then passed through the ForEach-Object loop
# This then eliminates the need to run the port test on every single IP address
# The port test also then eliminates any of the host which do not have the target port open
# You can modify this function slightly to look for different devices or services or even expand on what you are looking for
function Find-LocalDevicesV3 {
    $addressList = Start-PingSweepV2
    $port = 80
    $tableSpacer = "{0,-15} {1,-15} {2,-15} {3}"

    # Create table header
    $tableSpacer -f "IPAddress", "Type", "PageTitle", "Server"
    $tableSpacer -f "----------", "----", "---------", "------"

    $addressList | ForEach-Object {
        $address = $_
        try {
            if (Confirm-OpenPort -TargetHost $address -Port $port) {
                $response = Invoke-WebRequest $address -ErrorAction SilentlyContinue
                $server = $response.Headers["Server"]
                $title = $response.ParsedHtml.title
                $found = $false

                if ($response.Content -match "AccessPointName") { $found = $true; $tableSpacer -f $address, "AP", $title, $server }
                if ($response.Content -match "[Ll]ogin|[Uu]sername|[Pp]assword") { $found = $true; $tableSpacer -f $address, "Login Page", $title, $server }

                if (-not $found) {
                    $tableSpacer -f $address, "Unknown", $server
                }

            }
        } catch {
            # Do nothing
        }
    }
}

# Credit for this function goes to: xkln.net (mdjx)
# I modified it slightly to add a few small features
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
        Write-Output "Total Hosts: $hostCount"
        Write-Output $Hosts
    }
}

# Download a file similar to wget
function Get-WebFile {
    param([string]$Url, [string]$OutputFile)
    (New-Object System.Net.WebClient).DownloadFile($Url, $OutputFile)
}

# Identify potential network scanning activities
function Get-UnusualNetworkConnections {
    Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen' -and $_.RemoteAddress -ne '0.0.0.0'} | 
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
}

# Detect listening ports
function Get-ListeningPorts {
    Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort
}

# Identify unusual ARP table entries
function Get-ARPTable {
    Get-NetNeighbor | Where-Object {$_.State -eq 'Reachable' -and $_.AddressFamily -eq 'IPv4'} | 
        Select-Object ifIndex, IPAddress, LinkLayerAddress
}

# Try to detect network scanning attempts
function Get-NetworkScanAttempts {
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5156} | 
        Where-Object {($_.Properties[19].Value -match "Allowed") -and ($_.Properties[7].Value -ne "System")} | 
        Select-Object TimeCreated, @{n='SourceIP';e={$_.Properties[18].Value}}, @{n='DestinationIP';e={$_.Properties[2].Value}}
}

# Try to detect ARP scanning
function Get-ARPScanningEvents {
    Get-WinEvent -FilterHashtable @{LogName='System'; ID=104} | 
        Where-Object {$_.Message -match "ARP"} | 
        Select-Object TimeCreated, @{n='SourceIP';e={$_.Properties[0].Value}}, @{n='DestinationIP';e={$_.Properties[1].Value}}
}

# Get DNS Cache information
# Please note that this function will include entries from your host file should you have a custom one
function Get-DNSCache {
    $dnsCache = ipconfig /displaydns

    $records = @()
    $recordName = $null
    $ipAddresses = @()

    foreach ($line in $dnsCache) {
        if ($line -match "Record Name[\s\.]*:\s*(.*)") {
            # Save the previous record before starting a new one
            if ($recordName -and $ipAddresses.Count -gt 0) {
                $records += [PSCustomObject]@{
                    RecordName  = $recordName
                    IPAddresses = ($ipAddresses | Select-Object -Unique) -join ", "
                }
            }
            # Start new record
            $recordName = $matches[1].Trim()
            $ipAddresses = @()
        }

        if ($line -match "A \(Host\) Record[\s\.]*:\s*(.*)") {
            $ip = $matches[1].Trim()
            $ipAddresses += $ip
        }
    }

    # Add last record
    if ($recordName -and $ipAddresses.Count -gt 0) {
        $records += [PSCustomObject]@{
            RecordName  = $recordName
            IPAddresses = ($ipAddresses | Select-Object -Unique) -join ", "
        }
    }

    # Output as table
    $records | Sort-Object RecordName | Format-Table -AutoSize
}

function Get-IPv6Status {
    $globalStatus = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents").DisabledComponents

    if ($globalStatus -eq 255) {
        Write-Host "IPv6 is Globally Disabled"
    }

    if ($globalStatus -eq 0) {
        Write-Host "IPv6 is Globally Enabled"
    }

    # Show all interfaces with IPv6 capabilities
    Get-NetAdapterBinding -ComponentID ms_tcpip6
}

function Disable-InterfaceIPv6 {
    param(
        [string]$Interface
    )
    Disable-NetAdapterBinding -Name $Interface -ComponentID ms_tcpip6
}

function Enable-InterfaceIPv6 {
    param(
        [string]$Interface
    )
    Enable-NetAdapterBinding -Name $Interface -ComponentID ms_tcpip6
}

function Enable-IPv6Globally {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0 -Type 
}

function Enable-AllInterfacesIPv6 {
    Get-NetAdapterBinding -ComponentID ms_tcpip6 | ForEach-Object { Enable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 }
}

function Disable-IPv6Globally {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 255 -Type DWord
}

function Disable-AllInterfacesIPv6 {
    Get-NetAdapterBinding -ComponentID ms_tcpip6 | ForEach-Object { Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 }
}

#===========================================================================
# WIRELESS NETWORKING
#===========================================================================

# Get WiFi generation from radio type
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

# Show detailed WiFi access point information
function Show-WirelessAccessPoints {
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

# Get current connected WiFi SSID
function Get-CurrentSSID {
    return (netsh wlan show interfaces) -match '^\s*SSID\s*:(.+)' | ForEach-Object { ($_ -split ':')[1].Trim() }
}

# Output all the stored WiFi passwords in a table format
function Get-StoredWiFiPasswords {
    $results = (netsh wlan show profiles) | Select-String ":(.+)$" | ForEach-Object {
        # Fix encoding issues in profile names
        $wifiProfile = [System.Text.Encoding]::UTF8.GetString(
            [System.Text.Encoding]::GetEncoding(1252).GetBytes(
                $_.Matches.Groups[1].Value.Trim()
            )
        )
        
        $keyResult = netsh wlan show profile name="$wifiProfile" key=clear | Select-String "Key Content"
        
        [PSCustomObject]@{
            Profile = $wifiProfile
            Key = if ($keyResult) { 
                # Also fix potential encoding issues in keys
                $keyContent = $keyResult.ToString().Split(':')[1].Trim()
                [System.Text.Encoding]::UTF8.GetString(
                    [System.Text.Encoding]::GetEncoding(1252).GetBytes($keyContent)
                )
            } else { 
                "<no key>" 
            }
        }
    }

    return $results | Format-Table -AutoSize -Wrap
    
    # Optional: Export to CSV
    # $results | Export-Csv -Path "WifiProfiles.csv" -NoTypeInformation
}

#===========================================================================
# CERTIFICATES
#===========================================================================

# Get all certificates in the local machine store
Get-ChildItem -Path Cert:\LocalMachine\My

# Get all personal certificates
Get-ChildItem -Path Cert:\CurrentUser\My

#===========================================================================
# WINDOWS EVENT LOGS
#===========================================================================

# Get all the event logs that has records in them
Get-WinEvent -ListLog * | Select-Object LogName, LogType, RecordCount | Sort-Object LogName | Where-Object { $_.RecordCount -gt 0 } | Format-Table -AutoSize

# Get Windows events with specific filters
Get-WinEvent -Path .\security.evtx -FilterXPath '*[System[(EventID=4699)]] and *[EventData[Data[@Name="SubjectUserName"]="username"]]'

# Extract specific data from Windows events
Get-WinEvent -Path .\security.evtx -FilterXPath '*[System[(EventID=4624)]] and *[EventData[Data[@Name="TargetUserName"]="username"]]' | 
    Select-Object @{Name='SourceIP';Expression={$_.Properties[18].Value}}

# Filter Windows events by time
Get-WinEvent -Path .\application.evtx | Where-Object { $_.TimeCreated -eq '3/23/2017 8:08:53 PM' }

# Filter Windows events by record ID
Get-WinEvent -Path .\application.evtx | Where-Object { $_.RecordId -eq '1151' }

# Extract scheduled task logs
Get-WinEvent -LogName Microsoft-Windows-TaskScheduler/Operational

# Extract properties from event messages
([xml](Get-WinEvent -Path .\security.evtx -FilterXPath '*[System[(EventID=4699)]] and *[EventData[Data[@Name="SubjectUserName"]="username"]]').Message.Split("`n")[-12]).Arguments

# Search logs for specific keywords
Get-Content -Path C:\inetpub\logs\logfiles\w3svc1\u_ex160413.log | Select-String "password"

# Get security events for user creation/modification
Get-WinEvent -Path .\security.evtx -FilterXPath '*[System[EventID=4720]]'
Get-WinEvent -Path .\security.evtx -FilterXPath '*[System[EventID=4722]]' | Where-Object { $_.Message -like "*username*" }

# Filter events by date and time
Get-WinEvent -Path .\security.evtx -FilterXPath '*[System[EventID=4720]]' | Where-Object { $_.TimeCreated.Date -eq "5/11/2017" -and $_.TimeCreated.ToString("mm:ss") -like "26*" }

# Look for event log clearing events
Get-WinEvent -Path .\Oracle3_Security.evtx | Where-Object { $_.Id -eq 1102 -or $_.Id -eq 104 }

# Find security group changes
Get-WinEvent -Path .\security.evtx -FilterXPath '*[System[(EventID=4727)]]'
Get-WinEvent -Path .\security.evtx -FilterXPath '*[System[(EventID=4728)]]'

#===========================================================================
# ACTIVE DIRECTORY
#===========================================================================

# Get Active Directory Users
Get-ADUser -Filter * -Property DisplayName, Title, Department | Select-Object DisplayName, Title, Department

# Get all Active Directory Users' SID
Get-ADUser -Filter * -Properties * | Select-Object Name, SID

# Active Directory Group Enumeration
Get-ADGroup -Filter * -Property Members | Select-Object Name, @{n='Members';e={$_.Members -join ", "}}

# Find all admin users
function Find-AdminUsers {
    $adminGroups = (Get-ADGroup -Filter "SamAccountName -like '*admin*'").Name

    foreach ($group in $adminGroups) {
        Get-ADGroupMember -Identity "$group" | Select-Object @{Name='GroupName';Expression={$group}}, name
    }
}

# Get AD user information (extended)
Get-ADUser -Filter *
Get-ADUser -Filter "UserPrincipalName -eq 'username'" -Properties *
Get-ADUser -Filter "OfficePhone -like '876-5309'" -Properties *

# Get AD domain controller information
Get-ADDomainController -Filter *
Get-ADDomainController -Identity DomainController

# Get AD computer information
Get-ADComputer -Identity ComputerName
Get-ADComputer -Identity ComputerName -Properties *
Get-ADComputer -Filter {PrimaryGroupID -eq 516} -Properties Description

# Get AD group information
Get-ADGroup -Filter "Name -eq 'groupname'" -Properties *

# Count AD group members
(Get-ADGroupMember -Identity "GroupName" -Recursive | Where-Object {$_.objectClass -eq "user"}).Count
(Get-ADGroup -Identity "GroupName" -Properties Members).Members.Count

# Find AD users with specific properties
Get-ADUser -Filter * -Properties * | Where-Object { $_.LogonHours -ne $null }

# Get AD organizational units
Get-ADOrganizationalUnit -Filter * -Properties *
Get-ADOrganizationalUnit -Filter * -Properties * | Where-Object { $_.ProtectedFromAccidentalDeletion -eq $false }

# Get AD trust relationships
(Get-ADTrust -Filter *).Name

# Get default password policy
Get-ADDefaultDomainPasswordPolicy

#===========================================================================
# USER MANAGEMENT & LOCAL ACCOUNTS
#===========================================================================

# Get all local users
Get-LocalUser | Select-Object Name, Enabled, LastLogon | Format-Table -AutoSize

# Get local Administrators and Privileged Groups
Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass | Format-Table -AutoSize

# Get Local groups and their memberships
function Get-LocalGroupMembers {
    Get-LocalGroup | ForEach-Object { 
        [PSCustomObject]@{ 
            GroupName = $_.Name 
            Members = (Get-LocalGroupMember -Group $_.Name | Select-Object -ExpandProperty Name) -join ", " 
        } 
    }
}

# Logoff all users connected to a server
function Logoff-AllUsers {
    $CURRENT_USER = $env:USERNAME.ToLower()

    $sessions = quser /server:$env:COMPUTERNAME

    $sessions | Select-Object -Skip 1 | ForEach-Object {
        $sessionInfo = ($_ -split '\s+').Where({$_ -ne ''})

        # Username and SessionId
        $username = $sessionInfo[0]
        if ($sessionInfo[1] -match 'rdp' -or $sessionInfo[1] -match 'console') { 
            $sessionId = $sessionInfo[2] 
        } else { 
            $sessionId = $sessionInfo[1] 
        }
    
        # Status
        if ($sessionInfo[3] -match 'Active|Disc') { $status = $sessionInfo[3] } else { $status = $sessionInfo[2] }

        # Logoff users
        if ($status -ne 'Disc' -and $username -ne $CURRENT_USER) {
            Write-Host "Logging off session $sessionId (user: $username)"
            logoff $sessionId /server:$env:COMPUTERNAME
        }
    }
}

# Close open shared files
function Close-OpenFiles {
    $openfiles = openfiles /query /fo table | Select-Object -Skip 1 | Where-Object { $_ -match "SharedFileName" }

    if ($openFiles) {
        Write-Host "Closing the following locked files:"
        $openFiles | ForEach-Object {
            $fileInfo = $_ -split "\s+" | Where-Object { $_ }
            $filePath = $fileInfo[-1]
            $fileId = $fileInfo[0]
        
            Write-Host " - $filePath (ID: $fileId)"
            openfiles /disconnect /id $fileId
        }
    }
}

# Detect active logon sessions through user processes
function Get-ActiveUserSessions {
    Get-Process -IncludeUserName | Where-Object { $_.UserName } | Select-Object ProcessName, UserName, StartTime
}

#===========================================================================
# WINDOWS REGISTRY
#===========================================================================

# Get registry keys
Get-Item 'HKCU:\Control Panel\Accessibility\StickyKeys'
Get-Item "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs"

# Search for specific registry keys
Get-ChildItem -Path "HKCU:\" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq "KeyName" }

# Get registry values
(Get-ChildItem -Path "HKCU:\" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq "KeyName" }).Property

# Get specific registry properties
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs" | Get-ItemProperty

# Search registry recursively
Get-ChildItem -Path "HKLM:\" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq "keyname" }

#===========================================================================
# WINDOWS SERVICES AND PROCESSES
#===========================================================================

# Show all running processes
Get-Process | Select-Object Name, Id, Path, StartTime | Format-Table -AutoSize

# An alternative view of process modules
(Get-Process).Modules | Select-Object Company, Description, ModuleName, Product

# Show running services
Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name, DisplayName, Status, StartType

# Get information about a particular process.
# In this case I am able to see the actual file that executed a particular process
Get-WmiObject Win32_Process -Filter "Name = 'MSACCESS.EXE'" | Select-Object CommandLine

# Show all startup applications
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location | Format-Table -AutoSize

# Get Windows service information
Get-CimInstance -Class Win32_Service -Filter "Name='ServiceName'"
(Get-CimInstance -Class Win32_Service -Filter "Name='ServiceName'").PathName
Get-Service -Name "servicename" | Select-Object *

# Get startup commands
Get-WmiObject -Class Win32_StartupCommand

# Get distributed COM applications
Get-CimInstance -Namespace "root\cimv2" -ClassName Win32_DCOMApplication -Filter "AppID='{59B8AFA0-229E-46D9-B980-DDA2C817EC7E}'"

# Show installed software
function Get-InstalledSoftware {
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
        Select-Object DisplayName, DisplayVersion, Publisher | Format-Table -AutoSize
}

# Another variant for getting installed software
function Get-InstalledSoftwareAll {
    try {
        Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, 
                         HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, 
                         HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
        Select-Object DisplayName, DisplayVersion, InstallDate | Format-Table -AutoSize
        exit 0 # success
    } catch {
        "Error in line $($_.InvocationInfo.ScriptLineNumber): $($Error[0])"
        exit 1
    }
}

# Another variant for getting installed software (v2)
# I prefer this version
function Get-InstalledSoftwareAllv2 {
    $registryPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $softwareList = $registryPaths | ForEach-Object {
        Get-Item $_ -ErrorAction SilentlyContinue |
        Get-ItemProperty |
        Where-Object { $_.DisplayName -and $_.DisplayVersion } |
        Select-Object DisplayName, DisplayVersion, Publisher
    }

    $softwareList | Sort-Object DisplayName
}

function Remove-InstalledSoftware {
    param (
        [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$SoftwareName,

        [Parameter(Mandatory=$false, Position=2)]
        [ValidateSet($true, $false)]
        [boolean]$Find = $false,

        [Parameter(Position=3)]
        [boolean]$Confirm = $true
    )

    $registryPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $uninstallPaths = $registryPaths | ForEach-Object {
        if ($Find) {
            Get-Item $_ -ErrorAction SilentlyContinue | Get-ItemProperty |
            Where-Object { $_.DisplayName -like "*SQL*" } | Select-Object DisplayName, UninstallString
        } else {
            Get-Item $_ -ErrorAction SilentlyContinue | Get-ItemProperty |
            Where-Object { $_.DisplayName -eq $SoftwareName } | Select-Object DisplayName, UninstallString
        }
    }

    if ($Confirm) {
        $uninstallPaths # Show the software to be removed
        $confirmation = Read-Host "Are you sure you want to remove '$SoftwareName'? (Y/N)"
        if ($confirmation -ne 'Y') {
            Write-Host "Operation cancelled."
            return
        } else {
            Write-Host "Removing '$SoftwareName'..."
            $uninstallPaths | ForEach-Object {
                if ($_.UninstallString -ne "") {
                    if ($_.UninstallString -like "MsiExec.exe*") {
                        $msiExecParts = $_.UninstallString -split ' '
                        $uninstallPath = $msiExecParts[0]
                        $uninstallArguments = $msiExecParts[1]

                        Start-Process -FilePath $uninstallPath -ArgumentList $uninstallArguments -Wait
                    } else {
                        Start-Process -FilePath $_.UninstallString -Wait
                    }
                }
            }
        }
    }
}

# Get ready scheduled tasks
function Get-ReadyScheduledTasks {
    Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' } | Select-Object TaskName, TaskPath
}

# Get startup programs
function Get-StartupPrograms {
    Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object PSChildName, *
}

# Kill all the docker processes
# This can be a useful way of killing a process that has multiple instances
Stop-Process (Get-Process | Where-Object { $_.Name -ilike "*docker*" }).Id

#===========================================================================
# GROUP POLICY
#===========================================================================

# Get all group policies
Get-GPO -All

# Sort group policies by creation time
Get-GPO -All | Sort-Object CreationTime -Descending

# Find group policies with specific descriptions
Get-GPO -All | Where-Object { $_.Description -eq 'Description' }

# Get AppLocker policy
Get-AppLockerPolicy -Effective -Xml

#===========================================================================
# FILE SYSTEM AND DISK
#===========================================================================

# See contents of Recycle Bin
function Get-RecycleBinContents {
    $shell = New-Object -ComObject Shell.Application
    $recycleBin = $shell.Namespace(10)
    $recycleBin.Items() | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            Type = $_.Type
            Date = $_.ModifyDate
        }
    } | Format-Table -A
}

# Clear Recycle Bin
Clear-RecycleBin -Force

# Enumeration of administrative shares
function Get-AdminShares {
    Get-WmiObject -Query "SELECT * FROM Win32_Share WHERE Type=0" | Select-Object Name, Path
}

#===========================================================================
# SECURITY AND PRIVACY
#===========================================================================

# Look at the GeoLocation information
function Get-GeoLocationInfo {
    Add-Type -AssemblyName System.Device
    [System.Device.Location.GeoCoordinate]::Unknown
    [System.Device.Location.GeoCoordinate]::Unknown.Latitude
    [System.Device.Location.GeoCoordinate]::Unknown.Longitude
}

# Grant Location Access in Registry
function Grant-LocationAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Location Access in Registry
function Revoke-LocationAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
}

function Disable-SSL2.0 {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Name 'Enabled' -Value '0' -Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Name 'DisabledByDefault' -value '1' -Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'Enabled' -value '0' -Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value '1' -Type 'DWORD'
}

function Disable-SSL3.0 {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'Enabled' -Value '0' -Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'DisabledByDefault' -Value '1' -Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'Enabled'  -Value '0' -Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'DisabledByDefault' -Value '1' -Type 'DWORD'  
}

function Disable-TLS1.0 {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'Enabled' -value '0' -Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'DisabledByDefault' -value '1' -Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' -value '0' -Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' -value '1' -Type 'DWORD'
}

function Disable-TLS1.1 {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value '0' -Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value '1' -Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value '0' -Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' -value '1' -Type 'DWORD'
}

function Enable-TLS1.2 {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force                                  
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value '1' -Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value '0' -Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value '1' -Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value '0' -Type 'DWORD'    
}

function Enable-TLS1.3 {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Force
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Force                                  
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -name 'Enabled' -value '1' -Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -name 'DisabledByDefault' -value '0' -Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -name 'Enabled' -value '1' -Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -name 'DisabledByDefault' -value '0' -Type 'DWORD'    
}

function Get-SecureProtocolStatus {
    $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

    $protocols = @(
        @{ Name = "SSL 2.0"; Expected = @{ Client = @{Enabled=0; DisabledByDefault=1}; Server = @{Enabled=0; DisabledByDefault=1} } },
        @{ Name = "SSL 3.0"; Expected = @{ Client = @{Enabled=0; DisabledByDefault=1}; Server = @{Enabled=0; DisabledByDefault=1} } },
        @{ Name = "TLS 1.0"; Expected = @{ Client = @{Enabled=0; DisabledByDefault=1}; Server = @{Enabled=0; DisabledByDefault=1} } },
        @{ Name = "TLS 1.1"; Expected = @{ Client = @{Enabled=0; DisabledByDefault=1}; Server = @{Enabled=0; DisabledByDefault=1} } },
        @{ Name = "TLS 1.2"; Expected = @{ Client = @{Enabled=1; DisabledByDefault=0}; Server = @{Enabled=1; DisabledByDefault=0} } },
        @{ Name = "TLS 1.3"; Expected = @{ Client = @{Enabled=1; DisabledByDefault=0}; Server = @{Enabled=1; DisabledByDefault=0} } }
    )

    $results = @()
    foreach ($protocol in $protocols) {
        $name = $protocol.Name
        foreach ($role in @("Client", "Server")) {
            $path = Join-Path -Path $basePath -ChildPath "$name\$role"
            $status = @{
                Protocol = $name
                Role     = $role
                Enabled  = "Missing"
                DisabledByDefault = "Missing"
                Status   = "Missing"
            }

            if (Test-Path $path) {
                try {
                    $enabled = Get-ItemPropertyValue -Path $path -Name "Enabled" -ErrorAction Stop
                    $disabled = Get-ItemPropertyValue -Path $path -Name "DisabledByDefault" -ErrorAction Stop
                    $status.Enabled = $enabled
                    $status.DisabledByDefault = $disabled

                    $expectedEnabled = $protocol.Expected[$role]["Enabled"]
                    $expectedDisabled = $protocol.Expected[$role]["DisabledByDefault"]

                    if ($enabled -eq $expectedEnabled -and $disabled -eq $expectedDisabled) {
                        $status.Status = "OK"
                    } else {
                        $status.Status = "Mismatch"
                    }
                } catch {
                    $status.Status = "Error"
                }
            }
            $results += New-Object PSObject -Property $status
        }
    }
    return $results | Format-Table -AutoSize
}

function Enable-SecureProtocols {
    Disable-SSL2.0
    Disable-SSL3.0
    Disable-TLS1.0
    Disable-TLS1.1
    Enable-TLS1.2
    Enable-TLS1.3

    Get-SecureProtocolStatus
}

# Get Windows Defender Logs
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -ErrorAction SilentlyContinue

# Get Windows Firewall Logs
Get-WinEvent -LogName 'Security' -FilterXPath "*[System[EventID=5152 or EventID=5153]]" -ErrorAction SilentlyContinue

# Get PowerShell History Files
Get-ChildItem -Path (Split-Path -Parent (Get-PSReadLineOption).HistorySavePath)

# Another way to get PowerShell history
Get-ChildItem -Path "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"

#===========================================================================
# UTILITY FUNCTIONS
#===========================================================================

# Get the current date and time
# Default format is "dd/MM/yyyy HH:mm:ss"
Get-Date

# Get current date in a specific format
# This will return a human readable date format
# Example: 23 March 2023
Get-Date -Format "dd MMMM yyyy"

# Get yesterday's date in previous format
((Get-Date).AddDays(-1)).ToString("dd MMMM yyyy")

# Convert Bytes to Human Readable Size
function Convert-FromBytes {
    param ([long]$Size)
    switch ($Size) {
        {$_ -ge 1PB} { "{0:N2} PB" -f ($Size / 1PB); break }
        {$_ -ge 1TB} { "{0:N2} TB" -f ($Size / 1TB); break }
        {$_ -ge 1GB} { "{0:N2} GB" -f ($Size / 1GB); break }
        {$_ -ge 1MB} { "{0:N2} MB" -f ($Size / 1MB); break }
        {$_ -ge 1KB} { "{0:N2} KB" -f ($Size / 1KB); break }
        default { "$Size bytes" }
    }
}

# Convert any human readable size into bytes
function Convert-ToBytes {
    param (
        [double]$Size,
        [ValidateSet('PB', 'TB', 'GB', 'MB', 'KB', 'Bytes')]
        [string]$Unit
    )
    
    switch ($Unit) {
        'PB'    { return [long]($Size * 1PB) }
        'TB'    { return [long]($Size * 1TB) }
        'GB'    { return [long]($Size * 1GB) }
        'MB'    { return [long]($Size * 1MB) }
        'KB'    { return [long]($Size * 1KB) }
        'Bytes' { return [long]$Size }
    }
}

# Base64 Encoding or Decoding of either a file or a string
function B64 {
[CmdletBinding(DefaultParameterSetName="encFile")]
param(
    [Parameter(Position=0, ParameterSetName="encFile")]
    [Alias("ef")]
    [string]$encFile,

    [Parameter(Position=0, ParameterSetName="encString")]
    [Alias("es")]
    [string]$encString,

    [Parameter(Position=0, ParameterSetName="decFile")]
    [Alias("df")]
    [string]$decFile,

    [Parameter(Position=0, ParameterSetName="decString")]
    [Alias("ds")]
    [string]$decString

)

if ($psCmdlet.ParameterSetName -eq "encFile") {
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes((Get-Content -Path $encFile -Raw -Encoding UTF8)))
        return $encoded
        }

elseif ($psCmdlet.ParameterSetName -eq "encString") {
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($encString))
        return  $encoded
        }

elseif ($psCmdlet.ParameterSetName -eq "decFile") {
        $data = Get-Content $decFile
        $decoded = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($data))
        return $decoded        
        }

elseif ($psCmdlet.ParameterSetName -eq "decString") {        
        $decoded = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($decString))
        return $decoded
        }
}

# Get string hash (equivalent to 'echo -n "Hello" | sha256sum')
function Get-StringHash {
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$String,
        
        [Parameter(Position=1)]
        [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5')]
        [string]$Algorithm = 'SHA256'
    )
    
    return (Get-FileHash -InputStream ([IO.MemoryStream]::new([byte[]][char[]]$String)) -Algorithm $Algorithm).Hash
}

# Example usage of Get-StringHash
# Get-StringHash "Hello"
# Get-StringHash "Hello" -Algorithm MD5

function ConvertFrom-Hours {
    param (
        [int]$Hours,
        [string]$ConvertTo
    )
    switch -Regex ($ConvertTo) {
        "^[mM]illiseconds$|^[mM][sS]$" {$Hours * 60 * 60 * 1000}
        "^[sS]econds$|^[sS]$" {$Hours * 60 * 60}
        "^[mM]inutes$|^[mM]$" {$Hours * 60}
    }
}

function ConvertFrom-Minutes {
    param (
        [int]$Minutes,
        [string]$ConvertTo
    )
    switch -Regex ($ConvertTo) {
        "^[mM]illiseconds$|^[mM][sS]$" {$Minutes * 60 * 1000}
        "^[sS]econds$|^[sS]$" {$Minutes * 60}
        "^[hH]ours$|^[hH]$" {$Minutes / 60}
    }
}

function ConvertFrom-DateToISO8601 {
    param (
        [datetime]$Date
    )
    return $Date.ToUniversalTime().ToString("o")      
}

function ConvertFrom-HexToAscii {
    param(
        [string]$HexString
    )
    # Split the hex string into bytes (2 characters each)
    $bytes = -split ($hexString -replace '..', '$0 ')
    # Convert each byte to an integer and then to a char
    return ($bytes | ForEach-Object { [char]([convert]::ToInt32($_, 16)) }) -join ''
}

function ConvertFrom-AsciiToHex {
    param(
        [string]$AsciiString
    )
    # Convert each character to its hex representation
    return ($AsciiString.ToCharArray() | ForEach-Object { '{0:X2}' -f [int]$_ }) -join ''
}

#===========================================================================
# MODULES
#===========================================================================

# Install a module from the PowerShell Gallery for the CurrentUser
Install-Module -Name "PSReadLine" -Scope CurrentUser 

# Install a module from the PowerShell Gallery for the LocalMachine
Install-Module -Name "PSWindowsUpdate" -Scope LocalMachine

# Create a new PowerShell module by creating a .psm1 file
# Add all your functions to the .psm1 file
# At the end you want to add the following line to export all functions
Export-ModuleMember -Function Function1, Function2, Function3

# Run this to create a new module metadate file
New-ModuleManifest -Path ".\MyAwesomeModule.psd1" `
    -RootModule "MyAwesomeModule.psm1" `
    -Author "Your Name" `
    -Description "My first PowerShell module" `
    -ModuleVersion "1.0.0"

Import-Module -Name "MyAwesomeModule"