# Input bytes and receive a human-readable format
function ConvertFrom-Bytes {
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
function ConvertTo-Bytes {
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

# Find files larger than a specified size
# Usage: Find-FileLargerThan -Path "C:\" -MinSize 1GB
# This function looks in the C:\ drive and finds files larger than 1GB by default.
function Find-FileLargerThan {
    param(
        [string]$Path = "C:\",
        [long]$MinSize = 1GB
    )
        Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue -Force |
        Where-Object { -not $_.PSIsContainer -and $_.Length -gt $MinSize } |
        Select-Object FullName, @{Name="Size";Expression={(ConvertFrom-Bytes -Size $_.Length) -f ($_.Length / $MinSize)}}
}

function ConvertTo-Base64 {
    param (
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $false)]
        [string]
        [Alias("String")]
        $PlainTextString,

        [Parameter(Position = 0, Mandatory = $false)]
        [string]
        [Alias("File")]
        $PlainTextFilePath
    )
    if ($PlainTextString -ne "") {
        return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Base64String))
    }
    if ($PlainTextFilePath -ne "") {
        return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((Get-Content -Path $PlainTextFilePath -Raw -Encoding UTF8)))
    }
}

function ConvertFrom-Base64 {
    param (
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $false)]
        [string]
        [Alias("String")]
        $Base64String,

        [Parameter(Position = 0, Mandatory = $false)]
        [string]
        [Alias("File")]
        $EncodedFilePath
    )
    if ($Base64String -ne "") {
        return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Base64String))
    }
    if ($EncodedFilePath -ne "") {
        return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((Get-Content -Path $EncodedFilePath)))
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

function Get-InstalledSoftware {
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

function Get-StartupPrograms {
    Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command, Description, User, Location
}

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

# Convert PowerShell script to a batch file that runs the script using PowerShell
#Get-ChildItem -Path C:\Users\dexte\Documents\testing -Filter *.ps1 | Convert-PowerShellToBatch
#Convert-PowerShellToBatch -Path "C:\users\dexte\documents\testing\Test.ps1" -Extension bat
#Convert-PowerShellToBatch -Path "C:\users\dexte\documents\testing\Test.ps1" -Extension cmd
function ConvertFrom-PowerShellToBatch
{
    param
    (
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]
        [Alias("FullName")]
        $Path,

        [Parameter(Position = 1)]
        [ValidateSet("cmd", "bat")]
        [string]
        $Extension = "cmd",

        [Parameter(Position = 2)]
        [ValidateSet("Exit", "NoExit")]
        [string]
        $ExceptionType = "Exit"

    )
 
    process
    {
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes((Get-Content -Path $Path -Raw -Encoding UTF8)))
        $newExtension = ".$Extension"
        $newPath = [Io.Path]::ChangeExtension($Path, $newExtension)

        if ($ExceptionType -eq "NoExit") {
            "@echo off`npowershell.exe -NoExit -encodedCommand $encoded" | Set-Content -Path $newPath -Encoding Ascii
        } else {
            "@echo off`npowershell.exe -encodedCommand $encoded" | Set-Content -Path $newPath -Encoding Ascii
        }
    }
}

# This function checks if a file's hash matches a given checksum.
# Usage: Test-FileHash -FilePath ".\test.txt" -CheckSum "790FD9AB423DA9D5200B3533C5D4F519FA9D45183242C8E8FE64A77D92E11EE2" -Algorithm SHA256
function Test-FileHash {
    param(
        [Parameter(Position = 1, Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Position = 2, Mandatory = $true)]
        [string]$CheckSum,

        [Parameter(Position = 3,Mandatory = $true)]
        [ValidateSet("MD5","SHA1","SHA256")]
        [string]$Algorithm
    )
    $fileHash = (Get-FileHash -Path $FilePath -Algorithm $Algorithm).Hash
    
    return $fileHash -eq $CheckSum
}

function Reset-NetworkStack {

    Write-Host "Flushing DNS..."
    ipconfig /flushdns

    Write-Host "Releasing IP addresses..."
    ipconfig /release

    Write-Host "Renewing IP addresses..."
    ipconfig /renew

    Write-Host "Restarting DNS Client service..."
    Restart-Service -Name "Dnscache" -Force

    Write-Host "Restarting DHCP Client service..."
    Restart-Service -Name "Dhcp" -Force

    # Optional: restart TCP/IP stack (requires reboot)
    # netsh int ip reset

    # Optional: disable and re-enable network adapters
    $adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' }

    foreach ($adapter in $adapters) {
        Write-Host "Disabling adapter: $($adapter.Name)"
        Disable-NetAdapter -Name $adapter.Name -Confirm:$false
        Start-Sleep -Seconds 3
        Write-Host "Enabling adapter: $($adapter.Name)"
        Enable-NetAdapter -Name $adapter.Name -Confirm:$false
    }

    Write-Host "Networking stack restart complete."
}

Function ConvertTo-Unicode {
    Begin {
        $output=[System.Text.StringBuilder]::new()
    }
    Process {
        $output.Append($(
            if ($_ -is [int]) { [char]::ConvertFromUtf32($_) }
            else { [string]$_ }
        )) | Out-Null
    }
    End { $output.ToString() }
}

Export-ModuleMember -Function ConvertFrom-Bytes, ConvertTo-Bytes, Find-FileLargerThan, ConvertTo-Base64, ConvertFrom-Base64,
Get-StringHash, Get-InstalledSoftware, Get-StartupPrograms, ConvertFrom-Hours, ConvertFrom-Minutes, ConvertFrom-DateToISO8601,
ConvertFrom-HexToAscii, ConvertFrom-AsciiToHex, ConvertFrom-PowerShellToBatch, Test-FileHash,
Reset-NetworkStack, ConvertTo-Unicode