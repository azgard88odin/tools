# Input bytes and receive a human-readable format
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
        Select-Object FullName, @{Name="Size";Expression={(Convert-FromBytes -Size $_.Length) -f ($_.Length / $MinSize)}}
}

function Get-B64 {
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

Export-ModuleMember -Function Convert-FromBytes, Convert-ToBytes, Find-FileLargerThan, Get-B64, Get-StringHash, Get-InstalledSoftware, Get-StartupPrograms
