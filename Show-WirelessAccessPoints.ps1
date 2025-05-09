function Grant-LocationAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Allow" /f
}

function Revoke-LocationAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
}

function Connect-WiFiNetwork {
    param (
        [string]$SSID
    )
    netsh wlan connect name=$SSID
}

function Disable-WirelessInterface {
    netsh interface set interface name="Wi-Fi" admin=disabled
}

function Enable-WirelessInterface {
    netsh interface set interface name="Wi-Fi" admin=enabled
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

$currentSSID = (netsh wlan show interfaces) -match '^\s*SSID\s*:(.+)' | ForEach-Object { ($_ -split ':')[1].Trim() }

Grant-LocationAccess

Disable-WirelessInterface
Start-Sleep -Seconds 3
Enable-WirelessInterface

Connect-WiFiNetwork -SSID $currentSSID
Show-WirelessAccessPoints

Revoke-LocationAccess
