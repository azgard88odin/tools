function Set-DesktopWallpaper {
    $desktopImages = "$env:WALLPAPERS\Desktop"
    $newDesktopWallpaper = Get-ChildItem -Path $desktopImages | Get-Random

    Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public class Wallpaper {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
'@
    [Wallpaper]::SystemParametersInfo(20, 0, $newDesktopWallpaper.FullName, 3)
}

function Set-LockScreenWallpaper {
    $lockScreenImages = "$env:WALLPAPERS\Lockscreen"
    $newLockScreenWallpaper = Get-ChildItem -Path $lockScreenImages | Get-Random
    
    $Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP'
    if (!(Test-Path -Path $Key)) {
       New-Item -Path $Key -Force | Out-Null
    }
    Set-ItemProperty -Path $Key -Name LockScreenImagePath -Value $newLockScreenWallpaper.FullName
}

function Show-CryptoRate { param([string]$Symbol, [string]$Name)
	$rates = (Invoke-WebRequest -URI "https://min-api.cryptocompare.com/data/price?fsym=$Symbol&tsyms=USD,EUR,GBP,ZAR" -userAgent "curl" -useBasicParsing).Content | ConvertFrom-Json
	New-Object PSObject -property @{ 
        'CRYPTOCURRENCY' = "1 $Name ($Symbol) ="
        'US$' = "$($rates.USD)"
        '`u20AC' = "$($rates.EUR)"
        '`u00A3' = "$($rates.GBP)"
        'R' = "$($rates.ZAR)" 
    }
}

function Show-CryptoRates { 
	Show-CryptoRate AVAX  "Avalanche"
	Show-CryptoRate BNB   "Binance Coin"
	Show-CryptoRate BTC   "Bitcoin"
	Show-CryptoRate BCH   "Bitcoin Cash"
	Show-CryptoRate BUSD  "Binance USD"
	Show-CryptoRate ADA   "Cardano"
	Show-CryptoRate LINK  "Chainlink"
	Show-CryptoRate DOGE  "Dogecoin"
	Show-CryptoRate GALA  "Gala"
	Show-CryptoRate ETH   "Ethereum"
	Show-CryptoRate LTC   "Litecoin"
	Show-CryptoRate TRUMP "Official Trump"
	Show-CryptoRate DOT   "Polkadot"
	Show-CryptoRate MATIC "Polygon"
	Show-CryptoRate SOL   "Solana"
	Show-CryptoRate XLM   "Stellar"
	Show-CryptoRate SUI   "Sui"
	Show-CryptoRate LUNA  "Terra"
	Show-CryptoRate USDT  "Tether"
	Show-CryptoRate WBTC  "Wrapped Bitcoin"
	Show-CryptoRate XRP   "XRP"
	Show-CryptoRate UNI   "Uniswap"
	Show-CryptoRate USDC  "USD Coin"
}

function Get-CryptoPrices {
    try {
	    Show-CryptoRates | Format-Table -Property @{e='CRYPTOCURRENCY';width=28},'US$','€','£','R'
	    Write-Host "(by https://www.cryptocompare.com • Crypto is volatile and unregulated • Capital at risk • Taxes may apply)"
    } catch {
	    "Error in line $($_.InvocationInfo.ScriptLineNumber): $($Error[0])"
    }
}

function Set-AutoHideTaskbar {
    param(
        [boolean]$Enable = $true
    )    
    $regPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3'
    $regValueName = 'Settings'

    $settings = (Get-ItemProperty -Path $regPath -Name $regValueName).$regValueName

    # Clone the array to modify
    $modifiedSettings = [byte[]]::new($settings.Length)
    $settings.CopyTo($modifiedSettings, 0)

    # the 9th byte must be set to 03 for auto-hide and 02 for normal
    if ($Enable) {
        $modifiedSettings[8] = $modifiedSettings[8] -bor 0x03
    } else {
        $modifiedSettings[8] = $modifiedSettings[8] -band 0x02
    }

    # Write back the modified binary value
    Set-ItemProperty -Path $regPath -Name $regValueName -Value $modifiedSettings

    # Restart Explorer to apply changes
    Stop-Process -Name explorer -Force
    Start-Process explorer -NoNewWindow
}

function Set-TaskbarAlignment {
    param(
        [string]$Justify
    )
    switch -Regex ($Justify) {
        "[lL]eft" {Set-ItemProperty -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0}
        "[cC]enter" {Set-ItemProperty -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 1}
    }
}

function Show-CustomCommands {
    $modules = @(
        "PrivacyAndSecurity",
        "CheatSheets",
        "CustomUtilities",
        "InvestigateLogs",
        "NetworkEnumeration",
        "Personalization"
        )

    $results = @()
    $modules | ForEach-Object {
        $moduleName = $_
        $module = Get-Module -Name $moduleName -ErrorAction SilentlyContinue
        if ($module) {
            $module.ExportedCommands.Values.Name | ForEach-Object {
                $results += [PSCustomObject]@{
                    'Command' = $_
                    'Module' = $moduleName
                    'Version' = $module.Version
                }
            }
        }
    }
    $results | Sort-Object Module, Command | Format-Table -AutoSize
}

function Update-CustomModules {
    $modules = @(
        "PrivacyAndSecurity",
        "CheatSheets",
        "CustomUtilities",
        "InvestigateLogs",
        "NetworkEnumeration",
        "Personalization"
        )
    
    $modules | ForEach-Object {
        Remove-Module -Name $_ -Force -ErrorAction SilentlyContinue
    }
    $modules | ForEach-Object {
        Import-Module -Name $_ -Force
    }
}

function Get-CyberNews {
    param(
        [int]$EventsPerSource = 5
    )
      
    # Ensure BurntToast is installed
    if (-not (Get-Module -ListAvailable -Name BurntToast)) {
        Install-Module -Name BurntToast -Force -Scope CurrentUser
    }
    Import-Module BurntToast

    $htmlFile = "$env:TEMP\CyberNewsReport.html"

    # Define RSS feeds
    $feeds = @(
        "https://www.bleepingcomputer.com/feed/",
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.darkreading.com/rss.xml",
        "https://www.cyberscoop.com/feed/",
        "https://krebsonsecurity.com/feed/",
        "https://www.securityweek.com/feed/",
        "https://threatpost.com/feed/"

    )

    $newsItems = @()
    foreach ($url in $feeds) {
        try {
            $rss = [xml](Invoke-WebRequest -Uri $url -UseBasicParsing).Content
            $source = $rss.rss.channel.title
            $items = $rss.rss.channel.item | Select-Object -First $EventsPerSource

            foreach ($item in $items) {
                $newsItems += [PSCustomObject]@{
                    Title  = if ($item.title.'#cdata-section') { $item.title.'#cdata-section' } else { $item.title }
                    Link   = if ($item.link.'#cdata-section')  { $item.link.'#cdata-section'  } else { $item.link }
                    Source = $source
                }
            }
        } catch {
            Write-Warning "Failed to fetch or parse feed: $url"
        }
    }

    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="color-scheme" content="dark light">
    <title>Cybersecurity Headlines</title>
    <style>
        :root {
            --bg-color: #121212;
            --text-color: #e0e0e0;
            --link-color: #64b5f6;
            --source-color: #90caf9;
        }

        .light-mode {
            --bg-color: #ffffff;
            --text-color: #000000;
            --link-color: #0078d7;
            --source-color: #0066cc;
        }

        body {
            font-family: Segoe UI, sans-serif;
            margin: 2em;
            background-color: var(--bg-color);
            color: var(--text-color);
            transition: background-color 0.3s, color 0.3s;
        }

        h1 {
            color: var(--text-color);
        }

        .source {
            font-size: 1.2em;
            color: var(--source-color);
            margin-top: 1em;
        }

        ul {
            list-style: none;
            padding: 0;
        }

        li {
            margin: 0.5em 0;
        }

        a {
            text-decoration: none;
            color: var(--link-color);
        }

        a:hover {
            text-decoration: underline;
        }

        .toggle-button {
            position: fixed;
            top: 1em;
            right: 1em;
            padding: 0.5em 1em;
            background-color: #333;
            color: #fff;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            z-index: 1000;
        }

        .light-mode .toggle-button {
            background-color: #ccc;
            color: #000;
        }
    </style>
</head>
<body>
    <button class="toggle-button" onclick="toggleTheme()">Toggle Theme</button>
    <h1>🛡️ Top Cybersecurity Headlines</h1>

    <script>
        function toggleTheme() {
            document.body.classList.toggle('light-mode');
        }
    </script>
"@

    # Group by source
    $grouped = $newsItems | Group-Object Source
    foreach ($group in $grouped) {
        $htmlContent += "<div class='source'>$($group.Name)</div><ul>"
        foreach ($item in $group.Group) {
            $htmlContent += "<li><a href='$($item.Link)' target='_blank'>$($item.Title)</a></li>"
        }
        $htmlContent += "</ul>"
    }

    $htmlContent += "</body></html>"

    # Save HTML
    $htmlContent | Set-Content -Path $htmlFile -Encoding UTF8

    # Open in default web browser
    Start-Process $htmlFile

    # Toast Notification
    New-BurntToastNotification -Text "Cybersecurity News Ready", "Top stories opened in your browser"
}

Export-ModuleMember -Function Set-DesktopWallpaper, Set-LockScreenWallpaper, Show-CryptoRate,
Show-CryptoRates, Get-CryptoPrices, Set-AutoHideTaskbar, Set-TaskbarAlignment, Show-CustomCommands,
Update-CustomModules, Get-CyberNews