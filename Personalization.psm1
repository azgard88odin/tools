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
Export-ModuleMember -Function Set-DesktopWallpaper, Set-LockScreenWallpaper, Show-CryptoRate, Show-CryptoRates, Get-CryptoPrices
