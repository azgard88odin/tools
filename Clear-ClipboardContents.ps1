Add-Type -AssemblyName System.Windows.Forms

function Get-SHA256OfString {
    param (
        [string]$String
    )
    return (Get-FileHash -InputStream ([IO.MemoryStream]::new([byte[]][char[]]$String)) -Algorithm SHA256).Hash
}

function Get-ClipboardDataHash {
    if ([System.Windows.Forms.Clipboard]::ContainsText()) {
        $text = [System.Windows.Forms.Clipboard]::GetText()
        return Get-SHA256OfString -String $text
    } elseif ([System.Windows.Forms.Clipboard]::ContainsFileDropList()) {
        $files = ([System.Windows.Forms.Clipboard]::GetFileDropList() | Sort-Object) -join "|"
        return Get-SHA256OfString -String $files
    } else {
        return Get-SHA256OfString -String $null
    }
}

$lastClipboardChange = Get-Date
$clearDelayMinutes = 2
$oldClipboardDataHash = Get-ClipboardDataHash

while ($true) {
    $clipboardDataFormats = [System.Windows.Forms.Clipboard]::GetDataObject().GetFormats()
    $timeSinceLastChange = ((Get-Date) - $lastClipboardChange).TotalMinutes
    $currentClipboardDataHash = Get-ClipboardDataHash

    if ($clipboardDataFormats -gt 0 -and $timeSinceLastChange -lt $clearDelayMinutes -and $currentClipboardDataHash -ne $oldClipboardDataHash) {
        $oldClipboardDataHash = $currentClipboardDataHash
        $lastClipboardChange = Get-Date
    }

    if ($timeSinceLastChange -ge $clearDelayMinutes -and $currentClipboardDataHash -eq $oldClipboardDataHash) {
        [System.Windows.Forms.Clipboard]::Clear()
        Write-Output "[$(Get-Date)] Clipboard cleared."
        $lastClipboardChange = Get-Date
    }

    Start-Sleep -Seconds 5
}
