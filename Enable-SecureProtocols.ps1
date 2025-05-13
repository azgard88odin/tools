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
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'Enabled' -value '0' –Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'DisabledByDefault' -value '1' –Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' -value '0' –Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' -value '1' –Type 'DWORD'
}

function Disable-TLS1.1 {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value '0' –Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value '1' –Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value '0' –Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' -value '1' –Type 'DWORD'
}

function Enable-TLS1.2 {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force                                  
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value '1' –Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value '0' –Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value '1' –Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value '0' –Type 'DWORD'    
}

function Enable-TLS1.3 {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Force
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Force                                  
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -name 'Enabled' -value '1' –Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -name 'DisabledByDefault' -value '0' –Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -name 'Enabled' -value '1' –Type 'DWORD'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -name 'DisabledByDefault' -value '0' –Type 'DWORD'    
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

Enable-SecureProtocols
