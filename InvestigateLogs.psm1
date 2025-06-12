# This function helps to find the event ID of a specific event type
# Look at the comments for the word you can use to find the event ID
# Example: Get-SecurityEventID -EventType "Logon"
# This will return the event ID for Logon which is 4624
function Get-SecurityEventID {
    param(
        [string]$EventType
    )
    switch -Regex ($EventType) {
        "[lL]og[sS]ervice[sS]hutdown" {1100}                    # LogServiceShutdown
        "[aA]udit[lL]og[cC]leared" {1102}                       # AuditLogCleared
        "[sS]ecurity[lL]og[fF]ull" {1104}                       # SecurityLogFull
        "[wW]indows[sS]tartup" {4608}                           # WindowsStartup
        "[wW]indows[sS]hutdown" {4609}                          # WindowsShutdown
        "[sS]ystem[tT]ime[cC]hanged" {4616}                     # SystemTimeChanged
        "[lL]ogon|[lL]ogin" {4624}                              # Logon
        "[fF]ailed ([lL]ogon|[lL]ogin)" {4625}                  # FailedLogon
        "[lL]ogoff|[lL]ogout" {4634}                            # Logoff
        "[eE]xplicit[lL]ogon" {4648}                            # ExplicitLogon
        "[rR]eplay[aA]ttack" {4649}                             # ReplayAttack
        "[oO]bject[dD]eleted" {4660}                            # ObjectDeleted
        "[oO]peration[oO]n[oO]bject" {4662}                     # OperationOnObject
        "[aA]pplication[oO]peration" {4666}                     # ApplicationOperation
        "[oO]bject[pP]ermissions[cC]hanged" {4670}              # ObjectPermissionsChanged
        "[sS]pecial[pP][lL]ogon" {4672}                         # SpecialLogon
        "[nN]ew[pP]rocess[cC]reated" {4688}                     # NewProcessCreated
        "[uU]nprotection[aA]uditable[dD]ata" {4695}             # UnprotectionAuditableData
        "[sS]ervice[iI]nstalled" {4697}                         # ServiceInstalled
        "[sS]cheduled[tT]ask[cC]reated" {4698}                  # ScheduledTaskCreated
        "[sS]cheduled[tT]ask[dD]eleted" {4699}                  # ScheduledTaskDeleted
        "[sS]cheduled[tT]ask[uU]pdated" {4702}                  # ScheduledTaskUpdated
        "[uU]ser[aA]ccount[cC]reated" {4720}                    # UserAccountCreated
        "[uU]ser[aA]ccount[eE]nabled" {4722}                    # UserAccountEnabled
        "[aA]ttempt[cC]hange[pP]assword" {4723}                 # AttemptChangePassword
        "[aA]ttempt[rR]eset[pP]assword" {4724}                  # AttemptResetPassword
        "[uU]ser[aA]ccount[dD]isabled" {4725}                   # UserAccountDisabled
        "[uU]ser[aA]ccount[dD]eleted" {4726}                    # UserAccountDeleted
        "[mM]ember[aA]dded[sS]ecurity[gG]roup" {4728}           # MemberAddedSecurityGroup
        "[cC]omputer[aA]ccount[cC]reated" {4741}                # ComputerAccountCreated
        "[cC]omputer[aA]ccount[cC]hanged" {4742}                # ComputerAccountChanged
        "[cC]omputer[aA]ccount[dD]eleted" {4743}                # ComputerAccountDeleted
        "[uU]ser[aA]ccount[uU]nlocked" {4767}                   # UserAccountUnlocked
        "[aA]ccount[nN]ame[cC]hanged" {4781}                    # AccountNameChanged
        "[pP]assword[hH]ash[aA]ccessed" {4782}                  # PasswordHashAccessed
        "[bB]lank[pP]assword[qQ]uery" {4797}                    # BlankPasswordQuery
        "[uU]ser[gG]roup[mM]embership[eE]numerated" {4798}      # UserGroupMembershipEnumerated
        "[sS]ecurity[gG]roup[mM]embership[eE]numerated" {4799}  # SecurityGroupMembershipEnumerated
        "[wW]orkstation[lL]ocked" {4800}                        # WorkstationLocked
        "[wW]orkstation[uU]nlocked" {4801}                      # WorkstationUnlocked
        "[pP]ending[cC]ertificate[dD]enied" {4868}              # PendingCertificateDenied
        "[rR]evoked[cC]ertificate" {4870}                       # RevokedCertificate
        "[cC]ertificate[bB]ackup" {4875}                        # CertificateBackup
        "[cC]ertificate[sS]ervice[sS]tarted" {4880}             # CertificateServiceStarted
        "[cC]ertificate[sS]ervice[sS]topped" {4881}             # CertificateServiceStopped
        "[cC]ertificate[pP]ermissions[cC]hanged" {4882}         # CertificatePermissionsChanged
        "[fF]irewall[eE]xception[rR]ule[aA]dded" {4946}         # FirewallExceptionRuleAdded
        "[fF]irewall[dD]efault[sS]ettings" {4949}               # FirewallDefaultSettings
        "[fF]irewall[pP]rogram[dD]isable" {4950}                # FirewallProgramDisable
        "[fF]irewall[sS]topped" {5025}                          # FirewallStopped
        "[fF]irewall[dD]river[sS]topped" {5034}                 # FirewallDriverStopped
        "[dD]evice[dD]isabled" {6420}                           # DeviceDisabled
    }
}

# This function helps to find the event ID of a specific event type
# Example: Find-SecurityLogs -EventType "Logon"
# Example: Find-SecurityLogs -EventID 4624
# Both of these will return the same result
function Find-SecurityLogs {
    param(
        [string]$EventID,
        [string]$EventType,
        [string]$Path
    )
    
    if ($EventType -ne "") {
        $EventID = Get-SecurityEventID -EventType $EventType
    }

    if ($Path -eq "") {
        Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=$EventID]]"
    } else {
        Get-WinEvent -Path $Path -FilterXPath "*[System[EventID=$EventID]]"
    }
}

# This function helps to find the event ID of a specific event type linked to a specific user
# Example: Find-SecurityLogsByUser -EventType "Logon" -Username "Administrator"
# Example: Find-SecurityLogsByUser -EventID 4624 -Username "Administrator"
function Find-SecurityLogsByUser {
    param(
        [string]$EventID,
        [string]$EventType,
        [string]$Username,
        [string]$UserSID,
        [string]$Path
    )

    if ($EventID -ne "") {
        $EventID = Get-SecurityEventID -EventType $EventType
    }

    if ($Username -ne "" -and $Path -eq "") {
        Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=$EventID] and EventData[Data[@Name='TargetUserName']=$Username]]"
    } else {
        Get-WinEvent -Path $Path -FilterXPath "*[System[EventID=$EventID] and EventData[Data[@Name='TargetUserName']=$Username]]"
    }

    if ($UserSID -ne "" -and $Path -eq "") {
        Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=$EventID] and EventData[Data[@Name='TargetUserSid']=$UserSID]]"
    } else {
        Get-WinEvent -Path $Path -FilterXPath "*[System[EventID=$EventID] and EventData[Data[@Name='TargetUserSid']=$UserSID]]"
    }
}

# This function helps to find the event ID of a specific event type linked to a specific logon type
# Example: Find-SecurityAccountLogonsByType -LogonType "Interactive"
# Example: Find-SecurityAccountLogonsByType -LogonType "Network"
# Example: Find-SecurityAccountLogonsByType -LogonType "Service"
# These will all return the logs based on the specific types of logons
function Find-SecurityAccountLogonsByType {
    param(
        [string]$LogonType,
        [string]$Path
    )
    
    if ($Path -eq "") {
        switch -Regex ($LogonType) {
            "[iI]nteractive" {(Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='2']]")}
            "[nN]etwork" {(Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='3']]")}
            "[sS]ervice" {(Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='5']]")}
            "[uU]nlocked" {(Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='7']]")}
            "[rR]emote[iI]nteractive" {(Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='10']]")}
            "[cC]ached[iI]nteractive" {(Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='11']]")}
        }
    } else {
        switch -Regex ($LogonType) {
            "[iI]nteractive" {(Get-WinEvent -Path $Path -FilterXPath "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='2']]")}
            "[nN]etwork" {(Get-WinEvent -Path $Path -FilterXPath "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='3']]")}
            "[sS]ervice" {(Get-WinEvent -Path $Path -FilterXPath "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='5']]")}
            "[uU]nlocked" {(Get-WinEvent -Path $Path -FilterXPath "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='7']]")}
            "[rR]emote[iI]nteractive" {(Get-WinEvent -Path $Path -FilterXPath "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='10']]")}
            "[cC]ached[iI]nteractive" {(Get-WinEvent -Path $Path -FilterXPath "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='11']]")}
        }
    }
}

# This function helps to find the event ID of a specific event type linked to a specific time
# Example: Find-SecurityLogsInTime -StartDateTime "2023-01-01 00:00:00" -EndDateTime "2023-01-02 00:00:00"
# Example: Find-SecurityLogsInTime -StartDateTime "2023-01-01 00:00:00"
# You will see that the 'StartDateTime' is using a >= (greater than or equal to) operator so that you can find logs from that time
# The 'EndDateTime' is using a <= (less than or equal to) operator so that you can find logs until that time
# Combining both of these will give you the logs between those two times or in other words, within that time frame/window
function Find-SecurityLogsInTime {
    param (
        [string]$EventID,
        [string]$EventType,
        [datetime]$StartDateTime,
        [datetime]$EndDateTime,
        [string]$Path
    )
    
    if ($EventType -ne "") {
        $EventID = Get-SecurityEventID -EventType $EventType
    }

    if (-not $EndDateTime) {
        # Convert datetime string to ISO8601
        $StartDate = $StartDateTime.ToUniversalTime().ToString("o")
        if ($Path -eq "") {
            Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=$EventID and TimeCreated[@SystemTime >= '$StartDate']]]"
        } else {
            Get-WinEvent -Path $Path -FilterXPath "*[System[EventID=$EventID and TimeCreated[@SystemTime >= '$StartDate']]]"
        }
    } else {
        # Convert datetime string to ISO8601
        $StartDate = $StartDateTime.ToUniversalTime().ToString("o")
        $EndDate = $EndDateTime.ToUniversalTime().ToString("o")
        if ($Path -eq "") {
            Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=$EventID and TimeCreated[@SystemTime >= '$StartDate'] and TimeCreated[@SystemTime <= '$EndDate']]]"
        } else {
            Get-WinEvent -Path $Path -FilterXPath "*[System[EventID=$EventID and TimeCreated[@SystemTime >= '$StartDate'] and TimeCreated[@SystemTime <= '$EndDate']]]"
        }
    }
}

# This function helps to find the event ID of a specific event type linked to a specific workstation
# Example: Find-SecurityLogsByWorkstation -EventType "Logon" -WorkstationName "WORKSTATION1"
# Example: Find-SecurityLogsByWorkstation -EventID 4624 -WorkstationName "WORKSTATION1"
# This will return the logs based on the specific workstation having logged on
function Find-SecurityLogsByWorkstation {
    param(
        [string]$EventID,
        [string]$EventType,
        [string]$WorkstationName,
        [string]$Path
    )

    if ($EventType -ne "") {
        $EventID = Get-SecurityEventID -EventType $EventType
    }

    if ($Path -eq "") {
        Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=$EventID] and EventData[Data[@Name='WorkstationName']='$WorkstationName']]"
    } else {
        Get-WinEvent -Path $Path -FilterXPath "*[System[EventID=$EventID] and EventData[Data[@Name='WorkstationName']='$WorkstationName']]"
    }
}

# This function helps to find the event ID of a specific event type linked to a specific IP address
# Example: Find-SecurityLogsByIP -EventType "Logon" -IPAddress "127.0.0.1"
# Example: Find-SecurityLogsByIP -EventID 4624 -IPAddress "10.0.0.25"
# This will return the logs based on the specific IP address having logged on from that IP
# This is useful for tracing down events logging in from a specific IP address
function Find-SecurityLogsByIP {
    param(
        [string]$EventID,
        [string]$EventType,
        [string]$IPAddress,
        [string]$Path
    )

    if ($EventType -ne "") {
        $EventID = Get-SecurityEventID -EventType $EventType
    }

    if ($Path -eq "") {
        Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=$EventID] and EventData[Data[@Name='IpAddress']='$IPAddress']]"
    } else {
        Get-WinEvent -Path $Path -FilterXPath "*[System[EventID=$EventID] and EventData[Data[@Name='IpAddress']='$IPAddress']]"
    }
}

# This function helps to find the event ID of a specific event type linked to a specific domain
# Example: Find-SecurityLogsByDomain -EventType "Logon" -DomainName "DOMAIN1"
# Example: Find-SecurityLogsByDomain -EventID 4624 -DomainName "DOMAIN1"
# This will return the logs based on the specific domain having logged on from that domain
function Find-SecurityLogsByDomain {
    param(
        [string]$EventID,
        [string]$EventType,
        [string]$DomainName,
        [string]$Path
    )

    if ($EventType -ne "") {
        $EventID = Get-SecurityEventID -EventType $EventType
    }

    if ($Path -eq "") {
        Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=$EventID] and EventData[Data[@Name='TargetDomainName']='$DomainName']]"
    } else {
        Get-WinEvent -Path $Path -FilterXPath "*[System[EventID=$EventID] and EventData[Data[@Name='TargetDomainName']='$DomainName']]"
    }
}

# This function helps to combined all of the above functions into one
# Example: Find-SecurityLogsAdvanced -EventType "Logon" -Username "Administrator" -WorkstationName "WORKSTATION1" -IPAddress "127.0.0.1"
# Example: Find-SecurityLogsAdvanced -EventID 4624 -Username "Administrator" -StartDateTime "2023-01-01 00:00:00" -EndDateTime "2023-01-02 00:00:00"
# You should be able to see what each of these will return
function Find-SecurityLogsAdvanced {
    param (
        [string]$EventID,
        [string]$EventType,
        [string]$Username,
        [string]$UserSID,
        [string]$WorkstationName,
        [string]$IPAddress,
        [string]$DomainName,
        [datetime]$StartDateTime,
        [datetime]$EndDateTime,
        [string]$Path
    )

    $filterStart = "*[System["

    if ($EventType -ne "") {
        $EventID = Get-SecurityEventID -EventType $EventType
    }

    $conditions = @()

    if ($EventID) {
        $conditions += "EventID=$EventID"
    }

    if ($StartDateTime -ne $null) {
        $StartDate = $StartDateTime.ToUniversalTime().ToString("o")
        $conditions += "TimeCreated[@SystemTime >= '$StartDate']"
    }

    if ($EndDateTime) {
        $EndDate = $EndDateTime.ToUniversalTime().ToString("o")
        $conditions += "TimeCreated[@SystemTime <='$EndDate']"
    }

    $XPathConditions += ($conditions -join " and ") + "]"

    $eventDataConditions = @()
    if ($Username) { $eventDataConditions += "Data[@Name='TargetUserName']='$Username'" }
    if ($UserSID) { $eventDataConditions += "Data[@Name='TargetUserSid']='$UserSID'" }
    if ($WorkstationName) { $eventDataConditions += "Data[@Name='WorkstationName']='$WorkstationName'" }
    if ($IPAddress) { $eventDataConditions += "Data[@Name='IpAddress']='$IPAddress'" }
    if ($DomainName) { $eventDataConditions += "Data[@Name='TargetDomainName']='$DomainName'" }

    if ($eventDataConditions -gt 0) {
        $XPathConditions = $XPathConditions.Trim() + " and EventData[" + ($eventDataConditions -join " and ") + "]]"
        $filter = $filterStart + $XPathConditions
    } else {
        $filter = $filterStart + $XPathConditions + "]"
    }

    # So that you can see how the filter is constructed
    Write-Host "Filter: $filter"

    if ($Path -eq "") {
        Get-WinEvent -LogName Security -FilterXPath $filter
    } else {
        Get-WinEvent -Path $Path -FilterXPath $filter
    }
}

# This function helps to find Application logs linked to a specific user's SID (Security Identifier)
# You can find the SID of a user by using the functions at the very top of this script
# Example: Find-ApplicationLogsByUser -UserSID "S-1-5-18"
# Example: Find-ApplicationLogsByUser -UserSID "S-1-5-21-1234567890-1234567890-1234567890-1001"
function Find-ApplicationLogsByUserSID {
    param(
        [string]$UserSID,
        [string]$Path
    )

    if ($EventType -ne "") {
        $EventID = Get-SecurityEventID -EventType $EventType
    }

    if ($Path -eq "") {
        Get-WinEvent -LogName Application -FilterXPath "*[System[Security[@UserID = '$UserSID']]]"
    } else {
        Get-WinEvent -Path $Path -FilterXPath "*[System[Security[@UserID = '$UserSID']]]"
    }
}

# This function helps to find Application logs linked to a specific computer name
# Example: Find-ApplicationLogsByComputerName -ComputerName "COMPUTER1"
# Example: Find-ApplicationLogsByComputerName -ComputerName "COMPUTER2"
function Find-ApplicationLogsByComputerName {
    param(
        [string]$ComputerName,
        [string]$Path
    )

    if ($Path -eq "") {
        Get-WinEvent -LogName Application -FilterXPath "*[System[Computer='$ComputerName']]"
    } else {
        Get-WinEvent -Path $Path -FilterXPath "*[System[Computer='$ComputerName']]"
    }
}

# This function helps to find Application logs linked to a specific time
# Example: Find-ApplicationLogsByTime -StartDateTime "2023-01-01 00:00:00" -EndDateTime "2023-01-02 00:00:00"
# Example: Find-ApplicationLogsByTime -StartDateTime "2023-01-01 00:00:00"
function Find-ApplicationLogsByTime {
    param(
        [datetime]$StartDateTime,
        [datetime]$EndDateTime,
        [string]$Path
    )

    if (-not $EndDateTime) {
        # Convert datetime string to ISO8601
        $StartDate = $StartDateTime.ToUniversalTime().ToString("o")
        if ($Path -eq "") {
            Get-WinEvent -LogName Application -FilterXPath "*[System[TimeCreated[@SystemTime >= '$StartDate']]]"
        } else {
            Get-WinEvent -Path $Path -FilterXPath "*[System[TimeCreated[@SystemTime >= '$StartDate']]]"
        }
    } else {
        # Convert datetime string to ISO8601
        $StartDate = $StartDateTime.ToUniversalTime().ToString("o")
        $EndDate = $EndDateTime.ToUniversalTime().ToString("o")
        if ($Path -eq "") {
            Get-WinEvent -LogName Application -FilterXPath "*[System[TimeCreated[@SystemTime >= '$StartDate'] and TimeCreated[@SystemTime <= '$EndDate']]]"
        } else {
            Get-WinEvent -Path $Path -FilterXPath "*[System[TimeCreated[@SystemTime >= '$StartDate'] and TimeCreated[@SystemTime <= '$EndDate']]]"
        }
    }
}

# This function helps to find Application logs linked to a specific provider name
# A provider name is the name of the application that is logging the events
# Example: Find-ApplicationLogsByProviderName -ProviderName "Microsoft-Windows-Security-Auditing"
# Example: Find-ApplicationLogsByProviderName -ProviderName "Brave-Browser"
function Find-ApplicationLogsByProviderName {
    param(
        [string]$ProviderName,
        [string]$Path
    )

    if ($Path -eq "") {
        Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name = '$ProviderName']]]"
    } else {
        Get-WinEvent -Path $Path -FilterXPath "*[System[Provider[@Name = '$ProviderName']]]"
    }
}

# This function helps to combine all of the above functions into one
# Example: Find-ApplicationLogsAdvanced -ProviderName "Microsoft-Windows-Security-Auditing" -UserSID "S-1-5-18" -ComputerName "COMPUTER1" -StartDateTime "2023-01-01 00:00:00" -EndDateTime "2023-01-02 00:00:00"
# Example: Find-ApplicationLogsAdvanced -ProviderName "Microsoft-Windows-Security-Auditing" -UserSID "S-1-5-18" -ComputerName "COMPUTER1"
# Again, you should be able to see what each of these will return
function Find-ApplicationLogsAdvanced {
    param (
        [string]$ProviderName,
        [string]$UserSID,
        [string]$ComputerName,
        [datetime]$StartDateTime,
        [datetime]$EndDateTime,
        [string]$Path
    )

    $filterStart = "*[System["
    $conditions = @()

    if ($ProviderName) {$conditions += "Provider[@Name='$ProviderName']"}
    if ($UserSID) {$conditions += "Security[@UserID='$UserSID']"}
    if ($ComputerName) {$conditions += "Computer='$ComputerName'"}
    
    if ($StartDateTime -ne $null) {
        $StartDate = $StartDateTime.ToUniversalTime().ToString("o")
        $conditions += "TimeCreated[@SystemTime >= '$StartDate']"
    }
    if ($EndDateTime) {
        $EndDate = $EndDateTime.ToUniversalTime().ToString("o")
        $conditions += "TimeCreated[@SystemTime <='$EndDate']"
    }

    $XPathConditions = ($conditions -join " and ") + "]"
    $filter = $filterStart + $XPathConditions + "]"

    if ($Path -eq "") {
        Get-WinEvent -LogName Application -FilterXPath $filter
    } else {
        Get-WinEvent -Path $Path -FilterXPath $filter
    }
}