# Look at the GeoLocation information
function Get-GeoLocationInfo {
    Add-Type -AssemblyName System.Device
    [System.Device.Location.GeoCoordinate]::Unknown
    [System.Device.Location.GeoCoordinate]::Unknown.Latitude
    [System.Device.Location.GeoCoordinate]::Unknown.Longitude
}

# This function is used to find the SID of a local user
# Example: Get-LocalUserSID -Username "Administrator"
function Get-LocalUserSID {
    param (
        [string]$Username
    )
    (Get-LocalUser -Name $Username | Select-Object SID).SID.Value
}

# This function is used to find the SID of a user in Active Directory
# Example: Get-ADUserSID -Name "John Doe"
# Example: Get-ADUserSID -Username "jdoe"
# Example: Get-ADUserSID -UserADEmail "jdoe@activedirectory.com"
function Get-ADUserSID {
    param (
        [string]$Name,
        [string]$Username,
        [string]$UserADEmail
    )

    if ($Name -ne "") {
        return (Get-ADUser -Filter "Name -eq '$Name'").SID.Value
    }

    if ($Username -eq "") {
        return (Get-ADUser -Filter "SamAccountName -eq '$Username'").SID.Value
    }

    if ($UserADEmail -ne "") {
        return (Get-ADUser -Filter "UserPrincialName -eq '$UserADEmail'").SID.Value
    }
}

function Grant-Telemetry {
    reg add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d 1 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\TailoredExperiencesWithDiagnosticDataEnabled" /v "Value" /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\TailoredExperiencesWithDiagnosticDataEnabled" /v "Value" /t REG_DWORD /d 1 /f
}

function Revoke-Telemetry {
    reg add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d 0 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\TailoredExperiencesWithDiagnosticDataEnabled" /v "Value" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\TailoredExperiencesWithDiagnosticDataEnabled" /v "Value" /t REG_DWORD /d 0 /f
}

function Grant-FindMyDevice {
    reg add "HKLM\SOFTWARE\Microsoft\MdmCommon\SettingValues" /v "LocationSyncEnabled" /t REG_DWORD /d 1 /f
}

function Revoke-FindMyDevice {
    reg add "HKLM\SOFTWARE\Microsoft\MdmCommon\SettingValues" /v "LocationSyncEnabled" /t REG_DWORD /d 0 /f
}

function Grant-ActivityHistory {
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /f /v "PublishUserActivities" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /f /v "UploadUserActivities" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\System" /f /v "PublishUserActivities" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\System" /f /v "UploadUserActivities" /t REG_DWORD /d 1 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "Start_TrackProgs" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "Start_TrackDocs" /t REG_DWORD /d 1 /f
}

function Revoke-ActivityHistory {
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /f /v "PublishUserActivities" /t REG_DWORD /d 0
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /f /v "UploadUserActivities" /t REG_DWORD /d 0
    reg add "HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\System" /f /v "PublishUserActivities" /t REG_DWORD /d 0
    reg add "HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\System" /f /v "UploadUserActivities" /t REG_DWORD /d 0
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "Start_TrackProgs" /t REG_DWORD /d 0
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "Start_TrackDocs" /t REG_DWORD /d 0
}

# Grant Location Access in Registry
function Grant-LocationAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Location access permissions have been granted."
}

# Revoke Location Access in Registry
function Revoke-LocationAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Location access permissions have been revoked."
}

# Grant Bluetooth Access in Registry
function Grant-BluetoothAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Bluetooth access permissions have been granted."
}

# Revoke Bluetooth Access in Registry
function Revoke-BluetoothAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Bluetooth access permissions have been revoked."
}

# Grant App Diagnostic Access in Registry
function Grant-AppDiagnosticAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "App diagnostic access permissions have been granted."
}

# Revoke App Diagnostic Access in Registry
function Revoke-AppDiagnosticAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "App diagnostic access permissions have been revoked."
}

# Grant App Background Access in Registry
function Grant-AppointmentsAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Appointments access permissions have been granted."
}

# Revoke App Background Access in Registry
function Revoke-AppointmentsAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Appointments access permissions have been revoked."
}

function Grant-BroadFileSystemAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Broad file system access permissions have been granted."
}

function Revoke-BroadFileSystemAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Broad file system access permissions have been revoked."
}

function Grant-UserAccountAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "User account access permissions have been granted."
}

function Revoke-UserAccountAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "User account access permissions have been revoked."
}

# Grant Activity Access in Registry
function Grant-ActivityAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Activity access permissions have been granted."
}

# Revoke Activity Access in Registry
function Revoke-ActivityAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Activity access permissions have been revoked."
}

# Grant Cellular Data Access in Registry
function Grant-CellularDataAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Cellular data access permissions have been granted."
}

# Revoke Cellular Data Access in Registry
function Revoke-CellularDataAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Cellular data access permissions have been revoked."
}

# Grant Chat Access in Registry
function Grant-ChatAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Chat access permissions have been granted."
}

# Revoke Chat Access in Registry
function Revoke-ChatAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Chat access permissions have been revoked."
}

# Grant Contacts Access in Registry
function Grant-ContactsAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Contacts access permissions have been granted."
}

# Revoke Contacts Access in Registry
function Revoke-ContactsAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Contacts access permissions have been revoked."
}

# Grant Documents Library Access in Registry
function Grant-DocumentsLibraryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Documents library access permissions have been granted."
}

# Revoke Documents Library Access in Registry
function Revoke-DocumentsLibraryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Documents library access permissions have been revoked."
}

# Grant Downloads Folder Access in Registry
function Grant-DownloadsFolderAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Downloads folder access permissions have been granted."
}

# Revoke Downloads Folder Access in Registry
function Revoke-DownloadsFolderAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Downloads folder access permissions have been revoked."
}

# Grant Email Access in Registry
function Grant-EmailAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Email access permissions have been granted."
}

# Revoke Email Access in Registry
function Revoke-EmailAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Email access permissions have been revoked."
}

# Grant Gaze Input Access in Registry
function Grant-GazeInputAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Gaze input access permissions have been granted."
}

# Revoke Gaze Input Access in Registry
function Revoke-GazeInputAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Gaze input access permissions have been revoked."
}

# Grant Human Interface Device Access in Registry
function Grant-HumanInterfaceDeviceAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanInterfaceDevice" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanInterfaceDevice" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Human interface device access permissions have been granted."
}

# Revoke Human Interface Device Access in Registry
function Revoke-HumanInterfaceDeviceAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanInterfaceDevice" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanInterfaceDevice" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Human interface device access permissions have been revoked."
}

# Grant Microphone Access in Registry
function Grant-MicrophoneAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Microphone access permissions have been granted."
}

# Revoke Microphone Access in Registry
function Revoke-MicrophoneAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Microphone access permissions have been revoked."
}

# Grant Music Library Access in Registry
function Grant-MusicLibraryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Music library access permissions have been granted."
}

# Revoke Music Library Access in Registry
function Revoke-MusicLibraryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Music library access permissions have been revoked."
}

# Grant Phone Call Access in Registry
function Grant-PhoneCallAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Phone call access permissions have been granted."
}

# Revoke Phone Call Access in Registry
function Revoke-PhoneCallAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Phone call access permissions have been revoked."
}

# Grant Phone Call History Access in Registry
function Grant-PhoneCallHistoryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Phone call history access permissions have been granted."
}

# Revoke Phone Call History Access in Registry
function Revoke-PhoneCallHistoryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Phone call history access permissions have been revoked."
}

# Grant Pictures Library Access in Registry
function Grant-PicturesLibraryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Pictures library access permissions have been granted."
}

# Revoke Pictures Library Access in Registry
function Revoke-PicturesLibraryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Pictures library access permissions have been revoked."
}

# Grant Radios Access in Registry
function Grant-RadiosAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Radios access permissions have been granted."
}

# Revoke Radios Access in Registry
function Revoke-RadiosAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Radios access permissions have been revoked."
}

# Grant Custom Sensors Access in Registry
function Grant-CustomSensorsAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\sensors.custom" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\sensors.custom" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Custom sensors access permissions have been granted."
}

# Revoke Custom Sensors Access in Registry
function Revoke-CustomSensorsAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\sensors.custom" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\sensors.custom" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Custom sensors access permissions have been revoked."
}

# Grant Serial Communication Access in Registry
function Grant-SerialCommunicationAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\serialCommunication" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\serialCommunication" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Serial communication access permissions have been granted."
}

# Revoke Serial Communication Access in Registry
function Revoke-SerialCommunicationAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\serialCommunication" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\serialCommunication" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Serial communication access permissions have been revoked."
}

# Grant USB Access in Registry
function Grant-USBAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\usb" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\usb" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "USB access permissions have been granted."
}

# Revoke USB Access in Registry
function Revoke-USBAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\usb" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\usb" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "USB access permissions have been revoked."
}

# Grant User Data Tasks Access in Registry
function Grant-UserDataTasksAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "User data tasks access permissions have been granted."
}

# Revoke User Data Tasks Access in Registry
function Revoke-UserDataTasksAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "User data tasks access permissions have been revoked."
}

# Grant User Notification Listener Access in Registry
function Grant-UserNotificationListenerAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "User notification listener access permissions have been granted."
}

# Revoke User Notification Listener Access in Registry
function Revoke-UserNotificationListenerAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "User notification listener access permissions have been revoked."
}

# Grant Videos Library Access in Registry
function Grant-VideosLibraryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Videos library access permissions have been granted."
}

# Revoke Videos Library Access in Registry
function Revoke-VideosLibraryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Videos library access permissions have been revoked."
}

# Grant Webcam Access in Registry
function Grant-WebcamAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "Webcam access permissions have been granted."
}

# Revoke Webcam Access in Registry
function Revoke-WebcamAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "Webcam access permissions have been revoked."
}

# Grant WiFi Data Access in Registry
function Grant-WiFiDataAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "WiFi data access permissions have been granted."
}

# Revoke WiFi Data Access in Registry
function Revoke-WiFiDataAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "WiFi data access permissions have been revoked."
}

# Grant WiFi Direct Access in Registry
function Grant-WiFiDirectAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiDirect" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiDirect" /v "Value" /t REG_SZ /d "Allow" /f > $null 2>&1
    Write-Host "WiFi direct access permissions have been granted."
}

# Revoke WiFi Direct Access in Registry
function Revoke-WiFiDirectAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiDirect" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiDirect" /v "Value" /t REG_SZ /d "Deny" /f > $null 2>&1
    Write-Host "WiFi direct access permissions have been revoked."
}

function Get-AccessPermissionStatus {
    $hklmBasePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
    $hkcuBasePath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"

    $permissions = @(
        "location",
        "bluetooth",
        "bluetoothSync",
        "appDiagnostics",
        "appointments",
        "broadFileSystemAccess",
        "userAccountInformation",
        "activity",
        "cellularData",
        "chat",
        "contacts",
        "documentsLibrary",
        "downloadsFolder",
        "email",
        "gazeInput",
        "humanInterfaceDevice",
        "microphone",
        "musicLibrary", 
        "phoneCall",
        "phoneCallHistory",
        "picturesLibrary",
        "radios",
        "sensors.custom",
        "serialCommunication",
        "usb",
        "userDataTasks",
        "userNotificationListener",
        "videosLibrary",
        "webcam",
        "wifiData",
        "wifiDirect"
    )

    $results = @()
    
    foreach ($permission in $permissions) {
        # Check HKLM
        $hklmPath = Join-Path -Path $hklmBasePath -ChildPath $permission
        $hklmValue = "Missing"
        if (Test-Path $hklmPath) {
            try {
                $hklmValue = Get-ItemPropertyValue -Path $hklmPath -Name "Value" -ErrorAction SilentlyContinue
                if ($null -eq $hklmValue) { $hklmValue = "Missing" }
            } catch {
                $hklmValue = "Error"
            }
        }

        # Check HKCU
        $hkcuPath = Join-Path -Path $hkcuBasePath -ChildPath $permission
        $hkcuValue = "Missing"
        if (Test-Path $hkcuPath) {
            try {
                $hkcuValue = Get-ItemPropertyValue -Path $hkcuPath -Name "Value" -ErrorAction SilentlyContinue
                if ($null -eq $hkcuValue) { $hkcuValue = "Missing" }
            } catch {
                $hkcuValue = "Error"
            }
        }

        # Create result object
        $results += [PSCustomObject]@{
            Permission = $permission
            HKLM_Value = $hklmValue
            HKCU_Value = $hkcuValue
            Status = if ($hklmValue -eq "Allow" -and $hkcuValue -eq "Allow") { 
                     "Allowed" 
                 } elseif ($hklmValue -eq "Deny" -and $hkcuValue -eq "Deny") {
                     "Denied"
                 } else { 
                     "Mixed/Incomplete" 
                 }
        }
    }

    return $results | Format-Table -AutoSize
}

function Revoke-AllPermissions {
    Write-Host "Revoking all application permissions..." -ForegroundColor Yellow
    
    Revoke-LocationAccess
    Revoke-BluetoothAccess
    Revoke-AppDiagnosticAccess
    Revoke-AppointmentsAccess
    Revoke-BroadFileSystemAccess
    Revoke-UserAccountAccess
    Revoke-ActivityAccess
    Revoke-CellularDataAccess
    Revoke-ChatAccess
    Revoke-ContactsAccess
    Revoke-DocumentsLibraryAccess
    Revoke-DownloadsFolderAccess
    Revoke-EmailAccess
    Revoke-GazeInputAccess
    Revoke-HumanInterfaceDeviceAccess
    Revoke-MicrophoneAccess
    Revoke-MusicLibraryAccess
    Revoke-PhoneCallAccess
    Revoke-PhoneCallHistoryAccess
    Revoke-PicturesLibraryAccess
    Revoke-RadiosAccess
    Revoke-CustomSensorsAccess
    Revoke-SerialCommunicationAccess
    Revoke-USBAccess
    Revoke-UserDataTasksAccess
    Revoke-UserNotificationListenerAccess
    Revoke-VideosLibraryAccess
    Revoke-WebcamAccess
    Revoke-WiFiDataAccess
    Revoke-WiFiDirectAccess

    Write-Host "All permissions have been revoked." -ForegroundColor Green
    Write-Host "Displaying current permission status..." -ForegroundColor Cyan
    Get-AccessPermissionStatus
}

function Grant-AllPermissions {
    Write-Host "Granting all application permissions..." -ForegroundColor Yellow
    
    Grant-LocationAccess
    Grant-BluetoothAccess
    Grant-AppDiagnosticAccess
    Grant-AppointmentsAccess
    Grant-BroadFileSystemAccess
    Grant-UserAccountAccess
    Grant-ActivityAccess
    Grant-CellularDataAccess
    Grant-ChatAccess
    Grant-ContactsAccess
    Grant-DocumentsLibraryAccess
    Grant-DownloadsFolderAccess
    Grant-EmailAccess
    Grant-GazeInputAccess
    Grant-HumanInterfaceDeviceAccess
    Grant-MicrophoneAccess
    Grant-MusicLibraryAccess
    Grant-PhoneCallAccess
    Grant-PhoneCallHistoryAccess
    Grant-PicturesLibraryAccess
    Grant-RadiosAccess
    Grant-CustomSensorsAccess
    Grant-SerialCommunicationAccess
    Grant-USBAccess
    Grant-UserDataTasksAccess
    Grant-UserNotificationListenerAccess
    Grant-VideosLibraryAccess
    Grant-WebcamAccess
    Grant-WiFiDataAccess
    Grant-WiFiDirectAccess

    Write-Host "All permissions have been granted." -ForegroundColor Green
    Write-Host "Displaying current permission status..." -ForegroundColor Cyan
    Get-AccessPermissionStatus
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

function Show-ActiveRemoteConnections {
    param(
        [boolean]$ReverseLookup = $false
    )
    
    $CurrentTime = (Get-Date)
    $CurrentTimeUTC = $CurrentTime.ToUniversalTime()
    $CurrentTimeString = (Get-Date).ToString("o") # In ISO8601 format

    $ProgramData = "C:\ProgramData\ShowActiveRemoteConnections"
    $ProgramConfig = "$ProgramData\config.json"

    # Check and create if necessary
    if (!(Test-Path -Path $ProgramData)) {
        New-Item -Path $ProgramData -ItemType Directory
        New-Item -Path $ProgramConfig -ItemType File

        $initConfig = @{ FirstInstalled = $CurrentTimeString }
        $initConfig | ConvertTo-Json | Set-Content -Path $ProgramConfig
    }

    $configData = Get-Content -Path $ProgramConfig | ConvertFrom-Json
    $torNodeFile = "$ProgramData\TorNodeList.txt"
    $blackListFile = "$ProgramData\IPBlackList.txt"

    # For the first time the script runs
    if (!(Test-Path -Path $torNodeFile)) {
        $nodeList = (Invoke-WebRequest -Uri "https://www.dan.me.uk/torlist/?full").Content

        $configData | Add-Member -NotePropertyName 'LastTimeRanTor' -NotePropertyValue $CurrentTimeString
        $configData | ConvertTo-Json | Set-Content -Path $ProgramConfig

        New-Item -Path $torNodeFile -ItemType File
        Set-Content -Path $torNodeFile -Value $nodeList
    }

    if (!(Test-Path -Path $blackListFile)) {
        $blackListContent = (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/ipsum.txt").Content

        # Remove header items from the blacklist
        $updateLine = (($blackListContent -split "`n" | Where-Object { $_ -match "Last update:" }) -replace "# Last update: ","").ToString().Trim()
        [datetime]$lastUpdateString = $updateLine.ToString("o")
        $blackList = $blackListContent | Select-Object -Skip 7 | ForEach-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | Out-Null; $matches[0] }

        $configData | Add-Member -NotePropertyName 'LastUpdateBlackList' -NotePropertyValue $lastUpdateString.ToString("o")
        $configData | Add-Member -NotePropertyName 'LastTimeRanBlacklist' -NotePropertyValue $CurrentTimeString
        $configData | ConvertTo-Json | Set-Content -Path $ProgramConfig

        New-Item -Path $blackListFile -ItemType File
        Set-Content -Path $blackListFile -Value $blackList
    }

    # For updating the TorNodeList - Only run at most, every 35 minutes to prevent being blacklisted
    if ($CurrentTime -gt ([datetime]$configData.LastTimeRanTor).AddMinutes(35)) {
        $nodeList = (Invoke-WebRequest -Uri "https://www.dan.me.uk/torlist/?full").Content

        $configData.LastTimeRanTor = $CurrentTimeString
        $configData | ConvertTo-Json | Set-Content -Path $ProgramConfig
    }

    # For updating the IPBlacklist - Only run once a day at most after 3:30AM GMT+02:00 to get the updated list
    if ($CurrentTime -gt ([datetime]$configData.LastUpdateBlackList).AddDays(1) -and $CurrentTimeUTC.AddHours(2) -gt (Get-Date -Hour 3 -Minute 30 -Second 0)) {
        $blackListContent = (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/ipsum.txt").Content

        # Remove header items from the blacklist
        [datetime]$lastUpdateString = (($blackListContent -split "`n" | Where-Object { $_ -match "Last update:" }) -replace "# Last update: ","").ToString().Trim()
        $blackList = $blackListContent -split "`n" | Select-Object -Skip 7 | ForEach-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | Out-Null; $matches[0] }

        $configData.LastUpdateBlackList = $lastUpdateString.ToString("o")
        $configData.LastTimeRanBlacklist = $CurrentTimeString
        $configData | ConvertTo-Json | Set-Content -Path $ProgramConfig
    }

    $connections = Get-NetTCPConnection -State Established |
        Where-Object { $_.RemoteAddress -ne '::1' -and $_.RemoteAddress -ne '127.0.0.1' } |
        Select-Object -Property RemoteAddress, RemotePort, OwningProcess -Unique

    $remoteIPs = $connections.RemoteAddress

    $geoLookup = @{}

    if ($ReverseLookup) {
        $batchSize = 45
        $totalBatches = [Math]::Ceiling($remoteIPs.Count / $batchSize)
        $geoResponses = @()
        for ($i = 0; $i -lt $totalBatches; $i++) {
            $currentBatch = $remoteIPs[($i * $batchSize)..([Math]::Min(($i +1) * $batchSize -1, $remoteIPs.Count -1))]

            foreach ($ip in $currentBatch) {
                $url = "http://ip-api.com/json/" + $ip + "?fields=29713"
                $response = Invoke-RestMethod -Uri $url -Method GET
                $geoResponses += $response
            }

            foreach ($ipAddress in $geoResponses) {
                $geoLookup[$ipAddress.query] = $ipAddress
            }
            
            if ($totalBatches -gt 1) {
                Start-Sleep -Seconds 62
            }
        }
    } else {
        $batchSize = 100
        for ($i = 0; $i -lt $remoteIPs.Count; $i += $batchSize) {
            $batch = $connections.RemoteAddress[$i..([Math]::Min($i + $batchSize -1, $remoteIPs.Count -1))]
            $queryBatch = $batch | ForEach-Object { @{ query = $_ } } | ConvertTo-Json

            $geoResponse = Invoke-RestMethod -Uri "http://ip-api.com/batch?fields=25617" -Method POST -Body $queryBatch -ContentType "application/json"

            foreach ($ipAddress in $geoResponse) {
                $geoLookup[$ipAddress.query] = $ipAddress
            }

            if ($connections.RemoteAddress -gt 100)  {
                Start-Sleep -Seconds 2
            }
        }
    }

    $results = @()
    $connections | ForEach-Object {
        $ip = $_.RemoteAddress
        $port = $_.RemotePort
        $processName = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        $geo = $geoLookup[$ip]

        $torNode = Select-String -Path $torNodeFile -Pattern "^$ip$" -Quiet
        $blackListed = Select-String -Path $blackListFile -Pattern "^$ip$" -Quiet

        if ($ReverseLookup) {
            $results += [PSCustomObject]@{
                IPAddress = $ip
                Port = $port
                ProcessName = $processName
                Country = $geo.country
                City = $geo.city
                Organization = $geo.org
                Reverse = $geo.reverse
                TorNode = $torNode
                BlackListed = $blackListed
            }
        } else {
            $results += [PSCustomObject]@{
                IPAddress = $ip
                Port = $port
                ProcessName = $processName
                Country = $geo.country
                City = $geo.city
                Organization = $geo.org
                TorNode = $torNode
                BlackListed = $blackListed
            }
        }
    }
    $results | Format-Table -AutoSize
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

# Function to check if running as Administrator
function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
# Example usage of the Test-IsAdmin function
# Relaunch the script as Administrator if not already
#if (-not (Test-IsAdmin)) {
#    Write-Output "Elevation required. Relaunching with admin rights..."
#    $scriptPath = $MyInvocation.MyCommand.Definition
#    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
#    exit
#}

function Invoke-NetKill {
    param(
        [boolean]$Kill = $true
    )

    $cacheFile = "$env:ProgramData\InvokeNetKill\lastInterface.xml"
    $cacheDir = [System.IO.Path]::GetDirectoryName($cacheFile)

    if ($Kill) {
        if (!(Test-Path $cacheDir)) {
            New-Item -Path $cacheDir -ItemType Directory -Force | Out-Null
        }

        $activeInterface = Get-ActiveNetworkInterface
        if (-not $activeInterface) {
            Write-Warning "No active interface found. Please ensure you are connected to an interface."
            return
        }

        $activeInterface | Export-Clixml -Path $cacheFile -Force
        Disable-NetAdapter -Name $activeInterface.Name -Confirm:$false
        Write-Warning "$($activeInterface.Name) Interface Disabled."
    } else {
        if (Test-Path -Path $cacheFile) {
            $cachedAdapter = Import-Clixml -Path $cacheFile
        } else {
            Write-Warning "No cached adapter found. Please use manual override to re-enable your interface."
            return
        }
        
        Enable-NetAdapter -Name $cachedAdapter.Name -Confirm:$false
        Write-Warning "$($cachedAdapter.Name) Interface Re-Enabled."
    }
}

function Enable-AllASRRules {
    $ASRRuleIds = @{
        "56A863A9-875E-4185-98A7-B882C64B5CE5" = "Block abuse of exploited vulnerable signed drivers"
        "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = "Block Adobe Reader from creating child processes"
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block all Office applications from creating child processes"
        "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email client and webmail"
        "01443614-CD74-433A-B99E-2ECDC07BFC25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
        "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JavaScript or VBScript from launching downloaded executable content"
        "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content"
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office applications from injecting code into other processes"
        "26190899-1602-49E8-8B27-EB1D0A1CE869" = "Block Office communication application from creating child processes"
        "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = "Block persistence through WMI event subscription"
        "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = "Block process creations originating from PSExec and WMI commands"
        "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = "Block untrusted and unsigned processes that run from USB"
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
        "C1DB55AB-C21A-4637-BB3F-A12568109D35" = "Use advanced protection against ransomware"
        "A8F5898E-1DC8-49A9-9878-85004B8A61E6" = "Block Webshell creation for Servers"
        "33DDEDF1-C6E0-47CB-833E-DE6133960387" = "Block rebooting machine in Safe Mode (preview)"
        "C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB" = "Block use of copied or impersonated system tools (preview)"
    }

    $ASRRuleIds.Keys | ForEach-Object {
        Set-MpPreference -AttackSurfaceReductionRules_Ids $_ -AttackSurfaceReductionRules_Action Enabled
    }
}

function Disable-AllASRRules {
    $ASRRuleIds = @{
        "56A863A9-875E-4185-98A7-B882C64B5CE5" = "Block abuse of exploited vulnerable signed drivers"
        "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = "Block Adobe Reader from creating child processes"
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block all Office applications from creating child processes"
        "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email client and webmail"
        "01443614-CD74-433A-B99E-2ECDC07BFC25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
        "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JavaScript or VBScript from launching downloaded executable content"
        "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content"
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office applications from injecting code into other processes"
        "26190899-1602-49E8-8B27-EB1D0A1CE869" = "Block Office communication application from creating child processes"
        "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = "Block persistence through WMI event subscription"
        "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = "Block process creations originating from PSExec and WMI commands"
        "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = "Block untrusted and unsigned processes that run from USB"
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
        "C1DB55AB-C21A-4637-BB3F-A12568109D35" = "Use advanced protection against ransomware"
        "A8F5898E-1DC8-49A9-9878-85004B8A61E6" = "Block Webshell creation for Servers"
        "33DDEDF1-C6E0-47CB-833E-DE6133960387" = "Block rebooting machine in Safe Mode (preview)"
        "C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB" = "Block use of copied or impersonated system tools (preview)"
    }

    $ASRRuleIds.Keys | ForEach-Object {
        Set-MpPreference -AttackSurfaceReductionRules_Ids $_ -AttackSurfaceReductionRules_Action Disabled
    }
}

function Enable-BlockVulnerableDrivers {
    $ruleId = "56A863A9-875E-4185-98A7-B882C64B5CE5"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Enabled
    Write-Host "Block abuse of exploited vulnerable signed drivers has been enabled."
}

function Disable-BlockVulnerableDrivers {
    $ruleId = "56A863A9-875E-4185-98A7-B882C64B5CE5"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Disabled
    Write-Host "Block abuse of exploited vulnerable signed drivers has been disabled."
}

function Enable-BlockAdobeReaderChildProcesses {
    $ruleId = "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Enabled
    Write-Host "Block Adobe Reader from creating child processes has been enabled."
}

function Disable-BlockAdobeReaderChildProcesses {
    $ruleId = "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Disabled
    Write-Host "Block Adobe Reader from creating child processes has been disabled."
}

function Enable-BlockOfficeChildProcesses {
    $ruleId = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Enabled
    Write-Host "Block all Office applications from creating child processes has been enabled."
}

function Disable-BlockOfficeChildProcesses {
    $ruleId = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Disabled
    Write-Host "Block all Office applications from creating child processes has been disabled."
}

function Enable-CredentialStealingProtection {
    $ruleId = "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Enabled
    Write-Host "Block credential stealing from the Windows local security authority subsystem (lsass.exe) has been enabled."
}

function Disable-CredentialStealingProtection {
    $ruleId = "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Disabled
    Write-Host "Block credential stealing from the Windows local security authority subsystem (lsass.exe) has been disabled."
}

function Enable-BlockEmailExecutableContent {
    $ruleId = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Enabled
    Write-Host "Block executable content from email client and webmail has been enabled."
}

function Disable-BlockEmailExecutableContent {
    $ruleId = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Disabled
    Write-Host "Block executable content from email client and webmail has been disabled."
}

function Enable-BlockExecutableFiles {
    $ruleId = "01443614-CD74-433A-B99E-2ECDC07BFC25"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Enabled
    Write-Host "Block executable files from running unless they meet a prevalence, age, or trusted list criterion has been enabled."
}

function Disable-BlockExecutableFiles {
    $ruleId = "01443614-CD74-433A-B99E-2ECDC07BFC25"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Disabled
    Write-Host "Block executable files from running unless they meet a prevalence, age, or trusted list criterion has been disabled."
}

function Enable-BlockObfuscatedScripts {
    $ruleId = "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Enabled
    Write-Host "Block execution of potentially obfuscated scripts has been enabled."
}

function Disable-BlockObfuscatedScripts {
    $ruleId = "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Disabled
    Write-Host "Block execution of potentially obfuscated scripts has been disabled."
}

function Enable-BlockJavaScriptVBScript {
    $ruleId = "D3E037E1-3EB8-44C8-A917-57927947596D"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Enabled
    Write-Host "Block JavaScript or VBScript from launching downloaded executable content has been enabled."
}

function Disable-BlockJavaScriptVBScript {
    $ruleId = "D3E037E1-3EB8-44C8-A917-57927947596D"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Disabled
    Write-Host "Block JavaScript or VBScript from launching downloaded executable content has been disabled."
}

function Enable-BlockOfficeExecutableContent {
    $ruleId = "3B576869-A4EC-4529-8536-B80A7769E899"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Enabled
    Write-Host "Block Office applications from creating executable content has been enabled."
}

function Disable-BlockOfficeExecutableContent {
    $ruleId = "3B576869-A4EC-4529-8536-B80A7769E899"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Disabled
    Write-Host "Block Office applications from creating executable content has been disabled."
}

function Enable-BlockOfficeCodeInjection {
    $ruleId = "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Enabled
    Write-Host "Block Office applications from injecting code into other processes has been enabled."
}

function Disable-BlockOfficeCodeInjection {
    $ruleId = "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Disabled
    Write-Host "Block Office applications from injecting code into other processes has been disabled."
}

function Enable-BlockOfficeCommunicationChildProcesses {
    $ruleId = "26190899-1602-49E8-8B27-EB1D0A1CE869"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Enabled
    Write-Host "Block Office communication application from creating child processes has been enabled."
}

function Disable-BlockOfficeCommunicationChildProcesses {
    $ruleId = "26190899-1602-49E8-8B27-EB1D0A1CE869"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Disabled
    Write-Host "Block Office communication application from creating child processes has been disabled."
}

function Enable-BlockWMIPersistence {
    $ruleId = "E6DB77E5-3DF2-4CF1-B95A-636979351E5B"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Enabled
    Write-Host "Block persistence through WMI event subscription has been enabled."
}

function Disable-BlockWMIPersistence {
    $ruleId = "E6DB77E5-3DF2-4CF1-B95A-636979351E5B"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Disabled
    Write-Host "Block persistence through WMI event subscription has been disabled."
}

function Enable-BlockPSExecWMICommands {
    $ruleId = "D1E49AAC-8F56-4280-B9BA-993A6D77406C"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Enabled
    Write-Host "Block process creations originating from PSExec and WMI commands has been enabled."
}

function Disable-BlockPSExecWMICommands {
    $ruleId = "D1E49AAC-8F56-4280-B9BA-993A6D77406C"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Disabled
    Write-Host "Block process creations originating from PSExec and WMI commands has been disabled."
}

function Enable-BlockUnsignedUSBProcesses {
    $ruleId = "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Enabled
    Write-Host "Block untrusted and unsigned processes that run from USB has been enabled."
}

function Disable-BlockUnsignedUSBProcesses {
    $ruleId = "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Disabled
    Write-Host "Block untrusted and unsigned processes that run from USB has been disabled."
}

function Enable-BlockWin32APICallsFromOffice {
    $ruleId = "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Enabled
    Write-Host "Block Win32 API calls from Office macros has been enabled."
}

function Disable-BlockWin32APICallsFromOffice {
    $ruleId = "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Disabled
    Write-Host "Block Win32 API calls from Office macros has been disabled."
}

function Enable-AdvancedRansomwareProtection {
    $ruleId = "C1DB55AB-C21A-4637-BB3F-A12568109D35"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Enabled
    Write-Host "Use advanced protection against ransomware has been enabled."
}

function Disable-AdvancedRansomwareProtection {
    $ruleId = "C1DB55AB-C21A-4637-BB3F-A12568109D35"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Disabled
    Write-Host "Use advanced protection against ransomware has been disabled."
}

function Enable-BlockWebshellCreation {
    $ruleId = "A8F5898E-1DC8-49A9-9878-85004B8A61E6"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Enabled
    Write-Host "Block Webshell creation for Servers has been enabled."
}

function Disable-BlockWebshellCreation {
    $ruleId = "A8F5898E-1DC8-49A9-9878-85004B8A61E6"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Disabled
    Write-Host "Block Webshell creation for Servers has been disabled."
}

function Enable-BlockSafeModeReboot {
    $ruleId = "33DDEDF1-C6E0-47CB-833E-DE6133960387"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Enabled
    Write-Host "Block rebooting machine in Safe Mode (preview) has been enabled."
}

function Disable-BlockSafeModeReboot {
    $ruleId = "33DDEDF1-C6E0-47CB-833E-DE6133960387"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Disabled
    Write-Host "Block rebooting machine in Safe Mode (preview) has been disabled."
}

function Enable-BlockImpersonatedTools {
    $ruleId = "C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Enabled
    Write-Host "Block use of copied or impersonated system tools (preview) has been enabled."
}

function Disable-BlockImpersonatedTools {
    $ruleId = "C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB"
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Action Disabled
    Write-Host "Block use of copied or impersonated system tools (preview) has been disabled."
}

function Disable-MicrosoftWidgets {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"
    if (-not (Test-Path -Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    Set-ItemProperty -Path $regPath -Name "AllowNewsAndInterests" -Type DWord -Value 0

    $taskbarRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-ItemProperty -Path $taskbarRegPath -Name "TaskbarDa" -Type DWord -Value 0

    $widgetsProc = Get-Process -Name "Widgets" -ErrorAction SilentlyContinue
    if ($widgetsProc) {
        $widgetsProc | Stop-Process -Force
    }

    $widgetsServiceProc = Get-Process -Name "WidgetService" -ErrorAction SilentlyContinue
    if ($widgetsServiceProc) {
        $widgetsServiceProc | Stop-Process -Force
    }
}

function Disable-StartMenuNetworkCapabilities {
    # Disable Web search in start menu
    $regPath = "HKCU:\Software\Policies\Microsoft\Windows\Explorer"
    if (-not (Test-Path -Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "DisableSearchBoxSuggestions" -Type DWord -Value 1

    # Turn off Bing web search integration
    $searchRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
    if (-not (Test-Path $searchRegPath)) {
        New-Item -Path $searchRegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $searchRegPath -Name "BingSearchEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path $searchRegPath -Name "CortanaConsent" -Type DWord -Value 0

    $firewallRule = Get-NetFirewallRule -DisplayName "Block StartMenuExperienceHost" -ErrorAction SilentlyContinue
    if (-not $firewallRule) {
        New-NetFirewallRule -DisplayName "Block StartMenuExperienceHost" `
            -Program "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" `
            -Action Block -Direction Outbound | Out-Null
    }  
}

function ConvertFrom-SecureStringToPlainText {
    param ([System.Security.SecureString]$SecureString)
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

function Get-KeyIV {
    param (
        [string]$Password,
        [byte[]]$Salt,
        [int]$Iterations = 100000
    )

    $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $Salt, $Iterations)
    return @{
        Key = $pbkdf2.GetBytes(32)  # AES-256
        IV  = $pbkdf2.GetBytes(16)  # AES block size
    }
}

function Remove-FileWithOverwrite {
    param (
        [string]$FilePath,
        [int]$Passes = 50
    )

    $FilePathFull = (Resolve-Path -Path $FilePath).Path
    $PathDirectory = [System.IO.Path]::GetDirectoryName($FilePathFull)

    if (-not (Test-Path $FilePathFull)) {
        Write-Warning "File not found: $FilePathFull"
        return
    }

    $fileInfo = Get-Item $FilePathFull
    $length = $fileInfo.Length

    try {
        for ($i = 1; $i -le $Passes; $i++) {
            $randomData = New-Object byte[] $length
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($randomData)
            [System.IO.File]::WriteAllBytes($FilePathFull, $randomData)
        }

        # Rename file before deletion to mask name
        $newName = [guid]::NewGuid().ToString()
        Rename-Item -Path $FilePathFull -NewName $newName

        $newFilePathFull = Join-Path -Path $PathDirectory -ChildPath $newName
        Remove-Item -Path $newFilePathFull -Force

        Write-Host "Securely deleted: $FilePath"
    } catch {
        Write-Error "Failed to securely delete: $FilePath"
    }
}


function Protect-FileBasic {
    param (
        [string]$InputFile,
        [string]$OutputFile
    )

    $securePassword = Read-Host "Enter password to encrypt" -AsSecureString
    $password = ConvertFrom-SecureStringToPlainText $securePassword

    $salt = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)

    $keys = Get-KeyIV -Password $password -Salt $salt

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $keys.Key
    $aes.IV  = $keys.IV

    $plainText = Get-Content -Path $InputFile -Raw
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($plainText)

    $ms = New-Object System.IO.MemoryStream
    $cs = New-Object System.Security.Cryptography.CryptoStream $ms, $aes.CreateEncryptor(), 'Write'
    $cs.Write($plainBytes, 0, $plainBytes.Length)
    $cs.Close()

    $cipherData = $ms.ToArray()

    # Prepend salt to ciphertext and write to file
    [System.IO.File]::WriteAllBytes($OutputFile, $salt + $cipherData)

    Write-Host "File encrypted and saved to $OutputFile"
}

function Unprotect-FileBasic {
    param (
        [string]$InputFile,
        [string]$OutputFile
    )

    $securePassword = Read-Host "Enter password to decrypt" -AsSecureString
    $password = ConvertFrom-SecureStringToPlainText $securePassword

    $allBytes = [System.IO.File]::ReadAllBytes($InputFile)

    $salt = $allBytes[0..15]
    $cipherBytes = $allBytes[16..($allBytes.Length - 1)]

    $keys = Derive-KeyIV -Password $password -Salt $salt

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $keys.Key
    $aes.IV  = $keys.IV

    $ms = New-Object System.IO.MemoryStream
    $cs = New-Object System.Security.Cryptography.CryptoStream $ms, $aes.CreateDecryptor(), 'Write'
    try {
        $cs.Write($cipherBytes, 0, $cipherBytes.Length)
        $cs.Close()
        $plainText = [System.Text.Encoding]::UTF8.GetString($ms.ToArray())
        Set-Content -Path $OutputFile -Value $plainText
        Write-Host "File decrypted and saved to $OutputFile"
    } catch {
        Write-Error "Decryption failed. Possibly wrong password or corrupted file."
    }
}


Export-ModuleMember -Function Get-GeoLocationInfo, Grant-LocationAccess, Revoke-LocationAccess, 
    Disable-SSL2.0, Disable-SSL3.0, Disable-TLS1.0, Disable-TLS1.1, Enable-TLS1.2, Enable-TLS1.3, 
    Get-SecureProtocolStatus, Enable-SecureProtocols, Show-ActiveRemoteConnections,
    Grant-BluetoothAccess, Revoke-BluetoothAccess, Grant-AppDiagnosticAccess, Revoke-AppDiagnosticAccess,
    Grant-AppointmentsAccess, Revoke-AppointmentsAccess, Grant-BroadFileSystemAccess, Revoke-BroadFileSystemAccess,
    Grant-UserAccountAccess, Revoke-UserAccountAccess,
    Grant-ActivityAccess, Revoke-ActivityAccess, Grant-CellularDataAccess, Revoke-CellularDataAccess,
    Grant-ChatAccess, Revoke-ChatAccess, Grant-ContactsAccess, Revoke-ContactsAccess,
    Grant-DocumentsLibraryAccess, Revoke-DocumentsLibraryAccess, Grant-DownloadsFolderAccess, Revoke-DownloadsFolderAccess,
    Grant-EmailAccess, Revoke-EmailAccess, Grant-GazeInputAccess, Revoke-GazeInputAccess,
    Grant-HumanInterfaceDeviceAccess, Revoke-HumanInterfaceDeviceAccess, Grant-MicrophoneAccess, Revoke-MicrophoneAccess,
    Grant-MusicLibraryAccess, Revoke-MusicLibraryAccess, Grant-PhoneCallAccess, Revoke-PhoneCallAccess,
    Grant-PhoneCallHistoryAccess, Revoke-PhoneCallHistoryAccess, Grant-PicturesLibraryAccess, Revoke-PicturesLibraryAccess,
    Grant-RadiosAccess, Revoke-RadiosAccess, Grant-CustomSensorsAccess, Revoke-CustomSensorsAccess,
    Grant-SerialCommunicationAccess, Revoke-SerialCommunicationAccess, Grant-USBAccess, Revoke-USBAccess,
    Grant-UserDataTasksAccess, Revoke-UserDataTasksAccess, Grant-UserNotificationListenerAccess, Revoke-UserNotificationListenerAccess,
    Grant-VideosLibraryAccess, Revoke-VideosLibraryAccess, Grant-WebcamAccess, Revoke-WebcamAccess,
    Grant-WiFiDataAccess, Revoke-WiFiDataAccess, Grant-WiFiDirectAccess, Revoke-WiFiDirectAccess, Get-IPv6Status, 
    Disable-InterfaceIPv6, Enable-InterfaceIPv6, Enable-IPv6Globally, Disable-IPv6Globally, Disable-AllInterfacesIPv6, Enable-AllInterfacesIPv6,
    Get-StoredWiFiPasswords, Get-AccessPermissionStatus, Grant-AllPermissions, Revoke-AllPermissions, Test-IsAdmin, Invoke-NetKill,
    Enable-AllASRRules, Disable-AllASRRules,
    Enable-BlockVulnerableDrivers, Disable-BlockVulnerableDrivers,
    Enable-BlockAdobeReaderChildProcesses, Disable-BlockAdobeReaderChildProcesses,
    Enable-BlockOfficeChildProcesses, Disable-BlockOfficeChildProcesses,
    Enable-CredentialStealingProtection, Disable-CredentialStealingProtection,
    Enable-BlockEmailExecutableContent, Disable-BlockEmailExecutableContent,
    Enable-BlockExecutableFiles, Disable-BlockExecutableFiles,
    Enable-BlockObfuscatedScripts, Disable-BlockObfuscatedScripts,
    Enable-BlockJavaScriptVBScript, Disable-BlockJavaScriptVBScript,
    Enable-BlockOfficeExecutableContent, Disable-BlockOfficeExecutableContent,
    Enable-BlockOfficeCodeInjection, Disable-BlockOfficeCodeInjection,
    Enable-BlockOfficeCommunicationChildProcesses, Disable-BlockOfficeCommunicationChildProcesses,
    Enable-BlockWMIPersistence, Disable-BlockWMIPersistence,
    Enable-BlockPSExecWMICommands, Disable-BlockPSExecWMICommands,
    Enable-BlockUnsignedUSBProcesses, Disable-BlockUnsignedUSBProcesses,
    Enable-BlockWin32APICallsFromOffice, Disable-BlockWin32APICallsFromOffice,
    Enable-AdvancedRansomwareProtection, Disable-AdvancedRansomwareProtection,
    Enable-BlockWebshellCreation, Disable-BlockWebshellCreation,
    Enable-BlockSafeModeReboot, Disable-BlockSafeModeReboot,
    Enable-BlockImpersonatedTools, Disable-BlockImpersonatedTools,
    Disable-MicrosoftWidgets, Disable-StartMenuNetworkCapabilities,
    ConvertFrom-SecureStringToPlainText, Get-KeyIV, Remove-FileWithOverwrite,
    Protect-FileBasic, Unprotect-FileBasic