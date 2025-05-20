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

# Grant Bluetooth Access in Registry
function Grant-BluetoothAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Bluetooth Access in Registry
function Revoke-BluetoothAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant App Diagnostic Access in Registry
function Grant-AppDiagnosticAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke App Diagnostic Access in Registry
function Revoke-AppDiagnosticAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant App Background Access in Registry
function Grant-AppointmentsAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke App Background Access in Registry
function Revoke-AppointmentsAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f
}

function Grant-BroadFileSystemAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Allow" /f
}

function Revoke-BroadFileSystemAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Deny" /f
}

function Grant-UserAccountAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Allow" /f
}

function Revoke-UserAccountAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant Activity Access in Registry
function Grant-ActivityAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Activity Access in Registry
function Revoke-ActivityAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant Cellular Data Access in Registry
function Grant-CellularDataAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Cellular Data Access in Registry
function Revoke-CellularDataAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant Chat Access in Registry
function Grant-ChatAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Chat Access in Registry
function Revoke-ChatAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant Contacts Access in Registry
function Grant-ContactsAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Contacts Access in Registry
function Revoke-ContactsAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant Documents Library Access in Registry
function Grant-DocumentsLibraryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Documents Library Access in Registry
function Revoke-DocumentsLibraryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant Downloads Folder Access in Registry
function Grant-DownloadsFolderAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Downloads Folder Access in Registry
function Revoke-DownloadsFolderAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant Email Access in Registry
function Grant-EmailAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Email Access in Registry
function Revoke-EmailAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant Gaze Input Access in Registry
function Grant-GazeInputAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Gaze Input Access in Registry
function Revoke-GazeInputAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant Human Interface Device Access in Registry
function Grant-HumanInterfaceDeviceAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanInterfaceDevice" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanInterfaceDevice" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Human Interface Device Access in Registry
function Revoke-HumanInterfaceDeviceAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanInterfaceDevice" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanInterfaceDevice" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant Microphone Access in Registry
function Grant-MicrophoneAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Microphone Access in Registry
function Revoke-MicrophoneAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant Music Library Access in Registry
function Grant-MusicLibraryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Music Library Access in Registry
function Revoke-MusicLibraryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant Phone Call Access in Registry
function Grant-PhoneCallAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Phone Call Access in Registry
function Revoke-PhoneCallAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant Phone Call History Access in Registry
function Grant-PhoneCallHistoryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Phone Call History Access in Registry
function Revoke-PhoneCallHistoryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant Pictures Library Access in Registry
function Grant-PicturesLibraryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Pictures Library Access in Registry
function Revoke-PicturesLibraryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant Radios Access in Registry
function Grant-RadiosAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Radios Access in Registry
function Revoke-RadiosAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant Custom Sensors Access in Registry
function Grant-CustomSensorsAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\sensors.custom" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\sensors.custom" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Custom Sensors Access in Registry
function Revoke-CustomSensorsAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\sensors.custom" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\sensors.custom" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant Serial Communication Access in Registry
function Grant-SerialCommunicationAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\serialCommunication" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\serialCommunication" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Serial Communication Access in Registry
function Revoke-SerialCommunicationAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\serialCommunication" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\serialCommunication" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant USB Access in Registry
function Grant-USBAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\usb" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\usb" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke USB Access in Registry
function Revoke-USBAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\usb" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\usb" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant User Data Tasks Access in Registry
function Grant-UserDataTasksAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke User Data Tasks Access in Registry
function Revoke-UserDataTasksAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant User Notification Listener Access in Registry
function Grant-UserNotificationListenerAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke User Notification Listener Access in Registry
function Revoke-UserNotificationListenerAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant Videos Library Access in Registry
function Grant-VideosLibraryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Videos Library Access in Registry
function Revoke-VideosLibraryAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant Webcam Access in Registry
function Grant-WebcamAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke Webcam Access in Registry
function Revoke-WebcamAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant WiFi Data Access in Registry
function Grant-WiFiDataAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke WiFi Data Access in Registry
function Revoke-WiFiDataAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData" /v "Value" /t REG_SZ /d "Deny" /f
}

# Grant WiFi Direct Access in Registry
function Grant-WiFiDirectAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiDirect" /v "Value" /t REG_SZ /d "Allow" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiDirect" /v "Value" /t REG_SZ /d "Allow" /f
}

# Revoke WiFi Direct Access in Registry
function Revoke-WiFiDirectAccess {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiDirect" /v "Value" /t REG_SZ /d "Deny" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiDirect" /v "Value" /t REG_SZ /d "Deny" /f
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

        if ($ReverseLookup) {
            $results += [PSCustomObject]@{
                IPAddress = $ip
                Port = $port
                ProcessName = $processName
                Country = $geo.country
                City = $geo.city
                Organization = $geo.org
                Reverse = $geo.reverse
            }
        } else {
            $results += [PSCustomObject]@{
                IPAddress = $ip
                Port = $port
                ProcessName = $processName
                Country = $geo.country
                City = $geo.city
                Organization = $geo.org
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
    Get-StoredWiFiPasswords, Get-AccessPermissionStatus, Grant-AllPermissions, Revoke-AllPermissions
