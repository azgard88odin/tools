# Windows Tools - Custom Modules
This repo mainly consists of PowerShell modules that contain my own custom functions.  
All of these functions are something I either use or have used for some purpose or another.  
When I learn something I try to gather it in a way that is easy to use.  
You will also find the 'PowerShellCommandsLibrary' script that essentially works like a cheat sheet.   
As I learned something useful or important I generally kept a record of it so that can easily refer back to it later.  
  
I may, in the not too distant future, start sharing my entire command library which is divided by languages for both Linux and Windows.  
I believe it is essential to share knowledge and information.  
Should you have any suggestions on improvements I can make, I would love to hear it.

Other than that I hope you find these tools useful.

## DISCLAIMER
Some of the cmdlets and functions are security orientated. As such I take no responsibility nor condone any malicious use thereof.  
My intention is that this can help others with their day-to-day and learn from it as I do.  
And just to cover myself, I will use the choice favorite term 'for educational purposes only'

## Table of Contents

- [Credits](#credits)
- [Installation](#installation)
- [CheatSheets](#cheatsheets)
- [CustomUtilities](#customutilities)
- [InvestigateLogs](#investigatelogs)
- [NetworkEnumeration](#networkenumeration)
- [Personalization](#personalization)
- [PrivacyAndSecurity](#privacyandsecurity)
- [PowerShellCommandsLibary](#powershellcommandslibrary)

## Credits
I did not keep track of all of the sources used to create this resource. But notable mentions are:
1. Jakoby / PowerShellForHackers
2. UnderTheWire     -   This is what got me started on the PowerShell journey 
3. Mike Haggis

**NOTE:** Some of the utilities will require administrative privileges.

### Installation
When installing modules you will generally install them in $env:USERPROFILE\Documents\WindowsPowerShell\Modules  
In this directory you will have to create a directory for each module with the same name as the module. E.g. CheatSheets or PrivacyAndSecurity  
  
Then you will need to create a module manifest with the following cmdlet.  
Please provide the full path to the module directory:  

    New-ModuleManifest -Path "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\CheatSheets\CheatSheets.psd1" `  
        -RootModule "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\CheatSheets\CheatSheets.psm1" `  
        -Author "Fred Twostairs" `  
        -Description "I am a description of this module" `  
        -ModuleVersion "1.0.0"

### CheatSheets
This module contains some quick reference cheat sheets. I prefer a quick reference on the commandline than having to go search for one or open up one of my pdf versions.  
Look inside to see the different kinds of cheat sheets I currently have.  
Feel free to modify and add to the cheatsheets

### CustomUtilities
This module contains useful utilities for working with files, data and general tasks.
These utilities include some of the following:
- Converting Bytes to Human Readable values and back
- Finding file larger than a specified size
- Converting to and from Base64
- Getting the hash of a string
- Testing the checksum of a file
- Getting installed software and startup programs
- Time conversion utilities
- Date conversion (to ISO8601)
- Ascii/Hex conversion
- Converting PowerShell scripts to encoded batch scripts

### InvestigateLogs
This module I actually created for a friend to help him learn about how to search through Windows EventLogs.  
These contain functions that assist in searching through security and application logs:
- Security Event ID lookup and referal by string
- Finding Security Logs by User, Account Logon Type, Workstation, Time Window, IP, Domain or all of the above
- Finding Application Log by User SID, Computer Name, Time, Window, Provider Name or all of the above

### NetworkEnumeration
This module contains functions I use to gather network information around me.  
I have used many of these at work to find and debug basic network issues.
- Connecting to a Wi-Fi AP
- Get all Wireless Access Points around you - this shows their Wi-Fi generation, protections and signal strengths
- ARP Scan of a provided subnet
- Basic PowerShell port scanners - These ain't no Nmap but they work for some basics
- Ping sweep through a provided subnet
- Setting a static IP or unsetting it back to a dynamic IP
- Getting the active network interface - the internet facing interface (I use this in security script)

### Personalization
This module just contains functions I like to use for my own computer.  
I have a wallpapers repo should you want to use the wallpaper functions.
- Setting a random Desktop Wallpaper
- Setting a random LockScreen Wallpaper
- Getting daily crypto rates
- Setting the Taskbar to autohide itself - Windows sometimes undoes my setting and so I created this
- Setting the Taskbar alignment - sets the start menu either left or center
- Show-CustomCommands - shows all the function names of all my modules
- Update-CustomModules - this just makes it easier to update the modules in my session when updating the module code

### PrivacyAndSecurity
This module contains functions you can use to activate and deactive certain Window-isms.  
There are also functions you can use to easily gain information about a system or user.
- Getting geolocation information - should your location services be active
- Getting either local or AD user's SID
- Granting or Revoking all software permissions to hardware - Function to Grant or Revoke all
- Disabling Insecure SSL and TLS Protocols - Replace with Secure Protocols
- Checking Status of secure (SSL/TLS) protocols
- Showing active network connections to your computer - This compares the remote IP address to blacklist and tor node lists
- Enable and Disable IPv6 - I prefer having mine disabled until there is an actual security benefit to using it or it is more adopted
- Showing all Stored Wi-Fi Passwords on the machine
- Testing if your current user is an administrative user
- Network kill switch (NetKill) that will find your current internet facing interface and disable it. Flip the $Kill switch to re-enable
- If you are using Microsoft Defender, functions to activate and deactivate Attack Surface Reduction rules

### PowerShellCommandsLibrary
This script as described above, has cmdlets and functions that have helped me in CTFs and day-to-day operations.  
When I learn something I try to record it to easily refer back to it.  
This has too much to list, but includes some of the following:
- System information cmdlets
- Getting and setting environment variables
- Getting local users and groups
- Getting serial and usb devices - and printers
- The PowerShell version of grep and other file operation cmdlets
- Finding duplicate files using file hashes
- Working with Alternate Data Streams
- Getting and Setting Access Control Lists for files
- Compress-Files - for older versions of PowerShell
- Clipboard management functions and cmdlets
- Networking cmdlets - tcp, udp, dns, firewalls...
- Downloading files from the web (similar to wget)
- Getting the DNSCache
- Getting system certificates
- Windows EventLog cmdlets
- Active Directory cmdlets
- Registry cmdlets
- Recycle bin management
- Module installation