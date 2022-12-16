<#
.SYNOPSIS
Common IOC Powershell Detection Script
.DESCRIPTION
TL;DR the script will search common event viewer logs for exploitation attempts on machine or scan a local .evtx file.
Feel free to incorporate more patterns to detect additional dangerous patterns observed in the wild. 
*Use it on live system*
*Use it on a .evtx offline file to scan*
.EXAMPLE
PS> . .\IOCdetectWIN.ps1
Run the script with default settings search live local logs

PS> . .\IOCdetectWIN.ps1 /folder/name.evtx
Process evtx file through script
.NOTES
.Author: James Kelly
https://gmuisg.org
#>

#Requires -RunAsAdministrator

param(
  [string]$file = $env:file #Specify .evtx file to scan default is LIVE system
)

$datestring = (Get-Date).ToString('s').Replace(':','-')

$outputGrid = $True
$saveToFile = $False

$scanWinProcess = $True #You can enable/disable these *keep in mind speed will go down
$scanRegistry = $True #If enabled you must set proper SACls on registry entries you want to monitor https://github.com/jake-k-38/Win-SACL-ObjectAccess
$scanWinAudit = $True #You can enable/disable these *keep in mind speed will go down
$scanWinTask = $True #You can enable/disable these *keep in mind speed will go down
$scanWinAV = $True #You can enable/disable these *keep in mind speed will go down
$scanWinPSLogs = $False #disabled by default, need workaround script detecting itself
$scanWinShare = $True #You can enable/disable these *keep in mind speed will go down Sysmon event 17 or 5140
$scanWinService = $True #You can enable/disable these *keep in mind speed will go down

$scanBase64Process = $True #You can enable/disable these 
$scanBase64Tasks = $True #You can enable/disable these

#Find processes launched with arguments that have characters indicative of obfuscation on the command-line. https://github.com/splunk/security_content/blob/develop/detections/endpoint/malicious_powershell_process_with_obfuscation_techniques.yml
#To avoid false positives may need to increase obfuscateCommandSensitivity > 10
$obfuscateCommandSensitivity = 20
$obfuscateChars = @(
  '`',
  '"',
  '“',
  '”',
  "'",
  '^'
)

$IOCPatterns = $IOCRegistry = $IOCNetShare = $IOCMalServiceName = $IOCMalServiceFileName = $ioc_Process = $ioc_SysmonProcess = $ioc_SysmonRegistry = $ioc_WinPS = $ioc_WinDef = $ioc_task = $ioc_NetShare = $ioc_ProcessBase64 = $ioc_Sysmonprocessbase64 = $processFilter = $processSysmonFilter = $registryFilter = $registrySysmonFilter = $auditPolicyFilter = $taskFilter = $WinAvFilter = $winPSFilter = $netShareFilter = $serviceFilter = ''
$ioc_taskbase64 = New-Object System.Collections.ArrayList

$processFilter = @{
  LogName = 'Security'
  ID = 4688 #New process eventID
}

$processSysmonFilter = @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  ID = 1 #New process eventID
}

$registryFilter = @{
  LogName = 'Security'
  ID = 4657 #A registry value was changed Requires SACLs on specific entries: https://github.com/jake-k-38/Win-SACL-ObjectAccess read more @ https://www.criticalstart.com/windows-security-event-logs-what-to-monitor/
}

$registrySysmonFilter = @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  ID = 12,13 #Registry value changed
}

$auditPolicyFilter = @{
  LogName = 'Security'
  ID = 4719,1102 #Audit Policy change /All Events cleared log (System audit policy was changed.)
}

$taskFilter = @{
  LogName = 'Security'
  ID = 4698,4702 #New ScheduledTasks, Scheduled task was updated
}

$netShareFilter = @{
  LogName = 'Security'
  ID = 5140,5145 #Network share object was accessed https://atomicorp.com/how-to-defend-lateral-movement-in-windows-with-ossec/
}

$pipeFilter = @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  ID = 17 #Named Pipe events 17
}

$serviceFilter = @{
  LogName = 'System'
  ID = 7045 #https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md
}

$WinAvFilter = @{
  LogName = 'Microsoft-Windows-Windows Defender/Operational'
  ID = 5001,5007,1116,1121 #Defender modifications
}

$winPSFilter = @{ #WIP need to find workaround for script execution, Use out-grid filter DOES NOT CONTAIN
  LogName = 'Microsoft-Windows-PowerShell/Operational'
  ID = 4104 #Powershell Scriptblock - Execute a Remote Command
}

try {
  if (!(Test-Path -Path $file) -or !(($file -like '*.evtx'))) {
    Write-Warning ("File does not exist or not a .evtx file extension!, try again")
    return
  } else {
    Write-Warning ('Now Scanning....' + $file)
    $processFilter = @{
      Path = $file;
      ID = 4688
    }

    $processSysmonFilter = @{
      Path = $file;
      ID = 1
    }

    $registryFilter = @{
      Path = $file;
      ID = 4657
    }

    $registrySysmonFilter = @{
      Path = $file;
      ID = 12,13
    }

    $auditPolicyFilter = @{
      Path = $file;
      ID = 4719,1102
    }

    $taskFilter = @{
      Path = $file;
      ID = 4698,4702
    }

    $netShareFilter = @{
      Path = $file;
      ID = 5140,5145
    }

    $pipeFilter = @{
      Path = $file;
      ID = 17
    }

    $serviceFilter = @{
      Path = $file;
      ID = 7045
    }

    $WinAvFilter = @{
      Path = $file;
      ID = 5001,5007,1116,1121
    }

    $winPSFilter = @{
      Path = $file;
      ID = 4104
    }
  }
} catch {}
#https://github.com/SigmaHQ/sigma/blob/master/other/godmode_sigma_rule.yml
#got to add Sigma rules idea from https://github.com/dfirale/evtscanner, took some of his patterns too :)

$IOCPatterns = @(
  '[\-|\/|–|—|―][Ee^]{1,2}[NnCcOoDdEeMmAa^]+\s+[A-Za-z0-9+/=]{5,}',# Used in malicious PowerShell commands got regex from https://github.com/splunk/security_content/blob/develop/detections/endpoint/malicious_powershell_process___encoded_command.yml
  '[\-|\/|–|—|―][Ww^]{1,2}[IiNnDdOoWwSsTtYyLlEe^]+\s+[Hh^]{1,2}[IiDdDdEeNn^]+',# Used in malicious PowerShell commands https://github.com/splunk/security_content/blob/develop/detections/endpoint/powershell___connect_to_internet_with_hidden_window.yml
  ' -NoP ',# Used in malicious PowerShell commands 
  '-ep bypass',# Used in malicious PowerShell commands
  'powershell -w h',# Used in malicious PowerShell commands
  'powershell -window hidden -C',# Used in malicious PowerShell commands
  'powershell/w 1 /nop',# Used in malicious PowerShell commands
  'powershell/w 01 /ep 0/nop/c',# Used in malicious PowerShell commands
  'powershell -exec bypass',# Used in malicious PowerShell commands
  'powershell -command',# Used in malicious PowerShell commands
  'powershell -c iex',# Used in malicious PowerShell commands
  'powershell -c iwr',# Used in malicious PowerShell commands
  '.downloadstring\(',# PowerShell download command
  '.downloadfile\(',# PowerShell download command
  'FromBase64String\(',# Suspicious FromBase64String expressions
  'powershell . (nslookup -q=txt)',# Way to avoid iex and web request through webpage with code twitter @Alh4zr3d
  '& powershell (nslookup -q=txt)',# Way to avoid iex and web request through webpage with code twitter @Alh4zr3d
  '(nslookup -q=txt)[-1]',# Way to avoid iex and web request through webpage with code twitter @Alh4zr3d
  'nslookup -q=txt',# Way to avoid iex and web request through webpage with code twitter @Alh4zr3d
  ';iex\(',# PowerShell IEX
  '(?:gal+\s).*',# PowerShell obfucation example - IEX with Alias .(gal ?e[?x]) or Invoke-RestMethod with Alias .(gal ?rm)
  '-Value iex',# PowerShell Set-Alias command for iex
  'Set-Alias',# PowerShell Set-Alias command can be used to hide iex, eval, etc
  '(?:csc.exe|cvtres.exe).*?\\AppData\\',# Often used in malicious compiling on systems https://www.sentinelone.com/labs/solarwinds-understanding-detecting-the-supernova-webshell-trojan/
  ' -decode ',# Used with certutil
  ' /decode ',# Used with certutil 
  'vssadmin delete shadows',# Ransomware
  'reg SAVE HKLM\\SAM',# save registry SAM - syskey extraction
  ' -ma ',# ProcDump
  'Microsoft\\Windows\\CurrentVersion\\Run',# Run key in command line - often in combination with REG ADD
  'ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp',# Common persistence location
  'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',# Common persistence location
  ' /ticket:',# Rubeus
  ' sekurlsa',# Mimikatz
  ' p::d',# Mimikatz
  'pypykatz live lsa --method handledup',# Python of Mimikatz 
  'schtasks(?s).*/create(?s).*AppData',# Scheduled task creation pointing to AppData
  'attrib +H',# Hidden files
  'schtasks /create /s',# Create tasks on remote computer /s lateral movement
  'cmd /c schtasks /create /tn',# Create tasks using cmd /c
  'cmd /c schtasks /delete /tn',# Delete tasks using cmd /c
  'cmd.exe /Q /c(?s).*\\\\127.0.0.1\\',# wmiexec.py https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py#L287
  'cmd.exe /C(?s).*\\\\Temp\\',# atexec.py  https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py#L122
  'cmd.exe /Q /c',# Call cmd quietly, suspicious
  '%COMSPEC%',# Call cmd obfuscated
  'Scriptrunner.exe',# Lolbins used to compile/execute stagers
  'Cscript.exe',# Lolbins used to compile/execute stagers
  'WScript.exe',# Lolbins used to compile/execute stagers
  'regsvr32.exe',# Lolbins used to compile/execute stagers
  'net.exe',# Creating user accounts, net localgroup, enumerating
  'at.exe \\',# Create tasks on remote computer /s lateral movement
  ' comsvcs.dll,MiniDump',# Process dumping method apart from procdump
  ' comsvcs.dll,#24',# Process dumping method apart from procdump
  'Add-MpPreference(?s).*ExclusionPath',# Defender exclusion
  'Add-MpPreference(?s).*ExclusionExtension',# Defender exclusion
  'Add-MpPreference(?s).*ExclusionProcess',# Defender exclusion
  'DisableBehaviorMonitoring $true',# Defender disable
  'DisableRunTimeMonitoring $true',# Defender disable
  'sc(?s).*stop(?s).*WinDefend',# Defender disable
  'sc(?s).*config(?s).*WinDefend(?s).*disabled',# Defender disable
  'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions',# Defender disable
  'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring',
  'netsh advfirewall',# Create firewall rules
  'New-NetFirewallRule',# Create firewall rules
  'base64_encode',# Suspicious FromBase64String expressions
  'base64_decode',# Suspicious FromBase64String expressions
  'VBscript.Encode',# Suspicious FromBase64String expressions
  '[cC^]:\\Users\\.*?\\AppData\\[^\\].*?\.lnk',# Suspicious .lnk from AppData WIP maybe add .js .exe, etc 
  'rundll32.exe javascript:',# Suspicious call to run javascript code, stagers
  'rundll32.exe C:\Windows\system32\davclnt.dll,DavSetCookie',# Load DLLs and modules of program; indicator of exfiltration or use of WebDav to launch code
  'rundll32.exe C:\Windows\system32\advpack.dll,DelNodeRunDLL32',# Load DLLs and modules of program; indicator of exfiltration or use of WebDav to launch code
  '(?:whoami+\s).*',# Calling whoami, or /priv
  'bitsadmin',# Bitsadmin, used to download stagers, web request C2, etc
  'Start-BitsTransfer -Source',# Powershell bitsadmin, used to download stagers, web request C2, etc
  'WScript.Shell',
  'WScriptShell.CreateShortcut',
  'WScriptShell.SpecialFolders',
  'tasklist',
  'wmic process call create',
  'wmic /node',
  'System audit policy was changed.',
  'Microsoft Defender Antivirus Real-time Protection scanning for malware and other potentially unwanted software was disabled.',
  'Microsoft Defender Antivirus has detected malware or other potentially unwanted software.',
  'Microsoft Defender Exploit Guard has blocked an operation that is not allowed by your IT administrator.'
)

#Registry anomalies aka Persistence *Must enable Audit object access '4657 A registry value was changed' + SACLs for specific keys https://github.com/jake-k-38/Win-SACL-ObjectAccess
#Added Sysmon support
#idea from https://github.com/dfirale/evtscanner, took some of his patterns too :)

$TargetObject = @(
  'UserInitMprLogonScript',# Persistence
  '\\CurrentVersion\\Image File Execution Options\\',# Persistence
  '\\Microsoft\\Windows\\CurrentVersion\\Run\\',# Persistence
  '\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\',# Persistence
  '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders',# Persistence
  '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders',# Persistence
  '\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce',# Persistence
  '\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices',# Persistence
  '\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run' # Persistence
)

$IOCRegistry = @(
  'javascript',
  'powershell',
  '/nop'
  '-nop',
  'wmic',
  'rundll32',
  'cmd',
  '%COMSPEC%',
  'cscript',
  'wscript',
  'regsvr32',
  'mshta',
  'scrobj.dll',
  'bitsadmin',
  'certutil',
  'msiexec',
  'javaw',
  '\\Temp\\',
  'AppData',
  '\\Users\\Public\\'
)

#idea from https://github.com/dfirale/evtscanner, took some of his patterns too :)
$IOCNetShare = @(
  '\\*\\C$',# Lateral movement
  'postex',# Cobalt Strike Pipe Name                     
  'status_',# Cobalt Strike Pipe Name
  'msagent_',# Cobalt Strike Pipe Name
  'lsadump',# Password or Credential Dumpers
  'cachedump',# Password or Credential Dumpers
  'wceservicepipe',# Password or Credential Dumpers
  'isapi',# Malware named pipes
  'sdlrpc',# Malware named pipes
  'ahexec',# Malware named pipes
  'winsession',# Malware named pipes
  'lsassw',# Malware named pipes
  '46a676ab7f179e511e30dd2dc41bd388',# Malware named pipes
  '9f81f59bc58452127884ce513865ed20',# Malware named pipes
  'e710f28d59aa529d6792ca6ff0ca1b34',# Malware named pipes
  'rpchlp_3',# Malware named pipes
  'NamePipe_MoreWindows',# Malware named pipes
  'pcheap_reuse',# Malware named pipes
  'gruntsvc',# Malware named pipes
  '583da945-62af-10e8-4902-a8f205c72b2e',# Malware named pipes
  'bizkaz',# Malware named pipes
  'svcctl',# Malware named pipes
  'Posh',# Malware named pipes
  'jaccdpqnvbrrxlaf',# Malware named pipes
  'csexecsvc',# Malware named pipes
  'paexec',# Remote Command Execution Tools
  'remcom',# Remote Command Execution Tools
  'csexec',# Remote Command Execution Tools
  '\\(?:[0-9]{1,3}\.){3}[0-9]{1,3}\\\w+\$\\[^\\]*?\.exe' #Local IP/Remote pipes to .exe file
)

#idea from https://github.com/dfirale/evtscanner, took some of his patterns too :)
$IOCMalServiceName = @(
  'WCESERVICE',# PW Dumping https://attack.mitre.org/software/S0005/
  'WCE SERVICE',# PW Dumping https://attack.mitre.org/software/S0005/
  'winexesvc',# PsExec alternative https://attack.mitre.org/software/S0191/
  'DumpSvc',# PW Dumping
  'pwdump',# PW Dumping https://attack.mitre.org/software/S0006/
  'gsecdump',# PW Dumping https://attack.mitre.org/software/S0008/
  'cachedump' # PW Dumping https://attack.mitre.org/software/S0119/
)

#idea from https://github.com/dfirale/evtscanner, took some of his patterns too :)
$IOCMalServiceFileName = @(
  '\\\\.\\pipe',# Possible get-system usage. Named pipe service - https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/
  '\\\\127.0.0.1\\',# Detects smbexec from Impacket framework - https://neil-fox.github.io/Impacket-usage-&-detection/
  '\\(?:[0-9]{1,3}\.){3}[0-9]{1,3}\\\w+\$\\[^\\]*?\.exe' #Local IP/Remote pipes to .exe file
)

filter DecodeB64 {
  try {$Decode = [Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($extractedBase64)); return $Decode} catch {}
}

filter CommandLine-ConvertBase64String {
  if($_.CommandLine.Length -lt 24) { return }
  $regex = '\s+([A-Za-z0-9+/]{20}\S+)'
  $extractedBase64 = $_.CommandLine | Select-String -Pattern $regex -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value }
  $extractedBase64 | DecodeB64 #send extracted b64 to decode filter
}

filter TaskContent-ConvertBase64String {
  $regex = '\s+([A-Za-z0-9+/]{20}\S+)' #extract base64 
  $extractedBase64 = $_ | Select-String -Pattern $regex -Al lMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value }
  $extractedBase64 | DecodeB64
}

filter MultiSelect-StringIOCPatterns ([string[]]$Patterns) {
  foreach ($Pattern in $Patterns) { # Check the current item against all patterns.
    $found = $_ | Select-String -Pattern $Pattern -AllMatches #Optimize var cache 
    if ($found) { $_ }
  }
  if ($_.CommandLine) {
    foreach ($o in $obfuscateChars){
      $num_obfuscationCommandLine = (($_.CommandLine -split $o).Count) - 1
      $num_obfuscationParentCommandLine = (($_.ParentCommandLine -split $o).Count) - 1
      if ($num_obfuscationCommandLine -gt $obfuscateCommandSensitivity -Or $num_obfuscationParentCommandLine -gt $obfuscateCommandSensitivity) { $_ } #Sus commandline / Task arguments might be obfuscated
    }
  }elseif($_.TaskContent){
    #if(!([xml]$_.TaskContent)) {return}
    $task = [xml]$_.TaskContent
    $taskArguments = $task.Task.Actions.Exec.Arguments
    foreach ($o in $obfuscateChars){
      $num_obfuscationTaskArguments = (($taskArguments -split $o).Count) - 1
      if ($num_obfuscationTaskArguments -gt $obfuscateCommandSensitivity) { $_ }
    }
  }
}

# Registry anomalies / used in Persistence
filter MultiSelect-StringRegIOC ([string[]]$Target,[string[]]$Patterns) {
  foreach ($t in $Target) {
    if (!($_.TargetObject)) {
      $found = $_.ObjectName | Select-String -Pattern $t -AllMatches
    }
    else { #check if not sysmon template
      $found = $_.TargetObject | Select-String -Pattern $t -AllMatches
    }
    if ($found) { $_ }
  }
  foreach ($k in $Patterns) {
    if (!($_.Details)) {
      $found = $_ | Select-String -Pattern $k -AllMatches }
    else {
      $found = $_.Details | Select-String -Pattern $k -AllMatches #else scan details
    } #check if not sysmon template
    if ($found) { $_ }
  }
}

filter MultiSelect-StringNetIOC ([string[]]$Patterns) {
  # Net share pipes
  foreach ($pipe in $Patterns) {
    $found = $_ | Select-String -Pattern $pipe -AllMatches
    if ($found) { $_ }
  }
}

filter MultiSelect-StringServiceIOC {
  # Service scan
  foreach ($name in $IOCMalServiceName) {
    $found = $_ | Select-String -Pattern $name -AllMatches
    if ($found) { $_ }
  }
  foreach ($path in $IOCMalServiceFileName) {
    $found = $_ | Select-String -Pattern $path -AllMatches
    if ($found) { $_ }
  }
}

Write-Warning ("Checking for suspicious events/IOCs (Sysmon #1, 12, 13 + WinEvents: 4688, 4698, 5007, 5140, 7045):")
if ($scanWinProcess) { $ioc_Process = Get-WinEvent -FilterHashtable $processFilter -ErrorAction SilentlyContinue | Select-Object TimeCreated,@{ Name = 'User'; expression = { $_.Properties[1].Value } },@{ Name = 'ParentProcessName'; expression = { $_.Properties[13].Value } },@{ Name = 'NewProcessName'; expression = { $_.Properties[5].Value } },@{ Name = 'CommandLine'; expression = { $_.Properties[8].Value } } | MultiSelect-StringIOCPatterns $IOCPatterns }
if ($scanWinProcess) { $ioc_SysmonProcess = Get-WinEvent -FilterHashtable $processSysmonFilter -ErrorAction SilentlyContinue | Select-Object TimeCreated,@{ Name = 'User'; expression = { $_.Properties[12].Value } },@{ Name = 'Image'; expression = { $_.Properties[4].Value } },@{ Name = 'CommandLine'; expression = { $_.Properties[10].Value } }, @{ Name = 'ParentImage'; expression = { $_.Properties[20].Value } }, @{ Name = 'ParentCommandLine'; expression = { $_.Properties[21].Value } } | MultiSelect-StringIOCPatterns $IOCPatterns }
if ($scanRegistry) { $ioc_Registry = Get-WinEvent -FilterHashtable $registryFilter -ErrorAction SilentlyContinue | Select-Object TimeCreated,@{ Name = 'User'; expression = { $_.Properties[1].Value } },@{ Name = 'ObjectName'; expression = { $_.Properties[4].Value } },@{ Name = 'ObjectValueName'; expression = { $_.Properties[5].Value } },@{ Name = 'OldValue'; expression = { $_.Properties[10].Value } },@{ Name = 'NewValue'; expression = { $_.Properties[11].Value } },@{ Name = 'ProcessName'; expression = { $_.Properties[13].Value } } | MultiSelect-StringRegIOC $TargetObject $IOCRegistry }
if ($scanRegistry) { $ioc_SysmonRegistry = Get-WinEvent -FilterHashtable $registrySysmonFilter -ErrorAction SilentlyContinue | Select-Object TimeCreated,@{ Name = 'User'; expression = { $_.Properties[8].Value } },@{ Name = 'EventType'; expression = { $_.Properties[1].Value } },@{ Name = 'Image'; expression = { $_.Properties[5].Value } },@{ Name = 'TargetObject'; expression = { $_.Properties[6].Value } },@{ Name = 'Details'; expression = { $_.Properties[7].Value } } | MultiSelect-StringRegIOC $TargetObject $IOCRegistry }
if ($scanWinAudit) { $ioc_AuditPolicy = Get-WinEvent -FilterHashtable $auditPolicyFilter -ErrorAction SilentlyContinue | Select-Object TimeCreated,Message | MultiSelect-StringIOCPatterns $IOCPatterns }
if ($scanWinTask) { $ioc_task = Get-WinEvent -FilterHashtable $taskFilter -ErrorAction SilentlyContinue | Select-Object TimeCreated,@{ Name = 'TaskName'; expression = { $_.Properties[4].Value } },@{ Name = 'TaskContent'; expression = { $_.Properties[5].Value } } | MultiSelect-StringIOCPatterns $IOCPatterns }
if ($scanWinAV) { $ioc_WinDef = Get-WinEvent -FilterHashtable $WinAvFilter -ErrorAction SilentlyContinue | Select-Object TimeCreated,Message | MultiSelect-StringIOCPatterns $IOCPatterns }
if ($scanWinPSLogs) { $ioc_WinPS = Get-WinEvent -FilterHashtable $winPSFilter -ErrorAction SilentlyContinue | Select-Object TimeCreated,@{ Name = 'Message'; expression = { $_.Properties[2].Value } } | MultiSelect-StringIOCPatterns $IOCPatterns }
if ($scanWinShare) { $ioc_NetShare = Get-WinEvent -FilterHashtable $netShareFilter -ErrorAction SilentlyContinue | Select-Object TimeCreated,@{ Name = 'User'; expression = { $_.Properties[1].Value } },@{ Name = 'Share Name'; expression = { $_.Properties[7].Value } },@{ Name = 'Share Path'; expression = { $_.Properties[8].Value } } | MultiSelect-StringNetIOC $IOCNetShare }
if ($scanWinShare) { $ioc_SysmomPipe = Get-WinEvent -FilterHashtable $pipeFilter -ErrorAction SilentlyContinue | Select-Object TimeCreated,@{ Name = 'User'; expression = { $_.Properties[7].Value } },@{ Name = 'Pipe Name'; expression = { $_.Properties[5].Value } },@{ Name = 'Image'; expression = { $_.Properties[6].Value } } | MultiSelect-StringNetIOC $IOCNetShare }
if ($scanWinService) { $ioc_Service = Get-WinEvent -FilterHashtable $serviceFilter -ErrorAction SilentlyContinue | Select-Object TimeCreated,@{ Name = 'ServiceName'; expression = { $_.Properties[0].Value } },@{ Name = 'ImagePath'; expression = { $_.Properties[1].Value } } | MultiSelect-StringServiceIOC }

#Base64 section
Write-Warning ("Checking for suspicious Base64 encoded events/IOCs:")

if ($scanBase64Process) { 
  $ioc_ProcessBase64 = ($ioc_Process | CommandLine-ConvertBase64String)
  $ioc_Sysmonprocessbase64 = ($ioc_SysmonProcess | CommandLine-ConvertBase64String)
}

if ($scanBase64Tasks) { 
  foreach ($task in $ioc_task) {
    $entry = [xml]$task.TaskContent
    if($entry.Task.Actions.Exec.Arguments.Length -lt 24) { continue }
    $ioc_taskbase64.Add(($entry.Task.Actions.Exec.Arguments | TaskContent-ConvertBase64String)) > $null
  }
}

if ($outputGrid) {
  if ($ioc_Process -ne '') { $ioc_Process | Out-GridView -Title 'IOCs EventID 4688/1102' }
  if ($ioc_SysmonProcess -ne '') { $ioc_SysmonProcess | Out-GridView -Title 'IOCs Sysmon 1' }
  if ($ioc_Registry -ne '') { $ioc_Registry | Out-GridView -Title 'IOCs Registry EventID 4657' }
  if ($ioc_SysmonRegistry -ne '') { $ioc_SysmonRegistry | Out-GridView -Title 'IOCs Sysmon 12,13' }
  if ($ioc_AuditPolicy -ne '') { $ioc_AuditPolicy | Out-GridView -Title 'IOCs EventID 4719' }
  if ($ioc_task -ne '') { $ioc_task | Out-GridView -Title 'IOCs EventID 4698' }
  if ($ioc_WinDef -ne '') { $ioc_WinDef | Out-GridView -Title 'WinAv IOCs EventID 5007, 1116' }
  if ($ioc_WinPS -ne '') { $ioc_WinPS | Out-GridView -Title 'Win Powershell IOCs EventID 4104' }
  if ($ioc_NetShare -ne '') { $ioc_NetShare | Out-GridView -Title 'Win network share IOCs EventID 5140' }
  if ($ioc_SysmomPipe -ne '') { $ioc_SysmomPipe | Out-GridView -Title 'Sysmon Event 17' }
  if ($ioc_Service -ne '') { $ioc_Service | Out-GridView -Title 'Services IOCs EventID 7045' }
  if ($ioc_ProcessBase64 -ne '') { $ioc_ProcessBase64 | Out-GridView -Title 'Base64 IOCs EventID 4688' }
  if ($ioc_Sysmonprocessbase64 -ne '') { $ioc_Sysmonprocessbase64 | Out-GridView -Title 'Base64 IOCs Sysmon 1' }
  if ($ioc_taskbase64 -ne '') { $ioc_taskbase64 | Out-GridView -Title 'Base64 IOCs EventID 4698' }
}

if ($saveToFile) {
  $CurrentPath = Get-Location
  $folderName = "$CurrentPath\wIOC-$env:computername-$datestring"
  mkdir -Force $folderName | Out-Null
  if ($ioc_Process -ne '') { $ioc_Process | Select-Object * | Out-File -Append -FilePath "$folderName\4688Process.txt" }
  if ($ioc_SysmonProcess -ne '') { $ioc_SysmonProcess | Select-Object * | Out-File -Append -FilePath "$folderName\1Sysmon.txt" }
  if ($ioc_Registry -ne '') { $ioc_Registry | Select-Object * | Out-File -Append -FilePath "$folderName\4657Registry.txt" }
  if ($ioc_SysmonRegistry -ne '') { $ioc_SysmonRegistry | Select-Object * | Out-File -Append -FilePath "$folderName\1213Sysmon.txt" }
  if ($ioc_AuditPolicy -ne '') { $ioc_AuditPolicy | Select-Object -ExpandProperty Message | Out-File -Append -FilePath "$folderName\4719Audit.txt" }
  if ($ioc_task -ne '') { $ioc_task | Select-Object -ExpandProperty TaskContent | Out-File -Append -FilePath "$folderName\4698Task.txt" }
  if ($ioc_WinPS -ne '') { $ioc_WinPS | Out-File -Append -FilePath "$folderName\4104PS.txt" }
  if ($ioc_WinDef -ne '') { $ioc_WinDef | Select-Object -ExpandProperty Message | Out-File -Append -FilePath "$folderName\5001WinDef.txt" }
  if ($ioc_NetShare -ne '') { $ioc_NetShare | Out-File -Append -FilePath "$folderName\5140NetShare.txt" }
  if ($ioc_SysmomPipe -ne '') { $ioc_SysmomPipe | Out-File -Append -FilePath "$folderName\17SysmonPipe.txt" }
  if ($ioc_Service -ne '') { $ioc_Service | Out-File -Append -FilePath "$folderName\7045Services.txt" }
  if ($ioc_ProcessBase64 -ne '') { $ioc_ProcessBase64 | Out-File -Append -FilePath "$folderName\FoundBase64Process.txt" }
  if ($ioc_Sysmonprocessbase64 -ne '') { $ioc_Sysmonprocessbase64 | Out-File -Append -FilePath "$folderName\FoundBase64Sysmon.txt" }
  if ($ioc_taskbase64 -ne '') { $ioc_taskbase64 | Out-File -Append -FilePath "$folderName\FoundBase64Task.txt" }
}