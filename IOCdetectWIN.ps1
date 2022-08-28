<#
.SYNOPSIS
Common IOC Powershell Detection Script
.DESCRIPTION
Uses known Log4JShell IOC strings and common exploit patterns in APTs to find signs of compromise on a windows machine. Script will quickly check for obfuscation and Base64 encoding.
The script will search through the following event viewer logs:
(Audit Process Creation logging) Audit event 4688
(Audit Other Object Access Events) Audit event 4698
(AD FS/Admin RequestReceivedSuccessAudit) Audit event 403
REQUIRES POWERSHELL MODULE Get-Base64RegularExpression DOWNLOAD @ https://www.leeholmes.com/searching-for-content-in-base-64-strings/
.EXAMPLE
PS> . .\IOCdetectWIN.ps1
Run the script with default settings
.NOTES
.Author: James Kelly
https://gmuisg.org
#>

#///////////////////////////////////////////////////////////////////////////////////////////////////
# *** THIS MODULE IS REQUIRED FOR SCRIPT TO RUN ***
# Get-Base64RegularExpression https://www.leeholmes.com/searching-for-content-in-base-64-strings/
# Type in powershell Install-Script Get-Base64RegularExpression.ps1
# *** THIS MODULE IS REQUIRED FOR SCRIPT TO RUN ***
#///////////////////////////////////////////////////////////////////////////////////////////////////

# REQUIRES Audit Process Creation logging. Audit event 4688(S): "A new process has been created"
# REQUIRES Audit Other Object Access Events. Audit event 4698(S): "This policy setting allows you to audit events generated by the management of task scheduler jobs or COM+ objects."
# https://www.lansweeper.com/report/log4j-event-log-audit/
# Got the idea from https://github.com/Neo23x0/log4shell-detector
# You can add IOC patterns as the obfuscation of the reverse shells get tougher and more sophisticated

$datestring = (Get-Date).ToString('s').Replace(':','-')
$savedir = 'C:\ioc_Scan_' + $datestring + '.txt'
$savedir2 = 'C:\ioc_ScanBase64_' + $datestring + '.txt'

$outputGrid = 'True'
$saveToFile = 'False'
$scanADFSLogs = 'False' #Enable this if you need it


$processfilter = @{
  LogName = 'Security'
  ID = 4688 #New process eventID
  StartTime = [datetime]::Now.AddHours(-24) #How far to look back in logs
}

$taskfilter = @{
  LogName = 'Security'
  ID = 4698 #New ScheduledTasks
  StartTime = [datetime]::Now.AddHours(-24) #How far to look back in logs
}

$winavfilter = @{
	LogName = 'Microsoft-Windows-Windows Defender/Operational'
	ID = 5007 #Defender modifications
	StartTime = [datetime]::Now.AddHours(-24)
}

$adfsfilter = @{
  LogName = 'AD FS/Admin'
  ID = 403 #RequestReceivedSuccessAudit
  StartTime = [datetime]::Now.AddHours(-24) #How far to look back in logs
}

$IOCPatterns = ('jndi:ldap:',
  'jndi:rmi:/',
  'jndi:ldaps:/',
  'jndi:dns:/',
  'jndi:nis:/',
  'jndi:nds:/',
  'jndi:corba:/',
  'jndi:iiop:/',
  'jndi.LDAPRefServer',
  'jndi:ldap://',
  'env:BARFOO:-j',
  'env:BARFOO:-:',
  'env:BARFOO:-l',
  'env:BARFOO:-:',
  'jndi',
  'jndi:ld',
  'ldap:/',
  'jndi:ldap://127.0.0.1:1099',
  '{date:j}${date:n}${date:d}${date:i}:${date:l}${date:d}${date:a}${date:p}',
  '/Basic/Command/Base64',
  'at java.naming/com.sun.jndi.url.ldap.ldapURLContext.lookup',
  'log4j.core.lookup.JndiLookup.lookup',
  'Reference Class Name: foo',
  'base64:',
  '<Hidden>true</Hidden>',#Next 40 strings are common in APTs in schtasks/new process creation on infected machines
  '-WindowStyle Hidden',
  'powershell/w 01',
  'powershell/w 01 /ep 0/nop/c',
  'powershell.exe -exec bypass',
  'powershell -c iex',
  'powershell -c iwr',
  '[Reflection.Assembly]::Load',
  'Add-MpPreference -ExclusionPath',
  'Add-MpPreference -ExclusionExtension',
  'Add-MpPreference -ExclusionProcess',
  'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions',
  'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring',
  'IEX (New-Object Net.WebClient).DownloadString',
  '-NonInteractive',
  '-NoLogo',
  '-ExecutionPolicy bypass',
  '-encodedcommand',
  '-enc',
  'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp',
  '\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
  'base64_encode',
  'base64_decode',
  'cmd.exe /c',
  'cmd.exe /Q /c start',
  'Scriptrunner.exe',
  'Cscript.exe',
  'WScript.exe',
  'regsvr32.exe',
  'wmic process call create',
  'Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log',
  'Get-WinEvent -ListLog * -Force | % { Wevtutil.exe cl $_.LogName }',
  'Clear-EventLog',
  '[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog',
  'wevtutil.exe cl',
  'vssadmin.exe Delete Shadows /All /Quiet',
  'bitsadmin.exe',
  'bitsadmin /SetNotifyCmdLine',
  'bitsadmin /addfile',
  'bitsadmin /transfer',
  'Start-BitsTransfer -Source',
  'VBscript.Encode',
  'WScript.Shell',
  'WScriptShell.CreateShortcut',
  'WScriptShell.SpecialFolders',
  'msdt.exe',
  'PCWDiagnostic',
  'ms-msdt:-id',
  'ms-msdt:/id',
  'ms-msdt:/id PCWDiagnostic /skip force /param')

$temp = ''
$log4j_processtemp = ''
$log4j_adtemp = ''
$ioc_winav = ''
$ioc_task = ''
$ioc_base64 = ''
$log4j_base64 = ''
$log4j_base64ad = ''

$Width = -1 * ((Measure-Object -Maximum length).maximum + 1)

filter MultiSelect-String ([string[]]$Patterns) {
  if ($_ -match '}$' -and ($_ -match "lower" -or $_ -match "upper")) {
    $obfusCheck = $_.Split('}$').Split(':')
  } elseif ($_ -match '}$') {
    $obfusCheck = $_.Split('}$').Split('-')
  }
  $obfusString = ""
  for ($i = 0; $i -lt $obfusCheck.Length; $i++) {
    if ($obfusCheck[$i].Length -ne 1) {
      continue
    }
    $obfusString += -join ($obfusCheck[$i])
  }
  foreach ($Pattern in $Patterns) {
    if ($_ | Select-String 'Task Name') { $temp = $_ } #filter ScheduledTasks and save name
    if ($_ | Select-String -AllMatches -Pattern $Pattern) {
      if ($temp -ne "") { $temp } #skip SchTask
      $_ #We found a match!
      $temp = ''
    } elseif ($obfusString | Select-String -AllMatches -Pattern $Pattern) { #check if hidden strings
      Write-Warning ("*OBFUSCATION FOUND* Matched: {0,$Width} {1}" -f $Pattern,$obfusString)
    } else {
      continue
    }
  }
}
filter MultiSelect-Base64String ([string[]]$Patterns) {
  # Check the current item against all patterns.
  foreach ($Pattern in $Patterns) {
    # If one of the patterns does not match, continue checking same item.
    $regex = (Get-Base64RegularExpression $Pattern)
    if ($_ | Select-String -AllMatches -Pattern $regex) {
      $_ #We found a match!
      Write-Warning ("*BASE64 FOUND* Matched: {0,$Width} {1}" -f $Pattern,$_)
    } else { #Keep scanning
      continue
    }
  }
}

Write-Warning ("Checking for suspicious log4j events/IOCs (EventID 4688, EventID 4698, ADFS 403):")
$log4j_processtemp = Get-WinEvent -FilterHashtable $processfilter -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Message | MultiSelect-String $IOCPatterns
$ioc_task = Get-WinEvent -FilterHashtable $taskfilter -ErrorAction SilentlyContinue | Select-Object -Property * | Out-String -Stream | Select-String -Pattern 'Task Name','<Hidden>','<Command>','<Arguments>' | MultiSelect-String $IOCPatterns
$winav = Get-WinEvent -FilterHashtable $winavfilter -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Message | MultiSelect-String $IOCPatterns
if ($scanADFSLogs -eq 'True') { $log4j_adtemp = Get-WinEvent -FilterHashtable $adfsfilter -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Message | MultiSelect-String $IOCPatterns }

Write-Warning ("Checking for suspicious Base64 encoded log4j events/IOCs:")
$log4j_base64 = Get-WinEvent -FilterHashtable $processfilter -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Message | MultiSelect-Base64String $IOCPatterns
if ($scanADFSLogs -eq 'True') {$log4j_base64ad = Get-WinEvent -FilterHashtable $adfsfilter -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Message | MultiSelect-Base64String $IOCPatterns }
$ioc_base64 = Get-WinEvent -FilterHashtable $taskfilter -ErrorAction SilentlyContinue | Select-Object -Property * | Out-String -Stream | Select-String -Pattern 'Task Name','<Hidden>','<Command>','<Arguments>' | MultiSelect-Base64String $IOCPatterns

if ($outputGrid -eq 'True') {
  if ($log4j_processtemp -ne '') { $log4j_processtemp | Out-GridView -Title 'IOCs EventID 4688' }
  if ($log4j_adtemp -ne '') { $log4j_adtemp | Out-GridView -Title 'IOCs ADFS 403' }
  if ($ioc_task -ne '') { $ioc_task | Out-GridView -Title 'IOCs EventID 4698' }
  if ($winav -ne '') { $winav | Out-GridView -Title 'WinAv IOCs EventID 5007' }
  if ($log4j_base64 -ne '') { $log4j_base64 | Out-GridView -Title 'Base64 IOCs EventID 4688' }
  if ($ioc_base64 -ne '') { $ioc_base64 | Out-GridView -Title 'Base64 IOCs EventID 4698' }
  if ($log4j_base64ad -ne '') { $log4j_base64ad | Out-GridView -Title 'Base64 IOCs ADFS 403' }
}

if ($saveToFile -eq 'True') {
  if ($log4j_processtemp -ne '') { $log4j_processtemp | Out-File -Append -FilePath $savedir }
  if ($log4j_adtemp -ne '') { $log4j_adtemp | Out-File -Append -FilePath $savedir }
  if ($ioc_task -ne '') { $ioc_task | Out-File -Append -FilePath $savedir }
  if ($winav -ne '') { $winav | Out-File -Append -FilePath $savedir }
  if ($log4j_base64 -ne '') { $log4j_base64 | Out-File -Append -FilePath $savedir2 }
  if ($ioc_base64 -ne '') { $ioc_base64 | Out-File -Append -FilePath $savedir2 }
  if ($log4j_base64ad -ne '') { $log4j_base64ad | Out-File -Append -FilePath $savedir2 }
}
