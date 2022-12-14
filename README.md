# win-ioc-detect
Powershell IOC Exploit detection
## Table of contents
* [General info](#general-info)
* [Getting started](#getting-started)
* [Usage](#usage)

## General info
The script scans Windows event viewer logs for indicators of exploitation attempts using Powershell's Get-WinEvent command (such as new process creation, new scheduled tasks, WinAV, Audit policy, and WinPS). The script will decode single staged obfuscated Base64 commands. 

TL;DR the script will search common event viewer logs for exploitation attempts on machine or scan a local .evtx file.

![snip1](https://github.com/jake-k-38/win-ioc-detect/blob/main/images/screenshot_2.PNG?raw=true)
	
## Getting started
Users may need to change the default PowerShell execution policy. This can be achieved in a number of different ways:<br />

Open a command prompt and run ```powershell.exe -ExecutionPolicy Unrestricted``` and run scripts from that PowerShell session.<br />
Open a PowerShell prompt and run ```Set-ExecutionPolicy Unrestricted -Scope Process``` and run scripts from the current PowerShell session.<br />
Open an administrative PowerShell prompt and run ```Set-ExecutionPolicy Unrestricted``` and run scripts from any PowerShell session.<br />

Keep in mind the script requires certain security audit logging enabled to function and extract suspicious activity!!<br />

<b>REQUIRES Audit Process Creation logging. Audit event 4688(S): "A new process has been created"</b><br />
Configure/Enable the following: "Administrative Templates\System\Audit Process Creation" 'Include command line in process creation events'<br />
<b>RECOMMENDED Sysmon installed. Audit event 1,12,13,17 etc</b><br />

<b>OPTIONAL LOGGING CONFIG</b><br />
<ul>
<li>Audit Other Object Access Events. Audit event 4698(S)</li>
<li>Object access - Audit Registry "A registry value was modified". Audit event 4657 2</li>
<li>Turn on PowerShell Script Block Logging 4104</li>
<li>Turn on Detailed Audit Net Share access 5140</li>
</ul>

## Usage
Simply just run the script win-ioc-detect.ps1 to scan live system logs- or scan a .evtx file

```
.\win-ioc-detect
```
```
.\win-ioc-detect <path of .evtx>
```
## Notes

Got the idea from https://github.com/Neo23x0/log4shell-detector
https://github.com/sans-blue-team/DeepBlueCLI
https://github.com/CrowdStrike/Forensics

To-Do add Automation support via Syslog, improve local logging option
