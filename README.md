# win-ioc-detect
Powershell IOC Exploit detection
https://gmuisg.org/log4j-detect/
## Table of contents
* [General info](#general-info)
* [Getting started](#getting-started)
* [Usage](#usage)

## General info
The script scans Windows event viewer logs for indicators of exploitation attempts using Powershell's Get-WinEvent command (such as new process creation, new scheduled tasks, WinAV, Audit policy, and WinPS). The script will decode single staged obfuscated Base64 wrappers. 

TL;DR the script will search common event viewer logs for exploitation attempts on machine or scan a local .evtx file.

![snip1](https://github.com/jake-k-38/win-ioc-detect/blob/main/images/screenshot_2.PNG?raw=true)
	
## Getting started
Users may need to change the default PowerShell execution policy. This can be achieved in a number of different ways:<br />

Open a command prompt and run ```powershell.exe -ExecutionPolicy Unrestricted``` and run scripts from that PowerShell session.<br />
Open a PowerShell prompt and run ```Set-ExecutionPolicy Unrestricted -Scope Process``` and run scripts from the current PowerShell session.<br />
Open an administrative PowerShell prompt and run ```Set-ExecutionPolicy Unrestricted``` and run scripts from any PowerShell session.<br />

Keep in mind the script requires certain security audit logging enabled to function and extract suspicious activity!!<br />

<b>REQUIRES Audit Process Creation logging. Audit event 4688(S): "A new process has been created"<br />
Configure/Enable the following: "Administrative Templates\System\Audit Process Creation" 'Include command line in process creation events'<br />
Optional Audit Policy Change. Audit event 4719 : "If Success auditing is enabled, an audit entry is generated when an attempted change to user rights assignment policy, audit policy, or trust policy is successful."<br />
Optional Object access - Audit Registry "A registry value was modified". Audit event 4657 : Once enabled, please set SACL auditing permissions for keys you want to monitor - https://github.com/jake-k-38/Win-SACL-ObjectAccess<br />
Optional Turn on PowerShell Script Block Logging - This policy setting enables logging of all # PowerShell script input to the Microsoft-Windows-PowerShell/Operational event log Windows #PowerShell will log the processing of commands, script blocks, functions, and scripts - whether # invoked interactively, or through automation.<br />
Optional Turn on Audit Net Share access 5140 - Network share object was accessed check for files being remotely accessed.<br />

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

To-Do add Sysmon support in addition, with default audit policy
