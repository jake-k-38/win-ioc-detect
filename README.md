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
Keep in mind the script requires certain security audit logging enabled to function and extract suspicious activity!!<br />

<b>REQUIRES Audit Process Creation logging. Audit event 4688(S): "A new process has been created"<br />
Configure/Enable the following: "Administrative Templates\System\Audit Process Creation" 'Include command line in process creation events'<br />
REQUIRES PowerShell Script Block Logging Audit event 4104(S): "Verbose; Microsoft-Windows-PowerShell/Operational"<br />
REQUIRES Audit Other Object Access Events. Audit event 4698(S): "This policy setting allows you to audit events generated by the management of task scheduler"</b><br />

## Usage
Simply just run the script win-ioc-detect.ps1 to scan live system logs- or scan a .evtx file

```
.\win-ioc-detect
```
```
.\win-ioc-detect <path of .evtx>
```
## Notes

Got the ideas from
https://github.com/Neo23x0/log4shell-detector<br>
https://github.com/sans-blue-team/DeepBlueCLI<br>
https://github.com/CrowdStrike/Forensics<br>
https://github.com/dfirale/evtscanner

To-Do add Sysmon support in addition, with default audit policy
