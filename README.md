# win-log4j-detect
Powershell Log4j Exploit detection
https://gmuisg.org/log4j-detect/


# *** THIS MODULE IS REQUIRED FOR SCRIPT TO RUN ***
# Get-Base64RegularExpression https://www.leeholmes.com/searching-for-content-in-base-64-strings/
# Type in powershell Install-Script Get-Base64RegularExpression.ps1
# Open powershell as administrator and type set-executionpolicy remotesigned in order to run
# *** THIS MODULE IS REQUIRED FOR SCRIPT TO RUN ***

# REQUIRES Audit Process Creation logging. By enabling this, in addition to enabling the scanning of success audit events, you'll be able to scan and audit event 4688(S): A new process has been created
# https://www.lansweeper.com/report/log4j-event-log-audit/
# Got the idea from https://github.com/Neo23x0/log4shell-detector
# You can add IOC patterns as the obfuscation of the reverse shells get tougher and more sophisticated


Changelog: 12-15-2021 Added output saving to C directory, improved detection with obfuscation by splitting string at
‘}$’ and ‘:’ to detect obfuscation with {[upper|lower]:x} and {::-n}
