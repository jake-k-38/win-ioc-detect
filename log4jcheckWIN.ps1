$IOCPatterns = ('jndi:ldap:',
 'jndi:rmi:/',
 'jndi:ldaps:/',
 'jndi:dns:/',
 'jndi:nis:/',
 'jndi:nds:/',
 'jndi:corba:/',
 'jndi:iiop:/',
 'jndi:http:/',
 'log4j',
 'jndi.LDAPRefServer',
 'jndi:ldap://',
 'env:BARFOO:-j',
 'env:BARFOO:-:',
 'env:BARFOO:-l',
 'env:BARFOO:-:',
 'jndi',
 'jndi:ld',
 'jndi:ldap://127.0.0.1:1099/obj',
 'at java.naming/com.sun.jndi.url.ldap.ldapURLContext.lookup',
 'log4j.core.lookup.JndiLookup.lookup',
 'Reference Class Name: foo',
 'base64:')
 
 $log4j_temp = ''
 $log4j_adtemp = ''
 $log4j_base64 = ''
 $log4j_base64ad = ''
 $datestring = (Get-Date).ToString('s').Replace(':','-') 
 
 $saveToFile = 'True'
 $savedir = 'C:\sus_log4jScan_' + $datestring + '.txt' 
 $savedir2 = 'C:\sus_log4jScanBase64_' + $datestring + '.txt'
 
#///////////////////////////////////////////////////////////////////////////////////////////////////
# *** THIS MODULE IS REQUIRED FOR SCRIPT TO RUN ***
# Get-Base64RegularExpression https://www.leeholmes.com/searching-for-content-in-base-64-strings/
# Type in powershell Install-Script Get-Base64RegularExpression.ps1
# *** THIS MODULE IS REQUIRED FOR SCRIPT TO RUN ***
#///////////////////////////////////////////////////////////////////////////////////////////////////
# REQUIRES Audit Process Creation logging. By enabling this, in addition to enabling the scanning of success audit events, you'll be able to scan and audit event 4688(S): A new process has been created
# https://www.lansweeper.com/report/log4j-event-log-audit/
# Got the idea from https://github.com/Neo23x0/log4shell-detector
# You can add IOC patterns as the obfuscation of the reverse shells get tougher and more sophisticated

$filter = @{
  LogName = 'Security'
  ID = 4688 #New process eventID
  StartTime = [datetime]::Now.AddHours(-24) #How far to look back in logs
}

$adfsfilter = @{ 
  LogName = 'AD FS Auditing'
  ID = 403 #RequestReceivedSuccessAudit
  StartTime = [datetime]::Now.AddHours(-24) #How far to look back in logs
}

$Width = -1 * ((measure-object -maximum length).maximum + 1)

filter MultiSelect-String( [string[]]$Patterns ) {
  if($_ -match "lower" -Or $_ -match "upper"){
	  $obfusCheck = $_.Split('}$').Split(':')
  }else{
	  $obfusCheck = $_.Split('}$').Split('-')
  }
  $obfusString = ""
  for($i = 0; $i -lt $obfusCheck.Length; $i++){
	  if($obfusCheck[$i].Length -ne 1){
		  continue
	  }
	  $obfusString += -join($obfusCheck[$i])
  }
  foreach( $Pattern in $Patterns ) {
    # If one of the patterns does not match, continue checking same item.
	if($_ | Select-String -AllMatches -Pattern $Pattern){
		$_ #We found a match!
	}elseif($obfusString | Select-String -AllMatches -Pattern $Pattern){ #check if hidden strings
		Write-Warning("*OBFUSCATION FOUND* Matched: {0,$Width} {1}" -f $Pattern, $obfusString) 
		"*OBFUSCATION FOUND* Matched: {0,$Width} {1}" -f $Pattern, $obfusString | out-file -Append -FilePath $savedir
	}else{
		continue
	}
  }
}
filter MultiSelect-Base64String( [string[]]$Patterns ) {
  # Check the current item against all patterns.
  foreach( $Pattern in $Patterns ) {
    # If one of the patterns does not match, continue checking same item.
	$regex = (Get-Base64RegularExpression $Pattern)
	if($_ | Select-String -AllMatches -Pattern $regex){
		$_ #We found a match!
		write-warning ("*BASE64 FOUND* Matched: {0,$Width} {1}" -f $Pattern, $_)
		"*BASE64 FOUND* Matched: {0,$Width} {1}" -f $Pattern, $_ | out-file -Append -FilePath $savedir2
	}else{ #Keep scanning
		continue
	}
  }
}

Write-Warning("Checking for suspicious log4j events (EventID 4688, ADFS 403):")
$log4j_temp = Get-WinEvent -FilterHashtable $filter | Select-Object -ExpandProperty Message | MultiSelect-String $IOCPatterns
$log4j_adtemp = Get-WinEvent -FilterHashtable $adfsfilterfilter | Select-Object -ExpandProperty Message | MultiSelect-String $IOCPatterns
Write-Output($log4j_temp)
Write-Output($log4j_adtemp)

Write-Warning("Checking for suspicious Base64 encoded log4j events:")
$log4j_base64 = Get-WinEvent -FilterHashtable $filter | Select-Object -ExpandProperty Message | MultiSelect-Base64String $IOCPatterns
$log4j_base64ad = Get-WinEvent -FilterHashtable $filter | Select-Object -ExpandProperty Message | MultiSelect-Base64String $IOCPatterns


if($saveToFile){
	$log4j_temp | out-file -Append -FilePath $savedir
	$log4j_adtemp | out-file -Append -FilePath $savedir
	$log4j_base64 | out-file -Append -FilePath $savedir2
	$log4j_base64ad | out-file -Append -FilePath $savedir2
}
