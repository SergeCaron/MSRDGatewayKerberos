##******************************************************************
## Revision date: 2025.12.19
##
##		2025.12.19: Proof of concept / Initial release
##
## Copyright (c) 2025 PC-Évolution enr.
## This code is licensed under the GNU General Public License (GPL).
##
## THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
## ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
## IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
## PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
##
##******************************************************************
#
#
Write-Host
Write-Host -ForegroundColor Green "This script made possible with the kind assistance of VPHAN"
Write-Host -ForegroundColor Green "You can follow development here : https://learn.microsoft.com/en-us/answers/questions/5649813/"
Write-Host

$Realm = Read-Host "Please enter the remote Active Directory domain name (not the NetBIOS domain name)"
$KdcFQDN =  Read-Host "Please enter the fully qualified domain name (FQDN) of the Remote Desktop Gateway"

### Make sure proper case is used in these namespaces

$KdcFQDN = $KdcFQDN.ToLOWER()
$Realm = $Realm.ToUPPER()

### Warn if IIS is not reachable on $KdcFQDN
If ( -Not $(Test-NetConnection -ComputerName $KdcFQDN -Port 443) ) {
	Write-Warning "HTTPS is not enabled on $KdcFQDN"
}

### Location of Kerberos keys
$KerberosLSA = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\Kerberos"
$KerberosPolicies = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"

### Delete this realm and dump actual configuration

ksetup /DelHostToRealmMap ".$Realm" "$Realm"	# /RemoveRealm will not remove duplicate mappings
ksetup /RemoveRealm $Realm

ksetup /DumpState

## Host to Realm

	ksetup /AddHostToRealmMap ".$Realm" "$Realm"

	If ( (Get-ItemProperty -Path "$KerberosLSA\HostToRealm\$Realm").SpnMappings.Count -eq 2 ) {
		If ( ((Get-ItemProperty -Path "$KerberosLSA\HostToRealm\$Realm").SpnMappings[0] -ceq ".$Realm") `
				-and ("" -eq (Get-ItemProperty -Path "$KerberosLSA\HostToRealm\$Realm").SpnMappings[1] ) ) {
				Write-Host "Standard mapping for $Realm"
		} else { Write-Warning "Registy entries for $Realm mapping not managed by ksetup" }
	} else { Write-Warning "More than one mapping defined for $Realm" }

### KDC

	ksetup /addkdc "$Realm" $KdcFQDN

	If ( (Get-ItemProperty -Path "$KerberosLSA\Domains\$Realm").KdcNames.Count -eq 2 ) {
		If ( ((Get-ItemProperty -Path "$KerberosLSA\Domains\$Realm").KdcNames[0] -ceq $KdcFQDN) `
				-and ("" -eq (Get-ItemProperty -Path "$KerberosLSA\Domains\$Realm").KdcNames[1]) ) {
				Write-Host "Standard KDC setup for $Realm"
		} else { Write-Warning "Registy entries for $Realm KDC not managed by ksetup" }
	} else { Write-Warning "More than one KDC defined for $Realm" }

### Encryption Types

	$EncTypes = ksetup /Domain $Realm /SetEncTypeAttr AES-256-CTS-HMAC-SHA1-96 AES-128-CTS-HMAC-SHA1-96

	Try { Get-ItemProperty -Path "$KerberosLSA\Domains\$Realm" -Name SupportedEncryptionTypes -ErrorAction Stop  | `
				Select-Object -ExpandProperty SupportedEncryptionTypes | Format-Table
	}
	Catch {	Write-Warning "ksetup failed to create encryption attributes for $Realm"
			New-ItemProperty -Path "$KerberosLSA\Domains\$Realm" -Name "SupportedEncryptionTypes" -PropertyType DWORD -Value 24 -Force | `
				Select-Object SupportedEncryptionTypes | Format-Table -HideTableHeaders
	}
	
	If ( (Get-ItemProperty -Path "$KerberosLSA\Domains\$Realm").SupportedEncryptionTypes -ne `
			(Get-ItemProperty -Path "$KerberosPolicies").SupportedEncryptionTypes ) {
				Write-Warning "Encryption types for $Realm do not match default Kerberos policies for this computer."
			}

### LogLevel

	Write-Host "Kerberos Log Level", (Get-ItemProperty -Path "$KerberosLSA\Parameters").LogLevel

### Final configuration

ksetup /DumpState
