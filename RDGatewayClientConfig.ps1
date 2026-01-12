##******************************************************************
## Revision date: 2026.01.12
##
##		2025.12.19: Proof of concept / Initial release
##		2026.01.02:	Exit if not running in an elevated command prompt
##		2026.01.06: Use proper location for Kerberos policies
##		2026.01.11:	Allow removal of realm
##		2026.01.12:	Warn if creating realm using the domain name
##					Display current user authentication
##
## Copyright (c) 2026 PC-Évolution enr.
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

# Get the ID and security principal of the current user account
$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($myWindowsID)

# Get the security principal for the administrator role
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

# Check to see if we are currently running as an administrator
if (!$myWindowsPrincipal.IsInRole($adminRole)) {
	Write-Host -ForegroundColor Red "Administrative privileges are required to run this script."
	Write-Host
	exit 911
}

### Display current user authentication 
$Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
Write-Host "You are currently using $($Identity.AuthenticationType) to authenticate."
if ( $Identity.IsAuthenticated ) { Write-Host "You are authenticated as $($Identity.Name)." }
Write-Host

### Get the Realm and the Remote Desktop Gateway (with a minimum level of validation)
$Realm = Read-Host "Please enter the remote Active Directory domain name (not the NetBIOS domain name)"
$Realm = $Realm.ToUPPER()	# Realms are uppercase

# Delete existing mapping and dump actual configuration
if ( -not [string]::IsNullOrEmpty($(ksetup /DumpState | Select-String -Pattern "$Realm`:")) ) {
	ksetup /DelHostToRealmMap ".$Realm" "$Realm"	# /RemoveRealm will not remove duplicate mappings
	ksetup /RemoveRealm $Realm
	Write-Warning "Realm $Realm removed from Kerberos configuration."
}
ksetup /DumpState

### Try to avoid creating a realm for the currently joined Domain
if ( $Realm -eq $(Get-WmiObject -Class Win32_ComputerSystem).Domain.ToUpper() ) {
	If ($(Read-Host "This configuration will introduce long delays to login. Enter 'Yes' to abort, anything else to continue").tolower().StartsWith('yes')) `
	{ exit 911 }

}

# Issue warnings for unreachable hosts
$KdcFQDN = Read-Host "Please enter the fully qualified domain name (FQDN) of the Remote Desktop Gateway (^C to exit)"
$KdcConnection = Test-NetConnection -ComputerName $KdcFQDN -Port 443 -ErrorAction SilentlyContinue
 

### Make sure proper case is used in these namespaces

$KdcFQDN = $KdcFQDN.ToLOWER()

### Warn if IIS is not reachable on $KdcFQDN
if ( -not $(Test-NetConnection -ComputerName $KdcFQDN -Port 443) ) {
	Write-Warning "HTTPS is not enabled on $KdcFQDN"
}

### Location of Kerberos keys
$KerberosLSA = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\Kerberos"
$KerberosPolicies = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"

### Delete this realm and dump actual configuration


## Host to Realm

ksetup /AddHostToRealmMap ".$Realm" "$Realm"

if ( (Get-ItemProperty -Path "$KerberosLSA\HostToRealm\$Realm").SpnMappings.Count -eq 2 ) {
	if ( ((Get-ItemProperty -Path "$KerberosLSA\HostToRealm\$Realm").SpnMappings[0] -ceq ".$Realm") `
			-and ("" -eq (Get-ItemProperty -Path "$KerberosLSA\HostToRealm\$Realm").SpnMappings[1] ) ) {
		Write-Host "Standard mapping for $Realm"
	}
 else { Write-Warning "Registy entries for $Realm mapping not managed by ksetup" }
}
else { Write-Warning "More than one mapping defined for $Realm" }

### KDC

ksetup /addkdc "$Realm" $KdcFQDN

if ( (Get-ItemProperty -Path "$KerberosLSA\Domains\$Realm").KdcNames.Count -eq 2 ) {
	if ( ((Get-ItemProperty -Path "$KerberosLSA\Domains\$Realm").KdcNames[0] -ceq $KdcFQDN) `
			-and ("" -eq (Get-ItemProperty -Path "$KerberosLSA\Domains\$Realm").KdcNames[1]) ) {
		Write-Host "Standard KDC setup for $Realm"
	}
 else { Write-Warning "Registy entries for $Realm KDC not managed by ksetup" }
}
else { Write-Warning "More than one KDC defined for $Realm" }

### Encryption Types

$EncTypes = ksetup /Domain $Realm /SetEncTypeAttr AES-256-CTS-HMAC-SHA1-96 AES-128-CTS-HMAC-SHA1-96

try {
 Get-ItemProperty -Path "$KerberosLSA\Domains\$Realm" -Name SupportedEncryptionTypes -ErrorAction Stop | `
			Select-Object -ExpandProperty SupportedEncryptionTypes | Format-Table
}
catch {
	Write-Warning "ksetup failed to create encryption attributes for $Realm"
	New-ItemProperty -Path "$KerberosLSA\Domains\$Realm" -Name "SupportedEncryptionTypes" -PropertyType DWORD -Value 24 -Force | `
			Select-Object SupportedEncryptionTypes | Format-Table -HideTableHeaders
}
	
if ( (Get-ItemProperty -Path "$KerberosLSA\Domains\$Realm").SupportedEncryptionTypes -ne `
	(Get-ItemProperty -Path "$KerberosPolicies" -ErrorAction SilentlyContinue).SupportedEncryptionTypes ) {
	Write-Warning "Encryption types for $Realm do not match default Kerberos policies for this computer."
}

### LogLevel

Write-Host "Kerberos Log Level", (Get-ItemProperty -Path "$KerberosLSA\Parameters").LogLevel

### Final configuration

ksetup /DumpState
