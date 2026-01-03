##******************************************************************
## Revision date: 2026.01.03
##
## Copyright (c) 2020-2026 PC-Évolution enr.
## This code is licensed under the GNU General Public License (GPL).
##
## THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
## ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
## IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
## PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
##
##******************************************************************

# Certify The Web Deployment Script for Windows Server 20xx (Your Mileage May Vary ;-)

# Restart the "Network Policy Server", the SSTP protocol and the Terminal Server: all dependent services 
# are stopped and started in the exact reverse order they were stopped.

# Note: the Write-Warning is used so that messages will appear in the Certify The Web log file.

param($result)

# It is presumed that this task runs after the "Deploy to RDP Gateway Service" deploymnet task in the
# Certify The Web configuration for this certificate. Uncomment the next two lines to (Re)Apply certificate
#Import-Module RemoteDesktopServices
#Set-Item -Path RDS:\GatewayServer\SSLCertificate\Thumbprint -Value  $result.ManagedItem.CertificateThumbprintHash -ErrorAction Stop

### Replace the thumbprint of the certificate used by the RDP listener.
### This is required for the IIS kdcproxy service.
###
$RDServerListener = "HKLM:SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
try {
	Get-ItemProperty -Path $RDServerListener -Name SSLCertificateSHA1Hash -ErrorAction Stop | Out-Null
	$ThumbprintBinary = [byte[]] -split ($result.ManagedItem.CertificateThumbprintHash -replace '..', '0x$& ')
	New-ItemProperty -Path $RDServerListener -Name SSLCertificateSHA1Hash -Type Binary -Value $ThumbprintBinary -Force | Out-Null
	Write-Warning "The new certificate thumbprint is assigned to this terminal server."
}
catch {
	Write-Warning "No certificate thumbprint is assigned to this terminal server."
}

# Restart services required for "Access Anywhere"

$global:ServicesToStart = @()

function CollectDependent($TargetService) {
	# Caution: minimal effort done to prevent circular definitions
	if ($global:ServicesToStart -match "$service.name") {
		Write-Warning "Caution! Service $service.name is involved in a circular definition."
	}
	else {
		$wmidependents = (Get-Service $TargetService).dependentservices

		$wmidependentservices = Get-WmiObject Win32_Service | Select-Object name, state, startmode | Where-Object { $wmidependents.name -contains $_.name }
	
		# Write-Host $TargetService
	
		foreach ($service in $wmidependentservices) {
			if ($service.startmode -eq "auto" -or $service.status -eq "Running") {
				# Write-Host "-> $($service.name)"
				CollectDependent($service.name)
			} 
			else {
				Write-Warning "Omitting $($service.name) : service is $($service.state) with the startmode: $($service.startmode)"
			}
		}

		Stop-Service $TargetService -ErrorAction SilentlyContinue

		$global:ServicesToStart += $TargetService
	}

}

CollectDependent("IAS")

CollectDependent("SSTPSvc")

CollectDependent("TSGateway")

#Write-Host "----"

[array]::Reverse($global:ServicesToStart)

foreach ($service in $global:ServicesToStart ) {
	Write-Warning "Starting $service ..."
	Start-Service $service -ErrorAction SilentlyContinue
}

Write-Warning "Done!"
