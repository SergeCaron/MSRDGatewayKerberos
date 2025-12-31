##******************************************************************
## Revision date: 2025.12.31
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

### The Network Service User name is localized
$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = New-Object System.Text.UTF8Encoding

$NetworkServiceSid = [System.Security.Principal.SecurityIdentifier]:: `
	new([System.Security.Principal.WellKnownSidType]::NetworkServiceSid, $Null)
$NetworkServiceUserName = ($NetworkServiceSID.Translate([System.Security.Principal.NTAccount])).Value
Write-Host "The Network Service user name is:", $NetworkServiceUserName

try {
	$DefaultDomainEncTypes = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KDC" `
		-Name "DefaultDomainSupportedEncTypes" -ErrorAction Stop
	Write-Host -ForegroundColor Green "DefaultDomainSupportedEncTypes is $DefaultDomainEncTypes." 
}
catch {
	Write-Warning "DefaultDomainSupportedEncTypes not available. Presume 0x27"
}

$RDSRole = Get-WindowsFeature -Name RDS-Gateway | Select-Object Name, DisplayName, Installed, InstallState

### Make sure AD cmdlets are available
try { Import-Module ActiveDirectory -ErrorAction Stop }
catch { Install-WindowsFeature RSAT-AD-PowerShell }

### Who am I really ?
$RDG = $($env:COMPUTERNAME).ToUpper()
$PrivateExposure = (Get-ADComputer -Identity $RDG).DNSHostName.ToLower()

### Test if RDG is installed and parameters are set
if ($RDSRole.Installed) {
	
	# "Get-RDCertificate -Role RDGateway" will fail if only RDG is installed :-(
	Import-Module RemoteDesktopServices
	$Thumbprint = (Get-Item -Path RDS:\GatewayServer\SSLCertificate\Thumbprint).CurrentValue
	$MyCert = (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $Thumbprint } )

	if ($Nul -ne $MyCert) {
		### Revise the ssl bindings used by the Remote Desktop Gateway
		netsh http show sslcert | Select-String -Pattern ":443" -Context 0, 2 | `
				ForEach-Object {
				# Ugly screen washing leading to ugly Write-Only regex :-(
				$URL = $($($_.Line.ToString()) -split '.*: (.*)')[1]
				$CertHash = $($($_.Context.PostContext[0].ToString()) -split '.*: (.*)')[1]
				$AppID = $($($_.Context.PostContext[1].ToString()) -split '.*: (.*)')[1]

				$ThisCert = (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $CertHash } )

				if (($URL -eq "[::]:443") -and ($AppID -eq "{ba195980-cd49-458b-9e23-c84ee0adcd75}")) {
					Write-Warning "The AppID for SSTP (Secure Socket Tunneling Protocol) is configured on IPv6."
					Write-Warning "This may conflicts with IIS Remote Desktop Gateway."
					Write-Warning ""
				}
				if ($URL -eq "[::]:443") {
					Write-Warning "The binding for $($ThisCert.DNSNameList.Unicode) is configured for IPv6."
					Write-Warning "Unless there is a specific need, this binding should be deleted with:"
					Write-Warning "`tnetsh http delete sslcert ipport=[::]:443"
					Write-Warning ""
				}
				if ($CertHash -ne $Thumbprint) {
					Write-Warning "Multiple certificates configured on the HTTP service."
					Write-Warning "Application $AppID may be conflicting with the Remote Desktop Gateway"
					Write-Warning "using $URL and certificate $($ThisCert.DNSNameList.Unicode) expiring $($ThisCert.NotAfter.ToString("yyyy.MM.dd"))"
					Write-Warning ""
					Write-Warning "Consider updating this entry using:"
					Write-Warning "`tnetsh http update sslcert ipport=$URL certhash=$Thumbprint appid=$AppID"
					Write-Warning "Enclose the appid in double quotes if using PowerSehll."
					Write-Warning ""
					Write-Warning "This may be an orphaned certificate: $($ThisCert.FriendlyName)"
					Write-Warning ""
				}
			}

		# Who am I
		$Myself = @()
		$MySelf = $MyCert.Subject.Split("=")
		
		# Enumerate all SPNs for this host
		$SPNs = setspn -L $RDG
		
		if ($Myself.Count -eq 2) {
			Write-Host "Using certificate", $($MyCert.FriendlyName)
			$PublicExposure = $Myself[1]
			Write-Host "Remote Desktop Gateway is ", $PublicExposure

			$Result = ($SPNs | Select-String "HTTP/$PublicExposure")
			if ($Nul -ne $Result) { $Result = $Result.ToString().Trim() }

			if ($Result -eq "HTTP/$PublicExposure") { Write-Host "SPN HTTP/$PublicExposure is properly registered to $RDG" }
			else {
				Write-Warning "Registering SPN HTTP/$PublicExposure to $RDG"
				setspn -S HTTP/$PublicExposure $RDG
			}
		}
		else { Write-Warning "Cannot parse $($MyCert.Subject)" }
		
		if ( $PrivateExposure -ne $PublicExposure ) {
			$Result = ($SPNs | Select-String "HTTP/$PrivateExposure")
			if ($Nul -ne $Result) { $Result = $Result.ToString().Trim() }
			
			if ($Result -eq "HTTP/$PrivateExposure") { Write-Host "SPN HTTP/$PrivateExposure is properly registered to $RDG" }
			else {
				Write-Warning "Registering SPN HTTP/$PrivateExposure to $RDG"
				setspn -S HTTP/$PrivateExposure $RDG
			}
		}
		
		# Reset authentication DLLs
		Write-Warning "Resetting Proxy Service Parameters to default values"
		$KpsSvcSettingsReg = "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings"
		New-ItemProperty -Path $KpsSvcSettingsReg -Name "LibNames" -Type MultiString -Value @("kerberos.dll") -Force | Out-Null
		New-ItemProperty -Path $KpsSvcSettingsReg -Name "HttpsClientAuth" -Type DWORD -Value 0 -Force | Out-Null
		New-ItemProperty -Path $KpsSvcSettingsReg -Name "DisallowUnprotectedPasswordAuth" -Type DWORD -Value 0 -Force | Out-Null
		New-ItemProperty -Path $KpsSvcSettingsReg -Name "HttpsUrlGroup" -Type MultiString -Value "+`:443" -Force | Out-Null

		### List all objects supporting only WEAK encryption protocols
		# See https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d
		[Array] $RC4SupportedObjects = Get-ADObject -Filter "msDS-supportedEncryptionTypes -bor 0x7 -and -not msDS-supportedEncryptionTypes -bor 0x18"
		if ($RC4SupportedObjects.Count) {
			Write-Warning "Encryption type(s) DES / RC4 explicitly enabled on these AD objects but not AES:"
			$RC4SupportedObjects | Format-Table Name, ObjectClass, ObjectGUID -AutoSize
			Write-Warning ""
		}
		else { Write-Warning "No DES / RC4 Encryption exception detected on this domain." }

		### List all objects supporting AES128-CTS-HMAC-SHA1-96, AES256-CTS-HMAC-SHA1-96
		[Array] $AESSupportedObjects = Get-ADObject -Filter "msDS-supportedEncryptionTypes -band 0x18" -Properties *
		if ($AESSupportedObjects.Count) {
			Write-Warning "These AD objects explicitly support Kerberos type encryption:"
			$AESSupportedObjects | Format-Table Name, ObjectClass, ObjectGUID, msDS-supportedEncryptionTypes -AutoSize
			Write-Warning ""
		}
		else { Write-Warning "No AES Encryption supported on this domain. Kerberos may not be feasible." }


		### Explicit KDC Mapping (Critical for Non-DC Gateways)
		try { Get-ADDomainController -Identity $RDG -ErrorAction Stop | Out-Null }
		catch {
			Write-Host
			Write-Host "Configuring non DC Remote Desktop Gateway"
			Write-Host "-----------------------------------------"
			Write-Host
			### $DomainName = (Get-WmiObject Win32_ComputerSystem).Domain.ToUpper()
			$DomainName = $env:USERDNSDOMAIN.ToUPPer()
			$KdcProxyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings\KdcProxy\$DomainName"
			if (-not (Test-Path $KdcProxyPath)) { New-Item -Path $KdcProxyPath -Force | Out-Null }

			# Get actual DCs for the domain
			if ( $PrivateExposure -ne $PublicExposure ) {
				$DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
			}
			else {
				# the Proxy service sometimes de-prioritizes FQDNs that match the local domain suffix to
				# avoid conflicts with the OS's native Kerberos locator : use the DC's IP
				$DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty IPv4Address
			}

			# Use only reachable KDCs
			Write-Host "Resetting reachable KDCs from this gateway..."
			$LiveKDCs = @()
			foreach ($DC in $DCs) { if (Test-NetConnection -ComputerName $DC -Port 88) { $LiveKDCs += $DC } }
			New-ItemProperty -Path $KdcProxyPath -Name "KdcNames" -Type MultiString -Value $LiveKDCs -Force | Out-Null

			### See "Configure Remote Desktop server listener certificate" on Microsoft
			Write-Host "Resetting this gateway's Remote Desktop Server listener certificate..."
			$RDServerListener = "HKLM:SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
			$ThumbprintBinary = [byte[]] -split ($Thumbprint -replace '..', '0x$& ')
			New-ItemProperty -Path $RDServerListener -Name SSLCertificateSHA1Hash -Type Binary -Value $ThumbprintBinary -Force | Out-Null

			### Force a restart of Terminal Services
			Write-Warning "Restarting Terminal Services: this may disconnect the session..."
			try {
				# Note to self: this should be done recursively ;-(
				Stop-Service -Name UmRdpService -ErrorAction Stop
				Restart-Service -Name TermService -ErrorAction Stop
				Start-Service -Name UmRdpService -ErrorAction Stop
			}
			catch {
				Write-Warning "Restart Service TermService [$((Get-Service -Name TermService).DisplayName)]"
				Write-Warning "Restart Service UmRdpService [$((Get-Service -Name UmRdpService).DisplayName)]"

			}

			Write-Host "-----------------------------------------"
			Write-Host
		}
	
		# Test/Create reserved URLs
		if ($($( netsh http show urlacl url="https://+:443/kdcproxy/" ) | Select-String "kdcproxy").Count -eq 0) {
			netsh http add urlacl url=https://+:443/KdcProxy user="$NetworkServiceUserName"
		}
		else { Write-Warning "URL kdcproxy is already reserved." }

		if ($($( netsh http show urlacl url="https://+:443/remoteDesktopGateway/" ) | Select-String "remoteDesktopGateway").Count -eq 0) {
			netsh http add urlacl url=https://+:443/remoteDesktopGateway/ user="$NetworkServiceUserName"
		}
		else { Write-Warning "URL remoteDesktopGateway is already reserved." }

		# Restart RD Gateway
		Set-Service -Name KPSSVC -StartupType Automatic
		Restart-Service -Name KPSSVC
		
	}
 else { Write-Warning "No certificate is installed in the Remote Desktop Service." }

}
else { Write-Warning "You must install role $($RDSRole.DisplayName)" }


