##******************************************************************
##
## Revision date: 2026.08.10
##
## Copyright (c) 2026 PC-Évolution enr.
## This code is licensed under the GNU General Public License (GPL).
##
## THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
## ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
## IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
## PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
##
## Revision date: 2026.01.21
##
##		2026.01.21: Proof of concept / Initial release
##		2026.08.10:	Translation
##
##******************************************************************

Write-Host ""

$ValidCredentials = $False

if (Test-Path -Path "$env:USERPROFILE\LocalUserCredential.xml" -PathType leaf) {
	$CurrentErrorPreference = $ErrorActionPreference
	$ErrorActionPreference = "Stop"

	try {
		$Account = New-Object xml
		$Account.Load( "$env:USERPROFILE\LocalUserCredential.xml" )
		$Credential = New-Object -TypeName System.Management.Automation.PSCredential `
			-ArgumentList $Account.UserCredential.User, $(ConvertTo-SecureString $Account.UserCredential.Password)
		$ValidCredentials = $True
	}

	catch {
		Write-Warning "Error processing stored user credentials. They will be ignored."

		# Let the user decide what to do with this file ...
		Remove-Item -Path "$env:USERPROFILE\LocalUserCredential.xml" -Confirm

	}

	finally {
		$ErrorActionPreference = $CurrentErrorPreference
	}
}

if (-not $ValidCredentials) {
	Write-Host -ForegroundColor Green "Saving the credentials of a LOCAL user on this workstation."
	Write-Host -ForegroundColor Green "This recording can only be decoded by the active user on this computer."

	do {
		$Credential = Get-Credential -Message "Enter the credentials of a LOCAL user on $($env:COMPUTERNAME)."

	} until ($(Read-Host "Type 'Yes' to confirm the credentials, anything else to retry").tolower().StartsWith('yes'))

	$xmlWriter = New-Object System.XMl.XmlTextWriter("$env:USERPROFILE\LocalUserCredential.xml", $Null)
	$xmlWriter.Formatting = 'Indented'
	$xmlWriter.Indentation = 1
	$XmlWriter.IndentChar = "`t"

	$xmlWriter.WriteStartElement('UserCredential')
	$XmlWriter.WriteElementString('User', "$($Credential.UserName)")
	$XmlWriter.WriteElementString('Password', "$(ConvertFrom-SecureString $Credential.Password)")
	$xmlWriter.WriteEndElement()

	#$xmlWriter.WriteEndDocument()
	$xmlWriter.Flush()
	$xmlWriter.Close()

}

#Write-Host "      User: $($Credential.UserName)"

### Initiate Remote Desktop Connection
Add-Type -AssemblyName System.Windows.Forms
$FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
	# InitialDirectory = [Environment]::GetFolderPath('Desktop') 
	InitialDirectory = $script:MyInvocation.MyCommand.Path
	Filter           = 'RDP Connectors (*.rdp)|*.rdp'
	Title            = "Please locate the RDP Connector to be launched as $($Credential.UserName)"
}
$FileBrowser.ShowDialog() | Out-Null

if (-not [string]::IsNullOrEmpty( $FileBrowser.FileName)) {
	Start-Process mstsc.exe -ArgumentList $("/edit `"" + $FileBrowser.FileName + "`"") -Credential $Credential
}
