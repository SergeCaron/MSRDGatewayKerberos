##******************************************************************
## Revision date: 2026.01.25
##
##		2026.01.08: Proof of concept / Initial release
##		2026.01.25:	Add users and workstation filters
##
##
## The original script was generated from some AI and modified to 
## display NTLM events from all DCs in the domain.
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

<#
.SYNOPSIS
    Parse Windows Event ID 8004 (NTLM authentication) from Security logs.

.DESCRIPTION
    This script retrieves Event ID 8004 from the Security log, extracts useful
    NTLM authentication details, and outputs them in a structured table.
    It includes error handling and supports filtering by date range.

.NOTES
    Requires: PowerShell 5.1+ and appropriate permissions to read Security logs.
#>

param (
	[datetime]$StartTime = (Get-Date).AddDays(-1), # Default: last 24 hours
	[datetime]$EndTime = (Get-Date),              # Default: now
	[array] $Exclusions = @(),
	[array] $IncludeOnly = $null
)

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

# Restrict this script to servers (member server or domain controller)
if ($(Get-WmiObject -Class Win32_OperatingSystem) -eq 1) {
	Write-Host -ForegroundColor Red "Run this script on any server of the domain."
	Write-Host
	exit 911
}


### Make sure AD cmdlets are available
try { Import-Module ActiveDirectory -ErrorAction Stop }
catch { Install-WindowsFeature RSAT-AD-PowerShell }

# Output date range

Write-Host
Write-Host "NTLM audit from $StartTime to $EndTime"
Write-Host

# MS-NRPC NETLOGON_SECURE_CHANNEL_TYPE definition
$SChannelTypes = @("Null", "MsvAp", "Workstation", "TrustedDnsDomain", "TrustedDomain", "UasServer", "Server", "CdcServer")

# Get all DCs in this Domain
$DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

# Parse the logs
$parsed = @()
foreach ($DC in $DCs) {

	try {
		# Retrieve Event ID 8004 from Security log
		$events = Get-WinEvent -ComputerName $DC -FilterHashtable @{
			LogName   = 'Microsoft-Windows-NTLM/Operational'
			Id        = 8004
			StartTime = $StartTime
			EndTime   = $EndTime
		} -ErrorAction Stop

		if (-not $events) {
			Write-Host "No Event ID 8004 entries found in the specified time range." -ForegroundColor Yellow
		}
		else {
			# Parse and display relevant fields
			$parsed += foreach ($event in $events) {
				$xml = [xml]$event.ToXml()

				# Extract fields from EventData
				$data = @{}
				foreach ($d in $xml.Event.EventData.Data) {
					$data[$d.Name] = $d.'#text'
				}

				if ( (($null -eq $IncludeOnly) -or ($IncludeOnly -match $data['SChannelName'].ToLower())) `
						-and (-not ($Exclusions -match $data['UserName'].ToLower())) ) {
					[PSCustomObject]@{
						TimeCreated     = $event.TimeCreated
						Controller      = $DC.Split('.')[0]
						TargetUser      = $data['UserName']
						TargetDomain    = $data['DomainName']
						WorkstationName = $data['WorkstationName']
						SChannelName    = $data['SChannelName']
						SChannelType    = $SChannelTypes[$data['SChannelType']]
					}
				}
			}
		}

	}
 catch {
		Write-Host -ForegroundColor Red "Error retrieving Event ID 8004 from $DC :"
		Write-Host -ForegroundColor Red "->  $($_.Exception.Message)"
	}

}

# Output as a table
$parsed | Sort-Object TimeCreated -Descending | Format-Table -AutoSize

Write-Host
