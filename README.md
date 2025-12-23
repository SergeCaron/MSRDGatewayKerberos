# MSRDGatewayKerberos
This is a BYOD project for MS RD Gateway Kerberos authentication of non-domain joined workstations.

As documented *[here](https://awakecoding.com/posts/rd-gateway-without-kdc-proxy-causes-ntlm-downgrade/)*, *"if you have an RD Gateway deployed, did you know that unless a KDC proxy is also deployed on the same host and port, you have a guaranteed NTLM downgrade for the RD Gateway connection from mstsc"*.

The purpose of this project is to configure the RD Gateway to avoid this guaranteed downgrade for BYOD devices.

These configuration scripts are work in progress:

- Non domain joined workstations will sucessfully authenticate with Kerberos using these scripts.

- The definition of BYOD seems to exclude communications from domain joined workstations where there is no trust relationship between the caller's domain and the RD Gateway's domain. As of this writing, some Windows Server 2025 authenticate such workstations with kerberos, some downgrade to NTLM.

- In this instance, issuing the connection from a local account on the same workstation will successfully authenticate with Kerberos without any configuration change.

The gist of this development can be found at [Microsoft Learn](https://learn.microsoft.com/en-us/answers/questions/5649813/)

All servers and clients must be configured to accept AES-256-CTS-HMAC-SHA1-96 and AES-128-CTS-HMAC-SHA1-96 encryption in this context. There is no effort to turn RC4 encryption off domain wise: however, AES encryption types must be supported at the user and machine level. This may involved resetting the password of all affected account if AES is not supported on the DC before AES is used.

There are currently two scripts in this project. The name of these scripts may change in the future as this documentation is rewritten.

- RDGatewayConfigKerberos: This script configures the parameters on the RDG residing either on a DC or on a domain joined server.

- RDGatewayClientConfig: This script configures each "Realm" that a non-domain joined workstation will reach.

The first script runs on the RDG. It presume a valid public certificate is installed on the RDG and will setup the necessary parameters to exchange the appropriate tickets between the DC and the remote client. At this point, this is the documentation ;-).

The second script runs on the non-domain joined client. it simply asks the remote Active Directory domain name: on small domains, this is typically "mydomain.local", not the NetBIOS domain name "MYDOMAIN". It then asks the fully qualified domain name (FQDN) of the Remote Desktop Gateway: this is the name on the public certificate installed on the RD Gateway, typically "myserver.mydomain.tld".

Each RDP file must be edited to have a successful connection between client and server.
- The value rdgiskdcproxy must be set to 1
(rdgiskdcproxy:i:1)
- The value kdcproxyname must be set to the Remote Desktop Gateway fully qualified domain name
(kdcproxyname:s:fqdn)
- The value gatewayhostname must also be set to the Remote Desktop Gatway
(gatewayhostname:s:fqdn)

NOTE: If the RD Gateway is NOT a domain controller, the gateway's Remote Desktop Server listener certificate must be reset on every certificate renewal. Below is typical Powershell code that can be included in the renewal script:
````
Import-Module RemoteDesktopServices
$Thumbprint = (Get-Item -Path RDS:\GatewayServer\SSLCertificate\Thumbprint).CurrentValue
$ThumbprintBinary = [byte[]] -split ($Thumbprint -replace '..', '0x$& ')
$RDServerListener = "HKLM:SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
New-ItemProperty -Path $RDServerListener -Name SSLCertificateSHA1Hash -Type Binary -Value $ThumbprintBinary -Force | Out-Null
````



This document will be revised ;-)

