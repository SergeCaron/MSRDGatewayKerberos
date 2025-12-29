# MSRDGatewayKerberos
The convenience of NTLM convenience of credentials based authentication can be maintained with Kerberos. This is a BYOD project for MS RD Gateway Kerberos authentication of non-domain joined workstations.

As documented *[here](https://awakecoding.com/posts/rd-gateway-without-kdc-proxy-causes-ntlm-downgrade/)*, *"if you have an RD Gateway deployed, did you know that unless a KDC proxy is also deployed on the same host and port, you have a guaranteed NTLM downgrade for the RD Gateway connection from mstsc"*.

The purpose of this project is to configure the RD Gateway to avoid this guaranteed downgrade for BYOD devices.

These configuration scripts are work in progress:

- Non domain joined workstations will sucessfully authenticate with Kerberos using these scripts.

- The definition of BYOD seems to exclude communications from domain joined workstations where there is no trust relationship between the caller's domain and the RD Gateway's domain. As of this writing, Kerberos on Windows Server 2025 domains authenticates the Built-in Administrator Account connecting from such workstations. Connections using other domain accounts  downgrade to NTLM.

- In this instance, issuing the connection from a local account on the same workstation will successfully authenticate with Kerberos without any configuration change.

In essence, any workstation can authenticate without the *guaranteed NTLM downgrade*.

The gist of this development can be found at [Microsoft Learn](https://learn.microsoft.com/en-us/answers/questions/5649813/)

# Basic requirements
All servers and clients must be configured to accept AES-256-CTS-HMAC-SHA1-96 and AES-128-CTS-HMAC-SHA1-96 encryption in this context. There is no effort to turn RC4 encryption off domain wise: however, AES encryption types must be supported at the user and machine level. This may involved resetting the password of all affected accounts if AES is not supported on the DC before AES is used.

# The scripts
There are currently two scripts in this project. The name of these scripts may change in the future as this documentation is rewritten.

- RDGatewayConfigKerberos: This script configures the parameters on the RDG residing either on a DC or on a domain joined server. This script should run whenever the RD Gateway certificate is renewed/replaced.

- RDGatewayClientConfig: This script configures each "Realm" that a non-domain joined workstation will reach.

The first script runs on the RDG. It presume a valid public certificate is installed on the RDG and will setup the necessary parameters to exchange the appropriate tickets between the DC and the remote client. Basically, the script disable HTTPS client certificate authentication requirements for KDC Proxy operations and allow alternative methods, such as passwords or Kerberos over HTTPS, to be used without smart cards. At this point, this is the documentation ;-). See the note below regarding certificate renewals.


The second script runs on the client, domain joined or not, for EACH external realm this workstation connects to. It simply asks the remote Active Directory domain name: on small domains, this is typically "mydomain.local", not the NetBIOS domain name "MYDOMAIN". It then asks the fully qualified domain name (FQDN) of the Remote Desktop Gateway: this is the name on the public certificate installed on the RD Gateway, typically "myserver.mydomain.tld".

# Operations
Start Remote Desktop in Windows (mstsc.exe), configure the remote host to connect to within the *target realm* and the Remote Desktop Gateway. Save these Remote Desktop Connection Settings to a RDP File.

Each RDP file must be edited to have a successful connection between client and server.
- The value rdgiskdcproxy must be set to 1
(rdgiskdcproxy:i:1)
- The value kdcproxyname must be set to the Remote Desktop Gateway fully qualified domain name
(kdcproxyname:s:fqdn)
- The value gatewayhostname must also be set to the Remote Desktop Gatway
(gatewayhostname:s:fqdn)

On a non-domain joined workstation, connect using the RDP file (double click or explicit command line) and supply the credentials in UPN (*user@targetrealm*). Kerbeos is not concerned with SingleSignOn and multiple credentials are still allowed.

On a domain joined workstation, the user can login using a local user account. If it is not convenient, the user can invoke a local user account when initiating the remote desktop connection. In PowerShell 5.1, the command 

````
Start-Process mstsc.exe -ArgumentList PathToConnector.rdp `
    -Credential $(Get-Credential -Message "Specify a Local user account:")
````
will successfully connect through the RD Gateway using Kerberos. The RDP session runs under the context of the local user: operations such as cut and paste are limited and it is suggested to switch to a local session to support these and other features.

# Other notes

#### NOTE: If the RD Gateway is NOT a domain controller, the gateway's Remote Desktop Server listener certificate must be reset on every certificate renewal. Below is typical Powershell code that can be included in the renewal script:
````
Import-Module RemoteDesktopServices
$Thumbprint = (Get-Item -Path RDS:\GatewayServer\SSLCertificate\Thumbprint).CurrentValue
$ThumbprintBinary = [byte[]] -split ($Thumbprint -replace '..', '0x$& ')
$RDServerListener = "HKLM:SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
New-ItemProperty -Path $RDServerListener -Name SSLCertificateSHA1Hash -Type Binary -Value $ThumbprintBinary -Force | Out-Null
````

#### NOTE: Kerberos on the DC contacted by the RD Gateway will issue specific DNS requests before a connection is downgraded to NTLMv1.2
Specifically:

````
_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.SOMEDOMAIN.TLD: type SRV, class IN
and
_kerberos._tcp.dc._msdcs.SOMEDOMAIN.TLD: type SRV, class IN
````

Notice that the client domain name is in UPPERCASE, indicating this DC is making an effort to talk to a REALM.
In both cases, the answer from the SOA public DNS servers of "somedomain.tld" is "No such name" unless the KDC is publicly exposed.

At this point, two more DNS queries are made with the client domain name in lowercase:

````
_ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.somedomain.tld: type SRV, class IN
and
_ldap._tcp.dc._msdcs.somedomain.tld: type SRV, class IN
````

Again, in both cases, the answer from the SOA public DNS servers of "somedomain.tld" is "No such name" unless the AD is publicly exposed.

It is unclear if the decision to downgrade this connection is made between the two sets of DNS requests, but the connection is downgraded.




### This document will be revised ;-)

