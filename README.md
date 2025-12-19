# MSRDGatewayKerberos
MS RD Gateway Kerberos Configuration scripts for non-domain joined worksations

This is work in progress.

The gist of this development can be found at [Microsoft Learn](https://learn.microsoft.com/en-us/answers/questions/5649813/)

All servers and clients must be configured to accept AES-256-CTS-HMAC-SHA1-96 and AES-128-CTS-HMAC-SHA1-96 encryption in this context. There is no effort to turn RC4 encryption off domain wise: however, AES encryption types must be supported at the user and machine level. This may involved resetting the password of all affected account if AES is not supported on the DC before AES is used.

There are currently two scripts in this project. The name of these scripts may change in the future as this documentation is rewritten.

- RDGatewayConfigKerberos: This script configures the parameters on the RDG residing either on a DC or on a domain joined server.

- RDGatewayClientConfig: This script configures each "Realm" that a non-domain joined workstation will reach.

The first script runs on the RDG. It presume a valid public certificate is installed on the RDG and will setup the necessary parameters to exchange the appropriate tickets between the DC and the remote client. At this point, this is the documentation ;-).

The second script runs on the non-domain joined client. it simply asks the remote Active Directory domain name: on small domains, this is typically "mydomain.local", not the NetBIOS domain name "MYDOMAIN". It then asks the fully qualified domain name (FQDN) of the Remote Desktop Gateway: this is the name on the public certificate installed on the RD Gateway, typically "myserver.mydomain.tld".

Each RDP file must be edit to have a successful connection between client and server.
- The value rdgiskdcproxy must be set to 1
rdgiskdcproxy:i:1
- The value kdcproxyname must be set to the Remote Desktop Gateway
kdcproxyname:s:<fqdn>
- The value gatewayhostname must also be set to the Remote Desktop Gatway
gatewayhostname:s:<fqdn>

This document will be revised ;-)

