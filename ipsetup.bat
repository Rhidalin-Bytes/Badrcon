REM © Microsoft Corporation 1997-2003 

REM Packet Fileters for Server Hardening 
REM 
REM Name: PacketFilters-ServerHost.CMD 
REM Version: 1.0 

REM This CMD file provides the proper NETSH syntax for creating an IPSec Policy 
REM that blocks all network traffic to an SMTP Bastion Host except for what is 
REM explicitly allowed as described in the Windows 2003 Server Solution Guide. 
REM Please read the entire guide before using this CMD file. 

REM Revision History 
REM 0000	-	Original	March 21, 2003 
REM 0001	-	Original	April 16, 2003 

:IPSec Policy Definition 
netsh ipsec static add policy name="PacketFiltersBadRcon" description="Server Side IP Bans" assign=no 

:IPSec Filter List Definitions 
netsh ipsec static add filterlist name="BannedIPS" description="Server Hardening" 

:IPSec Filter Action Definitions 
netsh ipsec static add filteraction name=SecPermit description="Allows Traffic to Pass" action=permit 
netsh ipsec static add filteraction name=Block description="Blocks Traffic" action=block 

:IPSec Filter Definitions 
netsh ipsec static add filter filterlist="BannedIPS" srcaddr=100.100.100.100 dstaddr=me description="BannedIPS" protocol=any srcport=0 dstport=0 

:IPSec Rule Definitions 
netsh ipsec static add rule name="BannedIPRule" policy="PacketFiltersBadRcon" filterlist="BannedIPS" kerberos=yes filteraction=Block 
