# Port scan

## masscan

Reveal open ports:
```
sudo masscan -p1-65535,U:1-65535 $rhost --rate=1000 -e tun0
```

Save it into a file (tcpports.txt) and them use this script to take out newline and add a comma at the final of each sentence:
```
cat masscan.txt | grep "/tcp" | cut -d "/" -f1 | awk '{print $4}' | sort -n  | sed '$!s/$/,/' | tr -d '\n' > tcpports.txt
```
NOTE: Check also for UDP ports!

```
cat masscan.txt | grep "/udp" | cut -d "/" -f1 | awk '{print $4}' | sort -n  | sed '$!s/$/,/' | tr -d '\n' > udpports.txt
```

Then, use these ports with nmap `-sC` option
## nmap

```
nmap -p`cat tcpports.txt` -sC -sV -A -T4 $rhost
```
# Enumeration

## TCP

### ftp

List ftp scripts to use with nmap:
```
locate *.nse | grep ftp
```

```
find / -type f -name ftp* 2>/dev/null | grep scripts
```

Nmap command only ftp port and with default scrips for ftp
```
nmap -p21 -sC -A -T4 -sV $rhost
```
Options: version scan (-sV), aggressive scan (-A), and the default script scan (-sC))

Some credentials to tries:
```
admin:admin
user:admin
machinename:machinename
anonymous:anonymous
ftp:ftp
```

#### Anonymous login:
```
ftp $rhosts
>anonymous
>anonymous
>ls -a # List all files (even hidden) (yes, they could be hidden)
>binary #Set transmission to binary instead of ascii
>ascii #Set transmission to ascii instead of binary
>bye #exit
```

#### Commands:
Get an overview of the ftp server:
```
status
```

Recursive listing:
```
ls -R
```

Download a file:
```
get file
```

Download all files from ftp:
```
wget -m --no-passive ftp://anonymous:anonymous@10.10.10.98
```

Upload a file:
```
put file
```

### smb

Clone enum4linux repository:
```
git clone https://github.com/cddmp/enum4linux-ng
```

Enumeration via enum4linux:
```
python enum4linux-ng.py $ip
```
#### smbclient
List shares (sometimes can ask for a password):
```
smbclient -L //$ip
```

Then, after try to connect to the remote share.
For linux:
```
smbclient //$ip/share [-U username -P password]
```
NOTE: you can use this command with windows too.

For Windows:
```
smbclient \\\\$ip\\share [-U username -P password]
```

#### crackmapexec:
```
crackmapexec smb -u username -p password $ip --shares
```

### NFS

Basic nmap scan:
```
sudo nmap $rhosts -p111,2049 -sV -sC
```

with more scripts:
```
sudo nmap 10.129.14.128 -p111,2049 -sV --script nfs*
```

show available NFS shares:
```
showmount -e $rhosts
```

Mounting NFS Share:
```
mdkir target-NFS
sudo mount -t nfs $rhosts:/ ./target-NFS -o nolock
```

List contents with usernames & groups:
```
ls -l target-NFS/dir/
```

Unmount NFS Share:
```
sudo umount ./target-NFS
```
### SMTP

Scan with nmap:
```
sudo nmap $rhosts -sC -sV -p25
```

Checking for an open relay
```
sudo nmap $rhosts -p25 --script smtp-open-relay
```

Some commands:

| Command	| Description |  
| ---------- | --------------- |  
| AUTH PLAIN	| AUTH is a service extension used to authenticate the client.|
| HELO	| The client logs in with its computer name and thus starts the session.|
| MAIL FROM	| The client names the email sender.|
| RCPT TO	| The client names the email recipient.|
| DATA	| The client initiates the transmission of the email.|
| RSET	| The client aborts the initiated transmission but keeps the connection between client and server.|
| VRFY	| The client checks if a mailbox is available for message transfer.|
| EXPN	| The client also checks if a mailbox is available for messaging with this command.|
| NOOP	| The client requests a response from the server to prevent disconnection due to time-out.|
| QUIT	| The client terminates the session.|

To interact with the SMTP server, we can use the telnet tool to initialize a TCP connection with the SMTP server. The actual initialization of the session is done with the command mentioned above, HELO or EHLO.

Send an Email:
```
MAIL FROM: <user1@website.com>
RCPT TO: <user2@website.com> NOTIFY=success,failure
DATA
[Your data]
QUIT
```

### IMAP/POP3

#### IMAP Commands:

| Command	| Description |
| ------- | ----------- |
|1 LOGIN username password	| User's login.|
|1 LIST "" *	| Lists all directories.|
|1 CREATE "INBOX"	| Creates a mailbox with a specified name.|
|1 DELETE "INBOX"	| Deletes a mailbox.|
|1 RENAME "ToRead" "Important"	| Renames a mailbox.|
|1 LSUB "" *	| Returns a subset of names from the set of names that the User has declared as being active or subscribed.|
|1 SELECT INBOX	| Selects a mailbox so that messages in the mailbox can be accessed.|
|1 UNSELECT INBOX	| Exits the selected mailbox.|
|1 FETCH \<ID\> all	| Retrieves data associated with a message in the mailbox.|
|1 CLOSE	| Removes all messages with the Deleted flag set.|
|1 LOGOUT	| Closes the connection with the IMAP server.|

#### POP3 Commands:

| Command |	Description |
| ------- | ------------ |
| USER | username	Identifies the user.|
| PASS | password	Authentication of the user using its password.|
| STAT	| Requests the number of saved emails from the server.|
| LIST	| Requests from the server the number and size of all emails.|
| RETR id	| Requests the server to deliver the requested email by ID.|
| DELE id	| Requests the server to delete the requested email by ID.|
| CAPA	| Requests the server to display the server capabilities.|
| RSET	| Requests the server to reset the transmitted information.|
| QUIT	| Closes the connection with the POP3 server.|

OpenSSL - TLS Encrypted Interaction POP3
```
openssl s_client -connect $rhosts:pop3s
```

OpenSSL - TLS Encrypted Interaction IMAP
```
openssl s_client -connect $rhosts:imaps
```


Nmap scan:
```
sudo nmap $rhosts -sV -p110,143,993,995 -sC
```

### MySQL

Nmap scan:
```
sudo nmap $rhosts -sV -sC -p3306 --script mysql*
```

Interaction with the MySQL Server:
```
mysql -u root -h $rhosts
```
MySQL Commands:

| Command |	Description |
| -------- | ------------ |
| mysql -u user -ppassword -h $rhosts	| Connect to the MySQL server. There should not be a space between the '-p' flag, and the password. |
| show databases;	| Show all databases. |
| use database_name;	| Select one of the existing databases. |
| show tables;	| Show all available tables in the selected database. |
| show columns from table_name;	| Show all columns in the selected database. |
| select * from table_name;	| Show everything in the desired table. |
| select * from table_name where column = "string";	| Search for needed string in the desired table. |

### MSSQL

Nmap scan
```
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 $rhosts
```

Cheat Sheet:
[pentestmonkey](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)

### Oracle TNS

Nmap scan:
```
sudo nmap -p1521 -sV $rhosts --open
```

Setup tools:
```
#!/bin/bash

sudo apt-get install libaio1 python3-dev alien python3-pip -y
git clone https://github.com/quentinhardy/odat.git
cd odat/
git submodule init
sudo submodule update
sudo apt install oracle-instantclient-basic oracle-instantclient-devel oracle-instantclient-sqlplus -y
pip3 install cx_Oracle
sudo apt-get install python3-scapy -y
sudo pip3 install colorlog termcolor pycryptodome passlib python-libnmap
sudo pip3 install argcomplete && sudo activate-global-python-argcomplete
```

Using odat:
```
./odat.py all -s $rhosts
```

Login:
```
sqlplus username/password@$rhsots/XE;
```
If you come across the following error sqlplus: error while loading shared libraries: libsqlplus.so: cannot open shared object file: No such file or directory, please execute the below:
```
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig
```

List all available tables in the current database:
```
select table_name from all_tables;
```

Show privileges of current user:
```
select * from user_role_privs;
```

Trying to connect to sysdba:
```
sqlplus username/password@$rhsots/XE as sysdba;
```

If you have administrative privileges:
```
select name, password from sys.user$;
```
Get passwords and try to crack them offline.

Upload file:
```
echo "Oracle File Upload Test" > testing.txt
./odat.py utlfile -s $rhosts -d XE -U username -P password --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```

Default paths:

|   OS	  |  Path  |
|  -----  |  ----  |
|  Linux  |	/var/www/html |
| Windows	| C:\inetpub\wwwroot |

### IPMI

### SSH

Use sshaudit to check information about ssh service:
```
git clone https://github.com/jtesta/ssh-audit.git
```

```
python3 ssh-audit.py $rhosts
```

### RSYNC

Access dev share and list files:
```
rsync -av --list-only rsync://$rhosts/dev
```

Sync all files:
```
rsync -av rsync://$rhosts/dev
```
If Rsync is configured to use SSH to transfer files, we could modify our commands to include the `-e ssh` flag, or `-e "ssh -p2222"`

## UDP

### DNS

Checking SOA record:
```
dig soa www.website.com
```

DIG - NS Query:
```
dig ns website.com @dns_ip
```

DIG - Version Query:
```
dig CH TXT version.bind dns_ip
```

DIG - ANY Query:
```
dig any website.comb @dns_ip
```

DIG - AXFR Zone Transfer:
```
dig axfr website.comb @dns_ip
```

DIG - AXFR Zone Transfer - Internal:
```
dig axfr internal.website.comb @dns_ip
```

Subdomain Bruteforce:

Bash script:
```
for sub in $(cat /secLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.website.com @dns_ip | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```

With dnsenum:
```
dnsenum --dnsserver dns_ip --enum -p 0 -s 0 -o subdomains.txt -f /secLists/Discovery/DNS/subdomains-top1million-110000.txt website.com
```

### SNMP

Using snmpwalk
```
 snmpwalk -v2c -c public $rhosts
```

Using onesixtyone
```
onesixtyone -c /SecLists/Discovery/SNMP/snmp.txt $rhosts
```

Once we know a community string, we can use it with braa to brute-force the individual OIDs and enumerate the information behind them.
```
braa <community string>@<IP>:.1.3.6.*
```
