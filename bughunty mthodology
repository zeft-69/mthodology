***1. Recon on Wildcard Domain — Tools required:***

- [ ]  Amass (https://github.com/OWASP/Amass)
- [ ]  subfinder (https://github.com/projectdiscovery/subfinder)
- [ ]  Assetfinder (https://github.com/tomnomnom/assetfinder)
- [ ]  dnsgen (https://github.com/ProjectAnte/dnsgen)
- [ ]  massdns (https://github.com/blechschmidt/massdns)
- [ ]  httprobe (https://github.com/tomnomnom/httprobe)
- [ ]  aquatone (https://github.com/michenriksen/aquatone)

***2. Scanning:***

- [ ]  ***nmap***
- [ ]  ***burp crawler***
- [ ]  fuzzing
- [ ]  gau - hakerwler -  paramspider ( for URL gathring )

> 3. Manual Checking:
> 
- [ ]  showdan
- [ ]  Censys
- [ ]  googl dorkes
- [ ]  pastebin
- [ ]  githup
- [ ]  OSINT
- [ ]  leakIX

parmspider
katana

hakrawler

***4. Information Gathering:***

- [ ]  Manually explore the site to check for sensitive info from web page comments or metadata from source code.
- [ ]  Spider/Crawl for missed or hidden content.
- [ ]  Check for files that expose content such as robots.txt, sitemap.xml, .DS_Store.
- [ ]  Perform Web Application fingerprinting.
- [ ]  Check for caches of major search engines for publicly accessible sites.
- [ ]  Check for difference in content based on User Agent (Ex: Mobile sites).
- [ ]  Identify various technologies used with he help of Wappalyzer.
- [ ]  Identify user roles.
- [ ]  Identify application entry points.
- [ ]  Identify client-side code and go through it.
- [ ]  Identify multiple versions/channels of the software.
- [ ]  Identify co-hosted and related applications.
- [ ]  Identify all host names and ports.
- [ ]  Identify third party hosted content
- [ ]  Identify Debug parameters.
- [ ]  Find applications hosted in the webserver (Virtual hosts/Subdomain), non-standard ports, DNS zone transfers.
- [ ]  Identify application architecture including Web language, WAF, Reverse proxy, Application Server, Backend Database.

***5. Configuration Management:***

- [ ]  Check for commonly used application and administrative URL's.
- [ ]  Check for old backup and unreferenced files.
- [ ]  Check HTTP methods supported and Cross Site Tracing (XST).
- [ ]  Test file extensions handling.
- [ ]  Test for security HTTP headers (Ex: CSP, X-Frame-Options, HSTS).
- [ ]  Test for policies (Ex: Flash, Silverlight).
- [ ]  Test for non-production data in live environment.
- [ ]  Check for sensitive data in client-side code (Ex: API Keys, credentials).

> 6. Secure Transmission:
> 
- [ ]  Check for SSL Versions, algorithms and Key length.
- [ ]  Check for Digital Certificate Validity (Duration, Signature and CN).
- [ ]  Check credentials only delivered over HTTPS.
- [ ]  Check that the login form is delivered over only HTTPS.
- [ ]  Check session tokens only delivered over HTTPS.
- [ ]  Check if HTTP Strict Transport Security (HSTS) in use.

> 7. Authentication:
> 
- [ ]  Test for user enumeration.
- [ ]  Test for Authentication Bypass.
- [ ]  Test for bruteforce protection.
- [ ]  Test password quality rules.
- [ ]  Test for Remember Me functionality.
- [ ]  Test for auto-complete on password forms/user input pages.
- [ ]  Test password reset / recovery functionalities.
- [ ]  Test password changing process.
- [ ]  Test CAPTCHA if the website / web application has any.
- [ ]  Test multi-factor authentication for OTP expiration.
- [ ]  Test for logout functionality presence.
- [ ]  Test for cache management on HTTP (Ex: Pragma, Expires, Max-age).
- [ ]  Test for default logins.
- [ ]  Test for user-accessible authentication history.
- [ ]  Test for out-of-channel notifications of account lockouts and successful password changes.
- [ ]  Test for consistent authentication across applications with shared authentication schema / SSO.

> 8. Session Management:
> 
> - [ ]  Establish how session management is handled in the application (Ex: tokens in cookies, tokens in URL).
> - [ ]  Check session tokens for cookie flags (httpOnly and secure).
> - [ ]  Check session cookies scope (Path & Domain).
> - [ ]  Check session duration (Expiration and max-age).
> - [ ]  Check session termination after a maximum lifetime.
> - [ ]  Check session termination after relative timeout.
> - [ ]  Check session termination after logging out of the application.
> - [ ]  Test to see if users can have multiple simultaneous sessions.
> - [ ]  Test session cookies for randomness using brute-force techniques.
> - [ ]  Test to see if new session tokens are issued on login, role change (Ex: admin / User) and logout. Test for consistent session management across applications with shared session management. Test for session puzzling. (Application uses the same session variable for more than one purpose) Test for CSRF and Click jacking.

> 9. Authorization
> 
- [ ]  Test for path traversals.
- [ ]  Test for bypassing authorization schema.
- [ ]  Test for Vertical Access Control problems (a.k.a Privilege Escalation)
- [ ]  Test for Horizontal Access Control problems (Between two users at the same privilege level).
- [ ]  Test for any missing authorization techniques.
- [ ]  Testing for IDOR. (Force changing parameter values by intercepting the request in burp suite.)

> 10. Data Validation
> 
> - [ ]  Test for Reflected Cross-Site Scripting
> - [ ]  Test for Stored Cross-Site Scripting.
> - [ ]  Test for DOM based Cross Site Scripting.
> - [ ]  Test for Cross-Site Flashing.
> - [ ]  Test for HTML Injections.
> - [ ]  Test for SQL (Union, Boolean, Error based, Out-of-band, Time delay) / LDAP / ORM/XML/XXE /SSI/XPath / NoSQL Injections.
> - [ ]  Test for XQuery Injection
> - [ ]  Test for IMAP/SMTP Injections.
> - [ ]  Test for Code / Expression Language / Command/ Overflow (Stack, Heap and Integer) Injections.
> - [ ]  Test for Format String/HTTP Splitting/Smuggling/HTTP Verb Tampering / Local and Remote File Inclusions.
> - [ ]  Test for Open Redirection / incubated vulnerabilities.
> - [ ]  Compare client-side and server-side validation rules.
> - [ ]  Test for HTTP parameter pollution.
> - [ ]  Test for auto-binding vulnerabilities.
> - [ ]  Test for Mass Assignment vulnerabilities.
> - [ ]  Determine that the backend database engine is PostgreSQL by using the :: cast operator.
> - [ ]  Read/Write file, Shell Injection (OS command) and exploit it accordingly.

> `11. Denial-Of-Service(DOS)`
> 
> - [ ]  `Test for anti-automation security protocols.`
> - [ ]  `Test for account lockout.`
> - [ ]  `Test for HTTP protocol DoS.`
> - [ ]  `Test for SQL wildcard DOS.`

> `12. Business Logic`
> 
> - [ ]  `Test for feature misuse.`
> - [ ]  `Test for lack of non-repudiation.`
> - [ ]  `Test for trust relationships.`
> - [ ]  `Test for integrity of data.`
> - [ ]  `Test for segregation of duties.`
> - [ ]  `Look for data entry points or hand off points between systems or software.`
> - [ ]  `Once found try to insert logically invalid data into the application/system.`
> - [ ]  `Look for functions or features in the application or system that should not be executed more that a single time or specified number of times during the business logic workflow.`
> - [ ]  `For each of the functions and features found that should only be executed a single time or specified number of times during the business logic workflow, develop abuse/misuse cases that may allow a user to execute more than the allowable number of times.`
> - [ ]  `Look for methods to skip or go to steps in the application process in a different order from the designed/intended business logic flow.`
> - [ ]  `Review the project documentation and perform some exploratory testing looking for file types that should be "unsupported" by the application/system.`
> - [ ]  `Try to upload these unsupported files an verify that it are properly rejected.`

> 13. Crytographic Failures
> 
- [ ]  Check if data which is supposed to be encrypted is encrypted or not.
- [ ]  Check for wrong algorithms usage depending on context.
- [ ]  Check for weak algorithms usage. i.e. RC4, BEAST, CRIME, POODLE).
- [ ]  Check for proper use of salting mechanisms.
- [ ]  Check for randomness functions.
- [ ]  Identify SSL service.
- [ ]  Compare the responses in three different states:
    1. Cipher text gets decrypted, resulting data is correct.
    2. Cipher text gets decrypted, resulting data is garbled and causes some exception or error handling in the application logic. 3. Cipher text decryption fails due to padding errors.
    Check sensitive data during the transmission:
    3. Information used in authentication (e.g. Credentials, PINs, Session identifiers, Tokens, Cookies)
    4. Information protected by laws, regulations or specific organizational policy (e.g. Credit Cards, Customers data)

> 14. Risky Functionalities
> 
- [ ]  Check if acceptable file types are whitelisted or not.
- [ ]  Check the file size limits, upload frequency and total file counts are defined and are enforced.
- [ ]  Test that file contents match the defined file type.
- [ ]  Test that all file uploads have anti-virus scanning in place.
- [ ]  Check if unsafe filenames are sanitised or not.
- [ ]  Check if the uploaded files are not directly accessible within the web root directory.
- [ ]  Check if the uploaded files are not served on the same hostname/port.
- [ ]  Check if the files and other media are integrated with the authentication and authorization schemas.
- [ ]  CHECK FOR THE ABOVE CONDITIONS, THEN EXPLOIT BASED ON THE VULNERABILITIES.
++++++++++++++++++++++++++++++++++++++++
- [ ]  Test for known vulnerabilities and configuration issues on Web Server and applications based on the version of the software used.
- [ ]  Test for default or guessable passwords.
- [ ]  Test for non-production data in live environment.
- [ ]  Test for various injection vulnerabilities. (Ex: SQL/LDAP / ORM/XML/XXE /SSI/XPath / NoSQL Injections)
- [ ]  Test for Buffer Overflows.
- [ ]  Test for Insecure Cryptographic Storage.
- [ ]  Test for Improper Error Handling.
- [ ]  Test for all vulnerabilities with a CVSS v2 score > 4.0
- [ ]  Test for Authentication and Authorization Issues.
- [ ]  Test for CSRF.

> 15. Miscellaneous
> 
> - [ ]  Test Web Messaging.
> - [ ]  Test for Web Storage SQL Injection.
> - [ ]  Check for CORS misconfigurations.
