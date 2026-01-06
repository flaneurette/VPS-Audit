# Simple VPS Audit

Checks virtualization type, memory isolation, and **some** security hardening on a VPS and notifies if there are any glaring issues. If there are, discuss with your VPS provider. Memory isolation and memory protection is very important, especially if there are adjacent VPS instances running next to the current VPS.

- Uses: useful for having a quick glance for obvious faults, when instaling, modifying or auditing a VPS. 
- What it cannot do: the script doesn't do a comprehensive malware/virus/trojan scan.

`nano /usr/local/bin/vps-audit.sh`

paste .sh file contents.

`chmod +x /usr/local/bin/vps-audit.sh`

`sudo /usr/local/bin/vps-audit.sh`
