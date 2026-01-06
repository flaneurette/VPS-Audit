# Simple VPS Audit

Checks virtualization type, memory isolation, and **some** security hardening on a VPS and notifies if there are any glaring issues. If there are, discuss with your VPS provider.

- Uses: useful for having a quick glance for obvious faults, when instaling or modifying a VPS. 
- What it cannot do: the script doesn't do a comprehensive malware/virus/trojan scan.


`chmod +x /usr/local/bin/vps-audit.sh`

`sudo /usr/local/bin/vps-audit.sh`
