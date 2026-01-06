# Simple VPS Audit

Checks virtualization type, memory isolation, and **some** security hardening on a VPS and notifies if there are any glaring issues. If there are, discuss with your VPS provider. Memory isolation and memory protection is very important, especially if there are adjacent VPS instances running next to the current VPS.

- Uses: useful for having a quick glance for obvious faults, when instaling, modifying or auditing a VPS. 
- What it cannot do: the script doesn't do a comprehensive malware/virus/trojan scan.

`nano /usr/local/bin/vps-audit.sh`

paste .sh file contents.

`chmod +x /usr/local/bin/vps-audit.sh`

`sudo /usr/local/bin/vps-audit.sh`


# More testing

If you own two VPS instances on the same server, you can test if you can have memory access to the adjacent VPS. Simple test:

Theoretical test (requires 2 VMs you control).

### On VM1: Create identifiable data

```
#!/bin/bash
SECRET="CROSS_VM_TEST_$(date +%s)_UNIQUE_STRING"
echo $SECRET
while true; do
  echo $SECRET > /dev/null
  sleep 1
done
```

### On VM2: Try to find it

```
# On VM2: Try to find it
#!/bin/bash

for pid in /proc/[0-9]*; do
    grep -a "CROSS_VM_TEST" $pid/mem 2>/dev/null && echo "FOUND IN $pid"
done
```
