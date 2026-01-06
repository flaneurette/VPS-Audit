# Simple VPS Audit

Checks virtualization type, memory isolation, and **some** security hardening on a VPS and notifies if there are any glaring issues. If there are, discuss with your VPS provider. Memory isolation and memory protection is very important, especially if there are adjacent VPS instances running next to the current VPS.

- Uses: useful for having a quick glance for obvious faults, when instaling, modifying or auditing a VPS. 
- What it cannot do: the script doesn't do a comprehensive malware/virus/trojan scan.

`nano /usr/local/bin/vps-audit.sh`

paste .sh file contents.

`chmod +x /usr/local/bin/vps-audit.sh`

`sudo /usr/local/bin/vps-audit.sh`


# Test Cross-VM Isolation

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

# Or, if too massive

On VM1:

```
#!/bin/bash
SECRET="CROSS_VM_TEST_$(date +%s)_UNIQUE_STRING"
echo $SECRET > /dev/shm/cross_vm_test.txt
echo "VM1 secret created: $SECRET"
while true; do sleep 60; done
```

On VM2: 

```
#!/bin/bash
SECRET_PATTERN="CROSS_VM_TEST"
FOUND=0

# Check VM-local shared memory
if grep -q "$SECRET_PATTERN" /dev/shm/* 2>/dev/null; then
    echo "Isolation FAILED in /dev/shm!"
    FOUND=1
fi

# Attempt reading /proc/kcore (VM kernel memory)
if [ -r /proc/kcore ]; then
    if strings /proc/kcore 2>/dev/null | grep -q "$SECRET_PATTERN"; then
        echo "Isolation FAILED in /proc/kcore!"
        FOUND=1
    fi
fi

# Attempt reading /dev/mem (physical memory)
if [ -r /dev/mem ]; then
    if strings /dev/mem 2>/dev/null | grep -q "$SECRET_PATTERN"; then
        echo "Isolation FAILED in /dev/mem!"
        FOUND=1
    fi
fi

# Report result
if [ $FOUND -eq 0 ]; then
    echo "Isolation OK: No cross-VM secrets detected."
fi
```
