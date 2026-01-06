#!/bin/bash

# VPS Memory Security Audit Script
# Checks virtualization type, memory isolation, and security hardening
# chmod +x vps-audit.sh
# Usage: sudo ./vps-audit.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "======================================================================"
echo "           VPS MEMORY SECURITY AUDIT"
echo "======================================================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}Warning: Not running as root. Some checks may fail.${NC}"
    echo ""
fi

# 1. VIRTUALIZATION TYPE
echo -e "${BLUE}[1] VIRTUALIZATION TYPE${NC}"
echo "----------------------------------------------------------------------"
if command -v systemd-detect-virt &> /dev/null; then
    VIRT_TYPE=$(systemd-detect-virt)
    echo "Detected: $VIRT_TYPE"
    
    case "$VIRT_TYPE" in
        kvm|xen|microsoft|vmware)
            echo -e "${GREEN}Full hardware virtualization - Strong isolation${NC}"
            ;;
        openvz|lxc)
            echo -e "${RED}Container-based - Weaker isolation${NC}"
            ;;
        docker)
            echo -e "${RED}Docker container - Weak isolation${NC}"
            ;;
        none)
            echo -e "${GREEN}Bare metal${NC}"
            ;;
        *)
            echo -e "${YELLOW}? Unknown virtualization type${NC}"
            ;;
    esac
else
    echo -e "${YELLOW}systemd-detect-virt not found${NC}"
fi

# Check for container indicators
if [ -f "/.dockerenv" ]; then
    echo -e "${RED}Docker environment file detected${NC}"
fi

if grep -q docker /proc/1/cgroup 2>/dev/null; then
    echo -e "${RED}Docker cgroup detected${NC}"
fi

echo ""

# 2. KERNEL MEMORY PROTECTION
echo -e "${BLUE}[2] KERNEL MEMORY PROTECTION${NC}"
echo "----------------------------------------------------------------------"

check_sysctl() {
    local path=$1
    local name=$2
    local good_value=$3
    
    if [ -f "$path" ]; then
        local value=$(cat "$path" 2>/dev/null)
        echo -n "$name: $value "
        
        if [ "$value" -ge "$good_value" ]; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${RED}(should be >= $good_value)${NC}"
        fi
    else
        echo -e "$name: ${YELLOW}Not available${NC}"
    fi
}

check_sysctl "/proc/sys/kernel/dmesg_restrict" "dmesg_restrict" 1
check_sysctl "/proc/sys/kernel/kptr_restrict" "kptr_restrict" 1
check_sysctl "/proc/sys/kernel/perf_event_paranoid" "perf_event_paranoid" 2
check_sysctl "/proc/sys/kernel/yama/ptrace_scope" "ptrace_scope" 1

echo ""

# 3. CPU VULNERABILITIES
echo -e "${BLUE}[3] CPU SECURITY VULNERABILITIES${NC}"
echo "----------------------------------------------------------------------"

if [ -d "/sys/devices/system/cpu/vulnerabilities" ]; then
    for vuln in /sys/devices/system/cpu/vulnerabilities/*; do
        name=$(basename "$vuln")
        status=$(cat "$vuln" 2>/dev/null)
        
        echo -n "$name: "
        if echo "$status" | grep -iq "not affected"; then
            echo -e "${GREEN}Not affected${NC}"
        elif echo "$status" | grep -iq "mitigation"; then
            echo -e "${GREEN}Mitigated${NC}"
        elif echo "$status" | grep -iq "vulnerable"; then
            echo -e "${RED}Vulnerable: $status${NC}"
        else
            echo "$status"
        fi
    done
else
    echo -e "${YELLOW}CPU vulnerability information not available${NC}"
fi

echo ""

# 4. CROSS-PROCESS MEMORY ACCESS TEST
echo -e "${BLUE}[4] CROSS-PROCESS MEMORY ACCESS TEST${NC}"
echo "----------------------------------------------------------------------"

# Find a process owned by a different user
OTHER_PID=$(ps aux | grep -v "^$USER" | grep -v "^USER" | awk 'NR==1 {print $2}')

if [ ! -z "$OTHER_PID" ]; then
    OTHER_USER=$(ps -p "$OTHER_PID" -o user= 2>/dev/null)
    echo "Testing access to PID $OTHER_PID (owned by: $OTHER_USER)"
    
    if [ "$EUID" -eq 0 ]; then
        if cat /proc/$OTHER_PID/maps > /dev/null 2>&1; then
            echo -e "${GREEN}Root can access (expected behavior)${NC}"
        else
            echo -e "${YELLOW}? Root cannot access (unusual)${NC}"
        fi
    else
        if cat /proc/$OTHER_PID/maps > /dev/null 2>&1; then
            echo -e "${RED}Non-root can access other user's memory!${NC}"
        else
            echo -e "${GREEN}Access denied (expected behavior)${NC}"
        fi
    fi
else
    echo -e "${YELLOW}No other user processes found to test${NC}"
fi

echo ""

# 5. NAMESPACE ISOLATION (for containers)
echo -e "${BLUE}[5] NAMESPACE ISOLATION${NC}"
echo "----------------------------------------------------------------------"

if [ -d "/proc/$$/ns" ]; then
    echo "Current process namespaces:"
    ls -la /proc/$$/ns/ | grep -E "^l" | awk '{print "  " $9 " -> " $11}'
    
    # Compare with init process
    echo ""
    echo "Comparing with init (PID 1):"
    
    for ns in /proc/$$/ns/*; do
        ns_name=$(basename "$ns")
        current_ns=$(readlink "$ns" 2>/dev/null)
        init_ns=$(readlink "/proc/1/ns/$ns_name" 2>/dev/null)
        
        if [ "$current_ns" != "$init_ns" ]; then
            echo -e "  $ns_name: ${YELLOW}Different namespace (possible container)${NC}"
        fi
    done
else
    echo -e "${YELLOW}Namespace information not available${NC}"
fi

echo ""

# 6. MEMORY INFORMATION
echo -e "${BLUE}[6] MEMORY INFORMATION${NC}"
echo "----------------------------------------------------------------------"

if [ -f "/proc/meminfo" ]; then
    total_mem=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    total_mem_gb=$(echo "scale=2; $total_mem / 1024 / 1024" | bc)
    echo "Total Memory: ${total_mem_gb} GB"
    
    avail_mem=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    avail_mem_gb=$(echo "scale=2; $avail_mem / 1024 / 1024" | bc)
    echo "Available Memory: ${avail_mem_gb} GB"
fi

echo ""

# 7. SECURITY MODULES
echo -e "${BLUE}[7] SECURITY MODULES${NC}"
echo "----------------------------------------------------------------------"

if [ -d "/sys/kernel/security" ]; then
    if command -v aa-status &> /dev/null; then
        echo -n "AppArmor: "
        if systemctl is-active --quiet apparmor 2>/dev/null; then
            echo -e "${GREEN}Active${NC}"
        else
            echo "Inactive"
        fi
    fi
    
    if [ -d "/sys/fs/selinux" ]; then
        echo -n "SELinux: "
        if command -v getenforce &> /dev/null; then
            status=$(getenforce)
            if [ "$status" = "Enforcing" ]; then
                echo -e "${GREEN}$status${NC}"
            else
                echo "$status"
            fi
        else
            echo "Installed but status unknown"
        fi
    fi
fi

echo ""

# 8. SUMMARY
echo "======================================================================"
echo -e "${BLUE}SUMMARY${NC}"
echo "======================================================================"

echo ""
echo "Key Findings:"
echo ""

# Virtualization assessment
if [ "$VIRT_TYPE" = "kvm" ] || [ "$VIRT_TYPE" = "xen" ] || [ "$VIRT_TYPE" = "microsoft" ] || [ "$VIRT_TYPE" = "vmware" ]; then
    echo -e "${GREEN}Strong VM isolation (hardware virtualization)${NC}"
elif [ "$VIRT_TYPE" = "docker" ] || [ "$VIRT_TYPE" = "lxc" ] || [ "$VIRT_TYPE" = "openvz" ]; then
    echo -e "${RED}Weak isolation (container-based)${NC}"
fi

# Memory protection assessment
dmesg_val=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo 0)
kptr_val=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo 0)
ptrace_val=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 0)

if [ "$dmesg_val" -ge 1 ] && [ "$kptr_val" -ge 1 ] && [ "$ptrace_val" -ge 1 ]; then
    echo -e "${GREEN}Kernel memory protections enabled${NC}"
else
    echo -e "${YELLOW}Some kernel protections may be disabled${NC}"
fi

echo ""
echo "  - Use a reputable VPS provider with KVM/Xen/Hyper-V"
echo "  - Keep system updated and patched"
echo "  - Use strong file permissions (chmod 600 for sensitive files)"
echo "  - Store sensitive files outside web-accessible directories"
echo "  - Implement application-level rate limiting"
echo "  - Consider API keys with minimal required permissions"
echo ""
echo "======================================================================"
