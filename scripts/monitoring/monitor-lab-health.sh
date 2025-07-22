#!/bin/bash
#
# Wazuh SOC Lab Health Monitoring Script
# This script monitors the health and status of all lab components
# Compatible with Ubuntu 22.04
#
# Usage: ./monitor-lab-health.sh [--continuous] [--interval seconds]
#

set -euo pipefail

# Configuration
CONTINUOUS_MODE=false
CHECK_INTERVAL=60
ALERT_THRESHOLD_CPU=80
ALERT_THRESHOLD_MEMORY=85
ALERT_THRESHOLD_DISK=90
LOG_FILE="/var/log/lab-health-monitor.log"

# Lab component IPs
WAZUH_MANAGER="192.168.1.10"
UBUNTU_WEB="192.168.2.10"
WINDOWS_DC="192.168.3.10"
RHEL_DB="192.168.3.20"
PFSENSE_FW="192.168.1.1"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --continuous)
            CONTINUOUS_MODE=true
            shift
            ;;
        --interval)
            CHECK_INTERVAL="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--continuous] [--interval seconds]"
            echo "  --continuous    Run continuously"
            echo "  --interval      Check interval in seconds (default: 60)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

print_banner() {
    echo -e "${BLUE}"
    echo "=================================================="
    echo "    Wazuh SOC Lab Health Monitor"
    echo "=================================================="
    echo "Timestamp: $(date)"
    echo "Mode: $([ "$CONTINUOUS_MODE" = true ] && echo "Continuous" || echo "Single Check")"
    echo "Interval: ${CHECK_INTERVAL}s"
    echo "Log File: $LOG_FILE"
    echo "=================================================="
    echo -e "${NC}"
}

log_info() {
    local message="$1"
    echo -e "${GREEN}[INFO]${NC} $message"
    echo "$(date): INFO - $message" >> "$LOG_FILE"
}

log_warn() {
    local message="$1"
    echo -e "${YELLOW}[WARN]${NC} $message"
    echo "$(date): WARN - $message" >> "$LOG_FILE"
}

log_error() {
    local message="$1"
    echo -e "${RED}[ERROR]${NC} $message"
    echo "$(date): ERROR - $message" >> "$LOG_FILE"
}

log_status() {
    local status="$1"
    local message="$2"
    case $status in
        "OK")
            echo -e "${GREEN}[OK]${NC} $message"
            ;;
        "WARNING")
            echo -e "${YELLOW}[WARNING]${NC} $message"
            ;;
        "CRITICAL")
            echo -e "${RED}[CRITICAL]${NC} $message"
            ;;
        *)
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
    esac
    echo "$(date): $status - $message" >> "$LOG_FILE"
}

# Check network connectivity
check_network_connectivity() {
    echo -e "\n${PURPLE}=== Network Connectivity Check ===${NC}"
    
    local hosts=("$WAZUH_MANAGER:Wazuh Manager" "$UBUNTU_WEB:Ubuntu Web" "$WINDOWS_DC:Windows DC" "$RHEL_DB:RHEL DB" "$PFSENSE_FW:pfSense")
    local failed_hosts=0
    
    for host_info in "${hosts[@]}"; do
        local ip="${host_info%%:*}"
        local name="${host_info##*:}"
        
        if ping -c 1 -W 3 "$ip" >/dev/null 2>&1; then
            log_status "OK" "$name ($ip) is reachable"
        else
            log_status "CRITICAL" "$name ($ip) is unreachable"
            ((failed_hosts++))
        fi
    done
    
    if [ $failed_hosts -eq 0 ]; then
        log_status "OK" "All lab systems are reachable"
    else
        log_status "CRITICAL" "$failed_hosts systems are unreachable"
    fi
}

# Check Wazuh services
check_wazuh_services() {
    echo -e "\n${PURPLE}=== Wazuh Services Check ===${NC}"
    
    if ! ping -c 1 -W 3 "$WAZUH_MANAGER" >/dev/null 2>&1; then
        log_status "CRITICAL" "Cannot reach Wazuh Manager"
        return 1
    fi
    
    # Check Wazuh Manager service
    if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$WAZUH_MANAGER" "systemctl is-active wazuh-manager" >/dev/null 2>&1; then
        log_status "OK" "Wazuh Manager service is running"
    else
        log_status "CRITICAL" "Wazuh Manager service is not running"
    fi
    
    # Check Wazuh Indexer (Elasticsearch)
    if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$WAZUH_MANAGER" "systemctl is-active wazuh-indexer" >/dev/null 2>&1; then
        log_status "OK" "Wazuh Indexer service is running"
    else
        log_status "CRITICAL" "Wazuh Indexer service is not running"
    fi
    
    # Check Wazuh Dashboard
    if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$WAZUH_MANAGER" "systemctl is-active wazuh-dashboard" >/dev/null 2>&1; then
        log_status "OK" "Wazuh Dashboard service is running"
    else
        log_status "CRITICAL" "Wazuh Dashboard service is not running"
    fi
    
    # Check API connectivity
    if curl -k -s --connect-timeout 5 "https://$WAZUH_MANAGER:55000/" >/dev/null 2>&1; then
        log_status "OK" "Wazuh API is responding"
    else
        log_status "WARNING" "Wazuh API is not responding"
    fi
    
    # Check Dashboard web interface
    if curl -k -s --connect-timeout 5 "https://$WAZUH_MANAGER/" >/dev/null 2>&1; then
        log_status "OK" "Wazuh Dashboard web interface is accessible"
    else
        log_status "WARNING" "Wazuh Dashboard web interface is not accessible"
    fi
}

# Check agent connectivity
check_agent_connectivity() {
    echo -e "\n${PURPLE}=== Agent Connectivity Check ===${NC}"
    
    if ! ping -c 1 -W 3 "$WAZUH_MANAGER" >/dev/null 2>&1; then
        log_status "CRITICAL" "Cannot reach Wazuh Manager to check agents"
        return 1
    fi
    
    # Get agent status from manager
    local agent_status
    agent_status=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$WAZUH_MANAGER" "/var/ossec/bin/wazuh-control status" 2>/dev/null || echo "ERROR")
    
    if [[ "$agent_status" == "ERROR" ]]; then
        log_status "CRITICAL" "Cannot retrieve agent status from manager"
        return 1
    fi
    
    # Check individual agents
    local agents=("$UBUNTU_WEB:ubuntu-web" "$RHEL_DB:rhel-db" "$WINDOWS_DC:windows-dc")
    
    for agent_info in "${agents[@]}"; do
        local ip="${agent_info%%:*}"
        local name="${agent_info##*:}"
        
        if ping -c 1 -W 3 "$ip" >/dev/null 2>&1; then
            # Check if agent is reporting
            local agent_check
            agent_check=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$WAZUH_MANAGER" "/var/ossec/bin/manage_agents -l | grep -i $name" 2>/dev/null || echo "")
            
            if [[ -n "$agent_check" ]]; then
                log_status "OK" "Agent $name ($ip) is registered and reachable"
            else
                log_status "WARNING" "Agent $name ($ip) is reachable but not properly registered"
            fi
        else
            log_status "CRITICAL" "Agent $name ($ip) is unreachable"
        fi
    done
}

# Check system resources
check_system_resources() {
    echo -e "\n${PURPLE}=== System Resources Check ===${NC}"
    
    local systems=("$WAZUH_MANAGER:Wazuh Manager" "$UBUNTU_WEB:Ubuntu Web" "$RHEL_DB:RHEL DB")
    
    for system_info in "${systems[@]}"; do
        local ip="${system_info%%:*}"
        local name="${system_info##*:}"
        
        if ! ping -c 1 -W 3 "$ip" >/dev/null 2>&1; then
            log_status "CRITICAL" "$name ($ip) is unreachable for resource check"
            continue
        fi
        
        echo -e "\n${BLUE}--- $name ($ip) ---${NC}"
        
        # CPU usage
        local cpu_usage
        cpu_usage=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$ip" "top -bn1 | grep 'Cpu(s)' | awk '{print \$2}' | cut -d'%' -f1" 2>/dev/null || echo "N/A")
        
        if [[ "$cpu_usage" != "N/A" ]]; then
            local cpu_int=${cpu_usage%.*}
            if [ "$cpu_int" -gt "$ALERT_THRESHOLD_CPU" ]; then
                log_status "WARNING" "$name CPU usage: ${cpu_usage}% (threshold: ${ALERT_THRESHOLD_CPU}%)"
            else
                log_status "OK" "$name CPU usage: ${cpu_usage}%"
            fi
        else
            log_status "WARNING" "$name CPU usage: Unable to retrieve"
        fi
        
        # Memory usage
        local memory_usage
        memory_usage=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$ip" "free | grep Mem | awk '{printf \"%.1f\", \$3/\$2 * 100.0}'" 2>/dev/null || echo "N/A")
        
        if [[ "$memory_usage" != "N/A" ]]; then
            local mem_int=${memory_usage%.*}
            if [ "$mem_int" -gt "$ALERT_THRESHOLD_MEMORY" ]; then
                log_status "WARNING" "$name Memory usage: ${memory_usage}% (threshold: ${ALERT_THRESHOLD_MEMORY}%)"
            else
                log_status "OK" "$name Memory usage: ${memory_usage}%"
            fi
        else
            log_status "WARNING" "$name Memory usage: Unable to retrieve"
        fi
        
        # Disk usage
        local disk_usage
        disk_usage=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$ip" "df / | tail -1 | awk '{print \$5}' | cut -d'%' -f1" 2>/dev/null || echo "N/A")
        
        if [[ "$disk_usage" != "N/A" ]]; then
            if [ "$disk_usage" -gt "$ALERT_THRESHOLD_DISK" ]; then
                log_status "CRITICAL" "$name Disk usage: ${disk_usage}% (threshold: ${ALERT_THRESHOLD_DISK}%)"
            elif [ "$disk_usage" -gt 75 ]; then
                log_status "WARNING" "$name Disk usage: ${disk_usage}%"
            else
                log_status "OK" "$name Disk usage: ${disk_usage}%"
            fi
        else
            log_status "WARNING" "$name Disk usage: Unable to retrieve"
        fi
        
        # Load average
        local load_avg
        load_avg=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$ip" "uptime | awk -F'load average:' '{print \$2}' | cut -d',' -f1 | xargs" 2>/dev/null || echo "N/A")
        
        if [[ "$load_avg" != "N/A" ]]; then
            log_status "OK" "$name Load average: $load_avg"
        else
            log_status "WARNING" "$name Load average: Unable to retrieve"
        fi
    done
}

# Check log processing
check_log_processing() {
    echo -e "\n${PURPLE}=== Log Processing Check ===${NC}"
    
    if ! ping -c 1 -W 3 "$WAZUH_MANAGER" >/dev/null 2>&1; then
        log_status "CRITICAL" "Cannot reach Wazuh Manager for log processing check"
        return 1
    fi
    
    # Check recent log processing
    local recent_events
    recent_events=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$WAZUH_MANAGER" "tail -100 /var/ossec/logs/ossec.log | grep -c 'received'" 2>/dev/null || echo "0")
    
    if [ "$recent_events" -gt 0 ]; then
        log_status "OK" "Log processing active: $recent_events recent events processed"
    else
        log_status "WARNING" "No recent log processing activity detected"
    fi
    
    # Check for errors in logs
    local error_count
    error_count=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$WAZUH_MANAGER" "tail -100 /var/ossec/logs/ossec.log | grep -ci error" 2>/dev/null || echo "0")
    
    if [ "$error_count" -gt 5 ]; then
        log_status "WARNING" "High number of errors in recent logs: $error_count"
    elif [ "$error_count" -gt 0 ]; then
        log_status "OK" "Some errors in recent logs: $error_count (normal level)"
    else
        log_status "OK" "No errors in recent logs"
    fi
    
    # Check alert generation
    local recent_alerts
    recent_alerts=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$WAZUH_MANAGER" "find /var/ossec/logs/alerts -name '*.log' -mmin -60 | wc -l" 2>/dev/null || echo "0")
    
    if [ "$recent_alerts" -gt 0 ]; then
        log_status "OK" "Alert generation active: $recent_alerts recent alert files"
    else
        log_status "WARNING" "No recent alert files generated"
    fi
}

# Check web services
check_web_services() {
    echo -e "\n${PURPLE}=== Web Services Check ===${NC}"
    
    # Check DVWA on Ubuntu web server
    if curl -s --connect-timeout 5 "http://$UBUNTU_WEB/dvwa/" >/dev/null 2>&1; then
        log_status "OK" "DVWA web application is accessible"
    else
        log_status "WARNING" "DVWA web application is not accessible"
    fi
    
    # Check Apache service
    if ping -c 1 -W 3 "$UBUNTU_WEB" >/dev/null 2>&1; then
        if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$UBUNTU_WEB" "systemctl is-active apache2" >/dev/null 2>&1; then
            log_status "OK" "Apache web server is running"
        else
            log_status "CRITICAL" "Apache web server is not running"
        fi
    else
        log_status "CRITICAL" "Cannot reach Ubuntu web server"
    fi
}

# Check database services
check_database_services() {
    echo -e "\n${PURPLE}=== Database Services Check ===${NC}"
    
    if ! ping -c 1 -W 3 "$RHEL_DB" >/dev/null 2>&1; then
        log_status "CRITICAL" "Cannot reach RHEL database server"
        return 1
    fi
    
    # Check MySQL service
    if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$RHEL_DB" "systemctl is-active mysqld" >/dev/null 2>&1; then
        log_status "OK" "MySQL database service is running"
    else
        log_status "CRITICAL" "MySQL database service is not running"
    fi
    
    # Check database connectivity
    if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$RHEL_DB" "mysql -e 'SELECT 1;'" >/dev/null 2>&1; then
        log_status "OK" "MySQL database is accessible"
    else
        log_status "WARNING" "MySQL database connectivity issues"
    fi
}

# Generate health summary
generate_health_summary() {
    echo -e "\n${GREEN}"
    echo "=================================================="
    echo "    Lab Health Check Summary"
    echo "=================================================="
    echo "Timestamp: $(date)"
    echo ""
    
    # Count status types from log
    local ok_count warning_count critical_count
    ok_count=$(grep -c "OK -" "$LOG_FILE" | tail -1 || echo "0")
    warning_count=$(grep -c "WARNING -" "$LOG_FILE" | tail -1 || echo "0")
    critical_count=$(grep -c "CRITICAL -" "$LOG_FILE" | tail -1 || echo "0")
    
    echo "Status Summary:"
    echo "✓ OK: $ok_count"
    echo "⚠ WARNING: $warning_count"
    echo "✗ CRITICAL: $critical_count"
    echo ""
    
    if [ "$critical_count" -gt 0 ]; then
        echo -e "${RED}Overall Status: CRITICAL - Immediate attention required${NC}"
    elif [ "$warning_count" -gt 0 ]; then
        echo -e "${YELLOW}Overall Status: WARNING - Some issues detected${NC}"
    else
        echo -e "${GREEN}Overall Status: HEALTHY - All systems operational${NC}"
    fi
    
    echo ""
    echo "Log File: $LOG_FILE"
    echo "=================================================="
    echo -e "${NC}"
}

# Main health check function
run_health_check() {
    print_banner
    
    # Create log file if it doesn't exist
    touch "$LOG_FILE"
    
    # Run all checks
    check_network_connectivity
    check_wazuh_services
    check_agent_connectivity
    check_system_resources
    check_log_processing
    check_web_services
    check_database_services
    
    generate_health_summary
}

# Main execution
main() {
    if [ "$CONTINUOUS_MODE" = true ]; then
        log_info "Starting continuous monitoring mode (interval: ${CHECK_INTERVAL}s)"
        while true; do
            run_health_check
            echo -e "\n${BLUE}Waiting ${CHECK_INTERVAL} seconds for next check...${NC}"
            sleep "$CHECK_INTERVAL"
            clear
        done
    else
        run_health_check
    fi
}

# Handle Ctrl+C gracefully
trap 'echo -e "\n${YELLOW}Monitoring stopped by user${NC}"; exit 0' INT

# Run main function
main "$@"