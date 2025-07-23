#!/bin/bash
#
# Wazuh SOC Lab Deployment Validation Script
# This script validates the complete Wazuh and ELK stack deployment
# Compatible with Ubuntu 22.04
#
# Usage: sudo ./validate-deployment.sh
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Configuration
WAZUH_MANAGER_IP="192.168.1.10"
LOG_FILE="/var/log/deployment-validation.log"

# Counters for summary
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

print_banner() {
    echo -e "${BLUE}"
    echo "=========================================================="
    echo "    Wazuh SOC Lab Deployment Validation"
    echo "=========================================================="
    echo "Timestamp: $(date)"
    echo "Log File: $LOG_FILE"
    echo "=========================================================="
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
    echo "$(date): INFO - $1" >> "$LOG_FILE"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    echo "$(date): PASS - $1" >> "$LOG_FILE"
    ((PASSED_CHECKS++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    echo "$(date): FAIL - $1" >> "$LOG_FILE"
    ((FAILED_CHECKS++))
}

log_step() {
    echo -e "\n${PURPLE}=== $1 ===${NC}"
    echo "$(date): STEP - $1" >> "$LOG_FILE"
}

check() {
    local description="$1"
    local command_to_run="$2"
    
    ((TOTAL_CHECKS++))
    
    echo -n "  - $description: "
    
    if eval "$command_to_run" >/dev/null 2>&1; then
        echo -e "${GREEN}PASSED${NC}"
        log_pass "$description"
    else
        echo -e "${RED}FAILED${NC}"
        log_fail "$description"
    fi
}

check_service_status() {
    log_step "Checking Service Status"
    
    check "Wazuh Manager service is active" "systemctl is-active --quiet wazuh-manager"
    check "Wazuh Indexer service is active" "systemctl is-active --quiet wazuh-indexer"
    check "Wazuh Dashboard service is active" "systemctl is-active --quiet wazuh-dashboard"
    check "Filebeat service is active" "systemctl is-active --quiet filebeat"
    check "Logstash service is active" "systemctl is-active --quiet logstash"
    check "Fail2ban service is active" "systemctl is-active --quiet fail2ban"
}

check_network_ports() {
    log_step "Checking Network Ports"
    
    check "Port 1514 (Agent Communication) is listening" "ss -tln | grep -q ':1514'"
    check "Port 1515 (Agent Registration) is listening" "ss -tln | grep -q ':1515'"
    check "Port 55000 (Wazuh API) is listening" "ss -tln | grep -q ':55000'"
    check "Port 9200 (Elasticsearch) is listening" "ss -tln | grep -q ':9200'"
    check "Port 443 (Wazuh Dashboard) is listening" "ss -tln | grep -q ':443'"
    check "Port 5044 (Logstash Beats) is listening" "ss -tln | grep -q ':5044'"
    check "Port 514 (Syslog) is listening" "ss -uln | grep -q ':514'"
}

check_api_connectivity() {
    log_step "Checking API Connectivity"
    
    check "Wazuh API is responding" "curl -k -s https://$WAZUH_MANAGER_IP:55000/ | grep -q 'Wazuh API'"
    check "Elasticsearch API is responding" "curl -k -s https://$WAZUH_MANAGER_IP:9200/ | grep -q 'You Know, for Search'"
    check "Wazuh Dashboard is responding" "curl -k -s https://$WAZUH_MANAGER_IP/ | grep -q 'Wazuh'"
}

check_wazuh_components() {
    log_step "Checking Wazuh Components"
    
    check "Wazuh Manager is running" "/var/ossec/bin/wazuh-control status | grep -q 'wazuh-managerd is running'"
    check "Wazuh Analysisd is running" "/var/ossec/bin/wazuh-control status | grep -q 'wazuh-analysisd is running'"
    check "Wazuh Remoted is running" "/var/ossec/bin/wazuh-control status | grep -q 'wazuh-remoted is running'"
    check "Wazuh Logcollector is running" "/var/ossec/bin/wazuh-control status | grep -q 'wazuh-logcollector is running'"
    check "Wazuh Syscheckd is running" "/var/ossec/bin/wazuh-control status | grep -q 'wazuh-syscheckd is running'"
}

check_elasticsearch_cluster() {
    log_step "Checking Elasticsearch Cluster"
    
    check "Elasticsearch cluster health is green or yellow" "curl -k -s https://$WAZUH_MANAGER_IP:9200/_cluster/health | jq -e '.status == \"green\" or .status == \"yellow\"'"
    check "Elasticsearch has at least one node" "curl -k -s https://$WAZUH_MANAGER_IP:9200/_cluster/health | jq -e '.number_of_nodes >= 1'"
    check "Wazuh alerts index exists" "curl -k -s https://$WAZUH_MANAGER_IP:9200/_cat/indices/wazuh-alerts-* | grep -q 'wazuh-alerts'"
    check "Filebeat index exists" "curl -k -s https://$WAZUH_MANAGER_IP:9200/_cat/indices/filebeat-* | grep -q 'filebeat'"
    check "Syslog index exists" "curl -k -s https://$WAZUH_MANAGER_IP:9200/_cat/indices/syslog-* | grep -q 'syslog'"
}

check_agent_connectivity() {
    log_step "Checking Agent Connectivity"
    
    check "At least one agent is active" "/var/ossec/bin/agent_control -l | grep -q 'Active'"
}

check_log_ingestion() {
    log_step "Checking Log Ingestion"
    
    check "Recent alerts are being generated" "find /var/ossec/logs/alerts -name '*.log' -mmin -10 | grep -q 'alerts.log'"
    check "Recent logs are being received" "tail -100 /var/ossec/logs/ossec.log | grep -q 'received'"
}

check_security_configurations() {
    log_step "Checking Security Configurations"
    
    check "IPTables rules are loaded" "iptables -L INPUT | grep -q 'iptables-denied'"
    check "Fail2ban is active" "fail2ban-client status | grep -q 'Number of jail'"
    check "SSL certificates are in place" "ls /etc/ssl/wazuh/server-cert.pem"
}

check_performance_tuning() {
    log_step "Checking Performance Tuning"
    
    check "File limits are set correctly" "ulimit -n | grep -q '65536'"
    check "Max map count is set correctly" "sysctl vm.max_map_count | grep -q '262144'"
    check "Swappiness is set correctly" "sysctl vm.swappiness | grep -q '1'"
}

generate_summary() {
    echo -e "\n${BLUE}"
    echo "=========================================================="
    echo "    Validation Summary"
    echo "=========================================================="
    echo "Total checks: $TOTAL_CHECKS"
    echo -e "${GREEN}Passed: $PASSED_CHECKS${NC}"
    echo -e "${RED}Failed: $FAILED_CHECKS${NC}"
    echo "=========================================================="
    
    if [ "$FAILED_CHECKS" -gt 0 ]; then
        echo -e "\n${RED}Deployment validation failed. Please review the logs at $LOG_FILE${NC}"
        exit 1
    else
        echo -e "\n${GREEN}Deployment validation successful! The Wazuh SOC Lab is ready.${NC}"
        exit 0
    fi
}

main() {
    print_banner
    
    # Clear previous log file
    > "$LOG_FILE"
    
    check_service_status
    check_network_ports
    check_api_connectivity
    check_wazuh_components
    check_elasticsearch_cluster
    check_agent_connectivity
    check_log_ingestion
    check_security_configurations
    check_performance_tuning
    
    generate_summary
}

# Run main function
main "$@"