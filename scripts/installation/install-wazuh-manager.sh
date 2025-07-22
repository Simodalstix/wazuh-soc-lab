#!/bin/bash
#
# Wazuh Manager Installation Script for SOC Lab
# This script installs Wazuh Manager with ELK stack (all-in-one)
# Compatible with Ubuntu 22.04
#
# Usage: sudo ./install-wazuh-manager.sh
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
WAZUH_VERSION="4.7.0"
MANAGER_IP="192.168.1.10"
LAB_DOMAIN="lab.local"

# Logging
LOG_FILE="/var/log/wazuh-install.log"
exec 1> >(tee -a "$LOG_FILE")
exec 2> >(tee -a "$LOG_FILE" >&2)

print_banner() {
    echo -e "${BLUE}"
    echo "=================================================="
    echo "    Wazuh SOC Lab Manager Installation"
    echo "=================================================="
    echo "Version: $WAZUH_VERSION"
    echo "Manager IP: $MANAGER_IP"
    echo "Domain: $LAB_DOMAIN"
    echo "Log File: $LOG_FILE"
    echo "=================================================="
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_system() {
    log_info "Checking system requirements..."
    
    # Check OS
    if ! grep -q "Ubuntu 22.04" /etc/os-release; then
        log_warn "This script is designed for Ubuntu 22.04"
    fi
    
    # Check memory
    MEMORY_GB=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $MEMORY_GB -lt 6 ]]; then
        log_warn "Recommended minimum memory is 6GB, found ${MEMORY_GB}GB"
    fi
    
    # Check disk space
    DISK_GB=$(df -BG / | awk 'NR==2{print $4}' | sed 's/G//')
    if [[ $DISK_GB -lt 50 ]]; then
        log_warn "Recommended minimum disk space is 50GB, found ${DISK_GB}GB available"
    fi
    
    log_info "System check completed"
}

update_system() {
    log_info "Updating system packages..."
    apt update -y
    apt upgrade -y
    apt install -y curl wget gnupg2 software-properties-common apt-transport-https ca-certificates lsb-release
}

set_hostname() {
    log_info "Setting hostname to wazuh-manager..."
    hostnamectl set-hostname wazuh-manager
    echo "127.0.0.1 wazuh-manager" >> /etc/hosts
    echo "$MANAGER_IP wazuh-manager.$LAB_DOMAIN wazuh-manager" >> /etc/hosts
}

configure_firewall() {
    log_info "Configuring firewall..."
    
    # Install UFW if not present
    apt install -y ufw
    
    # Reset UFW
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # SSH access
    ufw allow 22/tcp
    
    # Wazuh Manager ports
    ufw allow 1514/tcp  # Agent communication
    ufw allow 1515/tcp  # Agent registration
    ufw allow 1516/tcp  # Cluster communication
    ufw allow 55000/tcp # Wazuh API
    
    # Wazuh Dashboard
    ufw allow 443/tcp   # HTTPS Dashboard
    
    # Elasticsearch
    ufw allow 9200/tcp  # Elasticsearch API
    
    # Syslog for pfSense
    ufw allow 514/udp   # Syslog
    
    # Enable firewall
    ufw --force enable
    
    log_info "Firewall configured successfully"
}

install_wazuh() {
    log_info "Installing Wazuh Manager with all-in-one installer..."
    
    # Download Wazuh installer
    curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
    
    # Make executable
    chmod +x wazuh-install.sh
    
    # Run all-in-one installation
    log_info "Running Wazuh all-in-one installation (this may take several minutes)..."
    ./wazuh-install.sh -a -i
    
    # Save installation output
    if [[ -f wazuh-install-files.tar ]]; then
        tar -tf wazuh-install-files.tar > /root/wazuh-install-files.list
        log_info "Installation files list saved to /root/wazuh-install-files.list"
    fi
    
    log_info "Wazuh installation completed"
}

configure_syslog() {
    log_info "Configuring syslog reception for pfSense..."
    
    # Backup original configuration
    cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.backup
    
    # Add syslog configuration
    cat >> /var/ossec/etc/ossec.conf << 'EOF'

  <!-- Remote syslog for pfSense -->
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>192.168.1.1</allowed-ips>
    <local_ip>192.168.1.10</local_ip>
  </remote>

EOF

    log_info "Syslog configuration added"
}

configure_api() {
    log_info "Configuring Wazuh API..."
    
    # Enable API
    systemctl enable wazuh-manager
    systemctl enable wazuh-indexer
    systemctl enable wazuh-dashboard
    
    # Wait for services to start
    sleep 30
    
    # Test API connectivity
    if curl -k -X GET "https://localhost:55000/" -H "Authorization: Bearer $(cat /var/ossec/etc/authd.pass)" &>/dev/null; then
        log_info "Wazuh API is responding"
    else
        log_warn "Wazuh API may not be ready yet"
    fi
}

create_lab_users() {
    log_info "Creating lab users and roles..."
    
    # Create SOC analyst user (this would typically be done via API)
    # For now, we'll document the default admin credentials
    
    if [[ -f /var/ossec/etc/authd.pass ]]; then
        log_info "Default admin password saved in /var/ossec/etc/authd.pass"
    fi
    
    # Create a lab-specific configuration file
    cat > /etc/wazuh-lab.conf << EOF
# Wazuh SOC Lab Configuration
WAZUH_MANAGER_IP=$MANAGER_IP
WAZUH_VERSION=$WAZUH_VERSION
LAB_DOMAIN=$LAB_DOMAIN
INSTALLATION_DATE=$(date)
EOF
    
    log_info "Lab configuration saved to /etc/wazuh-lab.conf"
}

optimize_performance() {
    log_info "Optimizing performance for lab environment..."
    
    # Increase file limits
    cat >> /etc/security/limits.conf << 'EOF'
wazuh-indexer soft nofile 65536
wazuh-indexer hard nofile 65536
wazuh-indexer soft memlock unlimited
wazuh-indexer hard memlock unlimited
EOF
    
    # Configure sysctl for Elasticsearch
    cat >> /etc/sysctl.conf << 'EOF'
vm.max_map_count=262144
vm.swappiness=1
EOF
    
    sysctl -p
    
    log_info "Performance optimization completed"
}

verify_installation() {
    log_info "Verifying installation..."
    
    # Check services
    services=("wazuh-manager" "wazuh-indexer" "wazuh-dashboard")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log_info "$service is running"
        else
            log_error "$service is not running"
        fi
    done
    
    # Check ports
    ports=("1514" "1515" "55000" "9200" "443")
    for port in "${ports[@]}"; do
        if netstat -tuln | grep -q ":$port "; then
            log_info "Port $port is listening"
        else
            log_warn "Port $port is not listening"
        fi
    done
    
    # Check disk usage
    log_info "Disk usage after installation:"
    df -h /
    
    log_info "Installation verification completed"
}

display_summary() {
    echo -e "${GREEN}"
    echo "=================================================="
    echo "    Wazuh SOC Lab Installation Complete!"
    echo "=================================================="
    echo "Manager IP: $MANAGER_IP"
    echo "Dashboard URL: https://$MANAGER_IP"
    echo "API URL: https://$MANAGER_IP:55000"
    echo ""
    echo "Default Credentials:"
    if [[ -f /var/ossec/etc/authd.pass ]]; then
        echo "Username: admin"
        echo "Password: $(cat /var/ossec/etc/authd.pass)"
    fi
    echo ""
    echo "Next Steps:"
    echo "1. Access the dashboard at https://$MANAGER_IP"
    echo "2. Deploy agents using the provided playbooks"
    echo "3. Configure pfSense to send logs to $MANAGER_IP:514"
    echo "4. Run attack simulations to test detection"
    echo ""
    echo "Log file: $LOG_FILE"
    echo "Configuration: /etc/wazuh-lab.conf"
    echo "=================================================="
    echo -e "${NC}"
}

cleanup() {
    log_info "Cleaning up installation files..."
    rm -f wazuh-install.sh
    rm -f wazuh-install-files.tar
}

main() {
    print_banner
    check_root
    check_system
    update_system
    set_hostname
    configure_firewall
    install_wazuh
    configure_syslog
    configure_api
    create_lab_users
    optimize_performance
    verify_installation
    cleanup
    display_summary
}

# Trap errors
trap 'log_error "Installation failed at line $LINENO"' ERR

# Run main function
main "$@"