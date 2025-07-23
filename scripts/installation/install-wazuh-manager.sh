#!/bin/bash
#
# Enhanced Wazuh Manager Installation Script for SOC Lab
# This script installs Wazuh Manager with ELK stack (all-in-one) optimized for 6GB RAM
# Compatible with Ubuntu 22.04
#
# Features:
# - All-in-one Wazuh deployment (Manager + Indexer + Dashboard)
# - Performance optimization for 6GB RAM constraint
# - SSL/TLS certificate generation and configuration
# - Security hardening and firewall configuration
# - Integration with pfSense firewall logging
# - Custom rules and dashboards for SOC operations
#
# Usage: sudo ./install-wazuh-manager.sh
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
WAZUH_VERSION="4.7.0"
MANAGER_IP="192.168.1.10"
LAB_DOMAIN="lab.local"
ELASTICSEARCH_HEAP_SIZE="2g"  # Optimized for 6GB RAM
KIBANA_MEMORY_LIMIT="1g"
WAZUH_INDEXER_MEMORY="2g"

# Directories
WAZUH_CONFIG_DIR="/var/ossec/etc"
ELASTICSEARCH_CONFIG_DIR="/etc/wazuh-indexer"
KIBANA_CONFIG_DIR="/etc/wazuh-dashboard"
SSL_CERT_DIR="/etc/ssl/wazuh"
BACKUP_DIR="/opt/wazuh-backup"

# Logging
LOG_FILE="/var/log/wazuh-install.log"
exec 1> >(tee -a "$LOG_FILE")
exec 2> >(tee -a "$LOG_FILE" >&2)

print_banner() {
    echo -e "${BLUE}"
    echo "=========================================================="
    echo "    Enhanced Wazuh SOC Lab Manager Installation"
    echo "=========================================================="
    echo "Version: $WAZUH_VERSION"
    echo "Manager IP: $MANAGER_IP"
    echo "Domain: $LAB_DOMAIN"
    echo "Elasticsearch Heap: $ELASTICSEARCH_HEAP_SIZE"
    echo "Log File: $LOG_FILE"
    echo "=========================================================="
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

log_step() {
    echo -e "${PURPLE}[STEP]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_system() {
    log_step "Checking system requirements..."
    
    # Check OS
    if ! grep -q "Ubuntu 22.04" /etc/os-release; then
        log_warn "This script is designed for Ubuntu 22.04"
    fi
    
    # Check memory
    MEMORY_GB=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $MEMORY_GB -lt 6 ]]; then
        log_error "Minimum memory requirement is 6GB, found ${MEMORY_GB}GB"
        exit 1
    fi
    
    # Check disk space
    DISK_GB=$(df -BG / | awk 'NR==2{print $4}' | sed 's/G//')
    if [[ $DISK_GB -lt 50 ]]; then
        log_error "Minimum disk space requirement is 50GB, found ${DISK_GB}GB available"
        exit 1
    fi
    
    # Check CPU cores
    CPU_CORES=$(nproc)
    if [[ $CPU_CORES -lt 2 ]]; then
        log_warn "Recommended minimum CPU cores is 2, found ${CPU_CORES}"
    fi
    
    log_info "System check completed - Memory: ${MEMORY_GB}GB, Disk: ${DISK_GB}GB, CPU: ${CPU_CORES} cores"
}

create_directories() {
    log_step "Creating required directories..."
    
    mkdir -p "$SSL_CERT_DIR"
    mkdir -p "$BACKUP_DIR"
    mkdir -p "/etc/wazuh-lab"
    mkdir -p "/var/log/wazuh-lab"
    
    log_info "Directories created successfully"
}

update_system() {
    log_step "Updating system packages..."
    
    export DEBIAN_FRONTEND=noninteractive
    apt update -y
    apt upgrade -y
    apt install -y curl wget gnupg2 software-properties-common apt-transport-https \
                   ca-certificates lsb-release unzip jq htop iotop net-tools \
                   python3-pip python3-venv openssl
    
    log_info "System packages updated successfully"
}

set_hostname() {
    log_step "Setting hostname and hosts file..."
    
    hostnamectl set-hostname wazuh-manager
    
    # Backup original hosts file
    cp /etc/hosts /etc/hosts.backup
    
    # Update hosts file
    cat >> /etc/hosts << EOF

# Wazuh SOC Lab entries
127.0.0.1 wazuh-manager
$MANAGER_IP wazuh-manager.$LAB_DOMAIN wazuh-manager
$MANAGER_IP elasticsearch.$LAB_DOMAIN
$MANAGER_IP kibana.$LAB_DOMAIN
EOF
    
    log_info "Hostname and hosts file configured"
}

configure_system_limits() {
    log_step "Configuring system limits for performance..."
    
    # File limits for Elasticsearch
    cat >> /etc/security/limits.conf << 'EOF'
# Wazuh Indexer (Elasticsearch) limits
wazuh-indexer soft nofile 65536
wazuh-indexer hard nofile 65536
wazuh-indexer soft memlock unlimited
wazuh-indexer hard memlock unlimited
root soft nofile 65536
root hard nofile 65536
EOF
    
    # Sysctl configuration for Elasticsearch
    cat >> /etc/sysctl.conf << 'EOF'
# Wazuh Indexer (Elasticsearch) configuration
vm.max_map_count=262144
vm.swappiness=1
net.core.rmem_default=262144
net.core.rmem_max=16777216
net.core.wmem_default=262144
net.core.wmem_max=16777216
EOF
    
    sysctl -p
    
    log_info "System limits configured for optimal performance"
}

generate_ssl_certificates() {
    log_step "Generating SSL/TLS certificates..."
    
    cd "$SSL_CERT_DIR"
    
    # Generate CA private key
    openssl genrsa -out ca-key.pem 4096
    
    # Generate CA certificate
    openssl req -new -x509 -days 3650 -key ca-key.pem -sha256 -out ca-cert.pem -subj "/C=US/ST=Lab/L=SOC/O=WazuhLab/CN=Wazuh-CA"
    
    # Generate server private key
    openssl genrsa -out server-key.pem 4096
    
    # Generate server certificate signing request
    openssl req -subj "/C=US/ST=Lab/L=SOC/O=WazuhLab/CN=wazuh-manager" -sha256 -new -key server-key.pem -out server.csr
    
    # Create extensions file for server certificate
    cat > server-extfile.cnf << EOF
subjectAltName = DNS:wazuh-manager,DNS:wazuh-manager.$LAB_DOMAIN,DNS:localhost,IP:$MANAGER_IP,IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF
    
    # Generate server certificate
    openssl x509 -req -days 3650 -sha256 -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -out server-cert.pem -extfile server-extfile.cnf -CAcreateserial
    
    # Set proper permissions
    chmod 600 *-key.pem
    chmod 644 *-cert.pem
    chown -R root:root "$SSL_CERT_DIR"
    
    # Clean up
    rm server.csr server-extfile.cnf
    
    log_info "SSL certificates generated successfully"
}

configure_firewall() {
    log_step "Configuring advanced firewall rules..."
    
    # Install UFW if not present
    apt install -y ufw
    
    # Reset UFW
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # SSH access (restrict to management network)
    ufw allow from 192.168.1.0/24 to any port 22 proto tcp
    
    # Wazuh Manager ports
    ufw allow 1514/tcp comment "Wazuh Agent Communication"
    ufw allow 1515/tcp comment "Wazuh Agent Registration"
    ufw allow 1516/tcp comment "Wazuh Cluster Communication"
    ufw allow 55000/tcp comment "Wazuh API"
    
    # Wazuh Dashboard (HTTPS only)
    ufw allow 443/tcp comment "Wazuh Dashboard HTTPS"
    
    # Elasticsearch (restrict to local and management network)
    ufw allow from 127.0.0.1 to any port 9200 proto tcp
    ufw allow from 192.168.1.0/24 to any port 9200 proto tcp comment "Elasticsearch API"
    
    # Syslog for pfSense and other network devices
    ufw allow from 192.168.1.0/24 to any port 514 proto udp comment "Syslog from network devices"
    
    # SNMP for network monitoring (optional)
    ufw allow from 192.168.1.0/24 to any port 161 proto udp comment "SNMP monitoring"
    
    # Enable firewall
    ufw --force enable
    
    # Configure fail2ban for additional security
    apt install -y fail2ban
    
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[wazuh-api]
enabled = true
port = 55000
filter = wazuh-api
logpath = /var/ossec/logs/api.log
maxretry = 5
EOF

    # Create Wazuh API fail2ban filter
    cat > /etc/fail2ban/filter.d/wazuh-api.conf << 'EOF'
[Definition]
failregex = ^.*Authentication failed.*<HOST>.*$
ignoreregex =
EOF
    
    systemctl enable fail2ban
    systemctl start fail2ban
    
    log_info "Advanced firewall and security rules configured"
}

install_wazuh_all_in_one() {
    log_step "Installing Wazuh all-in-one with performance optimization..."
    
    # Download Wazuh installer
    curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
    chmod +x wazuh-install.sh
    
    # Create configuration file for all-in-one installation
    cat > wazuh-install-config.yml << EOF
# Wazuh all-in-one installation configuration
nodes:
  # Wazuh indexer nodes
  indexer:
    - name: wazuh-indexer
      ip: $MANAGER_IP
  
  # Wazuh server nodes
  server:
    - name: wazuh-manager
      ip: $MANAGER_IP
      node_type: master
  
  # Wazuh dashboard nodes
  dashboard:
    - name: wazuh-dashboard
      ip: $MANAGER_IP
EOF
    
    # Run all-in-one installation with custom configuration
    log_info "Running Wazuh all-in-one installation (this may take 10-15 minutes)..."
    ./wazuh-install.sh -a -g wazuh-install-config.yml
    
    # Save installation output and credentials
    if [[ -f wazuh-install-files.tar ]]; then
        tar -tf wazuh-install-files.tar > /root/wazuh-install-files.list
        log_info "Installation files list saved to /root/wazuh-install-files.list"
    fi
    
    # Extract and save credentials
    if [[ -f wazuh-passwords.txt ]]; then
        cp wazuh-passwords.txt /etc/wazuh-lab/
        chmod 600 /etc/wazuh-lab/wazuh-passwords.txt
        log_info "Wazuh credentials saved to /etc/wazuh-lab/wazuh-passwords.txt"
    fi
    
    log_info "Wazuh all-in-one installation completed"
}

optimize_elasticsearch_performance() {
    log_step "Optimizing Elasticsearch performance for 6GB RAM..."
    
    # Configure Elasticsearch heap size
    cat > "$ELASTICSEARCH_CONFIG_DIR/jvm.options.d/heap.options" << EOF
# Heap size optimization for 6GB RAM system
-Xms$ELASTICSEARCH_HEAP_SIZE
-Xmx$ELASTICSEARCH_HEAP_SIZE
EOF
    
    # Configure Elasticsearch settings
    cat >> "$ELASTICSEARCH_CONFIG_DIR/opensearch.yml" << EOF

# Performance optimization for lab environment
indices.memory.index_buffer_size: 20%
indices.memory.min_index_buffer_size: 96mb
indices.fielddata.cache.size: 40%
indices.breaker.fielddata.limit: 60%
indices.breaker.request.limit: 40%
indices.breaker.total.limit: 70%

# Cluster settings for single node
cluster.routing.allocation.disk.threshold_enabled: true
cluster.routing.allocation.disk.watermark.low: 85%
cluster.routing.allocation.disk.watermark.high: 90%
cluster.routing.allocation.disk.watermark.flood_stage: 95%

# Index settings
index.number_of_replicas: 0
index.refresh_interval: 30s
index.translog.flush_threshold_size: 1gb

# Network and discovery
network.host: 0.0.0.0
discovery.type: single-node
EOF
    
    log_info "Elasticsearch performance optimization completed"
}

configure_wazuh_indexer_templates() {
    log_step "Configuring Wazuh indexer templates and policies..."
    
    # Wait for Elasticsearch to be ready
    sleep 30
    
    # Create index template for optimized storage
    curl -X PUT "localhost:9200/_index_template/wazuh-alerts-optimized" \
         -H 'Content-Type: application/json' \
         -d '{
           "index_patterns": ["wazuh-alerts-*"],
           "template": {
             "settings": {
               "number_of_shards": 1,
               "number_of_replicas": 0,
               "refresh_interval": "30s",
               "index.codec": "best_compression",
               "index.mapping.total_fields.limit": 2000
             },
             "mappings": {
               "properties": {
                 "@timestamp": {"type": "date"},
                 "agent": {
                   "properties": {
                     "id": {"type": "keyword"},
                     "name": {"type": "keyword"},
                     "ip": {"type": "ip"}
                   }
                 },
                 "rule": {
                   "properties": {
                     "id": {"type": "keyword"},
                     "level": {"type": "integer"},
                     "description": {"type": "text"}
                   }
                 }
               }
             }
           }
         }' || log_warn "Failed to create index template"
    
    # Create ILM policy for log retention
    curl -X PUT "localhost:9200/_ilm/policy/wazuh-lab-policy" \
         -H 'Content-Type: application/json' \
         -d '{
           "policy": {
             "phases": {
               "hot": {
                 "actions": {
                   "rollover": {
                     "max_size": "1GB",
                     "max_age": "1d"
                   }
                 }
               },
               "warm": {
                 "min_age": "7d",
                 "actions": {
                   "allocate": {
                     "number_of_replicas": 0
                   },
                   "forcemerge": {
                     "max_num_segments": 1
                   }
                 }
               },
               "delete": {
                 "min_age": "30d"
               }
             }
           }
         }' || log_warn "Failed to create ILM policy"
    
    log_info "Wazuh indexer templates and policies configured"
}

configure_advanced_syslog() {
    log_step "Configuring advanced syslog reception..."
    
    # Backup original configuration
    cp "$WAZUH_CONFIG_DIR/ossec.conf" "$WAZUH_CONFIG_DIR/ossec.conf.backup"
    
    # Add advanced syslog configuration
    cat >> "$WAZUH_CONFIG_DIR/ossec.conf" << 'EOF'

  <!-- Enhanced remote syslog configuration -->
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>192.168.1.0/24</allowed-ips>
    <local_ip>192.168.1.10</local_ip>
  </remote>

  <!-- Additional syslog for different sources -->
  <remote>
    <connection>syslog</connection>
    <port>515</port>
    <protocol>tcp</protocol>
    <allowed-ips>192.168.2.0/24,192.168.3.0/24</allowed-ips>
    <local_ip>192.168.1.10</local_ip>
  </remote>

EOF
    
    log_info "Advanced syslog configuration added"
}

configure_custom_rules() {
    log_step "Installing custom detection rules..."
    
    # Create custom rules directory
    mkdir -p "$WAZUH_CONFIG_DIR/rules/custom"
    
    # Web application attack detection rules
    cat > "$WAZUH_CONFIG_DIR/rules/custom/web_attacks.xml" << 'EOF'
<group name="web,attack,">
  <!-- SQL Injection Detection -->
  <rule id="100001" level="12">
    <if_sid>31100</if_sid>
    <url>union|select|insert|delete|drop|create|alter|exec|script</url>
    <description>Possible SQL injection attack detected</description>
    <group>sql_injection,attack,</group>
  </rule>

  <!-- XSS Detection -->
  <rule id="100002" level="10">
    <if_sid>31100</if_sid>
    <url>&lt;script|javascript:|vbscript:|onload=|onerror=</url>
    <description>Possible XSS attack detected</description>
    <group>xss,attack,</group>
  </rule>

  <!-- Directory traversal -->
  <rule id="100003" level="10">
    <if_sid>31100</if_sid>
    <url>../|..\\|%2e%2e%2f|%2e%2e%5c</url>
    <description>Possible directory traversal attack</description>
    <group>directory_traversal,attack,</group>
  </rule>
</group>
EOF
    
    # Brute force detection rules
    cat > "$WAZUH_CONFIG_DIR/rules/custom/brute_force.xml" << 'EOF'
<group name="authentication,brute_force,">
  <!-- SSH Brute Force -->
  <rule id="100010" level="10" frequency="5" timeframe="300">
    <if_matched_sid>5716</if_matched_sid>
    <description>Multiple SSH authentication failures</description>
    <group>authentication_failures,brute_force,</group>
  </rule>

  <!-- Web Authentication Brute Force -->
  <rule id="100011" level="10" frequency="10" timeframe="300">
    <if_sid>31100</if_sid>
    <url>login|signin|auth</url>
    <regex>POST</regex>
    <description>Possible web authentication brute force</description>
    <group>web_brute_force,attack,</group>
  </rule>
</group>
EOF
    
    # Include custom rules in main configuration
    sed -i '/<\/ossec_config>/i\  <include>rules/custom/web_attacks.xml</include>' "$WAZUH_CONFIG_DIR/ossec.conf"
    sed -i '/<\/ossec_config>/i\  <include>rules/custom/brute_force.xml</include>' "$WAZUH_CONFIG_DIR/ossec.conf"
    
    log_info "Custom detection rules installed"
}

configure_api_and_dashboard() {
    log_step "Configuring Wazuh API and Dashboard..."
    
    # Wait for services to start
    sleep 30
    
    # Enable and start services
    systemctl enable wazuh-manager wazuh-indexer wazuh-dashboard
    systemctl restart wazuh-manager wazuh-indexer wazuh-dashboard
    
    # Wait for services to be ready
    sleep 60
    
    # Test API connectivity
    local api_test=0
    for i in {1..10}; do
        if curl -k -s "https://localhost:55000/" >/dev/null 2>&1; then
            api_test=1
            break
        fi
        sleep 10
    done
    
    if [[ $api_test -eq 1 ]]; then
        log_info "Wazuh API is responding"
    else
        log_warn "Wazuh API may not be ready yet"
    fi
    
    # Test Dashboard connectivity
    local dashboard_test=0
    for i in {1..10}; do
        if curl -k -s "https://localhost/" >/dev/null 2>&1; then
            dashboard_test=1
            break
        fi
        sleep 10
    done
    
    if [[ $dashboard_test -eq 1 ]]; then
        log_info "Wazuh Dashboard is responding"
    else
        log_warn "Wazuh Dashboard may not be ready yet"
    fi
}

create_lab_configuration() {
    log_step "Creating lab-specific configuration..."
    
    # Create lab configuration file
    cat > /etc/wazuh-lab/lab-config.conf << EOF
# Wazuh SOC Lab Configuration
WAZUH_MANAGER_IP=$MANAGER_IP
WAZUH_VERSION=$WAZUH_VERSION
LAB_DOMAIN=$LAB_DOMAIN
ELASTICSEARCH_HEAP_SIZE=$ELASTICSEARCH_HEAP_SIZE
INSTALLATION_DATE=$(date)
SSL_CERT_DIR=$SSL_CERT_DIR
BACKUP_DIR=$BACKUP_DIR

# Network Configuration
MANAGEMENT_NETWORK=192.168.1.0/24
DMZ_NETWORK=192.168.2.0/24
INTERNAL_NETWORK=192.168.3.0/24

# Service Ports
WAZUH_AGENT_PORT=1514
WAZUH_REGISTRATION_PORT=1515
WAZUH_API_PORT=55000
ELASTICSEARCH_PORT=9200
DASHBOARD_PORT=443
SYSLOG_PORT=514
EOF
    
    # Create service status script
    cat > /usr/local/bin/wazuh-lab-status << 'EOF'
#!/bin/bash
echo "=== Wazuh SOC Lab Status ==="
echo "Timestamp: $(date)"
echo ""

# Check services
services=("wazuh-manager" "wazuh-indexer" "wazuh-dashboard")
for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        echo "✓ $service: Running"
    else
        echo "✗ $service: Stopped"
    fi
done

echo ""
echo "=== Network Ports ==="
netstat -tuln | grep -E ':(1514|1515|55000|9200|443|514) '

echo ""
echo "=== Disk Usage ==="
df -h / | tail -1

echo ""
echo "=== Memory Usage ==="
free -h
EOF
    
    chmod +x /usr/local/bin/wazuh-lab-status
    
    log_info "Lab configuration created successfully"
}

create_backup_script() {
    log_step "Creating automated backup script..."
    
    cat > /usr/local/bin/wazuh-lab-backup << 'EOF'
#!/bin/bash
# Wazuh SOC Lab Backup Script

BACKUP_DIR="/opt/wazuh-backup"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/wazuh-backup-$DATE.tar.gz"

echo "Starting Wazuh lab backup at $(date)"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Stop services for consistent backup
systemctl stop wazuh-manager

# Create backup
tar -czf "$BACKUP_FILE" \
    /var/ossec/etc/ \
    /etc/wazuh-indexer/ \
    /etc/wazuh-dashboard/ \
    /etc/wazuh-lab/ \
    /etc/ssl/wazuh/ \
    2>/dev/null

# Start services
systemctl start wazuh-manager

# Remove old backups (keep last 7 days)
find "$BACKUP_DIR" -name "wazuh-backup-*.tar.gz" -mtime +7 -delete

echo "Backup completed: $BACKUP_FILE"
echo "Backup size: $(du -h "$BACKUP_FILE" | cut -f1)"
EOF
    
    chmod +x /usr/local/bin/wazuh-lab-backup
    
    # Create cron job for daily backups
    echo "0 2 * * * root /usr/local/bin/wazuh-lab-backup >> /var/log/wazuh-lab/backup.log 2>&1" > /etc/cron.d/wazuh-lab-backup
    
    log_info "Automated backup script created"
}

verify_installation() {
    log_step "Verifying installation..."
    
    local errors=0
    
    # Check services
    services=("wazuh-manager" "wazuh-indexer" "wazuh-dashboard")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log_info "$service is running"
        else
            log_error "$service is not running"
            ((errors++))
        fi
    done
    
    # Check ports
    ports=("1514" "1515" "55000" "9200" "443" "514")
    for port in "${ports[@]}"; do
        if netstat -tuln | grep -q ":$port "; then
            log_info "Port $port is listening"
        else
            log_warn "Port $port is not listening"
            ((errors++))
        fi
    done
    
    # Check SSL certificates
    if [[ -f "$SSL_CERT_DIR/server-cert.pem" && -f "$SSL_CERT_DIR/server-key.pem" ]]; then
        log_info "SSL certificates are present"
    else
        log_error "SSL certificates are missing"
        ((errors++))
    fi
    
    # Check disk usage
    disk_usage=$(df / | tail -1 | awk '{print $5}' | cut -d'%' -f1)
    if [[ $disk_usage -lt 80 ]]; then
        log_info "Disk usage: ${disk_usage}% (healthy)"
    else
        log_warn "Disk usage: ${disk_usage}% (high)"
    fi
    
    # Check memory usage
    memory_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    log_info "Memory usage: ${memory_usage}%"
    
    if [[ $errors -eq 0 ]]; then
        log_info "Installation verification completed successfully"
    else
        log_warn "Installation verification completed with $errors issues"
    fi
    
    return $errors
}

display_summary() {
    echo -e "${GREEN}"
    echo "=========================================================="
    echo "    Wazuh SOC Lab Installation Complete!"
    echo "=========================================================="
    echo "Manager IP: $MANAGER_IP"
    echo "Dashboard URL: https://$MANAGER_IP"
    echo "API URL: https://$MANAGER_IP:55000"
    echo ""
    echo "Credentials:"
    if [[ -f /etc/wazuh-lab/wazuh-passwords.txt ]]; then
        echo "Stored in: /etc/wazuh-lab/wazuh-passwords.txt"
        echo "Admin user: admin"
        echo "Password: $(grep 'admin' /etc/wazuh-lab/wazuh-passwords.txt | cut -d"'" -f2 2>/dev/null || echo 'Check passwords file')"
    fi
    echo ""
    echo "SSL Certificates: $SSL_CERT_DIR"
    echo "Configuration: /etc/wazuh-lab/lab-config.conf"
    echo "Backup Directory: $BACKUP_DIR"
    echo ""
    echo "Management Commands:"
    echo "• Check status: wazuh-lab-status"
    echo "• Create backup: wazuh-lab-backup"
    echo "• View logs: tail -f $LOG_FILE"
    echo ""
    echo "Next Steps:"
    echo "1. Access the dashboard at https://$MANAGER_IP"
    echo "2. Deploy agents using Ansible playbooks"
    echo "3. Configure pfSense to send logs to $MANAGER_IP:514"
    echo "4. Run attack simulations to test detection"
    echo "5. Configure custom dashboards and alerts"
    echo ""
    echo "Performance Optimization:"
    echo "• Elasticsearch heap: $ELASTICSEARCH_HEAP_SIZE"
    echo "• Index replicas: 0 (single node)"
    echo "• Refresh interval: 30s"
    echo "• Compression: enabled"
    echo ""
    echo "Log Files:"
    echo "• Installation: $LOG_FILE"
    echo "• Wazuh Manager: /var/ossec/logs/ossec.log"
    echo "• Elasticsearch: /var/log/wazuh-indexer/"
    echo "• Dashboard: /var/log/wazuh-dashboard/"
    echo "=========================================================="
    echo -e "${NC}"
}

cleanup() {
    log_step "Cleaning up installation files..."
    
    rm -f wazuh-install.sh
    rm -f wazuh-install-config.yml
    rm -f wazuh-install-files.tar
    
    log_info "Installation files cleaned up"
}

main() {
    print_banner
    check_root
    check_system
    create_directories
    update_system
    set_hostname
    configure_system_limits
    generate_ssl_certificates
    configure_firewall
    install_wazuh_all_in_one
    optimize_elasticsearch_performance
    configure_wazuh_indexer_templates
    configure_advanced_syslog
    configure_custom_rules
    configure_api_and_dashboard
    create_lab_configuration
    create_backup_script
    verify_installation
    cleanup
    display_summary
}

# Trap errors
trap 'log_error "Installation failed at line $LINENO"' ERR

# Run main function
main "$@"