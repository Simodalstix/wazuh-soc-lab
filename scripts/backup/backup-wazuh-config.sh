#!/bin/bash
#
# Wazuh SOC Lab Backup Script
# This script creates backups of critical Wazuh configurations and data
# Compatible with Ubuntu 22.04
#
# Usage: ./backup-wazuh-config.sh [backup_type]
# backup_type: daily, weekly, manual (default: manual)
#

set -euo pipefail

# Configuration
BACKUP_BASE_DIR="/opt/wazuh-backups"
WAZUH_HOME="/var/ossec"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_TYPE="${1:-manual}"
RETENTION_DAYS=30

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
LOG_FILE="/var/log/wazuh-backup.log"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

print_banner() {
    echo -e "${BLUE}"
    echo "=================================================="
    echo "    Wazuh SOC Lab Backup Script"
    echo "=================================================="
    echo "Backup Type: $BACKUP_TYPE"
    echo "Timestamp: $TIMESTAMP"
    echo "Backup Directory: $BACKUP_BASE_DIR"
    echo "=================================================="
    echo -e "${NC}"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
    
    # Check if Wazuh is installed
    if [[ ! -d "$WAZUH_HOME" ]]; then
        log_error "Wazuh installation not found at $WAZUH_HOME"
        exit 1
    fi
    
    # Create backup directory
    mkdir -p "$BACKUP_BASE_DIR"
    
    log_info "Prerequisites check completed"
}

create_backup_structure() {
    local backup_dir="$BACKUP_BASE_DIR/${BACKUP_TYPE}_${TIMESTAMP}"
    
    log_info "Creating backup structure at $backup_dir"
    
    mkdir -p "$backup_dir"/{config,rules,decoders,lists,keys,logs,elasticsearch,scripts}
    
    echo "$backup_dir"
}

backup_wazuh_config() {
    local backup_dir="$1"
    
    log_info "Backing up Wazuh configuration files..."
    
    # Main configuration
    if [[ -f "$WAZUH_HOME/etc/ossec.conf" ]]; then
        cp "$WAZUH_HOME/etc/ossec.conf" "$backup_dir/config/"
        log_info "Backed up ossec.conf"
    fi
    
    # Internal options
    if [[ -f "$WAZUH_HOME/etc/internal_options.conf" ]]; then
        cp "$WAZUH_HOME/etc/internal_options.conf" "$backup_dir/config/"
        log_info "Backed up internal_options.conf"
    fi
    
    # Local internal options
    if [[ -f "$WAZUH_HOME/etc/local_internal_options.conf" ]]; then
        cp "$WAZUH_HOME/etc/local_internal_options.conf" "$backup_dir/config/"
        log_info "Backed up local_internal_options.conf"
    fi
    
    # Client keys
    if [[ -f "$WAZUH_HOME/etc/client.keys" ]]; then
        cp "$WAZUH_HOME/etc/client.keys" "$backup_dir/keys/"
        log_info "Backed up client.keys"
    fi
    
    # API configuration
    if [[ -d "$WAZUH_HOME/api/configuration" ]]; then
        cp -r "$WAZUH_HOME/api/configuration" "$backup_dir/config/api/"
        log_info "Backed up API configuration"
    fi
}

backup_custom_rules() {
    local backup_dir="$1"
    
    log_info "Backing up custom rules and decoders..."
    
    # Custom rules
    if [[ -d "$WAZUH_HOME/etc/rules" ]]; then
        cp -r "$WAZUH_HOME/etc/rules"/* "$backup_dir/rules/" 2>/dev/null || true
        log_info "Backed up custom rules"
    fi
    
    # Custom decoders
    if [[ -d "$WAZUH_HOME/etc/decoders" ]]; then
        cp -r "$WAZUH_HOME/etc/decoders"/* "$backup_dir/decoders/" 2>/dev/null || true
        log_info "Backed up custom decoders"
    fi
    
    # CDB lists
    if [[ -d "$WAZUH_HOME/etc/lists" ]]; then
        cp -r "$WAZUH_HOME/etc/lists"/* "$backup_dir/lists/" 2>/dev/null || true
        log_info "Backed up CDB lists"
    fi
}

backup_certificates() {
    local backup_dir="$1"
    
    log_info "Backing up SSL certificates..."
    
    # Wazuh certificates
    if [[ -d "$WAZUH_HOME/etc/sslmanager.cert" ]]; then
        cp "$WAZUH_HOME/etc/sslmanager.cert" "$backup_dir/keys/"
    fi
    
    if [[ -d "$WAZUH_HOME/etc/sslmanager.key" ]]; then
        cp "$WAZUH_HOME/etc/sslmanager.key" "$backup_dir/keys/"
    fi
    
    # Elasticsearch certificates
    if [[ -d "/etc/wazuh-indexer/certs" ]]; then
        cp -r "/etc/wazuh-indexer/certs" "$backup_dir/keys/elasticsearch-certs"
        log_info "Backed up Elasticsearch certificates"
    fi
    
    # Dashboard certificates
    if [[ -d "/etc/wazuh-dashboard/certs" ]]; then
        cp -r "/etc/wazuh-dashboard/certs" "$backup_dir/keys/dashboard-certs"
        log_info "Backed up Dashboard certificates"
    fi
}

backup_elasticsearch_config() {
    local backup_dir="$1"
    
    log_info "Backing up Elasticsearch configuration..."
    
    # Elasticsearch configuration
    if [[ -f "/etc/wazuh-indexer/opensearch.yml" ]]; then
        cp "/etc/wazuh-indexer/opensearch.yml" "$backup_dir/elasticsearch/"
        log_info "Backed up Elasticsearch configuration"
    fi
    
    # Dashboard configuration
    if [[ -f "/etc/wazuh-dashboard/opensearch_dashboards.yml" ]]; then
        cp "/etc/wazuh-dashboard/opensearch_dashboards.yml" "$backup_dir/elasticsearch/"
        log_info "Backed up Dashboard configuration"
    fi
}

backup_logs() {
    local backup_dir="$1"
    
    log_info "Backing up recent log files..."
    
    # Wazuh logs (last 7 days)
    find "$WAZUH_HOME/logs" -name "*.log" -mtime -7 -exec cp {} "$backup_dir/logs/" \; 2>/dev/null || true
    
    # Compress log files to save space
    if [[ -n "$(ls -A "$backup_dir/logs/" 2>/dev/null)" ]]; then
        tar -czf "$backup_dir/logs/wazuh-logs-${TIMESTAMP}.tar.gz" -C "$backup_dir/logs" . --exclude="*.tar.gz"
        find "$backup_dir/logs" -name "*.log" -delete
        log_info "Compressed and backed up log files"
    fi
}

backup_custom_scripts() {
    local backup_dir="$1"
    
    log_info "Backing up custom scripts and configurations..."
    
    # Lab-specific configurations
    if [[ -f "/etc/wazuh-lab.conf" ]]; then
        cp "/etc/wazuh-lab.conf" "$backup_dir/config/"
    fi
    
    # Custom active response scripts
    if [[ -d "$WAZUH_HOME/active-response/bin" ]]; then
        find "$WAZUH_HOME/active-response/bin" -name "*.sh" -o -name "*.py" | while read -r script; do
            if [[ ! -f "$WAZUH_HOME/active-response/bin/$(basename "$script").orig" ]]; then
                cp "$script" "$backup_dir/scripts/"
            fi
        done
    fi
    
    # Wodle scripts
    if [[ -d "$WAZUH_HOME/wodles" ]]; then
        find "$WAZUH_HOME/wodles" -name "*.py" -o -name "*.sh" | while read -r script; do
            cp "$script" "$backup_dir/scripts/" 2>/dev/null || true
        done
    fi
}

create_backup_manifest() {
    local backup_dir="$1"
    
    log_info "Creating backup manifest..."
    
    cat > "$backup_dir/backup_manifest.txt" << EOF
Wazuh SOC Lab Backup Manifest
=============================
Backup Type: $BACKUP_TYPE
Timestamp: $TIMESTAMP
Created: $(date)
Hostname: $(hostname)
Wazuh Version: $(cat $WAZUH_HOME/VERSION 2>/dev/null || echo "Unknown")

Backup Contents:
$(find "$backup_dir" -type f | sort)

System Information:
OS: $(lsb_release -d 2>/dev/null | cut -f2 || echo "Unknown")
Kernel: $(uname -r)
Uptime: $(uptime)
Disk Usage: $(df -h /)

Wazuh Services Status:
$(systemctl status wazuh-manager --no-pager -l 2>/dev/null || echo "Service status unavailable")
EOF
    
    log_info "Backup manifest created"
}

compress_backup() {
    local backup_dir="$1"
    local compressed_file="${backup_dir}.tar.gz"
    
    log_info "Compressing backup..."
    
    tar -czf "$compressed_file" -C "$(dirname "$backup_dir")" "$(basename "$backup_dir")"
    
    if [[ -f "$compressed_file" ]]; then
        rm -rf "$backup_dir"
        log_info "Backup compressed to: $compressed_file"
        echo "$compressed_file"
    else
        log_error "Failed to compress backup"
        exit 1
    fi
}

cleanup_old_backups() {
    log_info "Cleaning up old backups (older than $RETENTION_DAYS days)..."
    
    find "$BACKUP_BASE_DIR" -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete
    find "$BACKUP_BASE_DIR" -type d -empty -delete
    
    log_info "Old backup cleanup completed"
}

verify_backup() {
    local backup_file="$1"
    
    log_info "Verifying backup integrity..."
    
    if tar -tzf "$backup_file" >/dev/null 2>&1; then
        log_info "Backup verification successful"
        
        # Display backup size
        local size=$(du -h "$backup_file" | cut -f1)
        log_info "Backup size: $size"
        
        return 0
    else
        log_error "Backup verification failed"
        return 1
    fi
}

send_notification() {
    local backup_file="$1"
    local status="$2"
    
    # Simple notification (could be extended to send emails, Slack, etc.)
    local message="Wazuh backup $status: $(basename "$backup_file")"
    
    # Log to syslog
    logger -t "wazuh-backup" "$message"
    
    # Write to notification file
    echo "$(date): $message" >> "/var/log/wazuh-backup-notifications.log"
}

main() {
    print_banner
    check_prerequisites
    
    local backup_dir
    backup_dir=$(create_backup_structure)
    
    # Perform backup operations
    backup_wazuh_config "$backup_dir"
    backup_custom_rules "$backup_dir"
    backup_certificates "$backup_dir"
    backup_elasticsearch_config "$backup_dir"
    backup_logs "$backup_dir"
    backup_custom_scripts "$backup_dir"
    create_backup_manifest "$backup_dir"
    
    # Compress and verify
    local backup_file
    backup_file=$(compress_backup "$backup_dir")
    
    if verify_backup "$backup_file"; then
        send_notification "$backup_file" "completed successfully"
        cleanup_old_backups
        
        echo -e "${GREEN}"
        echo "=================================================="
        echo "    Backup Completed Successfully!"
        echo "=================================================="
        echo "Backup File: $backup_file"
        echo "Size: $(du -h "$backup_file" | cut -f1)"
        echo "Type: $BACKUP_TYPE"
        echo "=================================================="
        echo -e "${NC}"
    else
        send_notification "$backup_file" "failed verification"
        log_error "Backup process failed"
        exit 1
    fi
}

# Trap errors
trap 'log_error "Backup failed at line $LINENO"' ERR

# Run main function
main "$@"