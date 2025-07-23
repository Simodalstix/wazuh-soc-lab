#!/bin/bash
#
# SSL/TLS Certificate Generation Script for Wazuh SOC Lab
# This script generates a complete PKI infrastructure for the lab environment
# Compatible with Ubuntu 22.04
#
# Usage: sudo ./generate-certificates.sh
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
WAZUH_MANAGER_IP="192.168.1.10"
LAB_DOMAIN="lab.local"
SSL_DIR="/etc/ssl/wazuh"
CERT_VALIDITY_DAYS="3650"  # 10 years for lab environment
KEY_SIZE="4096"

# Certificate details
COUNTRY="US"
STATE="Lab"
CITY="SOC"
ORGANIZATION="WazuhLab"
OU="Security Operations Center"

# Logging
LOG_FILE="/var/log/ssl-certificate-generation.log"
exec 1> >(tee -a "$LOG_FILE")
exec 2> >(tee -a "$LOG_FILE" >&2)

print_banner() {
    echo -e "${BLUE}"
    echo "=========================================================="
    echo "    Wazuh SOC Lab SSL Certificate Generation"
    echo "=========================================================="
    echo "Manager IP: $WAZUH_MANAGER_IP"
    echo "Domain: $LAB_DOMAIN"
    echo "SSL Directory: $SSL_DIR"
    echo "Validity: $CERT_VALIDITY_DAYS days"
    echo "Key Size: $KEY_SIZE bits"
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

check_dependencies() {
    log_step "Checking dependencies..."
    
    # Check if OpenSSL is installed
    if ! command -v openssl &> /dev/null; then
        log_error "OpenSSL is not installed. Installing..."
        apt update
        apt install -y openssl
    fi
    
    # Check OpenSSL version
    OPENSSL_VERSION=$(openssl version | awk '{print $2}')
    log_info "OpenSSL version: $OPENSSL_VERSION"
    
    log_info "Dependencies check completed"
}

create_directories() {
    log_step "Creating SSL directory structure..."
    
    # Create main SSL directory
    mkdir -p "$SSL_DIR"
    
    # Create subdirectories for organization
    mkdir -p "$SSL_DIR/ca"
    mkdir -p "$SSL_DIR/server"
    mkdir -p "$SSL_DIR/client"
    mkdir -p "$SSL_DIR/private"
    
    # Create index and serial files for CA
    touch "$SSL_DIR/ca/index.txt"
    echo 1000 > "$SSL_DIR/ca/serial"
    
    # Set proper permissions
    chmod 755 "$SSL_DIR"
    chmod 700 "$SSL_DIR/private"
    
    log_info "SSL directory structure created"
}

generate_ca_certificate() {
    log_step "Generating Certificate Authority (CA)..."
    
    cd "$SSL_DIR"
    
    # Generate CA private key
    log_info "Generating CA private key..."
    openssl genrsa -out ca-key.pem $KEY_SIZE
    chmod 400 ca-key.pem
    
    # Generate CA certificate
    log_info "Generating CA certificate..."
    openssl req -new -x509 -days $CERT_VALIDITY_DAYS -key ca-key.pem -sha256 -out ca-cert.pem \
        -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=$OU/CN=Wazuh-Lab-CA"
    
    chmod 444 ca-cert.pem
    
    # Verify CA certificate
    log_info "Verifying CA certificate..."
    openssl x509 -noout -text -in ca-cert.pem | head -20
    
    log_info "Certificate Authority generated successfully"
}

generate_server_certificate() {
    log_step "Generating server certificate..."
    
    cd "$SSL_DIR"
    
    # Generate server private key
    log_info "Generating server private key..."
    openssl genrsa -out server-key.pem $KEY_SIZE
    chmod 400 server-key.pem
    
    # Generate server certificate signing request
    log_info "Generating server certificate signing request..."
    openssl req -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=$OU/CN=wazuh-manager" \
        -sha256 -new -key server-key.pem -out server.csr
    
    # Create extensions file for server certificate
    cat > server-extfile.cnf << EOF
subjectAltName = DNS:wazuh-manager,DNS:wazuh-manager.$LAB_DOMAIN,DNS:elasticsearch.$LAB_DOMAIN,DNS:kibana.$LAB_DOMAIN,DNS:localhost,IP:$WAZUH_MANAGER_IP,IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF
    
    # Generate server certificate
    log_info "Signing server certificate with CA..."
    openssl x509 -req -days $CERT_VALIDITY_DAYS -sha256 -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
        -out server-cert.pem -extfile server-extfile.cnf -CAcreateserial
    
    chmod 444 server-cert.pem
    
    # Clean up
    rm server.csr server-extfile.cnf
    
    # Verify server certificate
    log_info "Verifying server certificate..."
    openssl x509 -noout -text -in server-cert.pem | head -20
    
    # Verify certificate chain
    log_info "Verifying certificate chain..."
    openssl verify -CAfile ca-cert.pem server-cert.pem
    
    log_info "Server certificate generated successfully"
}

generate_client_certificates() {
    log_step "Generating client certificates..."
    
    cd "$SSL_DIR/client"
    
    # List of clients to generate certificates for
    clients=("admin" "analyst" "kibana" "logstash" "filebeat")
    
    for client in "${clients[@]}"; do
        log_info "Generating certificate for client: $client"
        
        # Generate client private key
        openssl genrsa -out "${client}-key.pem" $KEY_SIZE
        chmod 400 "${client}-key.pem"
        
        # Generate client certificate signing request
        openssl req -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=$OU/CN=${client}.$LAB_DOMAIN" \
            -new -key "${client}-key.pem" -out "${client}.csr"
        
        # Generate client certificate
        openssl x509 -req -days $CERT_VALIDITY_DAYS -sha256 -in "${client}.csr" \
            -CA ../ca-cert.pem -CAkey ../ca-key.pem -out "${client}-cert.pem" -CAcreateserial
        
        chmod 444 "${client}-cert.pem"
        
        # Clean up CSR
        rm "${client}.csr"
        
        # Verify client certificate
        openssl verify -CAfile ../ca-cert.pem "${client}-cert.pem"
        
        log_info "Client certificate for $client generated successfully"
    done
}

generate_dhparam() {
    log_step "Generating Diffie-Hellman parameters..."
    
    cd "$SSL_DIR"
    
    # Generate DH parameters for enhanced security
    openssl dhparam -out dhparam.pem 2048
    chmod 444 dhparam.pem
    
    log_info "Diffie-Hellman parameters generated successfully"
}

create_certificate_bundles() {
    log_step "Creating certificate bundles..."
    
    cd "$SSL_DIR"
    
    # Create full certificate chain for server
    cat server-cert.pem ca-cert.pem > server-fullchain.pem
    chmod 444 server-fullchain.pem
    
    # Create PKCS#12 bundles for easy distribution
    for client in admin analyst kibana logstash filebeat; do
        openssl pkcs12 -export \
            -out "client/${client}.p12" \
            -inkey "client/${client}-key.pem" \
            -in "client/${client}-cert.pem" \
            -certfile ca-cert.pem \
            -passout pass:wazuh-lab-2024
        chmod 400 "client/${client}.p12"
    done
    
    log_info "Certificate bundles created successfully"
}

set_permissions() {
    log_step "Setting proper file permissions..."
    
    # Set ownership to root
    chown -R root:root "$SSL_DIR"
    
    # Set directory permissions
    find "$SSL_DIR" -type d -exec chmod 755 {} \;
    
    # Set private key permissions
    find "$SSL_DIR" -name "*-key.pem" -exec chmod 600 {} \;
    find "$SSL_DIR" -name "*.p12" -exec chmod 600 {} \;
    
    # Set certificate permissions
    find "$SSL_DIR" -name "*-cert.pem" -exec chmod 644 {} \;
    find "$SSL_DIR" -name "ca-cert.pem" -exec chmod 644 {} \;
    
    log_info "File permissions set successfully"
}

create_certificate_info() {
    log_step "Creating certificate information file..."
    
    cat > "$SSL_DIR/certificate-info.txt" << EOF
# Wazuh SOC Lab SSL Certificate Information
# Generated on: $(date)

## Certificate Authority (CA)
Subject: $(openssl x509 -noout -subject -in "$SSL_DIR/ca-cert.pem")
Valid From: $(openssl x509 -noout -startdate -in "$SSL_DIR/ca-cert.pem")
Valid Until: $(openssl x509 -noout -enddate -in "$SSL_DIR/ca-cert.pem")
Fingerprint (SHA256): $(openssl x509 -noout -fingerprint -sha256 -in "$SSL_DIR/ca-cert.pem")

## Server Certificate
Subject: $(openssl x509 -noout -subject -in "$SSL_DIR/server-cert.pem")
Valid From: $(openssl x509 -noout -startdate -in "$SSL_DIR/server-cert.pem")
Valid Until: $(openssl x509 -noout -enddate -in "$SSL_DIR/server-cert.pem")
Fingerprint (SHA256): $(openssl x509 -noout -fingerprint -sha256 -in "$SSL_DIR/server-cert.pem")

## File Locations
CA Certificate: $SSL_DIR/ca-cert.pem
CA Private Key: $SSL_DIR/ca-key.pem (KEEP SECURE!)
Server Certificate: $SSL_DIR/server-cert.pem
Server Private Key: $SSL_DIR/server-key.pem (KEEP SECURE!)
Server Full Chain: $SSL_DIR/server-fullchain.pem
DH Parameters: $SSL_DIR/dhparam.pem

## Client Certificates
EOF

    for client in admin analyst kibana logstash filebeat; do
        echo "Client ($client): $SSL_DIR/client/${client}-cert.pem" >> "$SSL_DIR/certificate-info.txt"
        echo "Client ($client) Key: $SSL_DIR/client/${client}-key.pem" >> "$SSL_DIR/certificate-info.txt"
        echo "Client ($client) PKCS#12: $SSL_DIR/client/${client}.p12 (password: wazuh-lab-2024)" >> "$SSL_DIR/certificate-info.txt"
        echo "" >> "$SSL_DIR/certificate-info.txt"
    done
    
    cat >> "$SSL_DIR/certificate-info.txt" << EOF

## Usage Examples

### Nginx/Apache Configuration
ssl_certificate $SSL_DIR/server-fullchain.pem;
ssl_certificate_key $SSL_DIR/server-key.pem;
ssl_dhparam $SSL_DIR/dhparam.pem;

### Elasticsearch Configuration
xpack.security.http.ssl.certificate: $SSL_DIR/server-cert.pem
xpack.security.http.ssl.key: $SSL_DIR/server-key.pem
xpack.security.http.ssl.certificate_authorities: $SSL_DIR/ca-cert.pem

### Kibana Configuration
server.ssl.certificate: $SSL_DIR/server-cert.pem
server.ssl.key: $SSL_DIR/server-key.pem
elasticsearch.ssl.certificateAuthorities: [$SSL_DIR/ca-cert.pem]

### Curl Testing
curl -k --cert $SSL_DIR/client/admin-cert.pem --key $SSL_DIR/client/admin-key.pem https://$WAZUH_MANAGER_IP:9200

## Security Notes
- Keep private keys secure and never share them
- Regularly monitor certificate expiration dates
- Use strong passwords for PKCS#12 files
- Consider certificate rotation policies for production environments

EOF
    
    chmod 644 "$SSL_DIR/certificate-info.txt"
    
    log_info "Certificate information file created"
}

verify_certificates() {
    log_step "Performing final certificate verification..."
    
    local errors=0
    
    # Verify CA certificate
    if openssl x509 -noout -text -in "$SSL_DIR/ca-cert.pem" >/dev/null 2>&1; then
        log_info "CA certificate is valid"
    else
        log_error "CA certificate is invalid"
        ((errors++))
    fi
    
    # Verify server certificate
    if openssl verify -CAfile "$SSL_DIR/ca-cert.pem" "$SSL_DIR/server-cert.pem" >/dev/null 2>&1; then
        log_info "Server certificate is valid"
    else
        log_error "Server certificate is invalid"
        ((errors++))
    fi
    
    # Verify client certificates
    for client in admin analyst kibana logstash filebeat; do
        if openssl verify -CAfile "$SSL_DIR/ca-cert.pem" "$SSL_DIR/client/${client}-cert.pem" >/dev/null 2>&1; then
            log_info "Client certificate for $client is valid"
        else
            log_error "Client certificate for $client is invalid"
            ((errors++))
        fi
    done
    
    if [[ $errors -eq 0 ]]; then
        log_info "All certificates verified successfully"
    else
        log_error "Certificate verification completed with $errors errors"
        return 1
    fi
}

display_summary() {
    echo -e "${GREEN}"
    echo "=========================================================="
    echo "    SSL Certificate Generation Complete!"
    echo "=========================================================="
    echo "SSL Directory: $SSL_DIR"
    echo "Certificate Validity: $CERT_VALIDITY_DAYS days"
    echo "Key Size: $KEY_SIZE bits"
    echo ""
    echo "Generated Certificates:"
    echo "• Certificate Authority (CA)"
    echo "• Server Certificate (wazuh-manager.$LAB_DOMAIN)"
    echo "• Client Certificates (admin, analyst, kibana, logstash, filebeat)"
    echo "• PKCS#12 Bundles"
    echo "• Diffie-Hellman Parameters"
    echo ""
    echo "Key Files:"
    echo "• CA Certificate: $SSL_DIR/ca-cert.pem"
    echo "• Server Certificate: $SSL_DIR/server-cert.pem"
    echo "• Server Private Key: $SSL_DIR/server-key.pem"
    echo "• Certificate Info: $SSL_DIR/certificate-info.txt"
    echo ""
    echo "Next Steps:"
    echo "1. Configure Wazuh Manager to use SSL certificates"
    echo "2. Configure Elasticsearch with SSL settings"
    echo "3. Configure Kibana with SSL settings"
    echo "4. Distribute client certificates to agents"
    echo "5. Test SSL connectivity"
    echo ""
    echo "Log File: $LOG_FILE"
    echo "=========================================================="
    echo -e "${NC}"
}

main() {
    print_banner
    check_root
    check_dependencies
    create_directories
    generate_ca_certificate
    generate_server_certificate
    generate_client_certificates
    generate_dhparam
    create_certificate_bundles
    set_permissions
    create_certificate_info
    verify_certificates
    display_summary
}

# Trap errors
trap 'log_error "Certificate generation failed at line $LINENO"' ERR

# Run main function
main "$@"