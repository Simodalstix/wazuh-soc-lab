# Wazuh SOC Lab Implementation Guide

## Overview

This comprehensive guide walks you through the complete implementation of the Wazuh SOC Lab environment. The lab is designed for intermediate-level cybersecurity analyst training and provides hands-on experience with enterprise-grade SIEM operations.

## Prerequisites

### Hardware Requirements

- **Host System**: 16GB+ RAM, 8+ CPU cores, 300GB+ available storage
- **Hypervisor**: VMware Workstation Pro/ESXi or VirtualBox
- **Network**: Isolated lab network (recommended)

### Software Requirements

- **Hypervisor Software**: VMware Workstation 16+ or VirtualBox 6.1+
- **Operating Systems**:
  - Ubuntu 22.04 LTS Server ISO
  - Windows Server 2019 ISO
  - RHEL 9 ISO (or CentOS Stream 9)
  - pfSense CE ISO
- **Management Tools**: SSH client, RDP client, web browser

### Knowledge Prerequisites

- Basic Linux administration
- Windows Server administration
- Networking fundamentals (TCP/IP, DNS, DHCP)
- Basic understanding of security concepts

## Phase 1: Network Infrastructure Setup

### 1.1 Virtual Network Configuration

Create three isolated virtual networks in your hypervisor:

#### Management Network (192.168.1.0/24)

```
Network Type: Host-Only or Internal
Gateway: 192.168.1.1 (pfSense)
DNS: 192.168.3.10 (Windows DC)
Purpose: Management and SIEM infrastructure
```

#### DMZ Network (192.168.2.0/24)

```
Network Type: Internal
Gateway: 192.168.1.1 (pfSense)
DNS: 192.168.3.10 (Windows DC)
Purpose: Public-facing services (web server)
```

#### Internal Network (192.168.3.0/24)

```
Network Type: Internal
Gateway: 192.168.1.1 (pfSense)
DNS: 192.168.3.10 (Windows DC)
Purpose: Internal corporate services
```

### 1.2 pfSense Firewall Setup

1. **Create pfSense VM**:

   - RAM: 1GB
   - CPU: 1 core
   - Storage: 20GB
   - Network Adapters: 4 (WAN + 3 LANs)

2. **Initial Configuration**:

   ```bash
   # Console setup
   WAN Interface: em0 (NAT/Bridged to internet)
   LAN Interface: em1 (Management - 192.168.1.0/24)
   OPT1 Interface: em2 (DMZ - 192.168.2.0/24)
   OPT2 Interface: em3 (Internal - 192.168.3.0/24)
   ```

3. **Web Configuration** (https://192.168.1.1):
   - Enable interfaces and assign IP addresses
   - Configure DHCP for each network
   - Set up firewall rules for inter-VLAN communication
   - Enable logging to syslog (192.168.1.10:514)

### 1.3 Network Validation

Verify network connectivity between all segments:

```bash
# Test from each VM
ping 192.168.1.1    # pfSense gateway
ping 192.168.1.10   # Wazuh Manager
ping 192.168.3.10   # Windows DC
nslookup lab.local  # DNS resolution
```

## Phase 2: Core Infrastructure Deployment

### 2.1 Windows Server 2019 Domain Controller

#### VM Specifications

- **RAM**: 4GB
- **CPU**: 2 cores
- **Storage**: 60GB
- **Network**: Internal Network (192.168.3.10/24)

#### Installation Steps

1. **Install Windows Server 2019**:

   - Choose "Windows Server 2019 Standard (Desktop Experience)"
   - Set Administrator password: `P@ssw0rd123!`

2. **Configure Network**:

   ```powershell
   # Set static IP
   New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.3.10 -PrefixLength 24 -DefaultGateway 192.168.1.1
   Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1,8.8.8.8
   ```

3. **Run Domain Configuration Script**:

   ```powershell
   # Copy and run the domain configuration script
   .\scripts\installation\configure-domain.ps1
   ```

4. **Post-Installation Verification**:
   ```powershell
   # Verify AD services
   Get-Service ADWS,DNS,Netlogon
   Get-ADDomain
   Get-ADUser -Filter *
   ```

### 2.2 Wazuh Manager Installation

#### VM Specifications

- **RAM**: 6GB
- **CPU**: 2 cores
- **Storage**: 100GB
- **Network**: Management Network (192.168.1.10/24)

#### Installation Steps

1. **Install Ubuntu 22.04 Server**:

   - Minimal installation
   - Configure static IP: 192.168.1.10/24
   - Enable SSH server

2. **Run Wazuh Installation Script**:

   ```bash
   # Make script executable
   chmod +x scripts/installation/install-wazuh-manager.sh

   # Run installation
   sudo ./scripts/installation/install-wazuh-manager.sh
   ```

3. **Post-Installation Configuration**:

   ```bash
   # Verify services
   sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard

   # Check API connectivity
   curl -k -X GET "https://192.168.1.10:55000/"

   # Access dashboard
   # URL: https://192.168.1.10
   # Credentials: admin / <password from installation>
   ```

### 2.3 Ubuntu Web Server (DVWA)

#### VM Specifications

- **RAM**: 3GB
- **CPU**: 2 cores
- **Storage**: 40GB
- **Network**: DMZ Network (192.168.2.10/24)

#### Installation Steps

1. **Install Ubuntu 22.04 Server**:

   ```bash
   # Update system
   sudo apt update && sudo apt upgrade -y

   # Install LAMP stack
   sudo apt install apache2 mysql-server php php-mysql php-gd libapache2-mod-php -y
   ```

2. **Install DVWA**:

   ```bash
   # Download DVWA
   cd /var/www/html
   sudo git clone https://github.com/digininja/DVWA.git dvwa

   # Configure permissions
   sudo chown -R www-data:www-data /var/www/html/dvwa
   sudo chmod -R 755 /var/www/html/dvwa

   # Configure database
   sudo mysql -e "CREATE DATABASE dvwa; CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'password'; GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost'; FLUSH PRIVILEGES;"
   ```

3. **Configure DVWA**:

   ```bash
   # Copy configuration
   sudo cp /var/www/html/dvwa/config/config.inc.php.dist /var/www/html/dvwa/config/config.inc.php

   # Edit configuration
   sudo nano /var/www/html/dvwa/config/config.inc.php
   # Set database credentials: dvwa/password
   ```

### 2.4 RHEL 9 Database Server

#### VM Specifications

- **RAM**: 2GB
- **CPU**: 1 core
- **Storage**: 40GB
- **Network**: Internal Network (192.168.3.20/24)

#### Installation Steps

1. **Install RHEL 9**:

   ```bash
   # Register system (if using RHEL)
   sudo subscription-manager register

   # Update system
   sudo dnf update -y

   # Install MySQL
   sudo dnf install mysql-server -y
   sudo systemctl enable --now mysqld
   ```

2. **Configure MySQL**:

   ```bash
   # Secure installation
   sudo mysql_secure_installation

   # Create lab database
   sudo mysql -e "CREATE DATABASE labdb; CREATE USER 'labuser'@'%' IDENTIFIED BY 'LabPassword123!'; GRANT ALL PRIVILEGES ON labdb.* TO 'labuser'@'%'; FLUSH PRIVILEGES;"
   ```

## Phase 3: Agent Deployment

### 3.1 Automated Deployment with Ansible

1. **Configure Ansible Inventory**:

   ```bash
   # Edit inventory file
   cp ansible/inventory/hosts.yml.example ansible/inventory/hosts.yml
   # Update IP addresses to match your deployment
   ```

2. **Deploy All Agents**:

   ```bash
   # Run complete deployment
   ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/site.yml
   ```

3. **Deploy Individual Components**:

   ```bash
   # Linux agents only
   ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/deploy-linux-agents.yml

   # Windows agents only
   ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/deploy-windows-agents.yml
   ```

### 3.2 Manual Agent Installation

#### Linux Agent Installation

1. **Download and Install**:

   ```bash
   # Ubuntu/Debian
   wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.0-1_amd64.deb
   sudo dpkg -i wazuh-agent_4.7.0-1_amd64.deb

   # RHEL/CentOS
   sudo rpm -ivh https://packages.wazuh.com/4.x/yum/wazuh-agent-4.7.0-1.x86_64.rpm
   ```

2. **Configure Agent**:

   ```bash
   # Edit configuration
   sudo nano /var/ossec/etc/ossec.conf
   # Set manager IP to 192.168.1.10

   # Register agent
   sudo /var/ossec/bin/agent-auth -m 192.168.1.10

   # Start agent
   sudo systemctl enable --now wazuh-agent
   ```

#### Windows Agent Installation

1. **Download MSI Installer**:

   - Download from: https://packages.wazuh.com/4.x/windows/
   - Version: wazuh-agent-4.7.0-1.msi

2. **Install with Parameters**:

   ```cmd
   msiexec /i wazuh-agent-4.7.0-1.msi /quiet WAZUH_MANAGER="192.168.1.10" WAZUH_REGISTRATION_SERVER="192.168.1.10"
   ```

3. **Register and Start**:
   ```cmd
   "C:\Program Files (x86)\ossec-agent\agent-auth.exe" -m 192.168.1.10
   net start WazuhSvc
   ```

## Phase 4: Detection Configuration

### 4.1 Custom Rules Development

1. **Create Custom Rules File**:

   ```bash
   sudo nano /var/ossec/etc/rules/local_rules.xml
   ```

2. **Add SOC Lab Rules**:
   ```xml
   <!-- SOC Lab Custom Rules -->
   <group name="soc_lab,">
     <!-- SSH Brute Force Detection -->
     <rule id="100001" level="10">
       <if_matched_sid>5720</if_matched_sid>
       <same_source_ip />
       <description>SSH brute force attack detected</description>
       <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
     </rule>

     <!-- Web Application Attack Detection -->
     <rule id="100002" level="12">
       <if_sid>31100</if_sid>
       <url>select|union|insert|delete|drop|create|alter|exec</url>
       <description>SQL injection attack detected</description>
       <group>web,attack,sql_injection,</group>
     </rule>
   </group>
   ```

### 4.2 File Integrity Monitoring

1. **Configure FIM for Web Server**:

   ```xml
   <syscheck>
     <directories realtime="yes">/var/www/html</directories>
     <directories>/etc/apache2</directories>
     <directories>/etc/mysql</directories>
   </syscheck>
   ```

2. **Configure FIM for Windows**:
   ```xml
   <syscheck>
     <directories realtime="yes">C:\inetpub\wwwroot</directories>
     <windows_registry>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</windows_registry>
   </syscheck>
   ```

### 4.3 Log Analysis Configuration

1. **Apache Log Monitoring**:

   ```xml
   <localfile>
     <log_format>apache</log_format>
     <location>/var/log/apache2/access.log</location>
   </localfile>
   ```

2. **Windows Event Log Monitoring**:
   ```xml
   <localfile>
     <location>Security</location>
     <log_format>eventlog</log_format>
   </localfile>
   ```

## Phase 5: Dashboard Configuration

### 5.1 Access Wazuh Dashboard

1. **Login to Dashboard**:

   - URL: https://192.168.1.10
   - Username: admin
   - Password: (from installation output)

2. **Verify Agent Status**:
   - Navigate to "Agents" section
   - Confirm all agents are active and reporting

### 5.2 Create Custom Dashboards

1. **SOC Overview Dashboard**:

   - Alert summary by severity
   - Top attack types
   - Agent status overview
   - Geographic threat map

2. **Network Security Dashboard**:

   - Firewall activity
   - Port scan detection
   - Network anomalies
   - Bandwidth utilization

3. **Web Application Security Dashboard**:
   - HTTP status codes
   - Attack vectors
   - Top targeted URLs
   - Geographic access patterns

## Phase 6: Testing and Validation

### 6.1 Connectivity Testing

```bash
# Test agent connectivity
sudo /var/ossec/bin/wazuh-control status

# Test log flow
tail -f /var/ossec/logs/ossec.log

# Test API connectivity
curl -k -X GET "https://192.168.1.10:55000/agents"
```

### 6.2 Detection Testing

1. **Test SSH Brute Force Detection**:

   ```bash
   # From external system
   for i in {1..10}; do ssh invalid@192.168.2.10; done
   ```

2. **Test Web Application Attack Detection**:

   ```bash
   # SQL injection test
   curl "http://192.168.2.10/dvwa/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit"
   ```

3. **Test File Integrity Monitoring**:
   ```bash
   # Modify monitored file
   sudo touch /var/www/html/test_file.txt
   ```

### 6.3 Performance Validation

1. **Check System Resources**:

   ```bash
   # Memory usage
   free -h

   # CPU usage
   top

   # Disk usage
   df -h
   ```

2. **Monitor Log Processing**:
   ```bash
   # Check event processing rate
   grep "Total events processed" /var/ossec/logs/ossec.log
   ```

## Troubleshooting

### Common Issues

1. **Agent Not Connecting**:

   - Check firewall rules (ports 1514, 1515)
   - Verify manager IP configuration
   - Check agent registration

2. **Dashboard Not Accessible**:

   - Verify wazuh-dashboard service status
   - Check port 443 accessibility
   - Review SSL certificate configuration

3. **No Logs Appearing**:
   - Verify log file permissions
   - Check agent configuration
   - Review manager log processing

### Log Locations

```bash
# Wazuh Manager
/var/ossec/logs/ossec.log
/var/ossec/logs/alerts/alerts.log

# Elasticsearch
/var/log/wazuh-indexer/wazuh-cluster.log

# Dashboard
/var/log/wazuh-dashboard/wazuh-dashboard.log
```

## Next Steps

1. **Advanced Configuration**:

   - Custom rule development
   - Integration with external tools
   - Advanced correlation rules

2. **Attack Simulation**:

   - Run provided attack scenarios
   - Develop custom attack simulations
   - Test incident response procedures

3. **Performance Optimization**:
   - Tune Elasticsearch settings
   - Optimize rule processing
   - Configure log retention policies

## Support Resources

- **Wazuh Documentation**: https://documentation.wazuh.com/
- **Community Forum**: https://wazuh.com/community/
- **GitHub Repository**: https://github.com/wazuh/wazuh
- **Lab-Specific Issues**: See `docs/troubleshooting.md`

---

_This implementation guide provides a comprehensive walkthrough for deploying the Wazuh SOC Lab. For additional details and advanced configurations, refer to the specific documentation files in the `docs/` directory._
