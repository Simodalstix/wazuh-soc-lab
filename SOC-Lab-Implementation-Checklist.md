# SOC Lab Implementation Checklist - 1-2 Day Build

## Day 1: Core Infrastructure Setup (4-6 hours)

### Phase 1: Network and VM Preparation (1 hour)

- [ ] **Verify VM Resources**: Confirm 16GB RAM, 8 cores available
- [ ] **Network Configuration**: Set up VMware virtual networks
  - [ ] Management Network: 192.168.1.0/24
  - [ ] DMZ Network: 192.168.2.0/24
  - [ ] Internal Network: 192.168.3.0/24
- [ ] **pfSense Setup**: Configure firewall and basic rules
  - [ ] Set interfaces: WAN, LAN, DMZ, Internal
  - [ ] Enable logging to 192.168.1.10:514
  - [ ] Basic firewall rules for lab traffic

### Phase 2: Wazuh Manager Installation (2-3 hours)

- [ ] **Ubuntu 22.04 Setup** (192.168.1.10)

  - [ ] Install Ubuntu with 6GB RAM, 2 cores
  - [ ] Update system: `sudo apt update && sudo apt upgrade -y`
  - [ ] Set static IP: 192.168.1.10/24

- [ ] **Wazuh All-in-One Installation**

  ```bash
  # Download and run Wazuh installer
  curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
  sudo bash ./wazuh-install.sh -a
  ```

  - [ ] Save admin credentials displayed after installation
  - [ ] Verify dashboard access: https://192.168.1.10
  - [ ] Test Wazuh manager status: `sudo systemctl status wazuh-manager`

- [ ] **Basic Wazuh Configuration**
  - [ ] Configure syslog reception: Edit `/var/ossec/etc/ossec.conf`
  - [ ] Add remote syslog block for pfSense logs
  - [ ] Restart Wazuh manager: `sudo systemctl restart wazuh-manager`

### Phase 3: Target Systems Setup (1-2 hours)

- [ ] **Ubuntu Web Server** (192.168.2.10)

  - [ ] Install Ubuntu with 3GB RAM, 2 cores
  - [ ] Install Apache: `sudo apt install apache2 php mysql-server -y`
  - [ ] Download DVWA: `git clone https://github.com/digininja/DVWA.git /var/www/html/dvwa`
  - [ ] Configure DVWA database and permissions

- [ ] **Windows Server 2019** (192.168.3.10)

  - [ ] Install Windows Server with 4GB RAM, 2 cores
  - [ ] Set static IP: 192.168.3.10/24
  - [ ] Install Active Directory Domain Services
  - [ ] Create domain: lab.local

- [ ] **RHEL 9 Database** (192.168.3.20)
  - [ ] Install RHEL with 2GB RAM, 1 core
  - [ ] Set static IP: 192.168.3.20/24
  - [ ] Install MySQL: `sudo dnf install mysql-server -y`
  - [ ] Start and enable MySQL service

## Day 2: Agent Deployment and Detection Setup (4-6 hours)

### Phase 4: Wazuh Agent Deployment (2 hours)

#### Linux Agents (Ubuntu & RHEL)

- [ ] **Download Wazuh Agent**

  ```bash
  # On each Linux system
  wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.0-1_amd64.deb
  sudo dpkg -i wazuh-agent_4.7.0-1_amd64.deb
  ```

- [ ] **Configure Agents**

  ```bash
  # Edit /var/ossec/etc/ossec.conf on each agent
  sudo nano /var/ossec/etc/ossec.conf
  # Set manager IP to 192.168.1.10
  ```

- [ ] **Register and Start Agents**
  ```bash
  # On Wazuh Manager - register each agent
  sudo /var/ossec/bin/manage_agents
  # On each agent - add key and start
  sudo /var/ossec/bin/manage_agents
  sudo systemctl enable wazuh-agent
  sudo systemctl start wazuh-agent
  ```

#### Windows Agent

- [ ] **Download Windows Agent**: Get MSI from Wazuh downloads
- [ ] **Install Agent**: Run MSI with manager IP 192.168.1.10
- [ ] **Register Agent**: Use manage_agents on manager
- [ ] **Start Service**: Start Wazuh agent service

- [ ] **Verify All Agents**: Check agent status in Wazuh dashboard

### Phase 5: Detection Rules and Monitoring (1-2 hours)

- [ ] **Web Application Monitoring**

  - [ ] Configure Apache log monitoring on Ubuntu web server
  - [ ] Add custom rules for SQL injection detection
  - [ ] Test with DVWA SQL injection attempts

- [ ] **Network Monitoring**

  - [ ] Verify pfSense syslog reception in Wazuh
  - [ ] Configure port scan detection rules
  - [ ] Test with nmap scan from external system

- [ ] **Windows Monitoring**

  - [ ] Configure Windows Event Log collection
  - [ ] Set up authentication monitoring
  - [ ] Test with failed login attempts

- [ ] **File Integrity Monitoring**
  - [ ] Configure FIM for web directories
  - [ ] Configure FIM for system configuration files
  - [ ] Test by modifying monitored files

### Phase 6: Dashboard Configuration (1 hour)

- [ ] **SOC Dashboard Setup**

  - [ ] Access Wazuh dashboard: https://192.168.1.10
  - [ ] Configure alert views and filters
  - [ ] Set up security event dashboards
  - [ ] Create custom visualizations for lab data

- [ ] **Alert Testing**
  - [ ] Generate test alerts from each system
  - [ ] Verify alert correlation and severity
  - [ ] Test dashboard responsiveness and data flow

### Phase 7: Attack Simulation Setup (1 hour)

- [ ] **Vulnerable Applications**

  - [ ] Verify DVWA installation and configuration
  - [ ] Test SQL injection detection
  - [ ] Test XSS detection capabilities

- [ ] **Attack Tools Setup**

  - [ ] Install nmap on external system for port scanning
  - [ ] Prepare basic attack scripts
  - [ ] Test detection capabilities with simulated attacks

- [ ] **Documentation**
  - [ ] Document admin credentials and access methods
  - [ ] Create quick reference for common tasks
  - [ ] Note any configuration customizations

## Quick Verification Checklist

### System Health Check

- [ ] All VMs running and accessible
- [ ] Network connectivity between all systems
- [ ] Wazuh dashboard accessible and responsive
- [ ] All agents showing as active in manager

### Log Flow Verification

- [ ] pfSense logs appearing in Wazuh
- [ ] Apache logs from web server visible
- [ ] Windows event logs being collected
- [ ] Database server logs flowing properly

### Detection Testing

- [ ] Port scan detection working
- [ ] Web application attack detection functional
- [ ] Authentication monitoring operational
- [ ] File integrity monitoring active

### Dashboard Functionality

- [ ] Real-time alerts displaying
- [ ] Search functionality working
- [ ] Custom dashboards accessible
- [ ] Export/reporting capabilities functional

## Time-Saving Tips

### Parallel Tasks

- Install agents on multiple systems simultaneously
- Configure basic monitoring while agents are installing
- Set up attack simulations while verifying log flows

### Quick Wins

- Use Wazuh all-in-one installer for fastest setup
- Start with default rules before customizing
- Focus on high-impact detection scenarios first
- Document as you go to avoid backtracking

### Troubleshooting Quick Fixes

- **Agent not connecting**: Check firewall rules and IP configuration
- **No logs appearing**: Verify agent configuration and restart services
- **Dashboard not accessible**: Check Wazuh services status and restart if needed
- **Performance issues**: Monitor resource usage and adjust VM allocations

## Post-Implementation Tasks (Optional)

### Ansible Automation (Day 3+)

- [ ] Set up Ansible control node
- [ ] Create agent deployment playbooks
- [ ] Automate configuration management
- [ ] Implement backup automation

### Advanced Features (Week 2+)

- [ ] Custom rule development
- [ ] Advanced correlation rules
- [ ] Threat intelligence integration
- [ ] Compliance reporting setup

---

**Expected Timeline**: 8-12 hours total across 1-2 days
**Critical Path**: Wazuh Manager → Agent Deployment → Basic Detection → Testing
**Success Criteria**: All systems monitored, basic attacks detected, dashboard functional

_Focus on getting the core functionality working first, then iterate and improve!_
