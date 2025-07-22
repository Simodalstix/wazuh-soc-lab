# Wazuh SOC Lab - Enterprise Security Monitoring Training Environment

## Overview

This project provides a comprehensive SOC (Security Operations Center) lab environment designed for intermediate-level cybersecurity analyst training. The lab simulates real-world enterprise monitoring and threat detection capabilities using Wazuh as the primary SIEM platform, integrated with ELK stack components for enhanced log analysis and visualization.

## Learning Objectives

- **SIEM Operations**: Master Wazuh configuration, rule management, and alert correlation
- **Threat Detection**: Identify and analyze various attack vectors and techniques
- **Incident Response**: Develop structured investigation workflows and documentation
- **Log Analysis**: Understand log sources, parsing, and correlation across multiple systems
- **Dashboard Creation**: Build effective security visualizations and reporting
- **Automation**: Implement configuration management and deployment automation

## Architecture Summary

### Network Topology

```
Management Network (192.168.1.0/24)
├── pfSense Firewall (192.168.1.1) - Gateway/IDS
└── Wazuh Manager + ELK (192.168.1.10) - SIEM + Dashboard

DMZ Network (192.168.2.0/24)
└── Ubuntu Web Server (192.168.2.10) - Apache + DVWA + Agent

Internal Network (192.168.3.0/24)
├── Windows Server 2019 (192.168.3.10) - Domain Controller + Agent
└── RHEL 9 Database (192.168.3.20) - MySQL + Agent
```

### Resource Requirements

- **Total RAM**: 16GB
- **Total CPU**: 8 cores
- **Total Storage**: 260GB
- **Hypervisor**: VMware Workstation/ESXi or VirtualBox

## Quick Start Guide

### Prerequisites

- Hypervisor with 16GB+ RAM available
- Basic understanding of Linux administration
- Familiarity with networking concepts
- Windows Server administration knowledge

### 1. Environment Setup

```bash
# Clone the repository
git clone <repository-url>
cd wazuh-soc-lab

# Review architecture documentation
cat docs/SOC-Lab-Architecture.md

# Check implementation checklist
cat SOC-Lab-Implementation-Checklist.md
```

### 2. VM Deployment

Follow the implementation checklist for step-by-step VM setup:

1. **Day 1**: Core infrastructure (pfSense, Wazuh Manager, target systems)
2. **Day 2**: Agent deployment and detection configuration

### 3. Automated Deployment (Optional)

```bash
# Configure Ansible inventory
cp ansible/inventory/hosts.yml.example ansible/inventory/hosts.yml
# Edit with your VM IP addresses

# Deploy Wazuh agents
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/deploy-agents.yml

# Configure monitoring
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/configure-monitoring.yml
```

### 4. Access Points

- **Wazuh Dashboard**: https://192.168.1.10
- **DVWA**: http://192.168.2.10/dvwa
- **pfSense**: https://192.168.1.1

## Project Structure

```
wazuh-soc-lab/
├── README.md                          # This file
├── SOC-Lab-Architecture.md            # Detailed architecture documentation
├── SOC-Lab-Implementation-Checklist.md # Step-by-step implementation guide
├── docs/                              # Additional documentation
│   ├── implementation-guide.md        # Detailed setup instructions
│   ├── troubleshooting.md            # Common issues and solutions
│   └── attack-scenarios.md           # Attack simulation documentation
├── ansible/                          # Automation and configuration management
│   ├── inventory/                    # Environment-specific inventories
│   ├── playbooks/                    # Ansible playbooks
│   ├── roles/                        # Reusable Ansible roles
│   ├── group_vars/                   # Group-specific variables
│   └── host_vars/                    # Host-specific variables
├── configs/                          # Configuration templates
│   ├── wazuh/                        # Wazuh manager and agent configs
│   ├── filebeat/                     # Log shipping configurations
│   ├── kibana/                       # Dashboard and visualization configs
│   └── system/                       # System hardening configurations
├── scripts/                          # Automation scripts
│   ├── installation/                 # Installation and setup scripts
│   ├── backup/                       # Backup and recovery scripts
│   └── monitoring/                   # Health monitoring scripts
├── dashboards/                       # Custom Wazuh/Kibana dashboards
└── attack-simulations/               # Attack scenario scripts and documentation
```

## Key Features

### Detection Capabilities

- **Web Application Attacks**: SQL injection, XSS, directory traversal
- **Network Reconnaissance**: Port scanning, service enumeration
- **Privilege Escalation**: Linux and Windows privilege abuse
- **File Integrity Monitoring**: Configuration and web file changes
- **Authentication Monitoring**: Failed logins, privilege escalation

### Monitoring Sources

- **pfSense**: Firewall logs, Suricata IDS alerts
- **Ubuntu Web**: Apache logs, system authentication, FIM
- **Windows Server**: Security events, Active Directory, system logs
- **RHEL Database**: Authentication, database logs, system events

### Automation Features

- **Agent Deployment**: Automated Wazuh agent installation
- **Configuration Management**: Consistent configurations across systems
- **Health Monitoring**: Agent connectivity and system status
- **Backup Automation**: Scheduled backups of critical configurations

## Attack Simulation Scenarios

### Scenario 1: Web Application Attack Chain

1. Network reconnaissance (nmap scanning)
2. Web application exploitation (SQL injection)
3. Persistence establishment (web shell upload)
4. Privilege escalation attempts

### Scenario 2: Network Lateral Movement

1. Initial web server compromise
2. Internal network discovery
3. Service enumeration and probing
4. Credential-based attacks

## Training Modules

### Module 1: SIEM Fundamentals

- Wazuh architecture and components
- Log source configuration
- Basic rule creation and testing

### Module 2: Threat Detection

- Attack pattern recognition
- Alert correlation and analysis
- False positive reduction

### Module 3: Incident Response

- Alert triage and prioritization
- Investigation workflows
- Documentation and reporting

### Module 4: Advanced Analytics

- Custom dashboard creation
- Threat hunting techniques
- Performance optimization

## Support and Documentation

### Getting Help

- Review [`docs/troubleshooting.md`](docs/troubleshooting.md) for common issues
- Check the implementation checklist for step-by-step guidance
- Consult Wazuh official documentation for advanced configurations

### Contributing

- Follow the project structure when adding new components
- Document any custom configurations or modifications
- Test changes in a development environment first

### Maintenance

- Regular updates of Wazuh components
- Periodic review and update of detection rules
- Backup verification and recovery testing

## Security Considerations

### Lab Environment Only

⚠️ **Warning**: This lab contains intentionally vulnerable applications and configurations. Do not deploy in production environments or networks with sensitive data.

### Hardening Recommendations

- Use strong passwords for all accounts
- Enable TLS encryption for all communications
- Implement network segmentation
- Regular security updates and patching

## License and Disclaimer

This project is provided for educational purposes only. Users are responsible for ensuring compliance with applicable laws and regulations when using this lab environment.

---

**Version**: 1.0  
**Last Updated**: 2025-01-22  
**Compatibility**: Wazuh 4.7+, Ubuntu 22.04, Windows Server 2019, RHEL 9
