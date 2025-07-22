# Wazuh SOC Lab Architecture Documentation

## Executive Summary

This document outlines a comprehensive SOC lab architecture designed for intermediate-level cybersecurity analyst training. The lab simulates real-world enterprise monitoring and threat detection capabilities using Wazuh as the primary SIEM platform, integrated with ELK stack components for enhanced log analysis and visualization.

## Architecture Overview

### Network Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                    Management Network (192.168.1.0/24)         │
│  ┌─────────────────┐              ┌─────────────────────────────┐│
│  │   pfSense FW    │              │    Wazuh Manager + ELK      ││
│  │   192.168.1.1   │              │      192.168.1.10           ││
│  │   Gateway/IDS   │              │   (SIEM + Dashboard)        ││
│  └─────────────────┘              └─────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
           │                                      ▲
           │                                      │ Logs & Alerts
           ▼                                      │
┌─────────────────────────────────────────────────────────────────┐
│                      DMZ Network (192.168.2.0/24)              │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │           Ubuntu Web Server (192.168.2.10)                 ││
│  │         Apache + PHP + DVWA + Wazuh Agent                  ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
           │                                      ▲
           │                                      │ Logs & Alerts
           ▼                                      │
┌─────────────────────────────────────────────────────────────────┐
│                   Internal Network (192.168.3.0/24)            │
│  ┌─────────────────────────────┐  ┌─────────────────────────────┐│
│  │  Windows Server 2019        │  │     RHEL 9 Database         ││
│  │    192.168.3.10             │  │      192.168.3.20           ││
│  │  Domain Controller          │  │   MySQL + Wazuh Agent      ││
│  │  + Wazuh Agent              │  │                             ││
│  └─────────────────────────────┘  └─────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## VM Resource Allocation

| VM                 | Role               | RAM | CPU     | Storage | IP Address   |
| ------------------ | ------------------ | --- | ------- | ------- | ------------ |
| **Wazuh Manager**  | SIEM + ELK Stack   | 6GB | 2 cores | 100GB   | 192.168.1.10 |
| **pfSense**        | Firewall + IDS     | 1GB | 1 core  | 20GB    | 192.168.1.1  |
| **Ubuntu Web**     | Vulnerable Web App | 3GB | 2 cores | 40GB    | 192.168.2.10 |
| **Windows Server** | Domain Controller  | 4GB | 2 cores | 60GB    | 192.168.3.10 |
| **RHEL Database**  | Database Server    | 2GB | 1 core  | 40GB    | 192.168.3.20 |

**Total Resources**: 16GB RAM, 8 CPU cores, 260GB storage

## Wazuh Architecture Components

### Single-Node Deployment

- **Wazuh Manager**: Central event correlation and rule processing
- **Wazuh Indexer**: Elasticsearch-based data storage and indexing
- **Wazuh Dashboard**: Kibana-based visualization and SOC interface
- **Filebeat**: Log forwarding and data pipeline management

### Data Flow Architecture

```
[Agents] → [Wazuh Manager] → [Wazuh Indexer] → [Wazuh Dashboard]
    ↓              ↓                ↓               ↓
[Events]    [Rule Processing]  [Storage]    [Visualization]
```

## Log Sources and Collection Strategy

### Comprehensive Log Mapping

| System             | Log Sources                       | Collection Method | Expected Volume    |
| ------------------ | --------------------------------- | ----------------- | ------------------ |
| **pfSense**        | Firewall, Suricata IDS, System    | Syslog UDP 514    | 1K-5K events/day   |
| **Ubuntu Web**     | Apache, Auth, Syslog, FIM         | Wazuh Agent       | 2K-10K events/day  |
| **Windows Server** | Security, System, Application, AD | Wazuh Agent       | 1.5K-8K events/day |
| **RHEL Database**  | Auth, Database, Syslog, FIM       | Wazuh Agent       | 500-2K events/day  |

### Key Log Types

- **Network Traffic**: Firewall allow/deny, IDS alerts
- **Web Application**: HTTP requests, error logs, attack attempts
- **Authentication**: Login attempts, privilege escalation
- **File Integrity**: Configuration file changes, web shell uploads
- **System Events**: Service changes, process execution

## Detection Rules and Alert Correlation

### Attack Detection Categories

#### Web Application Attacks

- **SQL Injection**: Pattern matching for SQL keywords in HTTP parameters
- **Cross-Site Scripting**: Detection of script tags and JavaScript events
- **Directory Traversal**: Path traversal sequence identification
- **File Upload Attacks**: Suspicious file extensions and content

#### Network Reconnaissance

- **Port Scanning**: Multiple connection attempts correlation
- **Service Enumeration**: SMB, SSH, RDP probing detection
- **Network Discovery**: Internal network scanning from compromised hosts

#### Privilege Escalation

- **Linux**: Sudo abuse, SUID exploitation, /etc/passwd modifications
- **Windows**: Token manipulation, service creation, registry changes

### Alert Severity Levels

- **Critical**: Immediate security incident requiring response
- **High**: Significant security event needing investigation
- **Medium**: Suspicious activity requiring monitoring
- **Low**: Informational events for baseline establishment

## Attack Simulation Scenarios

### Scenario 1: Web Application Attack Chain

1. **Reconnaissance**: Nmap scan against web server
2. **Exploitation**: SQL injection against DVWA
3. **Persistence**: Web shell upload via file vulnerability
4. **Privilege Escalation**: Local privilege abuse

### Scenario 2: Network Lateral Movement

1. **Initial Compromise**: Web server exploitation
2. **Network Discovery**: Internal network scanning
3. **Service Enumeration**: SMB/SSH service probing
4. **Credential Attack**: Brute force authentication

### Expected Detection Points

- Port scan detection in pfSense logs
- SQL injection alerts from web application monitoring
- File integrity alerts for unauthorized uploads
- Privilege escalation detection from system monitoring
- Network scanning correlation across multiple systems

## Dashboard and Visualization Strategy

### Primary SOC Dashboards

#### 1. SOC Overview Dashboard

- Real-time alert queue and severity distribution
- Top attack types and geographic threat mapping
- System health indicators and SLA metrics
- Agent status and log ingestion rates

#### 2. Network Security Dashboard

- Firewall activity and blocked connections
- IDS/IPS alerts and port scan detection
- Bandwidth utilization and DNS analysis
- Top malicious IP addresses

#### 3. Web Application Security Dashboard

- HTTP status codes and attack vector analysis
- Top targeted URLs and suspicious user agents
- Geographic access patterns and response times
- Attack trend analysis over time

#### 4. Windows Environment Dashboard

- Authentication events and privilege escalation
- Service changes and PowerShell activity
- File access patterns and Group Policy changes
- Active Directory security monitoring

## Ansible Automation Structure

### Directory Organization

```
ansible/
├── inventories/
│   └── production/
│       ├── hosts.yml
│       └── group_vars/
├── playbooks/
│   ├── site.yml
│   ├── wazuh-agents.yml
│   └── linux-agents.yml
├── roles/
│   ├── wazuh-agent-linux/
│   ├── wazuh-agent-windows/
│   └── common/
└── group_vars/
    ├── all.yml
    ├── linux.yml
    └── windows.yml
```

### Automation Capabilities

- **Agent Deployment**: Automated Wazuh agent installation
- **Configuration Management**: Consistent agent configurations
- **Update Management**: Automated agent and rule updates
- **Health Monitoring**: Agent connectivity verification

## Backup and Recovery Strategy

### Backup Schedule

- **Daily**: Wazuh configurations, custom rules, system configs
- **Weekly**: Full VM snapshots, complete Elasticsearch backup
- **Pre-change**: Snapshots before major updates or testing

### Critical Data Protection

- **Priority 1**: Wazuh rules, Elasticsearch indices, SSL certificates
- **Priority 2**: System configurations, custom dashboards, playbooks
- **Priority 3**: Operating systems, application binaries

### Recovery Procedures

- **RTO**: 2 hours maximum for critical systems
- **RPO**: 24 hours maximum data loss for configurations
- **Disaster Recovery**: Complete lab rebuild capability

## Implementation Considerations

### Security Hardening

- TLS encryption for all Wazuh communications
- Role-based access control for dashboards
- Network segmentation with firewall rules
- Regular security updates and patching

### Performance Optimization

- Index lifecycle management for storage efficiency
- Resource monitoring and alerting
- Query optimization for dashboard performance
- Log retention policies for compliance

### Scalability Planning

- Horizontal scaling options for future growth
- Load balancing considerations for high availability
- Storage expansion planning
- Network bandwidth requirements

## Training and Educational Value

### SOC Analyst Skills Development

- **Alert Triage**: Prioritization and initial investigation
- **Incident Response**: Structured investigation workflows
- **Threat Hunting**: Proactive threat identification
- **Tool Proficiency**: Wazuh, ELK stack, and security tools

### Real-World Simulation

- **Enterprise Environment**: Realistic network topology
- **Attack Scenarios**: Common threat vectors and techniques
- **Compliance Requirements**: Audit trails and reporting
- **Operational Procedures**: SOC workflows and documentation

## Compliance and Audit Considerations

### Log Retention

- **Security Events**: 30 days hot storage, 90 days archive
- **Audit Logs**: Extended retention for compliance requirements
- **System Logs**: Configurable based on organizational needs

### Reporting Capabilities

- **Executive Dashboards**: High-level security metrics
- **Compliance Reports**: Automated audit trail generation
- **Incident Reports**: Detailed investigation documentation
- **Performance Metrics**: SOC efficiency and effectiveness

## Future Enhancement Opportunities

### Advanced Features

- **Machine Learning**: Behavioral anomaly detection
- **Threat Intelligence**: IOC integration and correlation
- **SOAR Integration**: Security orchestration and automation
- **Cloud Integration**: Hybrid cloud monitoring capabilities

### Expansion Options

- **Additional VMs**: Specialized security tools and services
- **Network Simulation**: More complex network topologies
- **Attack Frameworks**: MITRE ATT&CK technique coverage
- **Certification Prep**: Industry certification alignment

---

_This architecture provides a solid foundation for SOC analyst training while maintaining realistic enterprise security monitoring capabilities within resource constraints._
