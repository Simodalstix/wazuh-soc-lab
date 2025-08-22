# Wazuh SOC Lab - Clean DevSecOps Edition

## Overview

Modern SOC lab environment using DevSecOps practices with Vagrant, Ansible, and Jenkins for automated deployment and testing.

## Quick Start

```bash
# 1. Deploy VMs
cd infrastructure/vagrant
vagrant up

# 2. Configure with Ansible
cd ../ansible
ansible-playbook -i inventory/dev/hosts.yml site.yml

# 3. Run tests
cd ../../tests/integration
python3 -m pytest test_deployment.py -v
```

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Wazuh Manager  │    │   Ubuntu Web    │    │   Rocky DB      │
│  + ELK Stack    │    │   + DVWA        │    │   + MySQL       │
│  192.168.56.10  │    │  192.168.56.20  │    │  192.168.56.30  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Project Structure

```
wazuh-soc-lab/
├── infrastructure/           # Infrastructure as Code
│   ├── vagrant/             # VM provisioning
│   └── ansible/             # Configuration management
├── applications/            # Application configs
│   ├── wazuh/              # Wazuh configurations
│   └── elk/                # ELK stack configs
├── security/               # Security components
│   ├── attack-scenarios/   # Attack simulations
│   └── detection-rules/    # Custom rules
├── tests/                  # Automated testing
│   ├── integration/        # Deployment tests
│   └── security/          # Attack validation
├── environments/           # Environment configs
│   ├── dev/               # Development
│   ├── staging/           # Staging
│   └── prod/              # Production
└── .jenkins/              # CI/CD pipeline
```

## CI/CD Pipeline

Jenkins pipeline automates:
1. **Infrastructure deployment** (Vagrant)
2. **Configuration management** (Ansible)
3. **Integration testing** (pytest)
4. **Security validation** (attack scenarios)
5. **Reporting** (HTML reports)

## Key Changes from Original

- **Removed pfSense** - Simplified network topology
- **Rocky Linux** - No subscription management needed  
- **Clean separation** - Infrastructure, apps, security, tests
- **Jenkins integration** - Full CI/CD automation
- **Environment separation** - Dev/staging/prod configs
- **Automated testing** - Integration and security tests

## Benefits

- **Faster deployment** - Automated end-to-end
- **Real-world skills** - DevSecOps practices
- **Easier maintenance** - Clear structure
- **Scalable** - Add cloud deployment later
- **Testable** - Automated validation