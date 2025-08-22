# Minimal SOC Lab - Start Simple

## What We Actually Need Right Now

```
wazuh-soc-lab/
├── Vagrantfile                    # 3 VMs only
├── ansible/
│   ├── inventory.yml             # Simple inventory
│   ├── site.yml                  # Main playbook
│   └── roles/
│       ├── wazuh-manager/        # Install Wazuh
│       ├── wazuh-agent/          # Install agents
│       └── dvwa/                 # Install DVWA
├── Jenkinsfile                   # Simple pipeline
└── README.md                     # Getting started only
```

## Phase 1: Get It Working
1. VMs up and running
2. Wazuh installed and agents connected
3. DVWA accessible
4. Basic Jenkins pipeline

## Phase 2: Add Value
1. One simple attack scenario
2. Basic detection validation
3. Simple reporting

## Phase 3: Expand
1. More attack scenarios
2. Custom rules
3. Advanced testing

Stop building features nobody asked for!