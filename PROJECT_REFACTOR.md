# Wazuh SOC Lab - Project Refactoring Plan

## Current Issues

1. **Mixed responsibilities** - Configuration, scripts, and documentation scattered
2. **No clear separation** between infrastructure, application, and testing concerns
3. **Missing CI/CD integration** - No Jenkins pipeline definition
4. **Inconsistent naming** - Some files use underscores, others hyphens
5. **No environment separation** - Dev/staging/prod configurations mixed

## Proposed Clean Structure

```
wazuh-soc-lab/
├── .github/workflows/          # GitHub Actions (alternative to Jenkins)
├── .jenkins/                   # Jenkins pipeline definitions
├── infrastructure/             # Infrastructure as Code
│   ├── vagrant/               # VM provisioning
│   ├── terraform/             # Cloud deployment (AWS/Azure)
│   └── ansible/               # Configuration management
├── applications/              # Application configurations
│   ├── wazuh/                # Wazuh-specific configs
│   ├── elk/                  # ELK stack configs
│   └── monitoring/           # Additional monitoring tools
├── security/                  # Security-focused components
│   ├── attack-scenarios/     # Attack simulation scripts
│   ├── detection-rules/      # Custom Wazuh rules
│   └── dashboards/          # Security dashboards
├── tests/                    # All testing components
│   ├── integration/         # Integration tests
│   ├── security/           # Security validation tests
│   └── performance/        # Performance tests
├── docs/                    # Documentation only
├── scripts/                 # Utility scripts only
└── environments/           # Environment-specific configurations
    ├── dev/
    ├── staging/
    └── prod/
```

## Refactoring Steps

### Phase 1: Core Infrastructure (Day 1)
1. Create new directory structure
2. Move Vagrant files to `infrastructure/vagrant/`
3. Reorganize Ansible playbooks by responsibility
4. Create Jenkins pipeline file

### Phase 2: Application Separation (Day 2)
1. Separate Wazuh and ELK configurations
2. Create environment-specific variable files
3. Implement proper secret management

### Phase 3: Testing Integration (Day 3)
1. Move attack scenarios to proper testing structure
2. Create automated test suites
3. Integrate with CI/CD pipeline

### Phase 4: Documentation Cleanup (Day 4)
1. Consolidate documentation
2. Create proper README structure
3. Add architecture diagrams

## Benefits

- **Single Responsibility Principle** - Each directory has one clear purpose
- **Environment Separation** - Clear dev/staging/prod configurations
- **CI/CD Ready** - Proper pipeline integration
- **Scalable** - Easy to add new components
- **Maintainable** - Clear structure for team collaboration