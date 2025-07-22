# Wazuh SOC Lab Troubleshooting Guide

## Overview

This guide provides solutions to common issues encountered during the deployment and operation of the Wazuh SOC Lab environment. Issues are organized by category and include step-by-step resolution procedures.

## Quick Diagnostic Commands

### System Health Check

```bash
# Check all Wazuh services
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard

# Check agent connectivity
sudo /var/ossec/bin/wazuh-control status

# Check log processing
tail -f /var/ossec/logs/ossec.log

# Check API status
curl -k -X GET "https://192.168.1.10:55000/"

# Check disk space
df -h

# Check memory usage
free -h
```

### Network Connectivity Test

```bash
# Test basic connectivity
ping 192.168.1.10  # Wazuh Manager
ping 192.168.3.10  # Windows DC
ping 192.168.2.10  # Web Server
ping 192.168.3.20  # Database Server

# Test DNS resolution
nslookup lab.local
nslookup wazuh-manager.lab.local

# Test specific ports
telnet 192.168.1.10 1514  # Agent communication
telnet 192.168.1.10 1515  # Agent registration
telnet 192.168.1.10 55000 # API
telnet 192.168.1.10 443   # Dashboard
```

## Installation Issues

### 1. Wazuh Manager Installation Failures

#### Issue: "Package not found" or repository errors

**Symptoms:**

- apt/yum cannot find Wazuh packages
- Repository key verification failures

**Solution:**

```bash
# Re-add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update

# For RHEL/CentOS
sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
```

#### Issue: Insufficient disk space during installation

**Symptoms:**

- Installation stops with "No space left on device"
- Elasticsearch fails to start

**Solution:**

```bash
# Check disk usage
df -h

# Clean up space
sudo apt autoremove -y
sudo apt autoclean
sudo journalctl --vacuum-time=7d

# If still insufficient, expand VM disk or move to larger partition
```

#### Issue: Memory allocation errors

**Symptoms:**

- Elasticsearch fails to start
- Java heap space errors

**Solution:**

```bash
# Check available memory
free -h

# Adjust Elasticsearch heap size
sudo nano /etc/wazuh-indexer/jvm.options
# Modify:
# -Xms2g  (reduce if less than 6GB total RAM)
# -Xmx2g  (reduce if less than 6GB total RAM)

# Restart services
sudo systemctl restart wazuh-indexer
sudo systemctl restart wazuh-manager
```

### 2. Agent Installation Issues

#### Issue: Agent fails to connect to manager

**Symptoms:**

- Agent status shows "Never connected"
- Connection timeout errors in agent logs

**Solution:**

```bash
# Check firewall on manager
sudo ufw status
sudo ufw allow 1514/tcp
sudo ufw allow 1515/tcp

# Check agent configuration
sudo nano /var/ossec/etc/ossec.conf
# Verify manager IP is correct

# Test connectivity from agent
telnet 192.168.1.10 1514

# Re-register agent
sudo /var/ossec/bin/agent-auth -m 192.168.1.10 -A $(hostname)
sudo systemctl restart wazuh-agent
```

#### Issue: Windows agent installation fails

**Symptoms:**

- MSI installation returns error codes
- Service fails to start

**Solution:**

```powershell
# Run as Administrator
# Check Windows version compatibility
Get-ComputerInfo | Select WindowsProductName, WindowsVersion

# Install with verbose logging
msiexec /i wazuh-agent-4.7.0-1.msi /l*v install.log WAZUH_MANAGER="192.168.1.10"

# Check installation log
Get-Content install.log | Select-String "error"

# Manual service start
Start-Service WazuhSvc
```

## Network and Connectivity Issues

### 3. Network Segmentation Problems

#### Issue: VMs cannot communicate between networks

**Symptoms:**

- Ping fails between different network segments
- Agents cannot reach manager

**Solution:**

```bash
# Check pfSense firewall rules
# Access pfSense web interface: https://192.168.1.1
# Navigate to Firewall > Rules
# Ensure rules allow traffic between networks:

# Management to DMZ: Allow 192.168.1.0/24 to 192.168.2.0/24
# Management to Internal: Allow 192.168.1.0/24 to 192.168.3.0/24
# DMZ to Management: Allow 192.168.2.0/24 to 192.168.1.10 (Wazuh)
# Internal to Management: Allow 192.168.3.0/24 to 192.168.1.10 (Wazuh)
```

#### Issue: DNS resolution failures

**Symptoms:**

- Cannot resolve lab.local domain
- Name resolution timeouts

**Solution:**

```bash
# Check DNS server configuration
nslookup lab.local 192.168.3.10

# Update DNS settings on each VM
# Linux:
sudo nano /etc/systemd/resolved.conf
# Add: DNS=192.168.3.10 8.8.8.8

sudo systemctl restart systemd-resolved

# Windows:
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.168.3.10,8.8.8.8
```

### 4. Port and Service Issues

#### Issue: Dashboard not accessible

**Symptoms:**

- Browser shows "Connection refused" or timeout
- HTTPS certificate errors

**Solution:**

```bash
# Check dashboard service
sudo systemctl status wazuh-dashboard

# Check if port 443 is listening
sudo netstat -tlnp | grep :443

# Check firewall
sudo ufw allow 443/tcp

# Restart dashboard service
sudo systemctl restart wazuh-dashboard

# Check logs
sudo journalctl -u wazuh-dashboard -f
```

#### Issue: API not responding

**Symptoms:**

- API calls return connection errors
- Authentication failures

**Solution:**

```bash
# Check API service
sudo systemctl status wazuh-manager

# Check API port
sudo netstat -tlnp | grep :55000

# Test API locally
curl -k -X GET "https://localhost:55000/"

# Check API configuration
sudo nano /var/ossec/api/configuration/api.yaml

# Restart manager
sudo systemctl restart wazuh-manager
```

## Agent Communication Issues

### 5. Agent Registration Problems

#### Issue: Agent registration fails

**Symptoms:**

- "ERROR: Invalid key received" messages
- Agent shows as "Never connected"

**Solution:**

```bash
# On Manager - check agent registration
sudo /var/ossec/bin/manage_agents -l

# Remove duplicate agents
sudo /var/ossec/bin/manage_agents -r <agent_id>

# On Agent - re-register
sudo /var/ossec/bin/agent-auth -m 192.168.1.10 -A $(hostname) -v

# Check client.keys file
sudo cat /var/ossec/etc/client.keys

# Restart agent
sudo systemctl restart wazuh-agent
```

#### Issue: Agent disconnects frequently

**Symptoms:**

- Agent status changes from "Active" to "Disconnected"
- Intermittent log flow

**Solution:**

```bash
# Check network stability
ping -c 100 192.168.1.10

# Increase agent timeout values
sudo nano /var/ossec/etc/ossec.conf
# Add/modify:
<client>
  <notify_time>30</notify_time>
  <time-reconnect>120</time-reconnect>
</client>

# Check agent logs
sudo tail -f /var/ossec/logs/ossec.log

# Restart agent
sudo systemctl restart wazuh-agent
```

## Log Processing Issues

### 6. No Logs Appearing in Dashboard

#### Issue: Events not showing in Wazuh dashboard

**Symptoms:**

- Dashboard shows no recent events
- Agent appears active but no logs

**Solution:**

```bash
# Check log file permissions
sudo ls -la /var/log/auth.log
sudo ls -la /var/log/syslog

# Fix permissions if needed
sudo chmod 644 /var/log/auth.log
sudo chmod 644 /var/log/syslog

# Check agent configuration
sudo nano /var/ossec/etc/ossec.conf
# Verify localfile entries are correct

# Test log generation
sudo logger "Test message from $(hostname)"

# Check manager processing
sudo tail -f /var/ossec/logs/ossec.log | grep "$(hostname)"
```

#### Issue: Windows Event Logs not collecting

**Symptoms:**

- No Windows events in dashboard
- Agent active but no Windows-specific logs

**Solution:**

```powershell
# Check Windows Event Log service
Get-Service EventLog

# Verify agent configuration
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf"

# Check Windows Event Log permissions
# Run as Administrator:
wevtutil gl Security
wevtutil gl System
wevtutil gl Application

# Generate test events
eventcreate /T ERROR /ID 999 /L APPLICATION /D "Test event for Wazuh"

# Check agent logs
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20
```

## Performance Issues

### 7. High Resource Usage

#### Issue: Elasticsearch consuming too much memory

**Symptoms:**

- System becomes unresponsive
- Out of memory errors

**Solution:**

```bash
# Check current memory usage
free -h
ps aux | grep elasticsearch

# Reduce Elasticsearch heap size
sudo nano /etc/wazuh-indexer/jvm.options
# Modify for systems with 6GB RAM:
-Xms1g
-Xmx1g

# Restart Elasticsearch
sudo systemctl restart wazuh-indexer

# Monitor memory usage
watch -n 5 free -h
```

#### Issue: Slow dashboard response

**Symptoms:**

- Dashboard takes long time to load
- Timeouts when viewing large datasets

**Solution:**

```bash
# Check system resources
top
iotop

# Optimize Elasticsearch settings
sudo nano /etc/wazuh-indexer/opensearch.yml
# Add:
indices.query.bool.max_clause_count: 10000
search.max_buckets: 100000

# Implement index lifecycle management
# Reduce data retention period
# Archive old indices

# Restart services
sudo systemctl restart wazuh-indexer wazuh-dashboard
```

## Data and Storage Issues

### 8. Disk Space Problems

#### Issue: Disk space running low

**Symptoms:**

- "No space left on device" errors
- Elasticsearch stops indexing

**Solution:**

```bash
# Check disk usage
df -h
du -sh /var/ossec/logs/*
du -sh /var/lib/wazuh-indexer/*

# Clean up old logs
sudo find /var/ossec/logs -name "*.log.*" -mtime +30 -delete

# Configure log rotation
sudo nano /etc/logrotate.d/wazuh
# Add:
/var/ossec/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        /bin/kill -HUP $(cat /var/ossec/var/run/wazuh-logcollector.pid 2>/dev/null) 2>/dev/null || true
    endscript
}

# Implement Elasticsearch index lifecycle management
curl -X PUT "192.168.1.10:9200/_ilm/policy/wazuh-policy" -H 'Content-Type: application/json' -d'
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "1GB",
            "max_age": "7d"
          }
        }
      },
      "delete": {
        "min_age": "30d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}'
```

## Security and Access Issues

### 9. Authentication Problems

#### Issue: Cannot login to Wazuh dashboard

**Symptoms:**

- Invalid credentials error
- Authentication timeout

**Solution:**

```bash
# Reset admin password
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p <new_password>

# Update internal users
sudo nano /etc/wazuh-indexer/opensearch-security/internal_users.yml
# Update admin user hash

# Apply security configuration
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /etc/wazuh-indexer/opensearch-security \
  -icl -nhnv \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -key /etc/wazuh-indexer/certs/admin-key.pem

# Restart dashboard
sudo systemctl restart wazuh-dashboard
```

#### Issue: SSL certificate errors

**Symptoms:**

- Browser shows certificate warnings
- API calls fail with SSL errors

**Solution:**

```bash
# Check certificate validity
openssl x509 -in /etc/wazuh-indexer/certs/wazuh-indexer.pem -text -noout

# Regenerate certificates if expired
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-certs-tool.sh \
  -A wazuh-manager \
  -ca /etc/wazuh-indexer/certs/root-ca.pem \
  -cakey /etc/wazuh-indexer/certs/root-ca-key.pem

# Update certificate paths in configuration
sudo nano /etc/wazuh-indexer/opensearch.yml
sudo nano /etc/wazuh-dashboard/opensearch_dashboards.yml

# Restart services
sudo systemctl restart wazuh-indexer wazuh-dashboard
```

## Attack Simulation Issues

### 10. Detection Not Working

#### Issue: Attack simulations not generating alerts

**Symptoms:**

- No alerts for known attack patterns
- Rules not triggering

**Solution:**

```bash
# Check rule syntax
sudo /var/ossec/bin/wazuh-logtest

# Test specific rules
echo "Failed password for invalid user test from 192.168.1.100" | sudo /var/ossec/bin/wazuh-logtest

# Check rule loading
sudo grep "Rules loaded" /var/ossec/logs/ossec.log

# Verify custom rules
sudo nano /var/ossec/etc/rules/local_rules.xml

# Restart manager to reload rules
sudo systemctl restart wazuh-manager

# Check alert generation
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

## Emergency Recovery Procedures

### 11. Complete System Recovery

#### Issue: System completely unresponsive

**Solution:**

```bash
# Boot from rescue mode or live CD
# Mount the filesystem
sudo mount /dev/sda1 /mnt

# Check filesystem integrity
sudo fsck /dev/sda1

# Restore from backup
sudo tar -xzf /path/to/backup.tar.gz -C /mnt

# Check critical services
sudo chroot /mnt
systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
```

#### Issue: Corrupted Elasticsearch indices

**Solution:**

```bash
# Stop Elasticsearch
sudo systemctl stop wazuh-indexer

# Check index health
curl -X GET "192.168.1.10:9200/_cluster/health?pretty"

# Delete corrupted indices
curl -X DELETE "192.168.1.10:9200/wazuh-alerts-*"

# Restart Elasticsearch
sudo systemctl start wazuh-indexer

# Verify cluster health
curl -X GET "192.168.1.10:9200/_cluster/health?pretty"
```

## Getting Additional Help

### Log Locations

```bash
# Wazuh Manager
/var/ossec/logs/ossec.log
/var/ossec/logs/alerts/alerts.log
/var/ossec/logs/archives/archives.log

# Elasticsearch
/var/log/wazuh-indexer/wazuh-cluster.log

# Dashboard
/var/log/wazuh-dashboard/wazuh-dashboard.log

# System logs
/var/log/syslog
/var/log/auth.log
journalctl -u wazuh-manager
```

### Support Resources

- **Wazuh Documentation**: https://documentation.wazuh.com/
- **Community Forum**: https://wazuh.com/community/
- **GitHub Issues**: https://github.com/wazuh/wazuh/issues
- **Slack Community**: https://wazuh.com/community/join-us-on-slack/

### Creating Support Tickets

When seeking help, include:

1. Wazuh version: `cat /var/ossec/VERSION`
2. OS version: `lsb_release -a`
3. Error messages from logs
4. Steps to reproduce the issue
5. System specifications (RAM, CPU, disk)

---

_This troubleshooting guide covers the most common issues encountered in the Wazuh SOC Lab. For issues not covered here, consult the official Wazuh documentation or community resources._
