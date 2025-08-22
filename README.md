# Minimal SOC Lab

## Start Here

```bash
# 1. Deploy
vagrant up

# 2. Configure  
cd ansible.minimal
ansible-playbook -i inventory.yml site.yml

# 3. Access
# Wazuh: https://192.168.56.10
# DVWA: http://192.168.56.20/dvwa
```

## What You Get

- Wazuh Manager with dashboard
- Ubuntu web server with DVWA
- Rocky Linux database server
- All agents connected to Wazuh

## Next Steps

1. Get this working first
2. Add one attack scenario
3. Validate detection
4. Then expand

Stop building features. Start building value.