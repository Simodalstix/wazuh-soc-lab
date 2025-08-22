#!/usr/bin/env python3
"""
Integration tests for SOC Lab deployment
"""
import pytest
import requests
import subprocess
import time
from paramiko import SSHClient, AutoAddPolicy


class TestDeployment:
    """Test suite for validating SOC lab deployment"""
    
    def test_wazuh_manager_api(self):
        """Test Wazuh Manager API accessibility"""
        try:
            response = requests.get(
                'https://192.168.56.10:55000',
                verify=False,
                timeout=10
            )
            assert response.status_code in [200, 401]  # 401 is expected without auth
        except requests.exceptions.RequestException:
            pytest.fail("Wazuh Manager API not accessible")
    
    def test_wazuh_dashboard(self):
        """Test Wazuh Dashboard accessibility"""
        try:
            response = requests.get(
                'https://192.168.56.10:443',
                verify=False,
                timeout=10
            )
            assert response.status_code == 200
        except requests.exceptions.RequestException:
            pytest.fail("Wazuh Dashboard not accessible")
    
    def test_dvwa_web_server(self):
        """Test DVWA web application"""
        try:
            response = requests.get(
                'http://192.168.56.20/dvwa',
                timeout=10
            )
            assert response.status_code == 200
            assert 'DVWA' in response.text
        except requests.exceptions.RequestException:
            pytest.fail("DVWA not accessible")
    
    def test_ssh_connectivity(self):
        """Test SSH connectivity to all VMs"""
        hosts = [
            ('192.168.56.10', 'wazuh-manager'),
            ('192.168.56.20', 'ubuntu-web'),
            ('192.168.56.30', 'rocky-db')
        ]
        
        for host_ip, hostname in hosts:
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())
            
            try:
                client.connect(
                    host_ip,
                    username='vagrant',
                    key_filename='~/.vagrant.d/insecure_private_key',
                    timeout=10
                )
                
                stdin, stdout, stderr = client.exec_command('hostname')
                result = stdout.read().decode().strip()
                assert hostname in result
                
            except Exception as e:
                pytest.fail(f"SSH connection failed to {hostname}: {e}")
            finally:
                client.close()
    
    def test_wazuh_agents_connected(self):
        """Test that Wazuh agents are connected"""
        # This would require Wazuh API authentication
        # Placeholder for now
        pass


if __name__ == '__main__':
    pytest.main([__file__, '-v'])