# -*- mode: ruby -*-
# vi: set ft=ruby :

# Wazuh SOC Lab - VM Provisioning Configuration
# This Vagrantfile defines the complete lab environment with 5 VMs
# optimized for 16GB RAM constraint with proper network segmentation
# Uses actual ISO images available in the environment

Vagrant.configure("2") do |config|
  # Global VM configuration
  config.vm.box_check_update = false
  config.vm.synced_folder ".", "/vagrant", disabled: true
  
  # SSH configuration for Linux VMs
  config.ssh.insert_key = false
  config.ssh.private_key_path = ["~/.ssh/id_rsa", "~/.vagrant.d/insecure_private_key"]

  #############################################################################
  # 1. pfSense Firewall (192.168.1.1)
  # Gateway and IDS for all networks
  # Using: pfsense-CE-2.7.2-RELEASE-amd64
  #############################################################################
  config.vm.define "pfsense-fw" do |pfsense|
    # Use generic box and specify ISO path for manual installation
    pfsense.vm.box = "generic/freebsd13"
    pfsense.vm.hostname = "pfsense-fw"
    
    # Network configuration - 4 interfaces (WAN + 3 LANs)
    pfsense.vm.network "public_network", bridge: "en0: Wi-Fi (AirPort)"  # WAN
    pfsense.vm.network "private_network", ip: "192.168.1.1", netmask: "255.255.255.0", virtualbox__intnet: "management"
    pfsense.vm.network "private_network", ip: "192.168.2.1", netmask: "255.255.255.0", virtualbox__intnet: "dmz"
    pfsense.vm.network "private_network", ip: "192.168.3.1", netmask: "255.255.255.0", virtualbox__intnet: "internal"
    
    # Resource allocation
    pfsense.vm.provider "virtualbox" do |vb|
      vb.name = "SOC-Lab-pfSense"
      vb.memory = 2048
      vb.cpus = 2
      vb.gui = true  # Enable GUI for initial setup
      
      # Attach pfSense ISO for installation
      vb.customize ["storageattach", :id, "--storagectl", "IDE Controller", "--port", "0", "--device", "1", "--type", "dvddrive", "--medium", "C:/Users/Simoda/wazuh-soc-lab/ISOs/pfsense-CE-2.7.2-RELEASE-amd64.iso"]
      
      # Enable promiscuous mode for all interfaces
      vb.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
      vb.customize ["modifyvm", :id, "--nicpromisc3", "allow-all"]
      vb.customize ["modifyvm", :id, "--nicpromisc4", "allow-all"]
      vb.customize ["modifyvm", :id, "--nicpromisc5", "allow-all"]
    end
    
    # pfSense manual installation notes
    pfsense.vm.provision "shell", inline: <<-SHELL
      echo "=== pfSense Manual Installation Required ==="
      echo "1. Boot from attached ISO"
      echo "2. Install pfSense to hard disk"
      echo "3. Configure interfaces:"
      echo "   - WAN: em0 (DHCP)"
      echo "   - LAN: em1 (192.168.1.1/24)"
      echo "   - OPT1: em2 (192.168.2.1/24) - DMZ"
      echo "   - OPT2: em3 (192.168.3.1/24) - Internal"
      echo "4. Access web interface: https://192.168.1.1"
      echo "5. Default credentials: admin/pfsense"
    SHELL
  end

  #############################################################################
  # 2. Wazuh Manager + ELK Stack (192.168.1.10)
  # Central SIEM and monitoring platform
  # Using: ubuntu-24.04.2-live-server-amd64
  #############################################################################
  config.vm.define "wazuh-manager" do |wazuh|
    # Use generic Ubuntu box and specify ISO for custom installation
    wazuh.vm.box = "generic/ubuntu2404"
    wazuh.vm.hostname = "wazuh-manager"
    
    # Network configuration
    wazuh.vm.network "private_network", ip: "192.168.1.10", netmask: "255.255.255.0", virtualbox__intnet: "management"
    
    # Resource allocation - Optimized for ELK stack
    wazuh.vm.provider "virtualbox" do |vb|
      vb.name = "SOC-Lab-Wazuh-Manager"
      vb.memory = 6144  # 6GB RAM for ELK stack
      vb.cpus = 4
      vb.gui = false
      
      # Optimize for ELK performance
      vb.customize ["modifyvm", :id, "--ioapic", "on"]
      vb.customize ["modifyvm", :id, "--memory", "6144"]
      vb.customize ["modifyvm", :id, "--cpus", "4"]
      
      # Attach Ubuntu ISO if needed for custom installation
      # vb.customize ["storageattach", :id, "--storagectl", "IDE Controller", "--port", "0", "--device", "1", "--type", "dvddrive", "--medium", "~/ISOs/ubuntu-24.04.2-live-server-amd64.iso"]
    end
    
    # Base system provisioning
    wazuh.vm.provision "shell", inline: <<-SHELL
      # Update system
      apt-get update
      apt-get upgrade -y
      
      # Install basic tools
      apt-get install -y curl wget gnupg2 software-properties-common apt-transport-https ca-certificates
      
      # Configure timezone
      timedatectl set-timezone UTC
      
      # Optimize system for ELK
      echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
      sysctl -w vm.max_map_count=262144
      
      # Create wazuh user
      useradd -m -s /bin/bash wazuh
      usermod -aG sudo wazuh
      
      # Configure SSH key access
      mkdir -p /home/vagrant/.ssh
      chmod 700 /home/vagrant/.ssh
      chown vagrant:vagrant /home/vagrant/.ssh
      
      echo "Wazuh Manager VM provisioned successfully"
      echo "Run: vagrant provision wazuh-manager --provision-with ansible"
    SHELL
    
    # Ansible provisioning
    wazuh.vm.provision "ansible", run: "never" do |ansible|
      ansible.playbook = "ansible/playbooks/vm-provisioning/wazuh-manager.yml"
      ansible.inventory_path = "ansible/inventory/hosts.yml"
      ansible.limit = "wazuh_managers"
      ansible.verbose = "v"
    end
  end

  #############################################################################
  # 3. Ubuntu Web Server (192.168.2.10)
  # DVWA + Apache in DMZ network
  # Using: ubuntu-24.04.2-live-server-amd64
  #############################################################################
  config.vm.define "ubuntu-web" do |web|
    web.vm.box = "generic/ubuntu2404"
    web.vm.hostname = "ubuntu-web"
    
    # Network configuration
    web.vm.network "private_network", ip: "192.168.2.10", netmask: "255.255.255.0", virtualbox__intnet: "dmz"
    
    # Resource allocation
    web.vm.provider "virtualbox" do |vb|
      vb.name = "SOC-Lab-Ubuntu-Web"
      vb.memory = 2048  # 2GB RAM
      vb.cpus = 2
      vb.gui = false
    end
    
    # Base system provisioning
    web.vm.provision "shell", inline: <<-SHELL
      # Update system
      apt-get update
      apt-get upgrade -y
      
      # Install basic tools
      apt-get install -y curl wget git vim htop net-tools
      
      # Configure timezone
      timedatectl set-timezone UTC
      
      # Configure static route to management network via pfSense
      ip route add 192.168.1.0/24 via 192.168.2.1
      
      # Configure SSH key access
      mkdir -p /home/vagrant/.ssh
      chmod 700 /home/vagrant/.ssh
      chown vagrant:vagrant /home/vagrant/.ssh
      
      echo "Ubuntu Web Server VM provisioned successfully"
      echo "Access DVWA at: http://192.168.2.10/dvwa (after Ansible provisioning)"
    SHELL
    
    # Ansible provisioning
    web.vm.provision "ansible", run: "never" do |ansible|
      ansible.playbook = "ansible/playbooks/vm-provisioning/ubuntu-web.yml"
      ansible.inventory_path = "ansible/inventory/hosts.yml"
      ansible.limit = "linux_agents"
      ansible.verbose = "v"
    end
  end

  #############################################################################
  # 4. Windows Server 2019 Domain Controller (192.168.3.10)
  # Active Directory and Windows monitoring
  # Using: SERVER_EVAL_x64FRE_en-us
  #############################################################################
  config.vm.define "windows-dc" do |windows|
    # Use generic Windows box and specify ISO for installation
    windows.vm.box = "gusztavvargadr/windows-server-2019-standard"
    windows.vm.hostname = "windows-dc"
    
    # Network configuration
    windows.vm.network "private_network", ip: "192.168.3.10", netmask: "255.255.255.0", virtualbox__intnet: "internal"
    
    # Resource allocation
    windows.vm.provider "virtualbox" do |vb|
      vb.name = "SOC-Lab-Windows-DC"
      vb.memory = 4096  # 4GB RAM for Domain Controller
      vb.cpus = 2
      vb.gui = true  # Enable GUI for Windows
      
      # Windows-specific optimizations
      vb.customize ["modifyvm", :id, "--vram", "128"]
      vb.customize ["modifyvm", :id, "--clipboard", "bidirectional"]
      
      # Attach Windows Server ISO if manual installation needed
      # vb.customize ["storageattach", :id, "--storagectl", "IDE Controller", "--port", "0", "--device", "1", "--type", "dvddrive", "--medium", "~/ISOs/SERVER_EVAL_x64FRE_en-us.iso"]
    end
    
    # Windows-specific configuration
    windows.vm.communicator = "winrm"
    windows.winrm.username = "vagrant"
    windows.winrm.password = "vagrant"
    windows.winrm.transport = :plaintext
    windows.winrm.basic_auth_only = true
    windows.vm.boot_timeout = 600
    windows.vm.graceful_halt_timeout = 600
    
    # Base Windows provisioning
    windows.vm.provision "shell", inline: <<-SHELL
      # Configure timezone
      tzutil /s "UTC"
      
      # Configure network
      netsh interface ip set address "Ethernet 2" static 192.168.3.10 255.255.255.0 192.168.3.1
      netsh interface ip set dns "Ethernet 2" static 127.0.0.1
      netsh interface ip add dns "Ethernet 2" 8.8.8.8 index=2
      
      # Enable RDP
      Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -Name "fDenyTSConnections" -Value 0
      Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
      
      # Configure Windows Defender exclusions for lab environment
      Add-MpPreference -ExclusionPath "C:\\Program Files (x86)\\ossec-agent"
      
      Write-Host "Windows Server 2019 DC VM provisioned successfully"
      Write-Host "RDP access: 192.168.3.10:3389"
    SHELL
    
    # Ansible provisioning for Windows
    windows.vm.provision "ansible", run: "never" do |ansible|
      ansible.playbook = "ansible/playbooks/vm-provisioning/windows-dc.yml"
      ansible.inventory_path = "ansible/inventory/hosts.yml"
      ansible.limit = "windows_agents"
      ansible.verbose = "v"
    end
  end

  #############################################################################
  # 5. RHEL 9 Database Server (192.168.3.20)
  # MySQL database server for internal network
  # Using: rhel-9.5-x86_64-dvd
  #############################################################################
  config.vm.define "rhel-db" do |rhel|
    # Use generic RHEL box and specify ISO for installation
    rhel.vm.box = "generic/rhel9"
    rhel.vm.hostname = "rhel-db"
    
    # Network configuration
    rhel.vm.network "private_network", ip: "192.168.3.20", netmask: "255.255.255.0", virtualbox__intnet: "internal"
    
    # Resource allocation
    rhel.vm.provider "virtualbox" do |vb|
      vb.name = "SOC-Lab-RHEL-DB"
      vb.memory = 2048  # 2GB RAM
      vb.cpus = 2
      vb.gui = false
      
      # Attach RHEL ISO if manual installation needed
      # vb.customize ["storageattach", :id, "--storagectl", "IDE Controller", "--port", "0", "--device", "1", "--type", "dvddrive", "--medium", "~/ISOs/rhel-9.5-x86_64-dvd.iso"]
    end
    
    # Base system provisioning
    rhel.vm.provision "shell", inline: <<-SHELL
      # Update system
      dnf update -y
      
      # Install basic tools
      dnf install -y curl wget vim htop net-tools bind-utils
      
      # Configure timezone
      timedatectl set-timezone UTC
      
      # Configure static route to management network via pfSense
      ip route add 192.168.1.0/24 via 192.168.3.1
      
      # Configure SELinux for lab environment
      setenforce 0
      sed -i 's/SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
      
      # Configure SSH key access
      mkdir -p /home/vagrant/.ssh
      chmod 700 /home/vagrant/.ssh
      chown vagrant:vagrant /home/vagrant/.ssh
      
      echo "RHEL 9 Database Server VM provisioned successfully"
      echo "MySQL will be configured via Ansible provisioning"
    SHELL
    
    # Ansible provisioning
    rhel.vm.provision "ansible", run: "never" do |ansible|
      ansible.playbook = "ansible/playbooks/vm-provisioning/rhel-db.yml"
      ansible.inventory_path = "ansible/inventory/hosts.yml"
      ansible.limit = "linux_agents"
      ansible.verbose = "v"
    end
  end

  #############################################################################
  # VM Orchestration and Management
  #############################################################################
  
  # Define VM startup order for proper dependency management
  config.vm.define "startup-order", autostart: false do |order|
    order.vm.provision "shell", inline: <<-SHELL
      echo "=== Wazuh SOC Lab VM Startup Order ==="
      echo "1. pfsense-fw (Gateway/Firewall) - Manual setup required"
      echo "2. wazuh-manager (SIEM Platform)"
      echo "3. windows-dc (Domain Controller)"
      echo "4. ubuntu-web (Web Server)"
      echo "5. rhel-db (Database Server)"
      echo ""
      echo "Available ISOs:"
      echo "- pfSense: pfsense-CE-2.7.2-RELEASE-amd64.iso"
      echo "- Ubuntu: ubuntu-24.04.2-live-server-amd64.iso"
      echo "- Windows: SERVER_EVAL_x64FRE_en-us.iso"
      echo "- RHEL: rhel-9.5-x86_64-dvd.iso"
      echo ""
      echo "Usage:"
      echo "vagrant up pfsense-fw wazuh-manager windows-dc ubuntu-web rhel-db"
      echo "Or use: ./scripts/vm-orchestration/start-lab.sh"
    SHELL
  end
end

# Vagrant Plugin Requirements
# Required plugins for full functionality:
# - vagrant-vbguest (VirtualBox Guest Additions)
# - vagrant-hostmanager (Host file management)
# - vagrant-reload (VM restart capability)
#
# Install with: vagrant plugin install <plugin-name>

# Manual Installation Notes:
# 1. pfSense requires manual installation from ISO
# 2. Some VMs may need manual OS installation if boxes fail
# 3. ISOs should be placed in ~/ISOs/ directory
# 4. After VM creation, run Ansible provisioning for full configuration

# Post-deployment checklist:
# 1. Install pfSense manually and configure interfaces
# 2. Run Ansible provisioning: vagrant provision --provision-with ansible
# 3. Configure pfSense firewall rules via web interface
# 4. Access Wazuh Dashboard: https://192.168.1.10
# 5. Test connectivity between all VMs
# 6. Deploy Wazuh agents using Ansible playbooks