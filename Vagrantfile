Vagrant.configure("2") do |config|
  # Wazuh Manager
  config.vm.define "wazuh" do |wazuh|
    wazuh.vm.box = "ubuntu/jammy64"
    wazuh.vm.network "private_network", ip: "192.168.56.10"
    wazuh.vm.provider "virtualbox" do |vb|
      vb.memory = "4096"
      vb.cpus = 2
    end
  end

  # Web Server with DVWA
  config.vm.define "web" do |web|
    web.vm.box = "ubuntu/jammy64"
    web.vm.network "private_network", ip: "192.168.56.20"
    web.vm.provider "virtualbox" do |vb|
      vb.memory = "1024"
      vb.cpus = 1
    end
  end

  # Database Server
  config.vm.define "db" do |db|
    db.vm.box = "generic/rocky9"
    db.vm.network "private_network", ip: "192.168.56.30"
    db.vm.provider "virtualbox" do |vb|
      vb.memory = "1024"
      vb.cpus = 1
    end
  end
end