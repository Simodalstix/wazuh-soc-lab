# Getting Started with the Wazuh SOC Lab

This guide provides a simplified, step-by-step process to set up the Wazuh SOC Lab environment.

## Step 1: Prerequisites

Before you begin, ensure you have the following software installed on your host machine:

1.  **VMware Workstation**: The hypervisor to run the virtual machines.
2.  **Vagrant**: The tool that automates the creation and management of the virtual lab. You can download it from the [Vagrant website](https://www.vagrantup.com/downloads).
3.  **Vagrant Plugins**: These extend Vagrant's functionality. Install them by opening a terminal and running the following commands:
    ```bash
    vagrant plugin install vagrant-vbguest
    vagrant plugin install vagrant-hostmanager
    vagrant plugin install vagrant-reload
    ```

## Step 2: Download Required ISOs

The lab requires specific OS installation images (ISOs). You will need to download them and place them in a directory named `ISOs` within your user's home directory (`~/ISOs/` on Linux/macOS or `C:\Users\YourUser\ISOs` on Windows).

- **pfSense**: [pfSense-CE-2.7.2-RELEASE-amd64.iso](https://www.pfsense.org/download/)
- **Ubuntu**: [ubuntu-24.04.2-live-server-amd64.iso](https://ubuntu.com/download/server)
- **Windows Server 2019**: [SERVER_EVAL_x64FRE_en-us.iso](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019)
- **RHEL 9**: [rhel-9.5-x86_64-dvd.iso](https://developers.redhat.com/products/rhel/download) (Requires a Red Hat developer account)

## Step 3: Start the Lab Environment

With the prerequisites installed and ISOs in place, you can now start the virtual machines.

1.  Open a terminal in the project's root directory.
2.  Run the following command to start all the virtual machines in the correct order:
    ```bash
    vagrant up
    ```
    \*Note: This process will

take some time as it downloads the base virtual machine images and runs initial provisioning.\*

## Step 4: Manual pfSense Installation

The pfSense firewall requires manual installation. When you run `vagrant up`, a virtual machine with a graphical console will start. Follow these steps to install and configure it:

1.  \*\*Boot from ISO

**: At the boot menu, select the installer. 2. **Installation**: Follow the on-screen prompts to install pfSense to the virtual hard disk. The default options are generally sufficient. 3. **Interface Assignment**: Once the installation is complete and the system reboots, you will be prompted to assign network interfaces. Assign them as follows: - **WAN**: `em0` - **LAN**: `em1` - **OPT1 (DMZ)**: `em2` - **OPT2 (Internal)**: `em3` 4. **IP Address Configuration**: After assigning the interfaces, set the IP addresses: - **LAN**: `192.168.1.1` with a subnet mask of `24`. - **DMZ**: `192.168.2.1` with a subnet mask of `24`. - **Internal\*\*: `192.168.3.1` with a subnet mask of `24`. - Enable the DHCP server on the LAN interface when prompted.

## Step 5: Ansible Provisioning

After the virtual machines are running and pfSense is configured, you need to run Ansible to configure the rest of the lab environment.

1.  Open a terminal in the project's root directory.
2.  Run the following command:
    ```bash
    vagrant provision --provision-with ansible
    ```
    This will configure the Wazuh manager, deploy the web server, and set up the other systems.

## Step 6: Accessing the Lab

Once provisioning is complete, you can access the different components of the lab:

- **Wazuh Dashboard**: [https://192.168.1.10](https://192.168.1.10)
- **DVWA (Damn Vulnerable Web Application)**: [http://192.168.2.10/dvwa](http://192.168.2.10/dvwa)
- **pfSense Web Interface**: [https://192.168.1.1](https://192.168.1.1) (Default credentials: `admin`/`pfsense`)

You are now ready to start using the Wazuh SOC Lab.
