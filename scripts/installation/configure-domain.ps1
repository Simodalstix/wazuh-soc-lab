#
# Active Directory Domain Configuration Script for SOC Lab
# This script configures the Windows Server 2019 as a Domain Controller
# Run this script on the Windows Server 2019 VM (192.168.3.10)
#
# Usage: Run as Administrator in PowerShell
#

param(
    [string]$DomainName = "lab.local",
    [string]$NetBIOSName = "LAB",
    [string]$SafeModePassword = "P@ssw0rd123!",
    [string]$DomainAdminPassword = "P@ssw0rd123!"
)

# Colors for output
$Red = "Red"
$Green = "Green"
$Yellow = "Yellow"
$Blue = "Cyan"

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
    Add-Content -Path "C:\Windows\Temp\domain-setup.log" -Value "[$timestamp] $Message"
}

function Write-Banner {
    Write-Host "==================================================" -ForegroundColor $Blue
    Write-Host "    SOC Lab Active Directory Configuration" -ForegroundColor $Blue
    Write-Host "==================================================" -ForegroundColor $Blue
    Write-Host "Domain: $DomainName" -ForegroundColor $Blue
    Write-Host "NetBIOS: $NetBIOSName" -ForegroundColor $Blue
    Write-Host "Server IP: 192.168.3.10" -ForegroundColor $Blue
    Write-Host "==================================================" -ForegroundColor $Blue
}

function Test-Prerequisites {
    Write-Log "Checking prerequisites..." $Blue
    
    # Check if running as Administrator
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Log "This script must be run as Administrator" $Red
        exit 1
    }
    
    # Check Windows version
    $osVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
    if ($osVersion -notlike "*Server 2019*") {
        Write-Log "Warning: This script is designed for Windows Server 2019" $Yellow
    }
    
    # Check network configuration
    $networkAdapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1
    if (-not $networkAdapter) {
        Write-Log "No active network adapter found" $Red
        exit 1
    }
    
    Write-Log "Prerequisites check completed" $Green
}

function Set-StaticIP {
    Write-Log "Configuring static IP address..." $Blue
    
    $adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1
    
    # Remove existing IP configuration
    Remove-NetIPAddress -InterfaceAlias $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
    Remove-NetRoute -InterfaceAlias $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
    
    # Set static IP
    New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress "192.168.3.10" -PrefixLength 24 -DefaultGateway "192.168.1.1"
    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses "127.0.0.1", "8.8.8.8"
    
    Write-Log "Static IP configured: 192.168.3.10/24" $Green
}

function Install-ADDSRole {
    Write-Log "Installing Active Directory Domain Services role..." $Blue
    
    # Install AD DS role and management tools
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    
    if ($?) {
        Write-Log "AD DS role installed successfully" $Green
    } else {
        Write-Log "Failed to install AD DS role" $Red
        exit 1
    }
}

function Create-Domain {
    Write-Log "Creating new Active Directory domain..." $Blue
    
    # Convert password to secure string
    $securePassword = ConvertTo-SecureString $SafeModePassword -AsPlainText -Force
    
    # Create new forest and domain
    Install-ADDSForest `
        -DomainName $DomainName `
        -DomainNetbiosName $NetBIOSName `
        -SafeModeAdministratorPassword $securePassword `
        -InstallDns:$true `
        -CreateDnsDelegation:$false `
        -DatabasePath "C:\Windows\NTDS" `
        -LogPath "C:\Windows\NTDS" `
        -SysvolPath "C:\Windows\SYSVOL" `
        -Force:$true `
        -NoRebootOnCompletion:$false
    
    Write-Log "Domain creation initiated. System will reboot..." $Green
}

function Create-SOCUsers {
    Write-Log "Creating SOC lab users and groups..." $Blue
    
    # Import AD module
    Import-Module ActiveDirectory
    
    # Create SOC Analysts OU
    try {
        New-ADOrganizationalUnit -Name "SOC Lab" -Path "DC=lab,DC=local" -Description "SOC Lab Users and Computers"
        New-ADOrganizationalUnit -Name "SOC Analysts" -Path "OU=SOC Lab,DC=lab,DC=local" -Description "SOC Analyst Accounts"
        New-ADOrganizationalUnit -Name "Lab Computers" -Path "OU=SOC Lab,DC=lab,DC=local" -Description "Lab Computer Accounts"
        Write-Log "Organizational Units created" $Green
    } catch {
        Write-Log "OUs may already exist: $($_.Exception.Message)" $Yellow
    }
    
    # Create SOC Analysts group
    try {
        New-ADGroup -Name "SOC Analysts" -GroupScope Global -GroupCategory Security -Path "OU=SOC Analysts,OU=SOC Lab,DC=lab,DC=local" -Description "SOC Analyst Group"
        Write-Log "SOC Analysts group created" $Green
    } catch {
        Write-Log "SOC Analysts group may already exist: $($_.Exception.Message)" $Yellow
    }
    
    # Create SOC analyst users
    $socUsers = @(
        @{Name="analyst1"; FullName="SOC Analyst 1"; Description="Primary SOC Analyst"},
        @{Name="analyst2"; FullName="SOC Analyst 2"; Description="Secondary SOC Analyst"},
        @{Name="soc-admin"; FullName="SOC Administrator"; Description="SOC Lab Administrator"}
    )
    
    foreach ($user in $socUsers) {
        try {
            $secureUserPassword = ConvertTo-SecureString "SOCLab2024!" -AsPlainText -Force
            New-ADUser `
                -Name $user.Name `
                -DisplayName $user.FullName `
                -SamAccountName $user.Name `
                -UserPrincipalName "$($user.Name)@$DomainName" `
                -Path "OU=SOC Analysts,OU=SOC Lab,DC=lab,DC=local" `
                -AccountPassword $secureUserPassword `
                -Enabled $true `
                -Description $user.Description `
                -PasswordNeverExpires $true
            
            # Add to SOC Analysts group
            Add-ADGroupMember -Identity "SOC Analysts" -Members $user.Name
            
            Write-Log "Created user: $($user.Name)" $Green
        } catch {
            Write-Log "User $($user.Name) may already exist: $($_.Exception.Message)" $Yellow
        }
    }
}

function Configure-DNS {
    Write-Log "Configuring DNS settings..." $Blue
    
    # Add DNS forwarders
    Add-DnsServerForwarder -IPAddress "8.8.8.8", "8.8.4.4"
    
    # Create reverse lookup zone
    Add-DnsServerPrimaryZone -NetworkID "192.168.3.0/24" -ReplicationScope "Forest"
    Add-DnsServerPrimaryZone -NetworkID "192.168.2.0/24" -ReplicationScope "Forest"
    Add-DnsServerPrimaryZone -NetworkID "192.168.1.0/24" -ReplicationScope "Forest"
    
    # Add DNS records for lab systems
    Add-DnsServerResourceRecordA -ZoneName $DomainName -Name "wazuh-manager" -IPv4Address "192.168.1.10"
    Add-DnsServerResourceRecordA -ZoneName $DomainName -Name "ubuntu-web" -IPv4Address "192.168.2.10"
    Add-DnsServerResourceRecordA -ZoneName $DomainName -Name "rhel-db" -IPv4Address "192.168.3.20"
    Add-DnsServerResourceRecordA -ZoneName $DomainName -Name "pfsense" -IPv4Address "192.168.1.1"
    
    Write-Log "DNS configuration completed" $Green
}

function Configure-GroupPolicy {
    Write-Log "Configuring Group Policy for SOC lab..." $Blue
    
    # Import Group Policy module
    Import-Module GroupPolicy
    
    try {
        # Create SOC Lab GPO
        $gpo = New-GPO -Name "SOC Lab Security Policy" -Comment "Security settings for SOC lab environment"
        
        # Link GPO to SOC Lab OU
        New-GPLink -Name "SOC Lab Security Policy" -Target "OU=SOC Lab,DC=lab,DC=local"
        
        # Configure audit policies (basic settings)
        # Note: More detailed GPO configuration would typically be done through Group Policy Management Console
        
        Write-Log "Group Policy created and linked" $Green
    } catch {
        Write-Log "Group Policy configuration error: $($_.Exception.Message)" $Yellow
    }
}

function Enable-WindowsFeatures {
    Write-Log "Enabling additional Windows features..." $Blue
    
    # Enable Windows features useful for SOC lab
    $features = @(
        "RSAT-AD-Tools",
        "RSAT-DNS-Server",
        "RSAT-DHCP",
        "Telnet-Client"
    )
    
    foreach ($feature in $features) {
        try {
            Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart
            Write-Log "Enabled feature: $feature" $Green
        } catch {
            Write-Log "Could not enable feature $feature : $($_.Exception.Message)" $Yellow
        }
    }
}

function Create-ServiceAccounts {
    Write-Log "Creating service accounts for monitoring..." $Blue
    
    # Create service accounts for Wazuh monitoring
    $serviceAccounts = @(
        @{Name="svc-wazuh"; Description="Wazuh Agent Service Account"},
        @{Name="svc-monitoring"; Description="General Monitoring Service Account"}
    )
    
    foreach ($account in $serviceAccounts) {
        try {
            $secureServicePassword = ConvertTo-SecureString "ServiceAccount2024!" -AsPlainText -Force
            New-ADUser `
                -Name $account.Name `
                -SamAccountName $account.Name `
                -UserPrincipalName "$($account.Name)@$DomainName" `
                -Path "OU=SOC Lab,DC=lab,DC=local" `
                -AccountPassword $secureServicePassword `
                -Enabled $true `
                -Description $account.Description `
                -PasswordNeverExpires $true `
                -CannotChangePassword $true
            
            Write-Log "Created service account: $($account.Name)" $Green
        } catch {
            Write-Log "Service account $($account.Name) may already exist: $($_.Exception.Message)" $Yellow
        }
    }
}

function Display-Summary {
    Write-Host "==================================================" -ForegroundColor $Green
    Write-Host "    Active Directory Configuration Complete!" -ForegroundColor $Green
    Write-Host "==================================================" -ForegroundColor $Green
    Write-Host "Domain: $DomainName" -ForegroundColor $Green
    Write-Host "Domain Controller: 192.168.3.10" -ForegroundColor $Green
    Write-Host ""
    Write-Host "Created Users:" -ForegroundColor $Green
    Write-Host "- analyst1 / SOCLab2024!" -ForegroundColor $Green
    Write-Host "- analyst2 / SOCLab2024!" -ForegroundColor $Green
    Write-Host "- soc-admin / SOCLab2024!" -ForegroundColor $Green
    Write-Host ""
    Write-Host "Service Accounts:" -ForegroundColor $Green
    Write-Host "- svc-wazuh / ServiceAccount2024!" -ForegroundColor $Green
    Write-Host "- svc-monitoring / ServiceAccount2024!" -ForegroundColor $Green
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor $Green
    Write-Host "1. Configure other VMs to use 192.168.3.10 as DNS" -ForegroundColor $Green
    Write-Host "2. Join Linux systems to domain (optional)" -ForegroundColor $Green
    Write-Host "3. Deploy Wazuh agents with domain authentication" -ForegroundColor $Green
    Write-Host "==================================================" -ForegroundColor $Green
}

# Main execution
try {
    Write-Banner
    Test-Prerequisites
    Set-StaticIP
    Install-ADDSRole
    
    # Check if domain already exists
    try {
        Get-ADDomain -ErrorAction Stop
        Write-Log "Domain already exists, skipping domain creation" $Yellow
        
        # Configure additional settings
        Create-SOCUsers
        Configure-DNS
        Configure-GroupPolicy
        Enable-WindowsFeatures
        Create-ServiceAccounts
        Display-Summary
        
    } catch {
        Write-Log "Domain does not exist, creating new domain..." $Blue
        Create-Domain
        # Note: System will reboot after domain creation
        # Run this script again after reboot to complete configuration
    }
    
} catch {
    Write-Log "Script execution failed: $($_.Exception.Message)" $Red
    exit 1
}