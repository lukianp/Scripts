# Active Directory Multi-Domain Lab Deployment Scripts

Automated Hyper-V deployment scripts for building enterprise-realistic Active Directory environments. Designed for M&A discovery testing, security assessments, and AD administration training.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Deployment Order](#deployment-order)
- [Script 1: Deploy-LabDC-WithBulkAD.ps1](#script-1-deploy-labdc-withbulkadps1)
- [Script 2: Deploy-ChildDomainDC.ps1](#script-2-deploy-childdomaindcps1)
- [Script 3: Deploy-ExternalForestDC.ps1](#script-3-deploy-externalforestdcps1)
- [DNS Architecture](#dns-architecture)
- [Troubleshooting](#troubleshooting)
- [Credentials Reference](#credentials-reference)

---

## Architecture Overview

```
+-----------------------------------------------------------------------------+
|                           FOREST: ljpops.com                                |
|                                                                             |
|  +-------------------------+         +-------------------------+           |
|  |   ljpops.com (Root)     |         |  corp.ljpops.com        |           |
|  |   DC: uran              |<--------->|  DC: corp-dc01          |           |
|  |   IP: 192.168.0.10      |  Parent |  IP: 192.168.0.11       |           |
|  |                         |  Child  |                         |           |
|  |  * 21 OUs               |  Trust  |  * 9 OUs                |           |
|  |  * 50+ Groups           |         |  * 8 Groups             |           |
|  |  * 25+ Users            |         |  * 10 Users             |           |
|  |  * 27 GPOs              |         |                         |           |
|  |  * DHCP, CA, NTP        |         |                         |           |
|  +-------------------------+         +-------------------------+           |
|              |                                                              |
+--------------+--------------------------------------------------------------+
               |
               | Two-Way Forest Trust
               v
+-----------------------------------------------------------------------------+
|                      FOREST: ljpgroupholdings.com                           |
|                         (Acquired Company)                                  |
|                                                                             |
|  +-------------------------+                                               |
|  |  ljpgroupholdings.com   |                                               |
|  |  DC: ljpgroup           |                                               |
|  |  IP: 192.168.0.20       |                                               |
|  |                         |                                               |
|  |  * 11 OUs               |                                               |
|  |  * 10 Groups            |                                               |
|  |  * 15 Users             |                                               |
|  |  * 5 Stale Accounts     |                                               |
|  |  * Legacy Data Shares   |                                               |
|  +-------------------------+                                               |
|                                                                             |
+-----------------------------------------------------------------------------+
```

---

## Prerequisites

### Hardware Requirements
| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Host RAM | 16 GB | 32 GB |
| Host Storage | 150 GB free | 250 GB SSD |
| Host CPU | 4 cores | 8+ cores |

### Software Requirements
- Windows 10/11 Pro or Windows Server with Hyper-V enabled
- PowerShell 5.1 or later (run as Administrator)
- Windows Server 2022 Evaluation ISO (auto-downloaded if missing)

### Network Requirements
- Virtual switch with internet access (for ISO download)
- Static IP range available (default: 192.168.0.x/24)

---

## Deployment Order

**Scripts must be run in this order:**

1. **Deploy-LabDC-WithBulkAD.ps1** -> Creates forest root domain
2. **Deploy-ChildDomainDC.ps1** -> Creates child domain under root
3. **Deploy-ExternalForestDC.ps1** -> Creates separate forest with trust

Each script takes approximately 8-12 minutes to complete.

---

## Script 1: Deploy-LabDC-WithBulkAD.ps1

### Purpose
Creates the **forest root domain controller** with comprehensive enterprise-realistic AD objects including OUs, users, groups, GPOs, DHCP, Certificate Services, and file shares.

### Configuration Prompts

```
+----------------------------------------------------------------+
|         HYPER-V LAB DC DEPLOYMENT WITH BULK AD                 |
+----------------------------------------------------------------+

-- Domain Configuration --
  Domain FQDN [ljpops.com]: 
  NetBIOS Name [LJPOPS]: 
  Admin Password [LabAdmin2025!]: 

-- VM Configuration --
  VM Name [uran]: 
  Memory in GB [4]: 
  vCPU Count [2]: 
  Disk Size in GB [60]: 

-- Network Configuration --
  Static IP Address [192.168.0.10]: 
  Subnet Prefix Length [24]: 
  Default Gateway [192.168.0.1]: 

-- Virtual Switch --
  Switch Name [LabSwitch]: 

-- Optional Components --
  Install DHCP Server? (Y/n) [Y]: 
  Install Certificate Services? (Y/n) [Y]: 
  Create Bulk AD Objects? (Y/n) [Y]: 

-- Storage Location --
  VM Storage Path [C:\Hyper-V_VMs]: 
```

### Console Output Stages

```
[2025-12-26 20:00:00] [Info] Checking prerequisites...
[2025-12-26 20:00:01] [Success] Prerequisites check passed
[2025-12-26 20:00:01] [Info] Checking for Windows Server ISO...
[2025-12-26 20:00:05] [Success] ISO verification passed
[2025-12-26 20:00:05] [Info] Configuring virtual switch...
[2025-12-26 20:00:06] [Info] Creating Hyper-V VM 'uran'...
[2025-12-26 20:00:07] [Success] VM created: 4GB RAM, 2 vCPUs
[2025-12-26 20:00:07] [Info] Creating 60GB VHD...
[2025-12-26 20:00:15] [Info] Mounting ISO and applying Windows image...
[2025-12-26 20:00:16] [Info] Applying: Windows Server 2022 Datacenter Evaluation
[2025-12-26 20:01:30] [Info] Injecting unattend.xml...
[2025-12-26 20:01:31] [Success] Windows image applied
[2025-12-26 20:01:35] [Info] Starting VM...
[2025-12-26 20:01:35] [Info] Waiting for Windows Setup (timeout: 15m)...
  Waiting... (00:45 elapsed)
[2025-12-26 20:02:20] [Success] Windows Setup is ready
[2025-12-26 20:02:20] [Info] Stabilizing services (30s)...
[2025-12-26 20:02:50] [Info] Configuring network...
[2025-12-26 20:02:55] [Info] Installing AD Domain Services...
[2025-12-26 20:03:30] [Info] Promoting to Domain Controller for 'ljpops.com'...
[2025-12-26 20:04:00] [Info] Restarting VM...
[2025-12-26 20:04:30] [Info] Waiting for Domain Controller services (timeout: 15m)...
  Services: NTDS=Running, DNS=Running, ADWS=Running (2m)
[2025-12-26 20:06:30] [Success] Domain Controller operational: ljpops.com
[2025-12-26 20:06:30] [Info] Verifying DNS zones...
  DNS zone 'ljpops.com' exists
  _msdcs zone '_msdcs.ljpops.com' exists
[2025-12-26 20:06:35] [Info] Creating base AD objects...
[2025-12-26 20:06:40] [Info] Creating Organizational Units (21 OUs)...
[2025-12-26 20:06:45] [Info] Creating Security Groups (20+ groups)...
[2025-12-26 20:06:50] [Info] Creating User Accounts (25 users)...
[2025-12-26 20:07:00] [Info] Creating Service Accounts (10 accounts)...
[2025-12-26 20:07:10] [Info] Installing Group Policy Objects (27 GPOs)...
[2025-12-26 20:07:45] [Info] Installing DHCP Server...
[2025-12-26 20:08:00] [Info] Installing Certificate Services...
[2025-12-26 20:08:30] [Info] Configuring DNS Server...
[2025-12-26 20:08:45] [Info] Creating file shares...
[2025-12-26 20:09:00] [Success] ROOT DOMAIN DEPLOYMENT COMPLETE!
```

### Technical Implementation Details

#### VM Creation (New-LabVM, New-LabVHD)
```powershell
# Creates Gen2 VM with secure boot disabled for evaluation ISO
New-VM -Name $VMName -Generation 2 -MemoryStartupBytes ($MemoryGB * 1GB)
Set-VMFirmware -VMName $VMName -EnableSecureBoot Off
Set-VMProcessor -VMName $VMName -Count $CPUCount
```

#### Windows Image Application
```powershell
# Mounts VHD, applies WIM image, injects unattend.xml
$wimPath = "$mountPath\sources\install.wim"
$imageIndex = 4  # Datacenter Desktop Experience
Expand-WindowsImage -ImagePath $wimPath -Index $imageIndex -ApplyPath $vhdMount
```

#### Unattend.xml Key Settings
- Administrator password auto-set
- Auto-logon enabled for first boot
- Time zone set to UTC
- Network set to Private profile
- PowerShell remoting enabled

#### DC Promotion (Install-ForestRootDC)
```powershell
Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetBIOSName $NetBIOSName `
    -SafeModeAdministratorPassword $SafeModePwd `
    -InstallDNS:$true `
    -CreateDnsDelegation:$false `
    -DatabasePath "C:\Windows\NTDS" `
    -LogPath "C:\Windows\NTDS" `
    -SysvolPath "C:\Windows\SYSVOL" `
    -NoRebootOnCompletion:$false `
    -Force:$true
```

#### DNS Zone Verification
```powershell
# Checks and creates zones if missing after promotion
$primaryZone = Get-DnsServerZone -Name $DomainName -ErrorAction SilentlyContinue
if (-not $primaryZone) {
    Add-DnsServerPrimaryZone -Name $DomainName -ReplicationScope Domain -DynamicUpdate Secure
}

$msdcsZone = "_msdcs.$DomainName"
if (-not (Get-DnsServerZone -Name $msdcsZone -ErrorAction SilentlyContinue)) {
    Add-DnsServerPrimaryZone -Name $msdcsZone -ReplicationScope Forest -DynamicUpdate Secure
}
```

### Objects Created

#### Organizational Units (21)
```
DC=ljpops,DC=com
+-- OU=Corporate
|   +-- OU=Users
|   +-- OU=Computers
|   +-- OU=Groups
|   +-- OU=Servers
+-- OU=Departments
|   +-- OU=IT
|   +-- OU=HR
|   +-- OU=Finance
|   +-- OU=Marketing
|   +-- OU=Management
+-- OU=Service Accounts
+-- OU=Admin Accounts
+-- OU=Workstations
+-- OU=Disabled
+-- OU=Quarantine
+-- OU=Test
```

#### Security Groups (50+)
| Group Type | Examples |
|------------|----------|
| Department | IT-Staff, HR-Staff, Finance-Staff, Marketing-Staff |
| Role-Based | Helpdesk-L1, Helpdesk-L2, Server-Admins, Network-Admins |
| Access | VPN-Users, Remote-Desktop-Users, File-Share-Access |
| Privileged | Domain Admins, Enterprise Admins, Schema Admins |

#### User Accounts (25+)
| Category | Naming Convention | Example |
|----------|-------------------|---------|
| Standard Users | firstname.lastname | john.smith |
| Admin Accounts | username-sa | jsmith-sa |
| Service Accounts | svc-appname | svc-sql, svc-backup |
| Test Accounts | testuser# | testuser1, testuser2 |

#### Group Policy Objects (27)

**Domain-Wide Policies (3):**
- Password Policy (complexity, length, history)
- Security Audit Policy (logon events, object access)
- Kerberos Security (AES256 encryption)

**Computer Policies (9):**
- WSUS Configuration
- Security Baseline (SMBv1 disabled, NTLMv2 required, LLMNR disabled)
- Windows Firewall Settings
- BitLocker Drive Encryption
- Power Management
- Windows Defender Settings
- RDP Security Settings
- Credential Guard (disabled - for testing)
- AppLocker (disabled - for testing)

**User Policies (6):**
- Desktop Settings
- Folder Redirection (disabled)
- Drive Mappings
- Removable Storage Restrictions (USB write blocked)
- Edge Browser Settings
- Office Macro Settings (blocked by default)

**Department-Specific (6):**
- IT Department (RDP enabled, PowerShell RemoteSigned)
- IT Workstations (elevated privileges)
- HR Department (5min screen lock, clear pagefile)
- Finance Department (3min screen lock, USB blocked)
- Marketing Department (USB allowed - override)
- Management (30min timeout, minimal restrictions)

**Legacy/Orphaned (3):**
- IE Deprecated Settings (for discovery)
- OLD WSUS Server (orphaned - for discovery)
- TEST Policy (orphaned - for discovery)

#### Additional Services
| Service | Configuration |
|---------|---------------|
| DHCP | Scope 192.168.0.100-200, DNS/Gateway options |
| Certificate Services | Enterprise Root CA |
| DNS | Forwarders to 8.8.8.8, 1.1.1.1 |
| NTP | time.windows.com |
| File Shares | \\DC\temp, \\DC\shared |

---

## Script 2: Deploy-ChildDomainDC.ps1

### Purpose
Creates a **child domain** under the existing forest root, establishing automatic parent-child trust and shared Configuration/Schema partitions.

### Configuration Prompts

```
+----------------------------------------------------------------+
|           HYPER-V CHILD DOMAIN DC DEPLOYMENT                   |
+----------------------------------------------------------------+

-- Parent Domain Configuration --
  Parent Domain FQDN [ljpops.com]: 
  Parent DC IP Address [192.168.0.10]: 
  Parent DC Hyper-V VM Name [uran]: 
  Parent Domain Admin Password [LabAdmin2025!]: 

-- Child Domain Configuration --
  Child Domain Prefix [corp]: 
  Child Domain FQDN: corp.ljpops.com
  Child NetBIOS Name [CORP]: 

-- VM Configuration --
  VM Name [corp-dc01]: 
  Memory in GB [4]: 
  vCPU Count [2]: 
  Disk Size in GB [60]: 

-- Network Configuration --
  Static IP Address [192.168.0.11]: 
  Subnet Prefix Length [24]: 
  Default Gateway [192.168.0.1]: 

-- Virtual Switch --
  Switch Name [LabSwitch]: 

-- Bulk AD Objects --
  Create OUs, Groups, and Users? (Y/n) [Y]: 

-- Storage Location --
  VM Storage Path [C:\Hyper-V_VMs]: 
```

### Console Output Stages

```
[2025-12-26 20:45:00] [Info] Checking prerequisites...
[2025-12-26 20:45:01] [Info] Testing connectivity to parent DC (192.168.0.10)...
[2025-12-26 20:45:02] [Success] Parent DC reachable
[2025-12-26 20:45:02] [Success] Prerequisites check passed
[2025-12-26 20:45:02] [Info] Checking for Windows Server ISO...
[2025-12-26 20:45:06] [Success] ISO verification passed
[2025-12-26 20:45:06] [Info] Configuring virtual switch...
[2025-12-26 20:45:07] [Info] Creating Hyper-V VM 'corp-dc01'...
[2025-12-26 20:45:08] [Success] VM created: 4GB RAM, 2 vCPUs
[2025-12-26 20:45:08] [Info] Creating 60GB VHD...
[2025-12-26 20:45:18] [Info] Mounting ISO and applying Windows image...
[2025-12-26 20:46:30] [Success] Windows image applied
[2025-12-26 20:46:35] [Info] Starting VM...
[2025-12-26 20:46:35] [Info] Waiting for Windows Setup (timeout: 10m)...
[2025-12-26 20:47:15] [Success] Windows Setup is ready
[2025-12-26 20:47:15] [Info] Configuring network...
[2025-12-26 20:47:20] [Info] Installing AD Domain Services...
[2025-12-26 20:47:50] [Info] Promoting to Child Domain Controller for 'corp.ljpops.com'...
[2025-12-26 20:48:50] [Info] Restarting VM...
[2025-12-26 20:49:20] [Info] Waiting for Domain Controller services (timeout: 15m)...
[2025-12-26 20:51:00] [Success] Child Domain DC operational: corp.ljpops.com
[2025-12-26 20:51:00] [Info] Verifying DNS zones...
  Primary zone exists: corp.ljpops.com
  DNS verification: corp.ljpops.com resolves correctly
[2025-12-26 20:51:05] [Success] DNS zones verified
[2025-12-26 20:51:05] [Info] Running post-deployment health checks...
  Post-Deployment Health Check:
    DNS Servers:        192.168.0.11, 192.168.0.10
    Self Resolution:    192.168.0.11
    DC GUID Record:     OK
    Parent Resolution:  ljpops.com -> 192.168.0.10
    Parent DC:          uran.ljpops.com -> 192.168.0.10
    Replication:        Initiated
    SYSVOL Ready:       True
[2025-12-26 20:51:20] [Success] Post-deployment health checks passed
[2025-12-26 20:51:20] [Info] Configuring DNS forwarders on parent DC (uran)...
  Added forwarder on parent: corp.ljpops.com -> 192.168.0.11
  Added forwarder on parent: _msdcs.corp.ljpops.com -> 192.168.0.11
[2025-12-26 20:51:25] [Success] DNS forwarders configured on parent DC
[2025-12-26 20:51:25] [Info] Creating privileged admin accounts...
[2025-12-26 20:51:35] [Info] Creating bulk AD objects...
[2025-12-26 20:51:50] [Info] Verifying trust relationship...
[2025-12-26 20:52:00] [Success] CHILD DOMAIN DEPLOYMENT COMPLETE!
```

### Technical Implementation Details

#### Child Domain Promotion
```powershell
Install-ADDSDomain `
    -NewDomainName $ChildPrefix `
    -ParentDomainName $ParentDomain `
    -DomainType ChildDomain `
    -InstallDNS:$true `
    -CreateDnsDelegation:$true `
    -Credential $ParentCredential `
    -SafeModeAdministratorPassword $SafeModePwd `
    -DatabasePath "C:\Windows\NTDS" `
    -LogPath "C:\Windows\NTDS" `
    -SysvolPath "C:\Windows\SYSVOL" `
    -NoRebootOnCompletion:$false `
    -Force:$true
```

#### DNS Configuration (Dual DNS Servers)
```powershell
# Child DC points to itself first, then parent
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex `
    -ServerAddresses @($SelfIP, $ParentDCIP)
```

#### Parent DC DNS Forwarder Configuration
```powershell
# Uses Hyper-V direct connection to configure parent DC
Invoke-Command -VMName $Config.ParentVMName -Credential $parentCred -ScriptBlock {
    Add-DnsServerConditionalForwarderZone -Name $ChildDomain -MasterServers $ChildDCIP
    Add-DnsServerConditionalForwarderZone -Name "_msdcs.$ChildDomain" -MasterServers $ChildDCIP
}
```

#### Post-Deployment Health Check
```powershell
# Verifies DNS, GUID resolution, replication, SYSVOL
$healthResults = Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
    # Check DNS servers configured correctly
    # Verify self-resolution (hostname -> IP)
    # Verify DC GUID record in _msdcs zone
    # Test parent domain resolution
    # Force replication with repadmin /syncall /AdeP
    # Check SYSVOL accessibility
}
```

### Objects Created

#### Organizational Units (9)
```
DC=corp,DC=ljpops,DC=com
+-- OU=Engineering
+-- OU=Sales
+-- OU=Support
+-- OU=Finance
+-- OU=Computers
+-- OU=Servers
+-- OU=Service Accounts
+-- OU=Admin Accounts
+-- OU=Disabled
```

#### Security Groups (8)
- Engineering-Team
- Sales-Team
- Support-Team
- Finance-Team
- Corp-Admins
- Corp-Users
- Remote-Workers
- Contractors

#### User Accounts (10)
| Department | Users |
|------------|-------|
| Engineering | eng.user1, eng.user2, eng.user3 |
| Sales | sales.user1, sales.user2 |
| Support | support.user1, support.user2 |
| Finance | finance.user1, finance.user2 |
| Admin | corp-admin |

#### Trust Relationship
| Property | Value |
|----------|-------|
| Type | Parent-Child (Automatic) |
| Direction | Bidirectional |
| Transitivity | Transitive |
| Authentication | Forest-wide |

---

## Script 3: Deploy-ExternalForestDC.ps1

### Purpose
Creates a **separate forest** simulating an acquired company, establishes a two-way forest trust with the primary forest, and populates with legacy-style AD objects for M&A discovery testing.

### Configuration Prompts

```
+----------------------------------------------------------------+
|       HYPER-V EXTERNAL FOREST DEPLOYMENT (ACQUIRED CO)         |
|         Creates Separate Forest with External Trust            |
+----------------------------------------------------------------+

-- Primary Forest Configuration (for trust) --
  Primary Forest Domain FQDN [ljpops.com]: 
  Primary Forest DC IP Address [192.168.0.10]: 
  Primary DC Hyper-V VM Name [uran]: 
  Primary Forest Admin Password [LabAdmin2025!]: 

-- External Forest Configuration (Acquired Company) --
  External Forest Domain FQDN (e.g., acquired.local) [acquired.local]: ljpgroupholdings.com
  NetBIOS Name (auto-derived): LJPGROUPHOLDING
  Press Enter to accept, or type new NetBIOS name (max 15 chars, no dots): 
  External Forest: ljpgroupholdings.com (LJPGROUPHOLDING)

-- VM Configuration --
  VM Name [acq-dc01]: ljpgroup
  Memory in GB [4]: 
  vCPU Count [2]: 
  Disk Size in GB [60]: 

-- Network Configuration --
  Static IP Address [192.168.0.20]: 
  Subnet Prefix Length [24]: 
  Default Gateway [192.168.0.1]: 

-- Virtual Switch --
  Switch Name [LabSwitch]: 

-- Trust Configuration --
  Create two-way forest trust with primary? (Y/n) [Y]: 

-- Bulk AD Object Creation --
  Create OUs, Groups, and Users? (Y/n) [Y]: 

-- Storage Location --
  VM Storage Path [C:\Hyper-V_VMs]: 
```

### Console Output Stages

```
[2025-12-26 21:54:38] [Info] Checking prerequisites...
[2025-12-26 21:54:39] [Info] Testing connectivity to primary DC (192.168.0.10) for trust...
[2025-12-26 21:54:40] [Success] Primary DC reachable
[2025-12-26 21:54:40] [Success] Prerequisites check passed
[2025-12-26 21:54:40] [Info] Checking for Windows Server ISO...
[2025-12-26 21:54:44] [Success] ISO verification passed
[2025-12-26 21:54:44] [Info] Creating Hyper-V VM 'ljpgroup'...
[2025-12-26 21:54:45] [Success] VM created: 4GB RAM, 2 vCPUs
[2025-12-26 21:54:45] [Info] Creating 60GB VHD...
[2025-12-26 21:55:00] [Info] Mounting ISO and applying Windows image...
[2025-12-26 21:56:10] [Success] Windows image applied
[2025-12-26 21:56:15] [Info] Starting VM...
[2025-12-26 21:56:15] [Info] Waiting for Windows Setup (timeout: 10m)...
[2025-12-26 21:56:50] [Success] Windows Setup is ready
[2025-12-26 21:56:50] [Info] Configuring network...
[2025-12-26 21:56:55] [Info] Installing AD Domain Services...
[2025-12-26 21:57:25] [Info] Promoting to Forest Root DC for 'ljpgroupholdings.com'...
[2025-12-26 21:58:25] [Info] Restarting VM...
[2025-12-26 21:59:00] [Info] Waiting for Domain Controller services (timeout: 15m)...
[2025-12-26 22:00:30] [Success] External Forest DC operational: ljpgroupholdings.com
[2025-12-26 22:00:30] [Info] Verifying DNS zones...
  Primary zone exists: ljpgroupholdings.com
  _msdcs zone exists: _msdcs.ljpgroupholdings.com
  DNS verification: ljpgroupholdings.com resolves correctly
[2025-12-26 22:00:40] [Success] DNS zones verified
[2025-12-26 22:00:40] [Info] Configuring DNS for cross-forest resolution...
  Added conditional forwarder: ljpops.com -> 192.168.0.10
  Added conditional forwarder: _msdcs.ljpops.com -> 192.168.0.10
  DNS verification: ljpops.com -> 192.168.0.10 (Correct)
[2025-12-26 22:00:50] [Info] Running post-deployment health checks...
  Post-Deployment Health Check:
    DNS Servers:        192.168.0.20
    Self Resolution:    192.168.0.20
    DC GUID Record:     OK
    Forwarders:         Configured
    Primary Resolution: ljpops.com -> 192.168.0.10
    SYSVOL Ready:       True
[2025-12-26 22:01:00] [Success] Post-deployment health checks passed
[2025-12-26 22:01:00] [Info] Creating privileged admin accounts...
  Created: acq-admin
  Created: svc-legacy-backup
  Created: svc-legacy-sql
[2025-12-26 22:01:20] [Info] Creating bulk AD objects (simulating acquired company)...
[2025-12-26 22:01:25] [Info] Creating Organizational Units...
  OUs created: 11
[2025-12-26 22:01:30] [Info] Creating Security Groups...
  Groups created: 10
[2025-12-26 22:01:35] [Info] Creating User Accounts...
  Users created: 10
[2025-12-26 22:01:40] [Info] Creating stale objects (acquisition cleanup candidates)...
  Created 5 disabled/stale users
[2025-12-26 22:01:45] [Info] Creating C:\temp share with legacy data...
[2025-12-26 22:01:50] [Info] Creating two-way forest trust with ljpops.com...
[2025-12-26 22:01:50] [Info] Configuring DNS conditional forwarder on primary DC (uran)...
  Added forwarder on primary: ljpgroupholdings.com -> 192.168.0.20
  Added forwarder on primary: _msdcs.ljpgroupholdings.com -> 192.168.0.20
[2025-12-26 22:01:55] [Success] DNS forwarders configured on primary DC
[2025-12-26 22:01:55] [Info] Creating trust from external forest...
  Trust created successfully
[2025-12-26 22:02:00] [Success] Forest trust created successfully
[2025-12-26 22:02:00] [Success] EXTERNAL FOREST DEPLOYMENT COMPLETE!
```

### Technical Implementation Details

#### Domain FQDN Validation
```powershell
# Ensures domain contains at least one dot
do {
    $externalDomain = Read-Host "External Forest Domain FQDN"
    if ($externalDomain -notmatch '\.') {
        Write-Host "ERROR: Domain must be fully qualified (contain at least one dot)"
    }
} while ($externalDomain -notmatch '\.')
```

#### NetBIOS Auto-Derivation
```powershell
# Extracts first label, removes invalid chars, limits to 15 chars
$derivedNetBIOS = ($externalDomain -split '\.')[0].ToUpper() -replace '[^A-Z0-9]',''
if ($derivedNetBIOS.Length -gt 15) { $derivedNetBIOS = $derivedNetBIOS.Substring(0,15) }
```

#### Forest Root Promotion (Separate Forest)
```powershell
Install-ADDSForest `
    -DomainName $ExternalDomain `
    -DomainNetBIOSName $ExternalNetBIOS `
    -SafeModeAdministratorPassword $SafeModePwd `
    -InstallDNS:$true `
    -CreateDnsDelegation:$false `
    -ForestMode WinThreshold `
    -DomainMode WinThreshold `
    -DatabasePath "C:\Windows\NTDS" `
    -LogPath "C:\Windows\NTDS" `
    -SysvolPath "C:\Windows\SYSVOL" `
    -NoRebootOnCompletion:$false `
    -Force:$true
```

#### DNS Zone Verification (Critical Fix)
```powershell
# Verifies and creates zones if missing after Install-ADDSForest
$primaryZone = Get-DnsServerZone -Name $DomainName -ErrorAction SilentlyContinue
if (-not $primaryZone) {
    Write-Host "WARNING: Primary DNS zone missing - creating..."
    Add-DnsServerPrimaryZone -Name $DomainName -ReplicationScope Domain -DynamicUpdate Secure
}

$msdcsZone = "_msdcs.$DomainName"
if (-not (Get-DnsServerZone -Name $msdcsZone -ErrorAction SilentlyContinue)) {
    Write-Host "WARNING: _msdcs zone missing - creating..."
    Add-DnsServerPrimaryZone -Name $msdcsZone -ReplicationScope Forest -DynamicUpdate Secure
}
```

#### Forest Trust Creation
```powershell
# Uses .NET DirectoryServices for trust creation
$localForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$remoteContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(
    [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Forest,
    $PrimaryDomain,
    "$PrimaryNetBIOS\Administrator",
    $PrimaryAdminPwd
)
$remoteForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($remoteContext)
$localForest.CreateTrustRelationship(
    $remoteForest,
    [System.DirectoryServices.ActiveDirectory.TrustDirection]::Bidirectional
)
```

#### Primary DC DNS Configuration (via Hyper-V)
```powershell
# Uses -VMName instead of -ComputerName to bypass WinRM issues
Invoke-Command -VMName $Config.PrimaryVMName -Credential $primaryCred -ScriptBlock {
    Add-DnsServerConditionalForwarderZone -Name $ExternalDomain -MasterServers $ExternalDCIP
    Add-DnsServerConditionalForwarderZone -Name "_msdcs.$ExternalDomain" -MasterServers $ExternalDCIP
}
```

### Objects Created

#### Organizational Units (11)
```
DC=ljpgroupholdings,DC=com
+-- OU=Staff
|   +-- OU=Development
|   +-- OU=QA
|   +-- OU=Support
|   +-- OU=Management
+-- OU=Computers
+-- OU=Servers
+-- OU=Groups
+-- OU=Service Accounts
+-- OU=Contractors
+-- OU=Disabled
```

#### Security Groups (10)
- DEV-Team
- QA-Team
- PROD-Support
- Mgmt-Team
- All-Staff
- Legacy-Admins
- Legacy-Users
- Contractors
- External-Access
- Deprecated-Group

#### User Accounts (15 total)

**Active Users (10):**
| Department | Users | Naming Convention |
|------------|-------|-------------------|
| Development | jsmith, mjohnson, rwilliams | Legacy: first initial + lastname |
| QA | pbrown, dgarcia | |
| Support | lmartinez, janderson | |
| Management | bthomas, mwilson | |

**Stale/Disabled Accounts (5):**
| Username | Description |
|----------|-------------|
| former.employee1 | Left company 2023 |
| former.employee2 | Terminated 2024 |
| oldcontractor | Contract ended |
| testuser.legacy | Old test account |
| svc.oldapp | Decommissioned app service |

#### Legacy Data (File Shares)
```
\\ljpgroup\temp
+-- README.txt
+-- Migration_Data\
|   +-- user_list.csv
|   +-- group_memberships.csv
|   +-- checklist.txt
+-- Documentation\
|   +-- network.txt
+-- Projects\
    +-- status.txt
```

#### Trust Relationship
| Property | Value |
|----------|-------|
| Type | Forest Trust |
| Direction | Bidirectional |
| Transitivity | Transitive |
| SID Filtering | Enabled (default) |
| Selective Auth | Disabled |

---

## DNS Architecture

### DNS Server Configuration

| DC | Zone Type | Zones Hosted | Forwarders |
|----|-----------|--------------|------------|
| uran | Primary | ljpops.com, _msdcs.ljpops.com | 8.8.8.8, 1.1.1.1 |
| uran | Conditional | corp.ljpops.com, ljpgroupholdings.com | 192.168.0.11, 192.168.0.20 |
| corp-dc01 | Primary | corp.ljpops.com | - |
| corp-dc01 | Secondary DNS | - | 192.168.0.10 (parent) |
| ljpgroup | Primary | ljpgroupholdings.com, _msdcs.ljpgroupholdings.com | - |
| ljpgroup | Conditional | ljpops.com, _msdcs.ljpops.com | 192.168.0.10 |

### DNS Resolution Flow

```
Query: corp-dc01.corp.ljpops.com from uran

1. uran checks local zones -> Not found
2. uran checks conditional forwarder for corp.ljpops.com -> 192.168.0.11
3. Query forwarded to corp-dc01
4. corp-dc01 returns A record -> 192.168.0.11
```

```
Query: ljpgroup.ljpgroupholdings.com from corp-dc01

1. corp-dc01 checks local zones -> Not found
2. corp-dc01 forwards to parent (192.168.0.10)
3. uran checks conditional forwarder for ljpgroupholdings.com -> 192.168.0.20
4. Query forwarded to ljpgroup
5. ljpgroup returns A record -> 192.168.0.20
```

---

## Troubleshooting

### Common Issues

#### 1. DC GUID Resolution Failure
**Symptom:** `dcdiag` shows "could not be resolved to an IP address" for GUID._msdcs.domain.com

**Cause:** _msdcs zone missing or DNS not registered

**Fix:**
```powershell
# On affected DC
Add-DnsServerPrimaryZone -Name "_msdcs.domain.com" -ReplicationScope Forest -DynamicUpdate Secure
ipconfig /registerdns
nltest /dsregdns
```

#### 2. Cross-Domain Resolution Failure
**Symptom:** Parent can't resolve child domain or vice versa

**Cause:** Missing conditional forwarders

**Fix:**
```powershell
# On parent DC
Add-DnsServerConditionalForwarderZone -Name "child.domain.com" -MasterServers <ChildDCIP>
Add-DnsServerConditionalForwarderZone -Name "_msdcs.child.domain.com" -MasterServers <ChildDCIP>
```

#### 3. DNS Points to Public IP
**Symptom:** nslookup returns external IP instead of DC IP

**Cause:** DNS forwarders resolving to internet instead of internal DC

**Fix:**
```powershell
# Ensure DNS client points to correct servers
Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter).ifIndex -ServerAddresses @("192.168.0.10")
Clear-DnsClientCache
```

#### 4. ADWS Not Starting
**Symptom:** "ADWS service not running" during object creation

**Cause:** Service startup type set to Disabled after promotion

**Fix:**
```powershell
Set-Service ADWS -StartupType Automatic
Start-Service ADWS
```

#### 5. Trust Creation Failure
**Symptom:** "Could not establish trust" error

**Cause:** DNS resolution between forests not working

**Fix:**
```powershell
# Verify both forests can resolve each other
nslookup primaryforest.com  # From external forest DC
nslookup externalforest.com # From primary forest DC

# Add forwarders if missing
Add-DnsServerConditionalForwarderZone -Name "otherforest.com" -MasterServers <OtherDCIP>
```

### Verification Commands

```powershell
# Full forest-wide DC diagnostic
dcdiag /a /e

# Single DC diagnostic
dcdiag /s:hostname

# Replication status
repadmin /replsummary

# Force replication
repadmin /syncall /AdeP

# DNS zone list
Get-DnsServerZone | Format-Table ZoneName, ZoneType

# Trust verification
Get-ADTrust -Filter *
nltest /trusted_domains

# DC GUID check
Get-ADDomainController | Select Name, InvocationId
```

---

## Credentials Reference

### ljpops.com (Forest Root)

| Account | Password | Notes |
|---------|----------|-------|
| LJPOPS\Administrator | LabAdmin2025! | Domain Admin |
| LJPOPS\lpoleschtschuk-sa | Lp0l3schtSchuk#2025! | Enterprise/Schema Admin |
| LJPOPS\svc-sql | Sql$3rv1c3P@ssw0rd!Str0ng2025 | SQL Service Account |
| LJPOPS\svc-backup | B@ckup$3rv1c3P@ssw0rd!Str0ng2025 | Backup Service Account |
| Test Users | P@ssw0rd123! | All standard test users |

### corp.ljpops.com (Child Domain)

| Account | Password | Notes |
|---------|----------|-------|
| CORP\Administrator | LabAdmin2025! | Domain Admin |
| CORP\corp-admin | C0rp@dm1n#2025! | Delegated Admin |
| CORP\svc-corp-backup | C0rpB@ckup#2025! | Backup Service Account |
| Test Users | P@ssw0rd123! | All standard test users |

### ljpgroupholdings.com (External Forest)

| Account | Password | Notes |
|---------|----------|-------|
| LJPGROUPHOLDING\Administrator | AcqAdmin2025! | Domain Admin |
| LJPGROUPHOLDING\acq-admin | @cqU1s1t10n#2025! | Acquisition Admin |
| LJPGROUPHOLDING\svc-legacy-backup | L3g@cyB@ckup#2025! | Legacy Backup Service |
| LJPGROUPHOLDING\svc-legacy-sql | L3g@cySQL#2025! | Legacy SQL Service |
| Legacy Users | L3g@cyP@ss123! | jsmith, mjohnson, etc. |
| Disabled Users | Disabled123! | former.employee1, etc. |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-12-26 | Initial release |
| 1.1 | 2025-12-26 | Added DNS zone verification after DC promotion |
| 1.2 | 2025-12-26 | Added parent VM name prompt for Hyper-V DNS config |
| 1.3 | 2025-12-26 | Enhanced post-deployment health checks with GUID verification |
| 1.4 | 2025-12-26 | Fixed _msdcs zone creation for all scripts |

---

## Author

Created for M&A Discovery Suite testing and AD lab environments.

## License

MIT License - Use freely for testing and educational purposes.
