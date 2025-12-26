#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Deploys a Windows Server 2022 Domain Controller for an External Forest with Trust.

.DESCRIPTION
    Creates a completely separate AD forest (simulating an acquired company) and
    establishes an external trust with the primary forest for M&A testing scenarios.

.PARAMETER SkipPrompts
    Use default configuration without interactive prompts.

.NOTES
    Author: Lab Automation Script
    Requires: Windows 11 with Hyper-V enabled, Administrator privileges
    Use Case: M&A Discovery Testing - External trust between separate forests
#>

[CmdletBinding()]
param(
    [switch]$SkipPrompts
)

# ============================================
# INTERACTIVE CONFIGURATION
# ============================================

function Get-UserConfiguration {
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "║       HYPER-V EXTERNAL FOREST DEPLOYMENT (ACQUIRED CO)         ║" -ForegroundColor Magenta
    Write-Host "║         Creates Separate Forest with External Trust            ║" -ForegroundColor Magenta
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  This creates a SEPARATE forest simulating an acquired company" -ForegroundColor DarkGray
    Write-Host "  and establishes a two-way external trust with your primary forest." -ForegroundColor DarkGray
    Write-Host ""
    
    # Primary Forest Configuration (for trust)
    Write-Host "── Primary Forest Configuration (for trust) ──" -ForegroundColor Yellow
    
    $primaryDomain = Read-Host "  Primary Forest Domain FQDN [ljpops.com]"
    if ([string]::IsNullOrWhiteSpace($primaryDomain)) { $primaryDomain = "ljpops.com" }
    $primaryDomain = $primaryDomain.ToLower()
    
    $primaryDCIP = Read-Host "  Primary Forest DC IP Address [192.168.0.10]"
    if ([string]::IsNullOrWhiteSpace($primaryDCIP)) { $primaryDCIP = "192.168.0.10" }
    
    # Get Primary DC VM Name for Hyper-V direct connection (required for DNS config)
    $defaultPrimaryVMName = "uran"
    $primaryVMName = Read-Host "  Primary DC Hyper-V VM Name [$defaultPrimaryVMName]"
    if ([string]::IsNullOrWhiteSpace($primaryVMName)) { $primaryVMName = $defaultPrimaryVMName }
    
    $primaryAdminPassword = Read-Host "  Primary Forest Admin Password [LabAdmin2025!]"
    if ([string]::IsNullOrWhiteSpace($primaryAdminPassword)) { $primaryAdminPassword = "LabAdmin2025!" }
    
    # External Forest Configuration
    Write-Host ""
    Write-Host "── External Forest Configuration (Acquired Company) ──" -ForegroundColor Yellow
    
    # Validate FQDN has at least one dot
    do {
        $externalDomain = Read-Host "  External Forest Domain FQDN (e.g., acquired.local) [acquired.local]"
        if ([string]::IsNullOrWhiteSpace($externalDomain)) { $externalDomain = "acquired.local" }
        $externalDomain = $externalDomain.ToLower()
        
        if ($externalDomain -notmatch '\.') {
            Write-Host "    ERROR: Domain must be fully qualified (contain at least one dot)" -ForegroundColor Red
            Write-Host "    Examples: acquired.local, newco.com, partner.internal" -ForegroundColor Yellow
        }
    } while ($externalDomain -notmatch '\.')
    
    # Auto-derive NetBIOS from domain name (first label, no dots, max 15 chars)
    $derivedNetBIOS = ($externalDomain -split '\.')[0].ToUpper() -replace '[^A-Z0-9]',''
    if ($derivedNetBIOS.Length -gt 15) { $derivedNetBIOS = $derivedNetBIOS.Substring(0,15) }
    
    Write-Host "  NetBIOS Name (auto-derived): $derivedNetBIOS" -ForegroundColor Cyan
    $netBIOSOverride = Read-Host "  Press Enter to accept, or type new NetBIOS name (max 15 chars, no dots)"
    
    if ([string]::IsNullOrWhiteSpace($netBIOSOverride)) {
        $externalNetBIOS = $derivedNetBIOS
    } else {
        # Clean up user input - remove invalid chars, limit to 15
        $externalNetBIOS = ($netBIOSOverride -replace '[^A-Za-z0-9]','').ToUpper()
        if ($externalNetBIOS.Length -gt 15) { $externalNetBIOS = $externalNetBIOS.Substring(0,15) }
    }
    
    Write-Host "  External Forest: $externalDomain ($externalNetBIOS)" -ForegroundColor Green
    
    # VM Configuration
    Write-Host ""
    Write-Host "── VM Configuration ──" -ForegroundColor Yellow
    
    $vmNameDefault = "acq-dc01"
    $vmName = Read-Host "  VM Name [$vmNameDefault]"
    if ([string]::IsNullOrWhiteSpace($vmName)) { $vmName = $vmNameDefault }
    
    Write-Host ""
    Write-Host "  Recommended minimums: 4GB RAM, 2 vCPUs, 40GB disk" -ForegroundColor DarkGray
    
    $vmMemory = Read-Host "  Memory in GB [4]"
    if ([string]::IsNullOrWhiteSpace($vmMemory)) { $vmMemory = 4 }
    $vmMemory = [int]$vmMemory
    if ($vmMemory -lt 2) { $vmMemory = 2 }
    
    $vmCPU = Read-Host "  vCPU Count [2]"
    if ([string]::IsNullOrWhiteSpace($vmCPU)) { $vmCPU = 2 }
    $vmCPU = [int]$vmCPU
    if ($vmCPU -lt 1) { $vmCPU = 1 }
    
    $vmDisk = Read-Host "  Disk Size in GB [60]"
    if ([string]::IsNullOrWhiteSpace($vmDisk)) { $vmDisk = 60 }
    $vmDisk = [int]$vmDisk
    if ($vmDisk -lt 40) { $vmDisk = 40 }
    
    # Network Configuration
    Write-Host ""
    Write-Host "── Network Configuration ──" -ForegroundColor Yellow
    Write-Host "  Must be on same network as primary DC for trust" -ForegroundColor DarkGray
    
    $vmIP = Read-Host "  Static IP Address [192.168.0.20]"
    if ([string]::IsNullOrWhiteSpace($vmIP)) { $vmIP = "192.168.0.20" }
    
    $vmPrefix = Read-Host "  Subnet Prefix Length [24]"
    if ([string]::IsNullOrWhiteSpace($vmPrefix)) { $vmPrefix = 24 }
    $vmPrefix = [int]$vmPrefix
    
    $vmGateway = Read-Host "  Default Gateway [192.168.0.1]"
    if ([string]::IsNullOrWhiteSpace($vmGateway)) { $vmGateway = "192.168.0.1" }
    
    # Virtual Switch
    Write-Host ""
    Write-Host "── Virtual Switch ──" -ForegroundColor Yellow
    $existingSwitches = Get-VMSwitch -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    if ($existingSwitches) {
        Write-Host "  Existing switches: $($existingSwitches -join ', ')" -ForegroundColor DarkGray
    }
    $switchName = Read-Host "  Switch Name [LabSwitch]"
    if ([string]::IsNullOrWhiteSpace($switchName)) { $switchName = "LabSwitch" }
    
    # Trust Configuration
    Write-Host ""
    Write-Host "── Trust Configuration ──" -ForegroundColor Yellow
    $createTrust = Read-Host "  Create two-way forest trust with primary? (Y/n) [Y]"
    if ([string]::IsNullOrWhiteSpace($createTrust)) { $createTrust = "Y" }
    $createTrust = $createTrust.ToUpper() -eq "Y"
    
    # Bulk AD Objects
    Write-Host ""
    Write-Host "── Bulk AD Object Creation ──" -ForegroundColor Yellow
    $installBulkAD = Read-Host "  Create OUs, Groups, and Users? (Y/n) [Y]"
    if ([string]::IsNullOrWhiteSpace($installBulkAD)) { $installBulkAD = "Y" }
    $installBulkAD = $installBulkAD.ToUpper() -eq "Y"
    
    # Storage Path
    Write-Host ""
    Write-Host "── Storage Location ──" -ForegroundColor Yellow
    $vmBasePath = Read-Host "  VM Storage Path [C:\Hyper-V_VMs]"
    if ([string]::IsNullOrWhiteSpace($vmBasePath)) { $vmBasePath = "C:\Hyper-V_VMs" }
    
    # Confirmation
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "  CONFIGURATION SUMMARY" -ForegroundColor Magenta
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "  Primary Forest:    $primaryDomain (DC: $primaryDCIP, VM: $primaryVMName)"
    Write-Host "  External Forest:   $externalDomain ($externalNetBIOS) ← ACQUIRED CO"
    Write-Host "  VM Name:           $vmName"
    Write-Host "  Specs:             ${vmMemory}GB RAM, $vmCPU vCPUs, ${vmDisk}GB Disk"
    Write-Host "  IP Address:        $vmIP/$vmPrefix (GW: $vmGateway)"
    Write-Host "  Virtual Switch:    $switchName"
    Write-Host "  Create Trust:      $(if($createTrust){'Yes - Two-way Forest Trust'}else{'No'})"
    Write-Host "  Bulk AD Objects:   $(if($installBulkAD){'Yes'}else{'No'})"
    Write-Host "  Storage Path:      $vmBasePath"
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host ""
    
    $confirm = Read-Host "  Proceed with deployment? (Y/n) [Y]"
    if ([string]::IsNullOrWhiteSpace($confirm)) { $confirm = "Y" }
    if ($confirm.ToUpper() -ne "Y") {
        Write-Host "  Deployment cancelled." -ForegroundColor Yellow
        exit 0
    }
    
    return @{
        # Primary Forest (for trust)
        PrimaryDomain       = $primaryDomain
        PrimaryDCIP         = $primaryDCIP
        PrimaryVMName       = $primaryVMName
        PrimaryAdminPassword = $primaryAdminPassword
        PrimaryNetBIOS      = ($primaryDomain -split '\.')[0].ToUpper()
        
        # External Forest
        ExternalDomain      = $externalDomain
        ExternalNetBIOS     = $externalNetBIOS
        AdminPassword       = "AcqAdmin2025!"  # Different password for realism
        SafeModePassword    = "AcqAdmin2025!"
        
        # VM Config
        VMName              = $vmName
        VMMemoryGB          = $vmMemory
        VMProcessorCount    = $vmCPU
        VHDSizeGB           = $vmDisk
        SwitchName          = $switchName
        VMIP                = $vmIP
        VMPrefix            = $vmPrefix
        VMGateway           = $vmGateway
        VMDNS               = $vmIP  # Points to itself initially (separate forest)
        VMBasePath          = $vmBasePath
        
        # Options
        CreateTrust         = $createTrust
        InstallBulkAD       = $installBulkAD
        
        # ISO Config
        ISOFileName         = "Windows_Server_2022_Evaluation.iso"
        ISOUrl              = "https://software-static.download.prss.microsoft.com/sg/download/888969d5-f34g-4e03-ac9d-1f9786c66749/SERVER_EVAL_x64FRE_en-us.iso"
        ExpectedSHA256      = "3E4FA6D8507B554856FC9CA6079CC402DF11A8B79344871669F0251535255325"
    }
}

function Get-DefaultConfiguration {
    return @{
        PrimaryDomain       = "ljpops.com"
        PrimaryDCIP         = "192.168.0.10"
        PrimaryVMName       = "uran"
        PrimaryAdminPassword = "LabAdmin2025!"
        PrimaryNetBIOS      = "LJPOPS"
        ExternalDomain      = "acquired.local"
        ExternalNetBIOS     = "ACQUIRED"
        AdminPassword       = "AcqAdmin2025!"
        SafeModePassword    = "AcqAdmin2025!"
        VMName              = "acq-dc01"
        VMMemoryGB          = 4
        VMProcessorCount    = 2
        VHDSizeGB           = 60
        SwitchName          = "LabSwitch"
        VMIP                = "192.168.0.20"
        VMPrefix            = 24
        VMGateway           = "192.168.0.1"
        VMDNS               = "192.168.0.20"
        VMBasePath          = "C:\Hyper-V_VMs"
        CreateTrust         = $true
        InstallBulkAD       = $true
        ISOFileName         = "Windows_Server_2022_Evaluation.iso"
        ISOUrl              = "https://software-static.download.prss.microsoft.com/sg/download/888969d5-f34g-4e03-ac9d-1f9786c66749/SERVER_EVAL_x64FRE_en-us.iso"
        ExpectedSHA256      = "3E4FA6D8507B554856FC9CA6079CC402DF11A8B79344871669F0251535255325"
    }
}

# Get configuration
if ($SkipPrompts) {
    $Config = Get-DefaultConfiguration
} else {
    $Config = Get-UserConfiguration
}

# Derived paths
$Config.ISODownloadPath = Join-Path $env:USERPROFILE "Downloads\$($Config.ISOFileName)"
$Config.VMPath = Join-Path $Config.VMBasePath $Config.VMName
$Config.VHDPath = Join-Path $Config.VMPath "$($Config.VMName).vhdx"
$Config.LogPath = Join-Path $Config.VMPath "deployment.log"

# ============================================
# ACQUIRED COMPANY PRIVILEGED ACCOUNTS
# ============================================

$PrivilegedAccounts = @(
    @{
        SamAccountName    = 'acq-admin'
        Name              = 'Acquisition Admin'
        GivenName         = 'Acquisition'
        Surname           = 'Admin'
        DisplayName       = 'Acquired Company Administrator'
        Description       = 'Legacy admin from acquired company'
        Password          = '@cqU1s1t10n#2025!'
        Groups            = @('Domain Admins', 'Enterprise Admins', 'Schema Admins')
    },
    @{
        SamAccountName    = 'svc-legacy-backup'
        Name              = 'Legacy Backup Service'
        GivenName         = 'Legacy'
        Surname           = 'Backup'
        DisplayName       = 'Legacy Backup Service Account'
        Description       = 'Pre-acquisition backup service'
        Password          = 'L3g@cyB@ckup#2025!'
        Groups            = @('Domain Admins', 'Backup Operators')
    },
    @{
        SamAccountName    = 'svc-legacy-sql'
        Name              = 'Legacy SQL Service'
        GivenName         = 'Legacy'
        Surname           = 'SQL'
        DisplayName       = 'Legacy SQL Service Account'
        Description       = 'Pre-acquisition SQL service'
        Password          = 'L3g@cySQL#2025!'
        Groups            = @('Domain Admins')
    }
)

# ============================================
# HELPER FUNCTIONS
# ============================================

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        'Info'    { 'White' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Success' { 'Green' }
    }
    
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage -ForegroundColor $color
    
    if ($Config.LogPath -and (Test-Path (Split-Path $Config.LogPath -Parent) -ErrorAction SilentlyContinue)) {
        Add-Content -Path $Config.LogPath -Value $logMessage -ErrorAction SilentlyContinue
    }
}

function Test-Prerequisites {
    Write-Log "Checking prerequisites..."
    
    $hyperv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
    if ($hyperv.State -ne 'Enabled') {
        throw "Hyper-V is not enabled. Run: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All"
    }
    
    $vmms = Get-Service -Name vmms -ErrorAction SilentlyContinue
    if ($vmms.Status -ne 'Running') {
        Write-Log "Starting Hyper-V Virtual Machine Management service..." -Level Warning
        Start-Service vmms -ErrorAction Stop
    }
    
    $drive = (Split-Path $Config.VMBasePath -Qualifier)
    $freeGB = [math]::Round((Get-PSDrive ($drive -replace ':','')).Free / 1GB, 2)
    $requiredGB = $Config.VHDSizeGB + 10
    if ($freeGB -lt $requiredGB) {
        throw "Insufficient disk space on $drive. Required: ${requiredGB}GB, Available: ${freeGB}GB"
    }
    
    if ($Config.CreateTrust) {
        Write-Log "Testing connectivity to primary DC ($($Config.PrimaryDCIP)) for trust..."
        if (-not (Test-Connection -ComputerName $Config.PrimaryDCIP -Count 2 -Quiet)) {
            Write-Log "Cannot reach primary DC - trust will need to be created manually later" -Level Warning
        } else {
            Write-Log "Primary DC reachable" -Level Success
        }
    }
    
    Write-Log "Prerequisites check passed" -Level Success
}

function Remove-ExistingVM {
    param([string]$Name)
    
    $existingVM = Get-VM -Name $Name -ErrorAction SilentlyContinue
    if ($existingVM) {
        Write-Log "Removing existing VM '$Name'..." -Level Warning
        
        if ($existingVM.State -ne 'Off') {
            Stop-VM -Name $Name -TurnOff -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }
        
        $vhds = $existingVM | Get-VMHardDiskDrive | Select-Object -ExpandProperty Path
        Remove-VM -Name $Name -Force -ErrorAction Stop
        
        foreach ($vhd in $vhds) {
            if (Test-Path $vhd) {
                Remove-Item $vhd -Force -ErrorAction SilentlyContinue
            }
        }
        
        Write-Log "Existing VM removed" -Level Success
    }
}

function Get-OrDownloadISO {
    Write-Log "Checking for Windows Server ISO..."
    
    if (Test-Path $Config.ISODownloadPath) {
        Write-Log "ISO exists at $($Config.ISODownloadPath), verifying..."
        
        $actualHash = (Get-FileHash -Path $Config.ISODownloadPath -Algorithm SHA256).Hash
        if ($actualHash -eq $Config.ExpectedSHA256) {
            Write-Log "ISO verification passed" -Level Success
            return $Config.ISODownloadPath
        } else {
            Write-Log "ISO hash mismatch, re-downloading..." -Level Warning
            Remove-Item $Config.ISODownloadPath -Force
        }
    }
    
    Write-Log "Downloading Windows Server 2022 Evaluation ISO (~5GB, please wait)..."
    
    try {
        $bitsJob = Start-BitsTransfer -Source $Config.ISOUrl -Destination $Config.ISODownloadPath -Asynchronous -Priority High
        
        while ($bitsJob.JobState -eq 'Transferring' -or $bitsJob.JobState -eq 'Connecting') {
            $pct = 0
            if ($bitsJob.BytesTotal -gt 0) {
                $pct = [int](($bitsJob.BytesTransferred / $bitsJob.BytesTotal) * 100)
            }
            Write-Progress -Activity "Downloading ISO" -Status "$pct% Complete" -PercentComplete $pct
            Start-Sleep -Seconds 2
        }
        
        Write-Progress -Activity "Downloading ISO" -Completed
        
        if ($bitsJob.JobState -eq 'Transferred') {
            Complete-BitsTransfer -BitsJob $bitsJob
            Write-Log "ISO download completed" -Level Success
        } else {
            throw "BITS transfer failed: $($bitsJob.JobState)"
        }
    }
    catch {
        Write-Log "BITS failed, trying WebClient..." -Level Warning
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($Config.ISOUrl, $Config.ISODownloadPath)
    }
    
    return $Config.ISODownloadPath
}

function New-LabVirtualSwitch {
    Write-Log "Configuring virtual switch..."
    
    $existingSwitch = Get-VMSwitch -Name $Config.SwitchName -ErrorAction SilentlyContinue
    if ($existingSwitch) {
        Write-Log "Using existing switch '$($Config.SwitchName)'"
        return
    }
    
    $physicalNIC = Get-NetAdapter | Where-Object { 
        $_.Status -eq "Up" -and 
        $_.InterfaceDescription -notmatch "Virtual|Hyper-V|Bluetooth|VPN" -and
        $_.MediaType -eq "802.3"
    } | Sort-Object -Property LinkSpeed -Descending | Select-Object -First 1
    
    if ($physicalNIC) {
        try {
            New-VMSwitch -Name $Config.SwitchName -NetAdapterName $physicalNIC.Name -AllowManagementOS $true -ErrorAction Stop | Out-Null
            Write-Log "Created external switch '$($Config.SwitchName)'" -Level Success
            return
        }
        catch {
            Write-Log "Failed to create external switch: $_" -Level Warning
        }
    }
    
    New-VMSwitch -Name $Config.SwitchName -SwitchType Internal -ErrorAction Stop | Out-Null
    Write-Log "Created internal switch '$($Config.SwitchName)'" -Level Warning
}

function New-LabVM {
    Write-Log "Creating Hyper-V VM '$($Config.VMName)'..."
    
    New-Item -ItemType Directory -Force -Path $Config.VMPath | Out-Null
    
    New-VM -Name $Config.VMName -Generation 2 -MemoryStartupBytes ($Config.VMMemoryGB * 1GB) -Path $Config.VMPath -NoVHD | Out-Null
    
    Set-VM -Name $Config.VMName -ProcessorCount $Config.VMProcessorCount -CheckpointType Disabled
    Set-VMMemory -VMName $Config.VMName -DynamicMemoryEnabled $false
    Get-VMNetworkAdapter -VMName $Config.VMName | Connect-VMNetworkAdapter -SwitchName $Config.SwitchName
    Set-VMFirmware -VMName $Config.VMName -EnableSecureBoot Off
    
    Write-Log "VM created: $($Config.VMMemoryGB)GB RAM, $($Config.VMProcessorCount) vCPUs" -Level Success
}

function New-LabVHD {
    param([string]$ISOPath)
    
    Write-Log "Creating $($Config.VHDSizeGB)GB VHD..."
    
    New-VHD -Path $Config.VHDPath -SizeBytes ($Config.VHDSizeGB * 1GB) -Dynamic | Out-Null
    
    $mountResult = Mount-VHD -Path $Config.VHDPath -Passthru
    $diskNumber = $mountResult.DiskNumber
    
    try {
        Initialize-Disk -Number $diskNumber -PartitionStyle GPT -Confirm:$false
        
        $efiPartition = New-Partition -DiskNumber $diskNumber -Size 260MB -GptType "{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}"
        $efiPartition | Format-Volume -FileSystem FAT32 -NewFileSystemLabel "SYSTEM" -Confirm:$false | Out-Null
        $efiPartition | Add-PartitionAccessPath -AssignDriveLetter
        $efiDrive = ($efiPartition | Get-Partition).DriveLetter
        
        New-Partition -DiskNumber $diskNumber -Size 16MB -GptType "{E3C9E316-0B5C-4DB8-817D-F92DF00215AE}" | Out-Null
        
        $osPartition = New-Partition -DiskNumber $diskNumber -UseMaximumSize -GptType "{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}"
        $osPartition | Format-Volume -FileSystem NTFS -NewFileSystemLabel "Windows" -Confirm:$false | Out-Null
        $osPartition | Add-PartitionAccessPath -AssignDriveLetter
        $osDrive = ($osPartition | Get-Partition).DriveLetter
        
        Write-Log "Mounting ISO and applying Windows image..."
        $isoMount = Mount-DiskImage -ImagePath $ISOPath -StorageType ISO -PassThru
        $isoLetter = ($isoMount | Get-Volume).DriveLetter
        
        try {
            $wimPath = "${isoLetter}:\sources\install.wim"
            $images = Get-WindowsImage -ImagePath $wimPath
            
            $targetImage = $images | Where-Object { $_.ImageName -match "Datacenter.*Desktop" } | Select-Object -First 1
            if (-not $targetImage) { $targetImage = $images | Where-Object { $_.ImageName -match "Desktop" } | Select-Object -First 1 }
            if (-not $targetImage) { $targetImage = $images | Select-Object -Last 1 }
            
            Write-Log "Applying: $($targetImage.ImageName)"
            
            Expand-WindowsImage -ImagePath $wimPath -Index $targetImage.ImageIndex -ApplyPath "${osDrive}:\" -Confirm:$false | Out-Null
            & bcdboot "${osDrive}:\Windows" /s "${efiDrive}:" /f UEFI | Out-Null
            
            Write-Log "Injecting unattend.xml..."
            $pantherPath = "${osDrive}:\Windows\Panther"
            New-Item -ItemType Directory -Force -Path $pantherPath | Out-Null
            
            [System.IO.File]::WriteAllText("$pantherPath\unattend.xml", (New-UnattendXml), [System.Text.UTF8Encoding]::new($true))
            
            New-Item -ItemType Directory -Force -Path "${osDrive}:\Windows\Setup\Scripts" | Out-Null
            
            Write-Log "Windows image applied" -Level Success
        }
        finally {
            Dismount-DiskImage -ImagePath $ISOPath -ErrorAction SilentlyContinue | Out-Null
        }
    }
    finally {
        Dismount-VHD -Path $Config.VHDPath -ErrorAction SilentlyContinue | Out-Null
    }
    
    Add-VMHardDiskDrive -VMName $Config.VMName -Path $Config.VHDPath
    $hdd = Get-VMHardDiskDrive -VMName $Config.VMName | Select-Object -First 1
    Set-VMFirmware -VMName $Config.VMName -FirstBootDevice $hdd
    
    Write-Log "VHD attached to VM" -Level Success
}

function New-UnattendXml {
    $adminPass = $Config.AdminPassword
    $computerName = $Config.VMName
    
    return @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <ComputerName>$computerName</ComputerName>
            <TimeZone>UTC</TimeZone>
        </component>
        <component name="Microsoft-Windows-ServerManager-SvrMgrNc" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <DoNotOpenServerManagerAtLogon>true</DoNotOpenServerManagerAtLogon>
        </component>
        <component name="Microsoft-Windows-IE-ESC" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <IEHardenAdmin>false</IEHardenAdmin>
            <IEHardenUser>false</IEHardenUser>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <InputLocale>en-US</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UserLocale>en-US</UserLocale>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideLocalAccountScreen>true</HideLocalAccountScreen>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <NetworkLocation>Work</NetworkLocation>
                <ProtectYourPC>3</ProtectYourPC>
            </OOBE>
            <UserAccounts>
                <AdministratorPassword>
                    <Value>$adminPass</Value>
                    <PlainText>true</PlainText>
                </AdministratorPassword>
            </UserAccounts>
            <AutoLogon>
                <Enabled>true</Enabled>
                <Username>Administrator</Username>
                <Password>
                    <Value>$adminPass</Value>
                    <PlainText>true</PlainText>
                </Password>
                <LogonCount>10</LogonCount>
            </AutoLogon>
            <FirstLogonCommands>
                <SynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <CommandLine>cmd /c netsh advfirewall set allprofiles state off</CommandLine>
                    <Description>Disable firewall</Description>
                </SynchronousCommand>
                <SynchronousCommand wcm:action="add">
                    <Order>2</Order>
                    <CommandLine>cmd /c winrm quickconfig -quiet -force</CommandLine>
                    <Description>Enable WinRM</Description>
                </SynchronousCommand>
                <SynchronousCommand wcm:action="add">
                    <Order>3</Order>
                    <CommandLine>powershell -NoProfile -Command "Enable-PSRemoting -Force -SkipNetworkProfileCheck"</CommandLine>
                    <Description>Enable PS Remoting</Description>
                </SynchronousCommand>
            </FirstLogonCommands>
        </component>
    </settings>
</unattend>
"@
}

function Wait-VMReady {
    param(
        [string]$VMName,
        [PSCredential]$Credential,
        [int]$TimeoutMinutes = 15,
        [string]$Description = "VM"
    )
    
    Write-Log "Waiting for $Description (timeout: ${TimeoutMinutes}m)..."
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $timeout = [TimeSpan]::FromMinutes($TimeoutMinutes)
    
    while ($stopwatch.Elapsed -lt $timeout) {
        try {
            $vm = Get-VM -Name $VMName -ErrorAction Stop
            if ($vm.State -ne 'Running') {
                Start-Sleep -Seconds 10
                continue
            }
            
            $null = Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            Write-Host ""
            Write-Log "$Description is ready" -Level Success
            return $true
        }
        catch {
            $elapsed = $stopwatch.Elapsed.ToString("mm\:ss")
            Write-Host "`r  Waiting... ($elapsed elapsed)          " -NoNewline
            Start-Sleep -Seconds 10
        }
    }
    
    throw "Timeout waiting for $Description"
}

function Install-ExternalForestDC {
    Write-Log "Configuring External Forest Domain Controller..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $localCred = New-Object PSCredential("Administrator", $securePassword)
    
    # Wait for VM to be ready
    Wait-VMReady -VMName $Config.VMName -Credential $localCred -TimeoutMinutes 10 -Description "Windows Setup" | Out-Null
    
    Write-Log "Stabilizing services (15s)..."
    Start-Sleep -Seconds 15
    
    # Configure network - DNS points to itself (new forest root)
    Write-Log "Configuring network..."
    Invoke-Command -VMName $Config.VMName -Credential $localCred -ScriptBlock {
        param($IP, $Prefix, $Gateway)
        $adapter = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
        Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
        Remove-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
        New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $IP -PrefixLength $Prefix -DefaultGateway $Gateway | Out-Null
        # DNS will point to itself after DC promotion
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $IP
    } -ArgumentList $Config.VMIP, $Config.VMPrefix, $Config.VMGateway
    
    # Install AD DS
    Write-Log "Installing AD Domain Services..."
    Invoke-Command -VMName $Config.VMName -Credential $localCred -ScriptBlock {
        Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools -IncludeAllSubFeature | Out-Null
    }
    
    # Promote as new Forest Root DC
    Write-Log "Promoting to Forest Root DC for '$($Config.ExternalDomain)'..."
    
    $secureSafeMode = ConvertTo-SecureString $Config.SafeModePassword -AsPlainText -Force
    
    Invoke-Command -VMName $Config.VMName -Credential $localCred -ScriptBlock {
        param($DomainName, $NetBIOS, $SafePwd)
        
        Install-ADDSForest `
            -DomainName $DomainName `
            -DomainNetbiosName $NetBIOS `
            -SafeModeAdministratorPassword $SafePwd `
            -InstallDns `
            -CreateDnsDelegation:$false `
            -DomainMode WinThreshold `
            -ForestMode WinThreshold `
            -NoRebootOnCompletion `
            -Force `
            -WarningAction SilentlyContinue | Out-Null
            
    } -ArgumentList $Config.ExternalDomain, $Config.ExternalNetBIOS, $secureSafeMode
    
    Write-Log "Restarting VM..."
    Restart-VM -Name $Config.VMName -Force
    Start-Sleep -Seconds 30
    
    # Wait for DC with domain creds
    $domainCred = New-Object PSCredential("$($Config.ExternalNetBIOS)\Administrator", $securePassword)
    
    $dcReady = $false
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $maxWaitMinutes = 15
    
    Write-Log "Waiting for Domain Controller services (timeout: ${maxWaitMinutes}m)..."
    
    # Wait for VM to respond
    $vmResponsive = $false
    while (-not $vmResponsive -and $stopwatch.Elapsed.TotalMinutes -lt 5) {
        Start-Sleep -Seconds 10
        foreach ($cred in @($domainCred, $localCred)) {
            try {
                $null = Invoke-Command -VMName $Config.VMName -Credential $cred -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
                $vmResponsive = $true
                Write-Host ""
                Write-Log "VM responsive after reboot" -Level Success
                break
            } catch { }
        }
        if (-not $vmResponsive) {
            Write-Host "`r  Waiting for VM to respond... ($([int]$stopwatch.Elapsed.TotalSeconds)s)          " -NoNewline
        }
    }
    
    # Wait for AD services
    Write-Log "Waiting for AD services to initialize (45s)..."
    Start-Sleep -Seconds 45
    
    while (-not $dcReady -and $stopwatch.Elapsed.TotalMinutes -lt $maxWaitMinutes) {
        Start-Sleep -Seconds 15
        
        foreach ($cred in @($domainCred, $localCred)) {
            try {
                $result = Invoke-Command -VMName $Config.VMName -Credential $cred -ScriptBlock {
                    $ntds = Get-Service NTDS -ErrorAction SilentlyContinue
                    $dns = Get-Service DNS -ErrorAction SilentlyContinue
                    $adws = Get-Service ADWS -ErrorAction SilentlyContinue
                    
                    # CRITICAL: Enable and start ADWS if not running
                    if ($adws) {
                        if ($adws.StartType -eq 'Disabled') {
                            Set-Service ADWS -StartupType Automatic -ErrorAction SilentlyContinue
                        }
                        if ($adws.Status -ne 'Running') {
                            try {
                                Start-Service ADWS -ErrorAction Stop
                                Start-Sleep -Seconds 5
                                $adws = Get-Service ADWS
                            } catch { }
                        }
                    }
                    
                    $status = @{
                        NTDS = if ($ntds) { $ntds.Status.ToString() } else { "NotFound" }
                        DNS = if ($dns) { $dns.Status.ToString() } else { "NotFound" }
                        ADWS = if ($adws) { $adws.Status.ToString() } else { "NotFound" }
                    }
                    
                    $allRunning = ($ntds.Status -eq 'Running') -and ($dns.Status -eq 'Running') -and ($adws.Status -eq 'Running')
                    
                    if ($allRunning) {
                        try {
                            $domain = Get-ADDomain -ErrorAction Stop
                            return @{ Ready = $true; Domain = $domain.DNSRoot; Services = $status }
                        } catch {
                            return @{ Ready = $false; Services = $status; Error = $_.Exception.Message }
                        }
                    }
                    return @{ Ready = $false; Services = $status }
                } -ErrorAction Stop
                
                if ($result.Ready) {
                    $dcReady = $true
                    Write-Host ""
                    Write-Log "External Forest DC operational: $($result.Domain)" -Level Success
                    Write-Log "Stabilizing AD services (20s)..."
                    Start-Sleep -Seconds 20
                    break
                } else {
                    $svcStatus = "NTDS=$($result.Services.NTDS), DNS=$($result.Services.DNS), ADWS=$($result.Services.ADWS)"
                    Write-Host "`r  Services: $svcStatus ($([int]$stopwatch.Elapsed.TotalMinutes)m)          " -NoNewline
                }
                break
            }
            catch { }
        }
    }
    
    if (-not $dcReady) {
        Write-Log "DC services timeout - attempting manual ADWS restart..." -Level Warning
        try {
            Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
                Set-Service ADWS -StartupType Automatic -ErrorAction SilentlyContinue
                Stop-Service ADWS -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 5
                Start-Service ADWS -ErrorAction Stop
                Start-Sleep -Seconds 20
                Get-ADDomain -ErrorAction Stop | Out-Null
            } -ErrorAction Stop
            Write-Log "ADWS manually restarted - continuing..." -Level Success
        } catch {
            Write-Log "Manual ADWS restart failed: $_" -Level Warning
        }
        Start-Sleep -Seconds 15
    }
    
    # Configure DNS conditional forwarders for cross-forest resolution
    if ($Config.CreateTrust) {
        Write-Log "Configuring DNS for cross-forest resolution..."
        Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
            param($PrimaryDomain, $PrimaryDCIP, $SelfIP)
            
            # Ensure DNS server is set to self as primary, with root hints for external
            $adapter = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @($SelfIP)
            
            # Add conditional forwarder for primary forest domain
            $existingForwarder = Get-DnsServerZone -Name $PrimaryDomain -ErrorAction SilentlyContinue
            if (-not $existingForwarder) {
                Add-DnsServerConditionalForwarderZone -Name $PrimaryDomain -MasterServers $PrimaryDCIP -ErrorAction SilentlyContinue
                Write-Host "  Added conditional forwarder: $PrimaryDomain -> $PrimaryDCIP" -ForegroundColor Green
            }
            
            # Add forwarder for _msdcs zone of primary forest (for DC GUID resolution)
            $msdcsZone = "_msdcs.$PrimaryDomain"
            $existingMsdcs = Get-DnsServerZone -Name $msdcsZone -ErrorAction SilentlyContinue
            if (-not $existingMsdcs) {
                Add-DnsServerConditionalForwarderZone -Name $msdcsZone -MasterServers $PrimaryDCIP -ErrorAction SilentlyContinue
                Write-Host "  Added conditional forwarder: $msdcsZone -> $PrimaryDCIP" -ForegroundColor Green
            }
            
            # Clear DNS cache
            Clear-DnsClientCache
            Clear-DnsServerCache -Force -ErrorAction SilentlyContinue
            
            # Verify resolution
            Start-Sleep -Seconds 2
            $testResolution = Resolve-DnsName -Name $PrimaryDomain -Type A -ErrorAction SilentlyContinue
            if ($testResolution.IPAddress -eq $PrimaryDCIP) {
                Write-Host "  DNS verification: $PrimaryDomain -> $PrimaryDCIP (Correct)" -ForegroundColor Green
            } else {
                Write-Host "  DNS verification: May need manual check" -ForegroundColor Yellow
            }
            
        } -ArgumentList $Config.PrimaryDomain, $Config.PrimaryDCIP, $Config.VMIP
    }
    
    # Disable auto-logon
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "0" -ErrorAction SilentlyContinue
    }
    
    # Enable AD Recycle Bin
    Write-Log "Enabling AD Recycle Bin..."
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($DomainName)
        Import-Module ActiveDirectory
        $forestDN = (Get-ADForest).Name
        Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $forestDN -Confirm:$false -ErrorAction SilentlyContinue
    } -ArgumentList $Config.ExternalDomain
    
    Write-Log "External Forest Domain Controller configured" -Level Success
}

function Install-ForestTrust {
    if (-not $Config.CreateTrust) {
        Write-Log "Skipping forest trust creation"
        return
    }
    
    Write-Log "Creating two-way forest trust with $($Config.PrimaryDomain)..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $externalCred = New-Object PSCredential("$($Config.ExternalNetBIOS)\Administrator", $securePassword)
    
    $primarySecurePassword = ConvertTo-SecureString $Config.PrimaryAdminPassword -AsPlainText -Force
    $primaryCred = New-Object PSCredential("$($Config.PrimaryNetBIOS)\Administrator", $primarySecurePassword)
    
    # First, configure DNS on primary DC to resolve external forest
    # Using Invoke-Command -VMName for direct Hyper-V connection (avoids WinRM issues)
    Write-Log "Configuring DNS conditional forwarder on primary DC ($($Config.PrimaryVMName))..."
    try {
        Invoke-Command -VMName $Config.PrimaryVMName -Credential $primaryCred -ScriptBlock {
            param($ExternalDomain, $ExternalDCIP)
            
            # Add conditional forwarder for external forest
            $existingForwarder = Get-DnsServerZone -Name $ExternalDomain -ErrorAction SilentlyContinue
            if (-not $existingForwarder) {
                Add-DnsServerConditionalForwarderZone -Name $ExternalDomain -MasterServers $ExternalDCIP -ErrorAction SilentlyContinue
                Write-Host "  Added forwarder on primary: $ExternalDomain -> $ExternalDCIP" -ForegroundColor Green
            } else {
                Write-Host "  Forwarder already exists: $ExternalDomain" -ForegroundColor Cyan
            }
            
            # Add _msdcs zone forwarder for external forest
            $msdcsZone = "_msdcs.$ExternalDomain"
            $existingMsdcs = Get-DnsServerZone -Name $msdcsZone -ErrorAction SilentlyContinue
            if (-not $existingMsdcs) {
                Add-DnsServerConditionalForwarderZone -Name $msdcsZone -MasterServers $ExternalDCIP -ErrorAction SilentlyContinue
                Write-Host "  Added forwarder on primary: $msdcsZone -> $ExternalDCIP" -ForegroundColor Green
            } else {
                Write-Host "  Forwarder already exists: $msdcsZone" -ForegroundColor Cyan
            }
            
            Clear-DnsServerCache -Force -ErrorAction SilentlyContinue
            
        } -ArgumentList $Config.ExternalDomain, $Config.VMIP -ErrorAction Stop
        Write-Log "DNS forwarders configured on primary DC" -Level Success
    }
    catch {
        Write-Log "Could not configure DNS on primary DC: $_" -Level Warning
        Write-Log "You may need to manually add a conditional forwarder" -Level Warning
    }
    
    # Create the trust from external forest side
    Write-Log "Creating trust from external forest..."
    $trustCreated = Invoke-Command -VMName $Config.VMName -Credential $externalCred -ScriptBlock {
        param($PrimaryDomain, $PrimaryNetBIOS, $PrimaryAdminUser, $PrimaryAdminPwd, $PrimaryDCIP)
        
        Import-Module ActiveDirectory
        
        try {
            # Create credential for primary forest
            $secPwd = ConvertTo-SecureString $PrimaryAdminPwd -AsPlainText -Force
            $primaryCred = New-Object PSCredential("$PrimaryNetBIOS\Administrator", $secPwd)
            
            # Get the local forest
            $localForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            
            # Get the remote forest context
            $remoteContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(
                [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Forest,
                $PrimaryDomain,
                "$PrimaryNetBIOS\Administrator",
                $PrimaryAdminPwd
            )
            
            $remoteForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($remoteContext)
            
            # Create two-way forest trust
            $localForest.CreateTrustRelationship(
                $remoteForest,
                [System.DirectoryServices.ActiveDirectory.TrustDirection]::Bidirectional
            )
            
            Write-Host "  Trust created successfully" -ForegroundColor Green
            return @{ Success = $true }
        }
        catch {
            Write-Warning "Trust creation via .NET failed: $_"
            
            # Fallback: try netdom
            try {
                $result = & netdom trust $env:USERDNSDOMAIN /Domain:$PrimaryDomain /Add /TwoWay /UserD:"$PrimaryNetBIOS\Administrator" /PasswordD:$PrimaryAdminPwd /UserO:"Administrator" /PasswordO:$PrimaryAdminPwd 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "  Trust created via netdom" -ForegroundColor Green
                    return @{ Success = $true; Method = "netdom" }
                } else {
                    return @{ Success = $false; Error = $result }
                }
            }
            catch {
                return @{ Success = $false; Error = $_.Exception.Message }
            }
        }
    } -ArgumentList $Config.PrimaryDomain, $Config.PrimaryNetBIOS, "$($Config.PrimaryNetBIOS)\Administrator", $Config.PrimaryAdminPassword, $Config.PrimaryDCIP
    
    if ($trustCreated.Success) {
        Write-Log "Forest trust created successfully" -Level Success
    } else {
        Write-Log "Trust creation failed: $($trustCreated.Error)" -Level Warning
        Write-Log "You may need to create the trust manually via Active Directory Domains and Trusts" -Level Warning
    }
}

function Install-PrivilegedAdminAccounts {
    Write-Log "Creating privileged admin accounts..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.ExternalNetBIOS)\Administrator", $securePassword)
    $domainDN = "DC=$($Config.ExternalDomain.Replace('.',',DC='))"
    
    foreach ($account in $PrivilegedAccounts) {
        Write-Log "Creating account: $($account.SamAccountName)..."
        
        $maxRetries = 3
        $retryCount = 0
        $success = $false
        
        while (-not $success -and $retryCount -lt $maxRetries) {
            $retryCount++
            try {
                Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
                    param($Account, $DomainDN, $DomainName)
                    
                    $adws = Get-Service ADWS -ErrorAction SilentlyContinue
                    if ($adws.Status -ne 'Running') {
                        Start-Service ADWS -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 5
                    }
                    
                    Import-Module ActiveDirectory -ErrorAction Stop
                    
                    $sam = $Account.SamAccountName
                    
                    if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue)) {
                        $userParams = @{
                            SamAccountName        = $sam
                            Name                  = $Account.Name
                            GivenName             = $Account.GivenName
                            Surname               = $Account.Surname
                            DisplayName           = $Account.DisplayName
                            Description           = $Account.Description
                            UserPrincipalName     = "$sam@$DomainName"
                            Path                  = "CN=Users,$DomainDN"
                            AccountPassword       = (ConvertTo-SecureString $Account.Password -AsPlainText -Force)
                            Enabled               = $true
                            PasswordNeverExpires  = $true
                        }
                        
                        New-ADUser @userParams
                        
                        foreach ($group in $Account.Groups) {
                            Add-ADGroupMember -Identity $group -Members $sam -ErrorAction SilentlyContinue
                        }
                        
                        Write-Host "  Created: $sam" -ForegroundColor Green
                    } else {
                        Write-Host "  Exists: $sam" -ForegroundColor Yellow
                    }
                } -ArgumentList $account, $domainDN, $Config.ExternalDomain -ErrorAction Stop
                
                $success = $true
            }
            catch {
                if ($retryCount -lt $maxRetries) {
                    Write-Log "Retry $retryCount for $($account.SamAccountName)..." -Level Warning
                    Start-Sleep -Seconds 15
                } else {
                    Write-Log "Failed to create $($account.SamAccountName): $_" -Level Error
                }
            }
        }
    }
    
    Write-Log "Privileged admin accounts created" -Level Success
}

function Install-BulkADObjects {
    if (-not $Config.InstallBulkAD) {
        Write-Log "Skipping bulk AD object creation"
        return
    }
    
    Write-Log "Creating bulk AD objects (simulating acquired company)..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.ExternalNetBIOS)\Administrator", $securePassword)
    $domainDN = "DC=$($Config.ExternalDomain.Replace('.',',DC='))"
    
    # Create OUs - typical acquired company structure
    Write-Log "Creating Organizational Units..."
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($NetBIOS, $DomainDN)
        
        $adws = Get-Service ADWS -ErrorAction SilentlyContinue
        if ($adws.Status -ne 'Running') {
            Start-Service ADWS -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 10
        }
        
        Import-Module ActiveDirectory
        
        # Legacy company OU structure (different from parent - realistic)
        $ous = @(
            @{ Name = "Staff"; Path = $DomainDN }
            @{ Name = "Workstations"; Path = $DomainDN }
            @{ Name = "Servers"; Path = $DomainDN }
            @{ Name = "Security Groups"; Path = $DomainDN }
            @{ Name = "Service Accounts"; Path = $DomainDN }
            @{ Name = "Development"; Path = "OU=Staff,$DomainDN" }
            @{ Name = "QA"; Path = "OU=Staff,$DomainDN" }
            @{ Name = "Production Support"; Path = "OU=Staff,$DomainDN" }
            @{ Name = "Management"; Path = "OU=Staff,$DomainDN" }
            @{ Name = "Contractors"; Path = "OU=Staff,$DomainDN" }
            @{ Name = "Disabled"; Path = $DomainDN }
        )
        
        $created = 0
        foreach ($ou in $ous) {
            try {
                if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$($ou.Name)'" -SearchBase $ou.Path -SearchScope OneLevel -ErrorAction SilentlyContinue)) {
                    New-ADOrganizationalUnit -Name $ou.Name -Path $ou.Path -ProtectedFromAccidentalDeletion $false
                    $created++
                }
            } catch {
                Write-Warning "Failed to create OU $($ou.Name): $_"
            }
        }
        Write-Host "  OUs created: $created" -ForegroundColor Cyan
        
    } -ArgumentList $Config.ExternalNetBIOS, $domainDN
    
    # Create Groups - legacy naming convention
    Write-Log "Creating Security Groups..."
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($NetBIOS, $DomainDN)
        
        Import-Module ActiveDirectory
        
        # Legacy group naming (different convention - realistic for acquired co)
        $groups = @(
            @{ Name = "DEV-Team"; Path = "OU=Security Groups,$DomainDN"; Scope = "Global" }
            @{ Name = "QA-Team"; Path = "OU=Security Groups,$DomainDN"; Scope = "Global" }
            @{ Name = "PROD-Support"; Path = "OU=Security Groups,$DomainDN"; Scope = "Global" }
            @{ Name = "All-Staff"; Path = "OU=Security Groups,$DomainDN"; Scope = "Global" }
            @{ Name = "Mgmt-Team"; Path = "OU=Security Groups,$DomainDN"; Scope = "Global" }
            @{ Name = "FS-DevShare-RW"; Path = "OU=Security Groups,$DomainDN"; Scope = "DomainLocal" }
            @{ Name = "FS-ProdDocs-RO"; Path = "OU=Security Groups,$DomainDN"; Scope = "DomainLocal" }
            @{ Name = "SQL-Admins"; Path = "OU=Security Groups,$DomainDN"; Scope = "Global" }
            @{ Name = "VPN-Users"; Path = "OU=Security Groups,$DomainDN"; Scope = "Global" }
            @{ Name = "Legacy-Admins"; Path = "OU=Security Groups,$DomainDN"; Scope = "Global" }
        )
        
        $created = 0
        foreach ($group in $groups) {
            try {
                if (-not (Get-ADGroup -Filter "Name -eq '$($group.Name)'" -ErrorAction SilentlyContinue)) {
                    New-ADGroup -Name $group.Name -Path $group.Path -GroupScope $group.Scope -GroupCategory Security
                    $created++
                }
            } catch {
                Write-Warning "Failed to create group $($group.Name): $_"
            }
        }
        Write-Host "  Groups created: $created" -ForegroundColor Cyan
        
    } -ArgumentList $Config.ExternalNetBIOS, $domainDN
    
    # Create Users - legacy accounts with different naming
    Write-Log "Creating User Accounts..."
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($NetBIOS, $DomainDN, $DomainName)
        
        Import-Module ActiveDirectory
        
        # Legacy user naming - first initial + last name (different from parent)
        $users = @(
            @{ Sam = "jsmith"; Name = "John Smith"; GivenName = "John"; Surname = "Smith"; Dept = "Development"; Title = "Senior Developer"; OU = "Development" }
            @{ Sam = "mjohnson"; Name = "Mary Johnson"; GivenName = "Mary"; Surname = "Johnson"; Dept = "Development"; Title = "Lead Developer"; OU = "Development" }
            @{ Sam = "rwilliams"; Name = "Robert Williams"; GivenName = "Robert"; Surname = "Williams"; Dept = "Development"; Title = "Developer"; OU = "Development" }
            @{ Sam = "pbrown"; Name = "Patricia Brown"; GivenName = "Patricia"; Surname = "Brown"; Dept = "QA"; Title = "QA Lead"; OU = "QA" }
            @{ Sam = "dgarcia"; Name = "David Garcia"; GivenName = "David"; Surname = "Garcia"; Dept = "QA"; Title = "QA Analyst"; OU = "QA" }
            @{ Sam = "lmartinez"; Name = "Linda Martinez"; GivenName = "Linda"; Surname = "Martinez"; Dept = "Production Support"; Title = "Support Lead"; OU = "Production Support" }
            @{ Sam = "janderson"; Name = "James Anderson"; GivenName = "James"; Surname = "Anderson"; Dept = "Production Support"; Title = "Support Analyst"; OU = "Production Support" }
            @{ Sam = "bthomas"; Name = "Barbara Thomas"; GivenName = "Barbara"; Surname = "Thomas"; Dept = "Management"; Title = "Director"; OU = "Management" }
            @{ Sam = "mwilson"; Name = "Michael Wilson"; GivenName = "Michael"; Surname = "Wilson"; Dept = "Management"; Title = "VP Engineering"; OU = "Management" }
            @{ Sam = "contractor1"; Name = "Contractor One"; GivenName = "Contractor"; Surname = "One"; Dept = "Contractors"; Title = "External Contractor"; OU = "Contractors" }
        )
        
        $created = 0
        foreach ($user in $users) {
            try {
                if (-not (Get-ADUser -Filter "SamAccountName -eq '$($user.Sam)'" -ErrorAction SilentlyContinue)) {
                    $path = "OU=$($user.OU),OU=Staff,$DomainDN"
                    
                    New-ADUser -SamAccountName $user.Sam -Name $user.Name -GivenName $user.GivenName -Surname $user.Surname `
                        -UserPrincipalName "$($user.Sam)@$DomainName" -Path $path -Department $user.Dept -Title $user.Title `
                        -EmailAddress "$($user.Sam)@$DomainName" -AccountPassword (ConvertTo-SecureString "L3g@cyP@ss123!" -AsPlainText -Force) `
                        -Enabled $true -PasswordNeverExpires $true
                    $created++
                }
            } catch {
                Write-Warning "Failed to create user $($user.Sam): $_"
            }
        }
        Write-Host "  Users created: $created" -ForegroundColor Cyan
        
        # Add users to groups
        Add-ADGroupMember -Identity "DEV-Team" -Members "jsmith","mjohnson","rwilliams" -ErrorAction SilentlyContinue
        Add-ADGroupMember -Identity "QA-Team" -Members "pbrown","dgarcia" -ErrorAction SilentlyContinue
        Add-ADGroupMember -Identity "PROD-Support" -Members "lmartinez","janderson" -ErrorAction SilentlyContinue
        Add-ADGroupMember -Identity "Mgmt-Team" -Members "bthomas","mwilson" -ErrorAction SilentlyContinue
        Add-ADGroupMember -Identity "All-Staff" -Members "DEV-Team","QA-Team","PROD-Support","Mgmt-Team" -ErrorAction SilentlyContinue
        
    } -ArgumentList $Config.ExternalNetBIOS, $domainDN, $Config.ExternalDomain
    
    # Create stale/disabled objects (common in acquisitions)
    Write-Log "Creating stale objects (acquisition cleanup candidates)..."
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($DomainDN, $DomainName)
        
        Import-Module ActiveDirectory
        $disabledOU = "OU=Disabled,$DomainDN"
        
        $staleUsers = @(
            @{ Sam = "former.employee1"; Name = "Former Employee1"; Desc = "Left company 2023" }
            @{ Sam = "former.employee2"; Name = "Former Employee2"; Desc = "Terminated 2024" }
            @{ Sam = "oldcontractor"; Name = "Old Contractor"; Desc = "Contract ended" }
            @{ Sam = "testuser.legacy"; Name = "Legacy Test User"; Desc = "Old test account" }
            @{ Sam = "svc.oldapp"; Name = "Old App Service"; Desc = "Decommissioned app service" }
        )
        
        foreach ($user in $staleUsers) {
            if (-not (Get-ADUser -Filter "SamAccountName -eq '$($user.Sam)'" -ErrorAction SilentlyContinue)) {
                New-ADUser -SamAccountName $user.Sam -Name $user.Name -Description $user.Desc `
                    -UserPrincipalName "$($user.Sam)@$DomainName" -Path $disabledOU `
                    -AccountPassword (ConvertTo-SecureString "Disabled123!" -AsPlainText -Force) `
                    -Enabled $false
            }
        }
        
        Write-Host "  Created $($staleUsers.Count) disabled/stale users" -ForegroundColor Cyan
        
    } -ArgumentList $domainDN, $Config.ExternalDomain
    
    Write-Log "Bulk AD object creation completed" -Level Success
}

function Install-TempShare {
    Write-Log "Creating C:\temp share with legacy data..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.ExternalNetBIOS)\Administrator", $securePassword)
    
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($DomainName, $NetBIOS)
        
        $tempPath = "C:\temp"
        New-Item -ItemType Directory -Path $tempPath -Force | Out-Null
        
        # Create share
        if (-not (Get-SmbShare -Name "temp" -ErrorAction SilentlyContinue)) {
            New-SmbShare -Name "temp" -Path $tempPath -FullAccess "Domain Admins" -ChangeAccess "Authenticated Users" -ReadAccess "Everyone" | Out-Null
        }
        
        # Create legacy folder structure
        @("Legacy_Apps", "Old_Projects", "Migration_Data", "Archives", "Documentation") | ForEach-Object {
            New-Item -ItemType Directory -Path (Join-Path $tempPath $_) -Force | Out-Null
        }
        
        # Create dummy legacy files
        "ACQUIRED COMPANY - $NetBIOS`nLegacy Systems Documentation`n`nThis server contains pre-acquisition data." | Out-File "$tempPath\README.txt" -Encoding UTF8
        
        @"
LEGACY APPLICATION INVENTORY
============================
Last Updated: 2024-01-15 (pre-acquisition)

Applications:
- LegacyERP v2.3 - Custom ERP system
- OldCRM v1.8 - Customer management
- DevTracker v3.1 - Bug tracking (deprecated)
- FileVault v1.0 - Document management

Database Servers:
- SQL2012-LEGACY (192.168.10.50) - Legacy databases
- MYSQL-OLD (192.168.10.51) - Old web apps

Service Accounts (to be migrated):
- svc.legacyerp
- svc.oldcrm
- svc.devtracker
"@ | Out-File "$tempPath\Legacy_Apps\inventory.txt" -Encoding UTF8

        @"
MIGRATION CHECKLIST
===================
[ ] Inventory all legacy accounts
[ ] Map group memberships
[ ] Document service accounts
[ ] Identify stale objects
[ ] Plan SID history migration
[ ] Test trust relationship
[ ] Validate application access
[ ] User communication plan
"@ | Out-File "$tempPath\Migration_Data\checklist.txt" -Encoding UTF8

        @"
NETWORK DOCUMENTATION (PRE-ACQUISITION)
=======================================
Domain: $DomainName
Forest Functional Level: Windows 2012 R2 (legacy)
Domain Functional Level: Windows 2012 R2 (legacy)

IP Ranges:
- Servers: 192.168.10.0/24
- Workstations: 192.168.20.0/24
- Printers: 192.168.30.0/24

Note: This forest will be trusted by parent organization
"@ | Out-File "$tempPath\Documentation\network.txt" -Encoding UTF8
        
        Write-Host "  Created C:\temp share with legacy data" -ForegroundColor Green
        
    } -ArgumentList $Config.ExternalDomain, $Config.ExternalNetBIOS
    
    Write-Log "C:\temp share created with legacy data" -Level Success
}

function Verify-PostDeploymentHealth {
    Write-Log "Running post-deployment health checks and DNS verification..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.ExternalNetBIOS)\Administrator", $securePassword)
    
    $healthResults = Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($PrimaryDomain, $PrimaryDCIP, $ExternalDomain, $SelfIP, $CreateTrust)
        
        $results = @{
            DNSServers = @()
            DNSFixed = $false
            SelfResolution = $null
            GuidResolution = $null
            PrimaryResolution = $null
            SysvolReady = $false
            ForwardersConfigured = $false
        }
        
        # CRITICAL: Ensure DNS client points to itself (this DC is its own DNS server)
        $adapter = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
        $currentDNS = (Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses
        
        if ($currentDNS -notcontains $SelfIP -or $currentDNS[0] -ne $SelfIP) {
            Write-Host "  Fixing DNS client configuration..." -ForegroundColor Yellow
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @($SelfIP)
            $results.DNSFixed = $true
            Start-Sleep -Seconds 3
        }
        
        $results.DNSServers = (Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses
        
        # Clear DNS cache
        Clear-DnsClientCache
        Clear-DnsServerCache -Force -ErrorAction SilentlyContinue
        
        # Re-register DNS records (CRITICAL for DC GUID resolution)
        Write-Host "  Registering DNS records..." -ForegroundColor Cyan
        ipconfig /registerdns | Out-Null
        Start-Sleep -Seconds 5
        nltest /dsregdns 2>&1 | Out-Null
        Start-Sleep -Seconds 3
        
        # Test self-resolution (hostname)
        try {
            $selfResolve = Resolve-DnsName -Name "$env:COMPUTERNAME.$ExternalDomain" -Type A -DnsOnly -ErrorAction Stop
            $results.SelfResolution = $selfResolve.IPAddress | Select-Object -First 1
        } catch {
            $results.SelfResolution = "FAILED"
        }
        
        # Test DC GUID resolution (critical for dcdiag)
        try {
            # Get the DC's GUID from AD
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            $dcGuid = (Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction SilentlyContinue).InvocationId.Guid
            if ($dcGuid) {
                $guidRecord = "$dcGuid._msdcs.$ExternalDomain"
                $guidResolve = Resolve-DnsName -Name $guidRecord -Type CNAME -DnsOnly -ErrorAction SilentlyContinue
                if ($guidResolve) {
                    $results.GuidResolution = "OK"
                } else {
                    $results.GuidResolution = "MISSING"
                    # Force DNS re-registration
                    nltest /dsregdns 2>&1 | Out-Null
                }
            }
        } catch {
            $results.GuidResolution = "UNKNOWN"
        }
        
        # Check conditional forwarders if trust enabled
        if ($CreateTrust) {
            $forwarder = Get-DnsServerZone -Name $PrimaryDomain -ErrorAction SilentlyContinue
            if ($forwarder -and $forwarder.ZoneType -eq 'Forwarder') {
                $results.ForwardersConfigured = $true
            } else {
                # Try to add it
                Add-DnsServerConditionalForwarderZone -Name $PrimaryDomain -MasterServers $PrimaryDCIP -ErrorAction SilentlyContinue
                Add-DnsServerConditionalForwarderZone -Name "_msdcs.$PrimaryDomain" -MasterServers $PrimaryDCIP -ErrorAction SilentlyContinue
                $results.ForwardersConfigured = (Get-DnsServerZone -Name $PrimaryDomain -ErrorAction SilentlyContinue) -ne $null
            }
            
            # Test primary domain resolution
            Start-Sleep -Seconds 2
            try {
                $primaryResolve = Resolve-DnsName -Name $PrimaryDomain -Type A -DnsOnly -ErrorAction Stop
                $results.PrimaryResolution = $primaryResolve.IPAddress | Select-Object -First 1
            } catch {
                $results.PrimaryResolution = "FAILED"
            }
        }
        
        # Check SYSVOL
        $results.SysvolReady = Test-Path "\\$ExternalDomain\SYSVOL\$ExternalDomain\Policies"
        
        return $results
        
    } -ArgumentList $Config.PrimaryDomain, $Config.PrimaryDCIP, $Config.ExternalDomain, $Config.VMIP, $Config.CreateTrust
    
    # Display results
    Write-Host ""
    Write-Host "  Post-Deployment Health Check:" -ForegroundColor Cyan
    Write-Host "    DNS Servers:        $($healthResults.DNSServers -join ', ')" -ForegroundColor $(if($healthResults.DNSServers -contains $Config.VMIP){'Green'}else{'Red'})
    if ($healthResults.DNSFixed) {
        Write-Host "    DNS Config:         Fixed (was misconfigured)" -ForegroundColor Yellow
    }
    Write-Host "    Self Resolution:    $($healthResults.SelfResolution)" -ForegroundColor $(if($healthResults.SelfResolution -eq $Config.VMIP){'Green'}else{'Red'})
    Write-Host "    DC GUID Record:     $($healthResults.GuidResolution)" -ForegroundColor $(if($healthResults.GuidResolution -eq 'OK'){'Green'}else{'Yellow'})
    if ($Config.CreateTrust) {
        Write-Host "    Forwarders:         $(if($healthResults.ForwardersConfigured){'Configured'}else{'NOT Configured'})" -ForegroundColor $(if($healthResults.ForwardersConfigured){'Green'}else{'Yellow'})
        Write-Host "    Primary Resolution: $($Config.PrimaryDomain) -> $($healthResults.PrimaryResolution)" -ForegroundColor $(if($healthResults.PrimaryResolution -eq $Config.PrimaryDCIP){'Green'}else{'Yellow'})
    }
    Write-Host "    SYSVOL Ready:       $($healthResults.SysvolReady)" -ForegroundColor $(if($healthResults.SysvolReady){'Green'}else{'Yellow'})
    Write-Host ""
    
    if ($healthResults.SelfResolution -ne $Config.VMIP -or $healthResults.GuidResolution -ne 'OK') {
        Write-Log "WARNING: DNS resolution issues detected. Running additional DNS repair..." -Level Warning
        
        # Additional repair attempt
        Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
            # Restart DNS Server service
            Restart-Service DNS -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 10
            
            # Force re-registration
            ipconfig /registerdns
            nltest /dsregdns 2>&1 | Out-Null
            
            Write-Host "  DNS repair completed - please verify with dcdiag" -ForegroundColor Yellow
        }
    } else {
        Write-Log "Post-deployment health checks passed" -Level Success
    }
}
    Write-Host ""
    
    if ($Config.CreateTrust -and $healthResults.PrimaryResolution -ne $Config.PrimaryDCIP) {
        Write-Log "WARNING: Primary domain resolution may need manual verification before trust creation." -Level Warning
    } else {
        Write-Log "Post-deployment health checks passed" -Level Success
    }
}

# ============================================
# MAIN EXECUTION
# ============================================

$ErrorActionPreference = 'Stop'
$startTime = Get-Date

try {
    New-Item -ItemType Directory -Force -Path $Config.VMPath | Out-Null
    
    Test-Prerequisites
    Remove-ExistingVM -Name $Config.VMName
    $isoPath = Get-OrDownloadISO
    New-LabVirtualSwitch
    New-LabVM
    New-LabVHD -ISOPath $isoPath
    
    Write-Log "Starting VM..."
    Start-VM -Name $Config.VMName
    
    Install-ExternalForestDC
    Verify-PostDeploymentHealth
    Install-PrivilegedAdminAccounts
    Install-BulkADObjects
    Install-TempShare
    Install-ForestTrust
    
    $duration = (Get-Date) - $startTime
    
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "║          EXTERNAL FOREST DEPLOYMENT COMPLETE!                  ║" -ForegroundColor Magenta
    Write-Host "║              (Acquired Company Simulation)                     ║" -ForegroundColor Magenta
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  VM Name:           $($Config.VMName)" -ForegroundColor White
    Write-Host "  External Forest:   $($Config.ExternalDomain) ($($Config.ExternalNetBIOS))" -ForegroundColor White
    Write-Host "  DC IP:             $($Config.VMIP)" -ForegroundColor White
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  FOREST TOPOLOGY (M&A Scenario)" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  $($Config.PrimaryDomain) (Primary Forest)" -ForegroundColor Green
    Write-Host "      │"
    Write-Host "      ├── corp.$($Config.PrimaryDomain) (Child Domain)" -ForegroundColor Green
    Write-Host "      │"
    Write-Host "      └──<TRUST>── $($Config.ExternalDomain) (Acquired Company)" -ForegroundColor Magenta
    Write-Host "                        └── DC: $($Config.VMName)" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  CREDENTIALS - EXTERNAL FOREST" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Domain Admin:"
    Write-Host "    $($Config.ExternalNetBIOS)\Administrator     $($Config.AdminPassword)"
    Write-Host ""
    Write-Host "  Privileged Accounts:" -ForegroundColor Yellow
    foreach ($account in $PrivilegedAccounts) {
        Write-Host "    $($Config.ExternalNetBIOS)\$($account.SamAccountName)"
        Write-Host "      Password: $($account.Password)"
    }
    Write-Host ""
    Write-Host "  Legacy Users:        L3g@cyP@ss123!"
    Write-Host "    jsmith, mjohnson, rwilliams (Development)"
    Write-Host "    pbrown, dgarcia (QA)"
    Write-Host "    lmartinez, janderson (Support)"
    Write-Host "    bthomas, mwilson (Management)"
    Write-Host ""
    Write-Host "  Disabled/Stale:      Disabled123!"
    Write-Host "    former.employee1, former.employee2, oldcontractor"
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  TRUST RELATIONSHIP" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    if ($Config.CreateTrust) {
        Write-Host "  Type:              Two-way Forest Trust"
        Write-Host "  Primary Forest:    $($Config.PrimaryDomain)"
        Write-Host "  External Forest:   $($Config.ExternalDomain)"
        Write-Host ""
        Write-Host "  Cross-Forest Access:" -ForegroundColor Yellow
        Write-Host "    - Users in either forest can authenticate to the other"
        Write-Host "    - Enterprise Admins have limited cross-forest access"
        Write-Host "    - SID filtering is enabled by default"
    } else {
        Write-Host "  Trust not configured - create manually if needed"
    }
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  M&A DISCOVERY TESTING" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  This external forest simulates an acquired company with:"
    Write-Host "    - Different OU structure (Staff/Development/QA/etc)"
    Write-Host "    - Different naming conventions (jsmith vs john.smith)"
    Write-Host "    - Legacy service accounts"
    Write-Host "    - Stale/disabled accounts to discover"
    Write-Host "    - Cross-forest trust for migration testing"
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  FILE SHARES" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  \\$($Config.VMName)\temp     (Everyone Read - legacy data)"
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "  Duration: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  Connect: vmconnect localhost $($Config.VMName)" -ForegroundColor Yellow
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host ""
}
catch {
    Write-Log "DEPLOYMENT FAILED: $_" -Level Error
    Write-Host ""
    Write-Host "  Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. This is an independent forest - no parent DC required initially"
    Write-Host "  2. For trust: ensure primary DC ($($Config.PrimaryDCIP)) is running"
    Write-Host "  3. Verify network connectivity between VMs"
    Write-Host "  4. Trust can be created manually later via AD Domains and Trusts"
    Write-Host ""
    throw
}
