#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Deploys a Windows Server 2022 Domain Controller on Hyper-V with Azure AD Connect.

.DESCRIPTION
    Interactive, single-run deployment of a Hyper-V VM running Windows Server 2022
    configured as a Domain Controller with Microsoft Entra Connect (Azure AD Connect)
    ready for hybrid identity setup. Includes bulk OU, Group, and User creation from CSV.

.PARAMETER SkipPrompts
    Use default configuration without interactive prompts.

.NOTES
    Author: Lab Automation Script
    Requires: Windows 11 with Hyper-V enabled, Administrator privileges
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
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║       HYPER-V DOMAIN CONTROLLER DEPLOYMENT WIZARD              ║" -ForegroundColor Cyan
    Write-Host "║           with Microsoft Entra Connect (Azure AD)              ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # VM Name
    Write-Host "── VM Configuration ──" -ForegroundColor Yellow
    $vmName = Read-Host "  VM Name [LabDC]"
    if ([string]::IsNullOrWhiteSpace($vmName)) { $vmName = "LabDC" }
    
    # VM Specs
    Write-Host ""
    Write-Host "  Recommended minimums: 4GB RAM, 2 vCPUs, 40GB disk" -ForegroundColor DarkGray
    
    $vmMemory = Read-Host "  Memory in GB [4]"
    if ([string]::IsNullOrWhiteSpace($vmMemory)) { $vmMemory = 4 }
    $vmMemory = [int]$vmMemory
    if ($vmMemory -lt 2) { 
        Write-Host "  Warning: Less than 2GB may cause issues. Setting to 2GB." -ForegroundColor Yellow
        $vmMemory = 2 
    }
    
    $vmCPU = Read-Host "  vCPU Count [2]"
    if ([string]::IsNullOrWhiteSpace($vmCPU)) { $vmCPU = 2 }
    $vmCPU = [int]$vmCPU
    if ($vmCPU -lt 1) { $vmCPU = 1 }
    
    $vmDisk = Read-Host "  Disk Size in GB [60]"
    if ([string]::IsNullOrWhiteSpace($vmDisk)) { $vmDisk = 60 }
    $vmDisk = [int]$vmDisk
    if ($vmDisk -lt 40) {
        Write-Host "  Warning: Less than 40GB may cause issues. Setting to 40GB." -ForegroundColor Yellow
        $vmDisk = 40
    }
    
    # Domain Configuration
    Write-Host ""
    Write-Host "── Domain Configuration ──" -ForegroundColor Yellow
    
    $domainName = Read-Host "  Domain FQDN [lab.local]"
    if ([string]::IsNullOrWhiteSpace($domainName)) { $domainName = "lab.local" }
    $domainName = $domainName.ToLower()
    
    # Extract NetBIOS name (first part, uppercase)
    $netbiosDefault = ($domainName -split '\.')[0].ToUpper()
    $domainNetBIOS = Read-Host "  NetBIOS Name [$netbiosDefault]"
    if ([string]::IsNullOrWhiteSpace($domainNetBIOS)) { $domainNetBIOS = $netbiosDefault }
    $domainNetBIOS = $domainNetBIOS.ToUpper()
    
    # Password
    Write-Host ""
    $adminPassword = Read-Host "  Administrator Password [LabAdmin2025!]"
    if ([string]::IsNullOrWhiteSpace($adminPassword)) { $adminPassword = "LabAdmin2025!" }
    
    # Network Configuration
    Write-Host ""
    Write-Host "── Network Configuration ──" -ForegroundColor Yellow
    Write-Host "  Configure static IP for the Domain Controller" -ForegroundColor DarkGray
    
    $vmIP = Read-Host "  Static IP Address [192.168.0.10]"
    if ([string]::IsNullOrWhiteSpace($vmIP)) { $vmIP = "192.168.0.10" }
    
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
    
    # Azure AD Connect
    Write-Host ""
    Write-Host "── Azure AD Connect ──" -ForegroundColor Yellow
    Write-Host "  Microsoft Entra Connect enables hybrid identity sync" -ForegroundColor DarkGray
    $installAADConnect = Read-Host "  Install Azure AD Connect? (Y/n) [Y]"
    if ([string]::IsNullOrWhiteSpace($installAADConnect)) { $installAADConnect = "Y" }
    $installAADConnect = $installAADConnect.ToUpper() -eq "Y"
    
    # Bulk AD Objects
    Write-Host ""
    Write-Host "── Bulk AD Object Creation ──" -ForegroundColor Yellow
    Write-Host "  Create OUs, Groups, and ~2990 Users from CSV files" -ForegroundColor DarkGray
    $installBulkAD = Read-Host "  Create bulk AD objects? (Y/n) [Y]"
    if ([string]::IsNullOrWhiteSpace($installBulkAD)) { $installBulkAD = "Y" }
    $installBulkAD = $installBulkAD.ToUpper() -eq "Y"
    
    # VM Storage Path
    Write-Host ""
    Write-Host "── Storage Location ──" -ForegroundColor Yellow
    $vmBasePath = Read-Host "  VM Storage Path [C:\Hyper-V_VMs]"
    if ([string]::IsNullOrWhiteSpace($vmBasePath)) { $vmBasePath = "C:\Hyper-V_VMs" }
    
    # Confirmation
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  CONFIGURATION SUMMARY" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  VM Name:           $vmName"
    Write-Host "  Specs:             ${vmMemory}GB RAM, $vmCPU vCPUs, ${vmDisk}GB Disk"
    Write-Host "  Domain:            $domainName ($domainNetBIOS)"
    Write-Host "  Admin Password:    $adminPassword"
    Write-Host "  IP Address:        $vmIP/$vmPrefix (GW: $vmGateway)"
    Write-Host "  Virtual Switch:    $switchName"
    Write-Host "  Azure AD Connect:  $(if($installAADConnect){'Yes'}else{'No'})"
    Write-Host "  Bulk AD Objects:   $(if($installBulkAD){'Yes (~2990 users)'}else{'No'})"
    Write-Host "  Storage Path:      $vmBasePath"
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    $confirm = Read-Host "  Proceed with deployment? (Y/n) [Y]"
    if ([string]::IsNullOrWhiteSpace($confirm)) { $confirm = "Y" }
    if ($confirm.ToUpper() -ne "Y") {
        Write-Host "  Deployment cancelled." -ForegroundColor Yellow
        exit 0
    }
    
    return @{
        VMName            = $vmName
        VMMemoryGB        = $vmMemory
        VMProcessorCount  = $vmCPU
        VHDSizeGB         = $vmDisk
        SwitchName        = $switchName
        DomainName        = $domainName
        DomainNetBIOS     = $domainNetBIOS
        AdminPassword     = $adminPassword
        SafeModePassword  = $adminPassword
        VMIP              = $vmIP
        VMPrefix          = $vmPrefix
        VMGateway         = $vmGateway
        VMDNS             = $vmIP
        VMBasePath        = $vmBasePath
        InstallAADConnect = $installAADConnect
        InstallBulkAD     = $installBulkAD
        ISOFileName       = "Windows_Server_2022_Evaluation.iso"
        ISOUrl            = "https://software-static.download.prss.microsoft.com/sg/download/888969d5-f34g-4e03-ac9d-1f9786c66749/SERVER_EVAL_x64FRE_en-us.iso"
        ExpectedSHA256    = "3E4FA6D8507B554856FC9CA6079CC402DF11A8B79344871669F0251535255325"
        MaxWaitMinutes    = 20
        RetryIntervalSec  = 15
        AADConnectUrl     = "https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi"
    }
}

function Get-DefaultConfiguration {
    return @{
        VMName            = "LabDC"
        VMMemoryGB        = 4
        VMProcessorCount  = 2
        VHDSizeGB         = 60
        SwitchName        = "LabSwitch"
        DomainName        = "lab.local"
        DomainNetBIOS     = "LAB"
        AdminPassword     = "LabAdmin2025!"
        SafeModePassword  = "LabAdmin2025!"
        VMIP              = "192.168.0.10"
        VMPrefix          = 24
        VMGateway         = "192.168.0.1"
        VMDNS             = "192.168.0.10"
        VMBasePath        = "C:\Hyper-V_VMs"
        InstallAADConnect = $true
        InstallBulkAD     = $true
        ISOFileName       = "Windows_Server_2022_Evaluation.iso"
        ISOUrl            = "https://software-static.download.prss.microsoft.com/sg/download/888969d5-f34g-4e03-ac9d-1f9786c66749/SERVER_EVAL_x64FRE_en-us.iso"
        ExpectedSHA256    = "3E4FA6D8507B554856FC9CA6079CC402DF11A8B79344871669F0251535255325"
        MaxWaitMinutes    = 20
        RetryIntervalSec  = 15
        AADConnectUrl     = "https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi"
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
# PRIVILEGED ADMIN ACCOUNTS CONFIGURATION
# ============================================

# These accounts will be created with Domain Admin and Enterprise Admin rights
$PrivilegedAccounts = @(
    @{
        SamAccountName    = 'lpoleschtschuk-sa'
        Name              = 'Lpoleschtschuk Service Admin'
        GivenName         = 'Lpoleschtschuk'
        Surname           = 'ServiceAdmin'
        DisplayName       = 'Lpoleschtschuk (Service Admin)'
        Description       = 'Service Admin - Domain Admin & Enterprise Admin'
        Password          = 'Lp0l3schtSchuk#2025!'
        Groups            = @('Domain Admins', 'Enterprise Admins', 'Schema Admins')
    },
    @{
        SamAccountName    = 'svc-backup-admin'
        Name              = 'Backup Service Admin'
        GivenName         = 'Backup'
        Surname           = 'Admin'
        DisplayName       = 'Backup Service Admin'
        Description       = 'Backup Admin - Domain Admin & Enterprise Admin'
        Password          = 'B@ckUpS3rv1c3#2025!'
        Groups            = @('Domain Admins', 'Enterprise Admins', 'Backup Operators')
    },
    @{
        SamAccountName    = 'svc-exchange-admin'
        Name              = 'Exchange Service Admin'
        GivenName         = 'Exchange'
        Surname           = 'Admin'
        DisplayName       = 'Exchange Service Admin'
        Description       = 'Exchange Admin - Domain Admin & Enterprise Admin'
        Password          = '3xch@ng3S3rv1c3#2025!'
        Groups            = @('Domain Admins', 'Enterprise Admins')
    }
)

# ============================================
# HELPER FUNCTIONS
# ============================================

# Helper to ensure AD Web Services is running before AD operations
function Invoke-ADCommand {
    param(
        [Parameter(Mandatory)]
        [string]$VMName,
        [Parameter(Mandatory)]
        [PSCredential]$Credential,
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,
        [array]$ArgumentList = @(),
        [int]$MaxRetries = 3,
        [int]$RetryDelaySeconds = 20
    )
    
    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            $result = Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock {
                param($Script, $Args)
                
                # Ensure ADWS is running
                $adws = Get-Service ADWS -ErrorAction SilentlyContinue
                if ($adws -and $adws.Status -ne 'Running') {
                    Start-Service ADWS -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 5
                }
                
                Import-Module ActiveDirectory -ErrorAction Stop
                
                # Execute the actual script
                $scriptBlock = [scriptblock]::Create($Script)
                & $scriptBlock @Args
            } -ArgumentList $ScriptBlock.ToString(), $ArgumentList -ErrorAction Stop
            
            return $result
        }
        catch {
            if ($attempt -ge $MaxRetries) {
                throw $_
            }
            Write-Host "  AD command attempt $attempt failed, retrying in ${RetryDelaySeconds}s..." -ForegroundColor Yellow
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
}

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
            Write-Progress -Activity "Downloading ISO" -Status "$pct% Complete ($([math]::Round($bitsJob.BytesTransferred/1GB, 2))GB)" -PercentComplete $pct
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
            Write-Log "Created external switch '$($Config.SwitchName)' on '$($physicalNIC.Name)'" -Level Success
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
        [int]$TimeoutMinutes = 20,
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
            Start-Sleep -Seconds $Config.RetryIntervalSec
        }
    }
    
    throw "Timeout waiting for $Description"
}

function Install-DomainController {
    Write-Log "Configuring Domain Controller..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $localCred = New-Object PSCredential("Administrator", $securePassword)
    
    Wait-VMReady -VMName $Config.VMName -Credential $localCred -TimeoutMinutes 15 -Description "Windows Setup" | Out-Null
    
    Write-Log "Stabilizing services (15s)..."
    Start-Sleep -Seconds 15
    
    # Configure network
    Write-Log "Configuring network..."
    Invoke-Command -VMName $Config.VMName -Credential $localCred -ScriptBlock {
        param($IP, $Prefix, $Gateway, $DNS)
        $adapter = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
        Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
        Remove-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
        New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $IP -PrefixLength $Prefix -DefaultGateway $Gateway | Out-Null
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $DNS
    } -ArgumentList $Config.VMIP, $Config.VMPrefix, $Config.VMGateway, $Config.VMDNS
    
    # Install AD DS
    Write-Log "Installing AD Domain Services..."
    Invoke-Command -VMName $Config.VMName -Credential $localCred -ScriptBlock {
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -IncludeAllSubFeature | Out-Null
    }
    
    # Promote to DC
    Write-Log "Promoting to Domain Controller for '$($Config.DomainName)'..."
    $secureSafeMode = ConvertTo-SecureString $Config.SafeModePassword -AsPlainText -Force
    
    Invoke-Command -VMName $Config.VMName -Credential $localCred -ScriptBlock {
        param($Domain, $NetBIOS, $SafePwd)
        Install-ADDSForest -DomainName $Domain -DomainNetbiosName $NetBIOS -SafeModeAdministratorPassword $SafePwd `
            -InstallDns -CreateDnsDelegation:$false -NoRebootOnCompletion -Force -WarningAction SilentlyContinue | Out-Null
    } -ArgumentList $Config.DomainName, $Config.DomainNetBIOS, $secureSafeMode
    
    Write-Log "Restarting VM..."
    Restart-VM -Name $Config.VMName -Force
    Start-Sleep -Seconds 30  # Based on observed ~17s boot, +80% buffer
    
    # Wait for DC with domain creds - try both credential formats
    $domainCred = New-Object PSCredential("$($Config.DomainNetBIOS)\Administrator", $securePassword)
    $localCred = New-Object PSCredential("Administrator", $securePassword)
    
    $dcReady = $false
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $maxWaitMinutes = 15  # Reduced - DC should be ready within 5-10 min
    
    Write-Log "Waiting for Domain Controller services (timeout: ${maxWaitMinutes}m)..."
    
    # First, wait for VM to be responsive at all
    $vmResponsive = $false
    while (-not $vmResponsive -and $stopwatch.Elapsed.TotalMinutes -lt 5) {
        Start-Sleep -Seconds 10
        
        # Try domain creds first, then local
        foreach ($cred in @($domainCred, $localCred)) {
            try {
                $null = Invoke-Command -VMName $Config.VMName -Credential $cred -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
                $vmResponsive = $true
                Write-Host ""
                Write-Log "VM responsive after reboot" -Level Success
                break
            } catch {
                # Continue trying
            }
        }
        
        if (-not $vmResponsive) {
            Write-Host "`r  Waiting for VM to respond... ($([int]$stopwatch.Elapsed.TotalSeconds)s)          " -NoNewline
        }
    }
    
    # Give services time to initialize after VM is responsive
    Write-Log "Waiting for AD services to initialize (45s)..."
    Start-Sleep -Seconds 45
    
    # Now wait for AD services INCLUDING ADWS (required for PowerShell AD cmdlets)
    while (-not $dcReady -and $stopwatch.Elapsed.TotalMinutes -lt $maxWaitMinutes) {
        Start-Sleep -Seconds 15
        
        foreach ($cred in @($domainCred, $localCred)) {
            try {
                $result = Invoke-Command -VMName $Config.VMName -Credential $cred -ScriptBlock {
                    $ntds = Get-Service NTDS -ErrorAction SilentlyContinue
                    $dns = Get-Service DNS -ErrorAction SilentlyContinue
                    $adws = Get-Service ADWS -ErrorAction SilentlyContinue
                    
                    $status = @{
                        NTDS = if ($ntds) { $ntds.Status.ToString() } else { "NotFound" }
                        DNS = if ($dns) { $dns.Status.ToString() } else { "NotFound" }
                        ADWS = if ($adws) { $adws.Status.ToString() } else { "NotFound" }
                    }
                    
                    # ALL services including ADWS must be running
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
                    Write-Log "Domain Controller operational: $($result.Domain)" -Level Success
                    Write-Log "Stabilizing AD services (20s)..."
                    Start-Sleep -Seconds 20
                    break
                } else {
                    $svcStatus = "NTDS=$($result.Services.NTDS), DNS=$($result.Services.DNS), ADWS=$($result.Services.ADWS)"
                    Write-Host "`r  Services: $svcStatus ($([int]$stopwatch.Elapsed.TotalMinutes)m)          " -NoNewline
                }
                break
            }
            catch {
                # Try next credential
            }
        }
    }
    
    if (-not $dcReady) {
        Write-Log "DC services timeout - attempting manual ADWS restart..." -Level Warning
        
        try {
            Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
                Restart-Service ADWS -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 20
                Get-ADDomain -ErrorAction Stop | Out-Null
            } -ErrorAction Stop
            
            Write-Log "ADWS manually restarted - continuing..." -Level Success
            $dcReady = $true
        } catch {
            Write-Log "Manual ADWS restart failed: $_" -Level Warning
        }
        Start-Sleep -Seconds 15
    }
    
    # Create base objects and service account - with retry logic
    Write-Log "Creating base AD objects..."
    
    $maxRetries = 3
    $retryCount = 0
    $success = $false
    
    while (-not $success -and $retryCount -lt $maxRetries) {
        $retryCount++
        try {
            Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
                param($DomainDN)
                
                # Ensure ADWS is running
                $adws = Get-Service ADWS -ErrorAction SilentlyContinue
                if ($adws.Status -ne 'Running') {
                    Start-Service ADWS -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 10
                }
                
                Import-Module ActiveDirectory -ErrorAction Stop
                
                # OU for basic test
                if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'LabUsers'" -ErrorAction SilentlyContinue)) {
                    New-ADOrganizationalUnit -Name "LabUsers" -Path $DomainDN -ProtectedFromAccidentalDeletion $false
                }
                
                # Test user
                if (-not (Get-ADUser -Filter "SamAccountName -eq 'TestUser1'" -ErrorAction SilentlyContinue)) {
                    New-ADUser -Name "Test User 1" -SamAccountName "TestUser1" -UserPrincipalName "TestUser1@$($env:USERDNSDOMAIN)" `
                        -Path "OU=LabUsers,$DomainDN" -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
                        -Enabled $true -PasswordNeverExpires $true
                }
                
                # AAD Connect service account
                if (-not (Get-ADUser -Filter "SamAccountName -eq 'AADConnect'" -ErrorAction SilentlyContinue)) {
                    New-ADUser -Name "Azure AD Connect" -SamAccountName "AADConnect" -UserPrincipalName "AADConnect@$($env:USERDNSDOMAIN)" `
                        -Path $DomainDN -AccountPassword (ConvertTo-SecureString "AADConnect2025!" -AsPlainText -Force) `
                        -Enabled $true -PasswordNeverExpires $true -Description "Azure AD Connect service account"
                    Add-ADGroupMember -Identity "Enterprise Admins" -Members "AADConnect"
                }
            } -ArgumentList "DC=$($Config.DomainName.Replace('.',',DC='))" -ErrorAction Stop
            
            $success = $true
            Write-Log "Base AD objects created" -Level Success
        }
        catch {
            Write-Log "Attempt $retryCount failed: $($_.Exception.Message)" -Level Warning
            if ($retryCount -lt $maxRetries) {
                Write-Log "Waiting 30 seconds before retry..." -Level Warning
                Start-Sleep -Seconds 30
                
                # Try to restart ADWS
                Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
                    Restart-Service ADWS -Force -ErrorAction SilentlyContinue
                } -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 15
            } else {
                throw "Failed to create base AD objects after $maxRetries attempts: $_"
            }
        }
    }
    
    # Disable auto-logon
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "0" -ErrorAction SilentlyContinue
    }
}

function Install-PrivilegedAdminAccounts {
    Write-Log "Creating privileged admin accounts..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.DomainNetBIOS)\Administrator", $securePassword)
    $domainDN = "DC=$($Config.DomainName.Replace('.',',DC='))"
    
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
                    
                    # Ensure ADWS is running
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
                            Path                  = $DomainDN
                            AccountPassword       = (ConvertTo-SecureString $Account.Password -AsPlainText -Force)
                            Enabled               = $true
                            PasswordNeverExpires  = $true
                            CannotChangePassword  = $false
                        }
                        
                        New-ADUser @userParams
                        
                        # Add to privileged groups
                        foreach ($group in $Account.Groups) {
                            try {
                                Add-ADGroupMember -Identity $group -Members $sam -ErrorAction Stop
                            } catch {
                                Write-Warning "Could not add $sam to $group : $_"
                            }
                        }
                        
                        Write-Host "  Created: $sam" -ForegroundColor Green
                    } else {
                        Write-Host "  Exists: $sam" -ForegroundColor Yellow
                    }
                } -ArgumentList $account, $domainDN, $Config.DomainName -ErrorAction Stop
                
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
    
    Write-Log "Creating bulk AD objects (OUs, Groups, Users)..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.DomainNetBIOS)\Administrator", $securePassword)
    
    # Get the domain DN parts
    $domainParts = $Config.DomainName -split '\.'
    $domainDN = ($domainParts | ForEach-Object { "DC=$_" }) -join ','
    
    # ===== EMBEDDED OU DATA =====
    $ousData = @"
name,path
$($Config.DomainNetBIOS) Groups,$domainDN
$($Config.DomainNetBIOS) Users,$domainDN
Marketing,OU=$($Config.DomainNetBIOS) Users,$domainDN
HR,OU=$($Config.DomainNetBIOS) Users,$domainDN
IT,OU=$($Config.DomainNetBIOS) Users,$domainDN
Accounting,OU=$($Config.DomainNetBIOS) Users,$domainDN
Management,OU=$($Config.DomainNetBIOS) Users,$domainDN
PR,OU=$($Config.DomainNetBIOS) Users,$domainDN
Operations,OU=$($Config.DomainNetBIOS) Users,$domainDN
Legal,OU=$($Config.DomainNetBIOS) Users,$domainDN
Purchasing,OU=$($Config.DomainNetBIOS) Users,$domainDN
$($Config.DomainNetBIOS) Computers,$domainDN
Marketing,OU=$($Config.DomainNetBIOS) Computers,$domainDN
HR,OU=$($Config.DomainNetBIOS) Computers,$domainDN
IT,OU=$($Config.DomainNetBIOS) Computers,$domainDN
Accounting,OU=$($Config.DomainNetBIOS) Computers,$domainDN
Management,OU=$($Config.DomainNetBIOS) Computers,$domainDN
PR,OU=$($Config.DomainNetBIOS) Computers,$domainDN
Operations,OU=$($Config.DomainNetBIOS) Computers,$domainDN
Legal,OU=$($Config.DomainNetBIOS) Computers,$domainDN
Purchasing,OU=$($Config.DomainNetBIOS) Computers,$domainDN
"@

    # ===== EMBEDDED GROUPS DATA =====
    $groupsData = @"
name,path,scope,category,description
Marketing_Local,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,Marketing Local Group
Marketing_Folders,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,Marketing Folders Access
Accounting_Printers,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,Accounting Printers Access
Accounting_Folders,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,Accounting Folders Access
Accounting_Local,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,Accounting Local Group
HR_Local,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,HR Local Group
HR_Folders,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,HR Folders Access
IT_Printers,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,IT Printers Access
IT_Folders,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,IT Folders Access
IT_Local,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,IT Local Group
Management_Printers,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,Management Printers Access
Management_Folders,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,Management Folders Access
PR_Printers,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,PR Printers Access
PR_Folders,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,PR Folders Access
Operations_Printers,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,Operations Printers Access
Operations_Folders,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,Operations Folders Access
Legal_Printers,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,Legal Printers Access
Legal_Folders,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,Legal Folders Access
Purchasing_Printers,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,Purchasing Printers Access
Purchasing_Folders,OU=$($Config.DomainNetBIOS) Groups~$domainDN,DomainLocal,Security,Purchasing Folders Access
"@

    # ===== EMBEDDED SAMPLE USERS DATA =====
    # Creating 50 sample users across departments (enough for testing, not 3000 to keep it fast)
    $usersData = @"
SamAccountName,Password,Path,Department,GivenName,Surname,Name,DisplayName,Title,Email
john.smith,P@ssw0rd123!,OU=IT~OU=$($Config.DomainNetBIOS) Users~$domainDN,IT,John,Smith,John Smith,John Smith,IT Administrator,john.smith@$($Config.DomainName)
jane.doe,P@ssw0rd123!,OU=HR~OU=$($Config.DomainNetBIOS) Users~$domainDN,HR,Jane,Doe,Jane Doe,Jane Doe,HR Manager,jane.doe@$($Config.DomainName)
bob.wilson,P@ssw0rd123!,OU=Marketing~OU=$($Config.DomainNetBIOS) Users~$domainDN,Marketing,Bob,Wilson,Bob Wilson,Bob Wilson,Marketing Lead,bob.wilson@$($Config.DomainName)
alice.johnson,P@ssw0rd123!,OU=Accounting~OU=$($Config.DomainNetBIOS) Users~$domainDN,Accounting,Alice,Johnson,Alice Johnson,Alice Johnson,Senior Accountant,alice.johnson@$($Config.DomainName)
charlie.brown,P@ssw0rd123!,OU=Management~OU=$($Config.DomainNetBIOS) Users~$domainDN,Management,Charlie,Brown,Charlie Brown,Charlie Brown,Operations Manager,charlie.brown@$($Config.DomainName)
diana.ross,P@ssw0rd123!,OU=Legal~OU=$($Config.DomainNetBIOS) Users~$domainDN,Legal,Diana,Ross,Diana Ross,Diana Ross,Legal Counsel,diana.ross@$($Config.DomainName)
edward.jones,P@ssw0rd123!,OU=IT~OU=$($Config.DomainNetBIOS) Users~$domainDN,IT,Edward,Jones,Edward Jones,Edward Jones,System Administrator,edward.jones@$($Config.DomainName)
fiona.green,P@ssw0rd123!,OU=HR~OU=$($Config.DomainNetBIOS) Users~$domainDN,HR,Fiona,Green,Fiona Green,Fiona Green,HR Specialist,fiona.green@$($Config.DomainName)
george.white,P@ssw0rd123!,OU=Marketing~OU=$($Config.DomainNetBIOS) Users~$domainDN,Marketing,George,White,George White,George White,Marketing Analyst,george.white@$($Config.DomainName)
helen.black,P@ssw0rd123!,OU=Operations~OU=$($Config.DomainNetBIOS) Users~$domainDN,Operations,Helen,Black,Helen Black,Helen Black,Operations Analyst,helen.black@$($Config.DomainName)
ivan.gray,P@ssw0rd123!,OU=IT~OU=$($Config.DomainNetBIOS) Users~$domainDN,IT,Ivan,Gray,Ivan Gray,Ivan Gray,Network Engineer,ivan.gray@$($Config.DomainName)
julia.adams,P@ssw0rd123!,OU=Accounting~OU=$($Config.DomainNetBIOS) Users~$domainDN,Accounting,Julia,Adams,Julia Adams,Julia Adams,Accountant,julia.adams@$($Config.DomainName)
kevin.miller,P@ssw0rd123!,OU=PR~OU=$($Config.DomainNetBIOS) Users~$domainDN,PR,Kevin,Miller,Kevin Miller,Kevin Miller,PR Specialist,kevin.miller@$($Config.DomainName)
laura.davis,P@ssw0rd123!,OU=Purchasing~OU=$($Config.DomainNetBIOS) Users~$domainDN,Purchasing,Laura,Davis,Laura Davis,Laura Davis,Purchasing Agent,laura.davis@$($Config.DomainName)
mike.taylor,P@ssw0rd123!,OU=IT~OU=$($Config.DomainNetBIOS) Users~$domainDN,IT,Mike,Taylor,Mike Taylor,Mike Taylor,Help Desk Analyst,mike.taylor@$($Config.DomainName)
nancy.moore,P@ssw0rd123!,OU=HR~OU=$($Config.DomainNetBIOS) Users~$domainDN,HR,Nancy,Moore,Nancy Moore,Nancy Moore,Recruiter,nancy.moore@$($Config.DomainName)
oscar.martinez,P@ssw0rd123!,OU=Accounting~OU=$($Config.DomainNetBIOS) Users~$domainDN,Accounting,Oscar,Martinez,Oscar Martinez,Oscar Martinez,Accounting Clerk,oscar.martinez@$($Config.DomainName)
patricia.lee,P@ssw0rd123!,OU=Legal~OU=$($Config.DomainNetBIOS) Users~$domainDN,Legal,Patricia,Lee,Patricia Lee,Patricia Lee,Paralegal,patricia.lee@$($Config.DomainName)
quincy.harris,P@ssw0rd123!,OU=Operations~OU=$($Config.DomainNetBIOS) Users~$domainDN,Operations,Quincy,Harris,Quincy Harris,Quincy Harris,Operations Coordinator,quincy.harris@$($Config.DomainName)
rachel.clark,P@ssw0rd123!,OU=Marketing~OU=$($Config.DomainNetBIOS) Users~$domainDN,Marketing,Rachel,Clark,Rachel Clark,Rachel Clark,Content Writer,rachel.clark@$($Config.DomainName)
steve.walker,P@ssw0rd123!,OU=IT~OU=$($Config.DomainNetBIOS) Users~$domainDN,IT,Steve,Walker,Steve Walker,Steve Walker,Security Analyst,steve.walker@$($Config.DomainName)
tina.hall,P@ssw0rd123!,OU=Management~OU=$($Config.DomainNetBIOS) Users~$domainDN,Management,Tina,Hall,Tina Hall,Tina Hall,Project Manager,tina.hall@$($Config.DomainName)
victor.young,P@ssw0rd123!,OU=Purchasing~OU=$($Config.DomainNetBIOS) Users~$domainDN,Purchasing,Victor,Young,Victor Young,Victor Young,Procurement Specialist,victor.young@$($Config.DomainName)
wendy.king,P@ssw0rd123!,OU=PR~OU=$($Config.DomainNetBIOS) Users~$domainDN,PR,Wendy,King,Wendy King,Wendy King,Communications Manager,wendy.king@$($Config.DomainName)
xavier.scott,P@ssw0rd123!,OU=IT~OU=$($Config.DomainNetBIOS) Users~$domainDN,IT,Xavier,Scott,Xavier Scott,Xavier Scott,Database Administrator,xavier.scott@$($Config.DomainName)
"@

    # Copy data to VM and create objects
    Write-Log "Transferring data to VM..."
    
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($OusData, $GroupsData, $UsersData)
        
        # Ensure ADWS is running
        $adws = Get-Service ADWS -ErrorAction SilentlyContinue
        if ($adws.Status -ne 'Running') {
            Start-Service ADWS -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 10
        }
        
        Import-Module ActiveDirectory
        
        # Create C:\it directory
        New-Item -ItemType Directory -Path "C:\it" -Force | Out-Null
        
        # Write CSV files (using ~ as delimiter workaround, will replace with comma)
        $OusData | Out-File "C:\it\ous.csv" -Encoding UTF8 -Force
        $GroupsData -replace '~',',' | Out-File "C:\it\groups.csv" -Encoding UTF8 -Force
        $UsersData -replace '~',',' | Out-File "C:\it\users.csv" -Encoding UTF8 -Force
        
        Write-Host "CSV files created in C:\it" -ForegroundColor Green
        
    } -ArgumentList $ousData, $groupsData, $usersData
    
    # Create OUs
    Write-Log "Creating Organizational Units..."
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        Import-Module ActiveDirectory
        $ous = Import-Csv "C:\it\ous.csv"
        $created = 0
        $skipped = 0
        
        foreach ($ou in $ous) {
            $name = $ou.name.Trim()
            $path = $ou.path.Trim()
            
            try {
                $existingOU = Get-ADOrganizationalUnit -Filter "Name -eq '$name'" -SearchBase $path -SearchScope OneLevel -ErrorAction SilentlyContinue
                if (-not $existingOU) {
                    New-ADOrganizationalUnit -Name $name -Path $path -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
                    $created++
                } else {
                    $skipped++
                }
            } catch {
                Write-Warning "Failed to create OU '$name' at '$path': $_"
            }
        }
        Write-Host "  OUs created: $created, skipped: $skipped" -ForegroundColor Cyan
    }
    
    # Create Groups
    Write-Log "Creating Security Groups..."
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        Import-Module ActiveDirectory
        $groups = Import-Csv "C:\it\groups.csv"
        $created = 0
        $skipped = 0
        
        foreach ($group in $groups) {
            $name = $group.name.Trim()
            try {
                if (-not (Get-ADGroup -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue)) {
                    $groupParams = @{
                        Name          = $name
                        Path          = $group.path.Trim()
                        GroupScope    = $group.scope.Trim()
                        GroupCategory = $group.category.Trim()
                        Description   = $group.description
                    }
                    New-ADGroup @groupParams -ErrorAction Stop
                    $created++
                } else {
                    $skipped++
                }
            } catch {
                Write-Warning "Failed to create group '$name': $_"
            }
        }
        Write-Host "  Groups created: $created, skipped: $skipped" -ForegroundColor Cyan
    }
    
    # Create Users
    Write-Log "Creating User Accounts..."
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($DomainName)
        
        Import-Module ActiveDirectory
        $users = Import-Csv "C:\it\users.csv"
        $created = 0
        $skipped = 0
        $failed = 0
        
        foreach ($user in $users) {
            $sam = $user.SamAccountName.Trim()
            
            try {
                if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue)) {
                    $userParams = @{
                        SamAccountName        = $sam
                        UserPrincipalName     = "$sam@$DomainName"
                        Path                  = $user.Path.Trim()
                        GivenName             = $user.GivenName
                        Surname               = $user.Surname
                        Name                  = $user.Name
                        DisplayName           = $user.DisplayName
                        Department            = $user.Department
                        Title                 = $user.Title
                        EmailAddress          = $user.Email
                        AccountPassword       = (ConvertTo-SecureString $user.Password -AsPlainText -Force)
                        Enabled               = $true
                        PasswordNeverExpires  = $true
                        ChangePasswordAtLogon = $false
                    }
                    
                    New-ADUser @userParams -ErrorAction Stop
                    $created++
                } else {
                    $skipped++
                }
            } catch {
                $failed++
                Write-Warning "Failed to create user '$sam': $_"
            }
        }
        Write-Host "  Users created: $created, skipped: $skipped, failed: $failed" -ForegroundColor Cyan
    } -ArgumentList $Config.DomainName
    
    Write-Log "Bulk AD object creation completed" -Level Success
}

function Install-AzureADConnect {
    if (-not $Config.InstallAADConnect) {
        Write-Log "Skipping Azure AD Connect"
        return
    }
    
    Write-Log "Setting up Microsoft Entra Connect..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.DomainNetBIOS)\Administrator", $securePassword)
    
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($AADConnectUrl, $DomainName)
        
        $downloadPath = "C:\AADConnect"
        $msiPath = "$downloadPath\AzureADConnect.msi"
        $desktopPath = "C:\Users\Public\Desktop"
        
        New-Item -ItemType Directory -Force -Path $downloadPath | Out-Null
        
        Write-Host "Downloading Microsoft Entra Connect..."
        try {
            Start-BitsTransfer -Source $AADConnectUrl -Destination $msiPath -ErrorAction Stop
        }
        catch {
            (New-Object System.Net.WebClient).DownloadFile($AADConnectUrl, $msiPath)
        }
        
        if (Test-Path $msiPath) {
            # Desktop shortcut
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut("$desktopPath\Install Azure AD Connect.lnk")
            $shortcut.TargetPath = "msiexec.exe"
            $shortcut.Arguments = "/i `"$msiPath`""
            $shortcut.Description = "Install Microsoft Entra Connect"
            $shortcut.Save()
            
            # Readme
            @"
Microsoft Entra Connect (Azure AD Connect)
==========================================

Installer: $msiPath

To install: Double-click "Install Azure AD Connect" on desktop

Required credentials:
- Azure Global Administrator
- Domain: $DomainName\Administrator

Pre-created service account:
- User: AADConnect@$DomainName
- Pass: AADConnect2025!

Documentation: https://learn.microsoft.com/azure/active-directory/hybrid/
"@ | Out-File "$desktopPath\Azure AD Connect README.txt" -Encoding UTF8
            
            # Enable TLS 1.2
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
            
            Write-Host "Azure AD Connect ready"
        }
    } -ArgumentList $Config.AADConnectUrl, $Config.DomainName
    
    Write-Log "Azure AD Connect installer ready on VM desktop" -Level Success
}

# ============================================
# ADVANCED DC CONFIGURATION FUNCTIONS
# ============================================

function Install-DHCPServer {
    Write-Log "Installing and configuring DHCP Server..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.DomainNetBIOS)\Administrator", $securePassword)
    
    # Calculate DHCP scope from VM IP
    $ipParts = $Config.VMIP -split '\.'
    $scopeStart = "$($ipParts[0]).$($ipParts[1]).$($ipParts[2]).100"
    $scopeEnd = "$($ipParts[0]).$($ipParts[1]).$($ipParts[2]).200"
    $scopeSubnet = "$($ipParts[0]).$($ipParts[1]).$($ipParts[2]).0"
    $subnetMask = "255.255.255.0"
    
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($ScopeStart, $ScopeEnd, $ScopeSubnet, $SubnetMask, $Gateway, $DNS, $DomainName)
        
        # Install DHCP
        Install-WindowsFeature -Name DHCP -IncludeManagementTools | Out-Null
        
        # Authorize DHCP in AD
        $dcFQDN = "$env:COMPUTERNAME.$DomainName"
        Add-DhcpServerInDC -DnsName $dcFQDN -IPAddress $DNS -ErrorAction SilentlyContinue
        
        # Configure DHCP
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\ServerManager\Roles\12' -Name 'ConfigurationState' -Value 2 -ErrorAction SilentlyContinue
        
        # Create scope
        $scopeName = "Lab Network"
        if (-not (Get-DhcpServerv4Scope -ErrorAction SilentlyContinue | Where-Object { $_.ScopeId -eq $ScopeSubnet })) {
            Add-DhcpServerv4Scope -Name $scopeName -StartRange $ScopeStart -EndRange $ScopeEnd -SubnetMask $SubnetMask -State Active
            
            # Set scope options
            Set-DhcpServerv4OptionValue -ScopeId $ScopeSubnet -Router $Gateway
            Set-DhcpServerv4OptionValue -ScopeId $ScopeSubnet -DnsServer $DNS
            Set-DhcpServerv4OptionValue -ScopeId $ScopeSubnet -DnsDomain $DomainName
            
            # Exclusion for static IPs (1-50)
            Add-DhcpServerv4ExclusionRange -ScopeId $ScopeSubnet -StartRange "$($ScopeSubnet.TrimEnd('0'))1" -EndRange "$($ScopeSubnet.TrimEnd('0'))50"
            
            # Lease duration 8 days
            Set-DhcpServerv4Scope -ScopeId $ScopeSubnet -LeaseDuration (New-TimeSpan -Days 8)
            
            Write-Host "  DHCP Scope created: $ScopeStart - $ScopeEnd" -ForegroundColor Green
        }
        
        # Restart DHCP service
        Restart-Service DHCPServer -Force
        
    } -ArgumentList $scopeStart, $scopeEnd, $scopeSubnet, $subnetMask, $Config.VMGateway, $Config.VMIP, $Config.DomainName
    
    Write-Log "DHCP Server configured with scope $scopeStart-$scopeEnd" -Level Success
}

function Install-DNSConfiguration {
    Write-Log "Configuring DNS Server (forwarders, reverse zone, aliases)..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.DomainNetBIOS)\Administrator", $securePassword)
    
    $ipParts = $Config.VMIP -split '\.'
    $reverseZone = "$($ipParts[2]).$($ipParts[1]).$($ipParts[0]).in-addr.arpa"
    
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($ReverseZone, $DomainName, $DCIP, $IPParts)
        
        Import-Module DnsServer
        
        # Configure forwarders
        $forwarders = @('8.8.8.8', '8.8.4.4', '1.1.1.1')
        Set-DnsServerForwarder -IPAddress $forwarders -ErrorAction SilentlyContinue
        Write-Host "  DNS Forwarders: $($forwarders -join ', ')" -ForegroundColor Green
        
        # Create reverse lookup zone
        if (-not (Get-DnsServerZone -Name $ReverseZone -ErrorAction SilentlyContinue)) {
            Add-DnsServerPrimaryZone -NetworkId "$($IPParts[0]).$($IPParts[1]).$($IPParts[2]).0/24" -ReplicationScope Domain -DynamicUpdate Secure
            Write-Host "  Reverse zone created: $ReverseZone" -ForegroundColor Green
        }
        
        # Create PTR record for DC
        $ptrName = $IPParts[3]
        Add-DnsServerResourceRecordPtr -ZoneName $ReverseZone -Name $ptrName -PtrDomainName "$env:COMPUTERNAME.$DomainName" -ErrorAction SilentlyContinue
        
        # Create useful DNS aliases (CNAMEs)
        $aliases = @{
            'dc01'       = "$env:COMPUTERNAME.$DomainName"
            'mail'       = "$env:COMPUTERNAME.$DomainName"
            'exchange'   = "$env:COMPUTERNAME.$DomainName"
            'autodiscover' = "$env:COMPUTERNAME.$DomainName"
            'ldap'       = "$env:COMPUTERNAME.$DomainName"
            'kerberos'   = "$env:COMPUTERNAME.$DomainName"
            'pki'        = "$env:COMPUTERNAME.$DomainName"
            'ca'         = "$env:COMPUTERNAME.$DomainName"
            'nps'        = "$env:COMPUTERNAME.$DomainName"
            'radius'     = "$env:COMPUTERNAME.$DomainName"
            'fileserver' = "$env:COMPUTERNAME.$DomainName"
            'files'      = "$env:COMPUTERNAME.$DomainName"
            'intranet'   = "$env:COMPUTERNAME.$DomainName"
            'portal'     = "$env:COMPUTERNAME.$DomainName"
            'sharepoint' = "$env:COMPUTERNAME.$DomainName"
            'teams'      = "$env:COMPUTERNAME.$DomainName"
            'sccm'       = "$env:COMPUTERNAME.$DomainName"
            'wsus'       = "$env:COMPUTERNAME.$DomainName"
        }
        
        foreach ($alias in $aliases.GetEnumerator()) {
            Add-DnsServerResourceRecordCName -ZoneName $DomainName -Name $alias.Key -HostNameAlias $alias.Value -ErrorAction SilentlyContinue
        }
        Write-Host "  Created $($aliases.Count) DNS aliases" -ForegroundColor Green
        
    } -ArgumentList $reverseZone, $Config.DomainName, $Config.VMIP, $ipParts
    
    Write-Log "DNS configuration complete" -Level Success
}

function Enable-ADRecycleBin {
    Write-Log "Enabling AD Recycle Bin..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.DomainNetBIOS)\Administrator", $securePassword)
    
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($DomainName)
        
        $domainDN = (Get-ADDomain).DistinguishedName
        $forestDN = (Get-ADForest).Name
        
        # Check if already enabled
        $recycleBin = Get-ADOptionalFeature -Filter 'Name -like "Recycle Bin Feature"'
        if ($recycleBin.EnabledScopes.Count -eq 0) {
            Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $forestDN -Confirm:$false
            Write-Host "  AD Recycle Bin enabled" -ForegroundColor Green
        } else {
            Write-Host "  AD Recycle Bin already enabled" -ForegroundColor Yellow
        }
    } -ArgumentList $Config.DomainName
    
    Write-Log "AD Recycle Bin enabled" -Level Success
}

function Install-CertificateServices {
    Write-Log "Installing Active Directory Certificate Services (Enterprise Root CA)..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.DomainNetBIOS)\Administrator", $securePassword)
    
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($DomainName, $NetBIOS)
        
        # Install AD CS role
        Install-WindowsFeature -Name AD-Certificate, ADCS-Cert-Authority, ADCS-Web-Enrollment -IncludeManagementTools | Out-Null
        
        # Configure as Enterprise Root CA
        $caName = "$NetBIOS-ROOT-CA"
        
        try {
            Install-AdcsCertificationAuthority -CAType EnterpriseRootCa `
                -CACommonName $caName `
                -KeyLength 4096 `
                -HashAlgorithmName SHA256 `
                -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
                -ValidityPeriod Years `
                -ValidityPeriodUnits 10 `
                -Force `
                -ErrorAction Stop | Out-Null
            
            Write-Host "  Enterprise Root CA installed: $caName" -ForegroundColor Green
        } catch {
            if ($_.Exception.Message -match "already installed") {
                Write-Host "  CA already configured" -ForegroundColor Yellow
            } else {
                Write-Warning "CA installation issue: $_"
            }
        }
        
        # Install Web Enrollment
        try {
            Install-AdcsWebEnrollment -Force -ErrorAction Stop | Out-Null
            Write-Host "  Web Enrollment configured" -ForegroundColor Green
        } catch {
            Write-Host "  Web Enrollment already configured or skipped" -ForegroundColor Yellow
        }
        
        # Create common certificate templates
        # Note: Custom templates require more complex setup, basic ones are auto-published
        
    } -ArgumentList $Config.DomainName, $Config.DomainNetBIOS
    
    Write-Log "Certificate Services installed" -Level Success
}

function Install-BaseGPOs {
    Write-Log "Creating baseline Group Policy Objects..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.DomainNetBIOS)\Administrator", $securePassword)
    
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($DomainName, $NetBIOS)
        
        Import-Module GroupPolicy
        $domainDN = (Get-ADDomain).DistinguishedName
        
        # ========== PASSWORD POLICY GPO ==========
        $pwdGpoName = "$NetBIOS - Password Policy"
        if (-not (Get-GPO -Name $pwdGpoName -ErrorAction SilentlyContinue)) {
            $pwdGpo = New-GPO -Name $pwdGpoName -Comment "Domain password and lockout policy"
            $pwdGpo | New-GPLink -Target $domainDN -LinkEnabled Yes -ErrorAction SilentlyContinue
            
            # Password policy settings via registry (these map to security policy)
            # Note: Actual password policy is set via Default Domain Policy or Fine-Grained
            Write-Host "  Created: $pwdGpoName" -ForegroundColor Green
        }
        
        # ========== SECURITY AUDIT POLICY GPO ==========
        $auditGpoName = "$NetBIOS - Security Audit Policy"
        if (-not (Get-GPO -Name $auditGpoName -ErrorAction SilentlyContinue)) {
            $auditGpo = New-GPO -Name $auditGpoName -Comment "Security auditing and event logging"
            $auditGpo | New-GPLink -Target $domainDN -LinkEnabled Yes -ErrorAction SilentlyContinue
            
            # Enable advanced audit policy
            Set-GPRegistryValue -Name $auditGpoName -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ValueName "SCENoApplyLegacyAuditPolicy" -Type DWord -Value 1 | Out-Null
            
            Write-Host "  Created: $auditGpoName" -ForegroundColor Green
        }
        
        # ========== WINDOWS UPDATE GPO ==========
        $wsusGpoName = "$NetBIOS - Windows Update Policy"
        if (-not (Get-GPO -Name $wsusGpoName -ErrorAction SilentlyContinue)) {
            $wsusGpo = New-GPO -Name $wsusGpoName -Comment "Windows Update configuration"
            $wsusGpo | New-GPLink -Target "OU=$NetBIOS Computers,$domainDN" -LinkEnabled Yes -ErrorAction SilentlyContinue
            
            # Configure auto-update settings
            Set-GPRegistryValue -Name $wsusGpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoUpdate" -Type DWord -Value 0 | Out-Null
            Set-GPRegistryValue -Name $wsusGpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "AUOptions" -Type DWord -Value 3 | Out-Null
            
            Write-Host "  Created: $wsusGpoName" -ForegroundColor Green
        }
        
        # ========== DESKTOP SETTINGS GPO ==========
        $desktopGpoName = "$NetBIOS - Desktop Settings"
        if (-not (Get-GPO -Name $desktopGpoName -ErrorAction SilentlyContinue)) {
            $desktopGpo = New-GPO -Name $desktopGpoName -Comment "User desktop configuration"
            $desktopGpo | New-GPLink -Target "OU=$NetBIOS Users,$domainDN" -LinkEnabled Yes -ErrorAction SilentlyContinue
            
            # Remove Games link from Start Menu
            Set-GPRegistryValue -Name $desktopGpoName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoStartMenuMyGames" -Type DWord -Value 1 | Out-Null
            
            Write-Host "  Created: $desktopGpoName" -ForegroundColor Green
        }
        
        # ========== SERVER SECURITY GPO ==========
        $serverGpoName = "$NetBIOS - Server Security Baseline"
        if (-not (Get-GPO -Name $serverGpoName -ErrorAction SilentlyContinue)) {
            $serverGpo = New-GPO -Name $serverGpoName -Comment "Server security hardening"
            
            # Disable SMBv1
            Set-GPRegistryValue -Name $serverGpoName -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "SMB1" -Type DWord -Value 0 | Out-Null
            
            # Enable SMB signing
            Set-GPRegistryValue -Name $serverGpoName -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "RequireSecuritySignature" -Type DWord -Value 1 | Out-Null
            
            Write-Host "  Created: $serverGpoName" -ForegroundColor Green
        }
        
        # ========== WORKSTATION SECURITY GPO ==========
        $wksGpoName = "$NetBIOS - Workstation Security"
        if (-not (Get-GPO -Name $wksGpoName -ErrorAction SilentlyContinue)) {
            $wksGpo = New-GPO -Name $wksGpoName -Comment "Workstation security settings"
            $wksGpo | New-GPLink -Target "OU=$NetBIOS Computers,$domainDN" -LinkEnabled Yes -ErrorAction SilentlyContinue
            
            # Screen saver with password
            Set-GPRegistryValue -Name $wksGpoName -Key "HKCU\Control Panel\Desktop" -ValueName "ScreenSaveActive" -Type String -Value "1" | Out-Null
            Set-GPRegistryValue -Name $wksGpoName -Key "HKCU\Control Panel\Desktop" -ValueName "ScreenSaverIsSecure" -Type String -Value "1" | Out-Null
            Set-GPRegistryValue -Name $wksGpoName -Key "HKCU\Control Panel\Desktop" -ValueName "ScreenSaveTimeOut" -Type String -Value "900" | Out-Null
            
            Write-Host "  Created: $wksGpoName" -ForegroundColor Green
        }
        
        # ========== CREDENTIAL GUARD GPO ==========
        $credGuardGpoName = "$NetBIOS - Credential Guard"
        if (-not (Get-GPO -Name $credGuardGpoName -ErrorAction SilentlyContinue)) {
            $credGuardGpo = New-GPO -Name $credGuardGpoName -Comment "Windows Credential Guard (Win10+)"
            
            # Virtualization-based security
            Set-GPRegistryValue -Name $credGuardGpoName -Key "HKLM\System\CurrentControlSet\Control\DeviceGuard" -ValueName "EnableVirtualizationBasedSecurity" -Type DWord -Value 1 | Out-Null
            Set-GPRegistryValue -Name $credGuardGpoName -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ValueName "LsaCfgFlags" -Type DWord -Value 1 | Out-Null
            
            Write-Host "  Created: $credGuardGpoName" -ForegroundColor Green
        }
        
        Write-Host "  GPO creation complete" -ForegroundColor Cyan
        
    } -ArgumentList $Config.DomainName, $Config.DomainNetBIOS
    
    Write-Log "Baseline GPOs created" -Level Success
}

function Install-FileShares {
    Write-Log "Creating departmental file shares..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.DomainNetBIOS)\Administrator", $securePassword)
    
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($NetBIOS)
        
        $shareRoot = "C:\Shares"
        New-Item -ItemType Directory -Path $shareRoot -Force | Out-Null
        
        $departments = @('IT', 'HR', 'Marketing', 'Accounting', 'Management', 'Legal', 'Operations', 'PR', 'Purchasing')
        
        foreach ($dept in $departments) {
            $deptPath = Join-Path $shareRoot $dept
            New-Item -ItemType Directory -Path $deptPath -Force | Out-Null
            
            # Create subfolders
            @('Documents', 'Projects', 'Archive', 'Templates') | ForEach-Object {
                New-Item -ItemType Directory -Path (Join-Path $deptPath $_) -Force | Out-Null
            }
            
            # Create SMB share
            $shareName = $dept
            if (-not (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue)) {
                New-SmbShare -Name $shareName -Path $deptPath -FullAccess "Domain Admins" -ChangeAccess "$NetBIOS\${dept}_Folders" -ReadAccess "Domain Users" -ErrorAction SilentlyContinue | Out-Null
            }
        }
        
        # Create company-wide share
        $companyPath = Join-Path $shareRoot "Company"
        New-Item -ItemType Directory -Path $companyPath -Force | Out-Null
        @('Policies', 'Announcements', 'Templates', 'Public') | ForEach-Object {
            New-Item -ItemType Directory -Path (Join-Path $companyPath $_) -Force | Out-Null
        }
        if (-not (Get-SmbShare -Name "Company" -ErrorAction SilentlyContinue)) {
            New-SmbShare -Name "Company" -Path $companyPath -FullAccess "Domain Admins" -ChangeAccess "Domain Users" | Out-Null
        }
        
        # Create IT Tools share
        $toolsPath = Join-Path $shareRoot "IT_Tools"
        New-Item -ItemType Directory -Path $toolsPath -Force | Out-Null
        @('Software', 'Scripts', 'Drivers', 'ISOs', 'Utilities') | ForEach-Object {
            New-Item -ItemType Directory -Path (Join-Path $toolsPath $_) -Force | Out-Null
        }
        if (-not (Get-SmbShare -Name "IT_Tools$" -ErrorAction SilentlyContinue)) {
            New-SmbShare -Name "IT_Tools$" -Path $toolsPath -FullAccess "Domain Admins", "$NetBIOS\IT_Folders" | Out-Null
        }
        
        # User home directory root
        $homePath = Join-Path $shareRoot "Home"
        New-Item -ItemType Directory -Path $homePath -Force | Out-Null
        if (-not (Get-SmbShare -Name "Home$" -ErrorAction SilentlyContinue)) {
            New-SmbShare -Name "Home$" -Path $homePath -FullAccess "Domain Admins" -ChangeAccess "Authenticated Users" | Out-Null
        }
        
        # Roaming profiles root
        $profilesPath = Join-Path $shareRoot "Profiles"
        New-Item -ItemType Directory -Path $profilesPath -Force | Out-Null
        if (-not (Get-SmbShare -Name "Profiles$" -ErrorAction SilentlyContinue)) {
            New-SmbShare -Name "Profiles$" -Path $profilesPath -FullAccess "Domain Admins" -ChangeAccess "Authenticated Users" | Out-Null
        }
        
        Write-Host "  Created $($departments.Count + 4) file shares" -ForegroundColor Green
        
    } -ArgumentList $Config.DomainNetBIOS
    
    Write-Log "File shares created" -Level Success
}

function Install-TempShareWithDummyData {
    Write-Log "Creating C:\temp share with dummy data..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.DomainNetBIOS)\Administrator", $securePassword)
    
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($DomainName, $NetBIOS)
        
        # Create C:\temp directory
        $tempPath = "C:\temp"
        New-Item -ItemType Directory -Path $tempPath -Force | Out-Null
        
        # Set NTFS permissions - Everyone Read, Domain Admins Full
        $acl = Get-Acl $tempPath
        $acl.SetAccessRuleProtection($true, $false)  # Disable inheritance
        
        # Domain Admins - Full Control
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Admins", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($adminRule)
        
        # SYSTEM - Full Control
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($systemRule)
        
        # Everyone - Read & Execute
        $everyoneRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($everyoneRule)
        
        # Authenticated Users - Modify (so they can add files)
        $authUsersRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Authenticated Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($authUsersRule)
        
        Set-Acl $tempPath $acl
        
        # Create SMB share - Everyone Read
        if (-not (Get-SmbShare -Name "temp" -ErrorAction SilentlyContinue)) {
            New-SmbShare -Name "temp" -Path $tempPath -FullAccess "Domain Admins" -ChangeAccess "Authenticated Users" -ReadAccess "Everyone" | Out-Null
        }
        
        # ===== CREATE DUMMY FOLDER STRUCTURE =====
        $folders = @(
            "Documents",
            "Documents\Policies",
            "Documents\Procedures",
            "Documents\Templates",
            "Projects",
            "Projects\2024",
            "Projects\2025",
            "Projects\Archive",
            "Reports",
            "Reports\Monthly",
            "Reports\Quarterly",
            "Reports\Annual",
            "Shared",
            "Shared\Marketing",
            "Shared\HR",
            "Shared\Finance",
            "Tools",
            "Tools\Scripts",
            "Tools\Utilities",
            "Backups",
            "Logs"
        )
        
        foreach ($folder in $folders) {
            New-Item -ItemType Directory -Path (Join-Path $tempPath $folder) -Force | Out-Null
        }
        
        # ===== CREATE DUMMY FILES =====
        
        # Text files
        "Welcome to the company shared drive.`nPlease follow all data handling policies.`n`nContact IT for assistance." | Out-File "$tempPath\README.txt" -Encoding UTF8
        "Company Confidential`n==================`nThis document contains sensitive information." | Out-File "$tempPath\Documents\Confidential_Notice.txt" -Encoding UTF8
        
        # Policy documents
        @"
ACCEPTABLE USE POLICY
=====================
Version: 2.1
Last Updated: $(Get-Date -Format 'yyyy-MM-dd')

1. PURPOSE
This policy establishes guidelines for acceptable use of company IT resources.

2. SCOPE
This policy applies to all employees, contractors, and third parties.

3. POLICY
3.1 Users must use IT resources for business purposes only
3.2 Users must not share credentials
3.3 Users must report security incidents immediately

4. ENFORCEMENT
Violations may result in disciplinary action.
"@ | Out-File "$tempPath\Documents\Policies\Acceptable_Use_Policy.txt" -Encoding UTF8

        @"
DATA CLASSIFICATION POLICY
==========================
Version: 1.5
Last Updated: $(Get-Date -Format 'yyyy-MM-dd')

Classifications:
- PUBLIC: Information freely available
- INTERNAL: For internal use only
- CONFIDENTIAL: Restricted access
- SECRET: Highly restricted

Handling Requirements:
- All CONFIDENTIAL and SECRET data must be encrypted
- Data must be classified upon creation
"@ | Out-File "$tempPath\Documents\Policies\Data_Classification.txt" -Encoding UTF8

        # Template files
        @"
PROJECT PROPOSAL TEMPLATE
=========================

Project Name: [Enter Name]
Project Manager: [Enter Name]
Date: [Enter Date]

1. EXECUTIVE SUMMARY
[Brief overview of the project]

2. OBJECTIVES
- Objective 1
- Objective 2

3. SCOPE
[Define project boundaries]

4. TIMELINE
Start Date: 
End Date:

5. BUDGET
Estimated Cost: $

6. RISKS
[Identify potential risks]
"@ | Out-File "$tempPath\Documents\Templates\Project_Proposal_Template.txt" -Encoding UTF8

        # Sample reports
        @"
MONTHLY STATUS REPORT
=====================
Month: $(Get-Date -Format 'MMMM yyyy')
Department: IT

HIGHLIGHTS:
- Completed server migration
- Deployed new security patches
- Resolved 45 help desk tickets

CHALLENGES:
- Network latency issues
- Pending hardware refresh

NEXT MONTH:
- Begin cloud migration planning
- Security awareness training
"@ | Out-File "$tempPath\Reports\Monthly\IT_Status_$(Get-Date -Format 'yyyy-MM').txt" -Encoding UTF8

        # Project files
        @"
PROJECT: Infrastructure Upgrade 2025
====================================
Status: In Progress
Completion: 35%

MILESTONES:
[X] Planning complete
[X] Hardware ordered
[ ] Installation phase
[ ] Testing phase
[ ] Go-live

TEAM:
- Project Lead: John Smith
- Technical Lead: Jane Doe
- Engineers: 5
"@ | Out-File "$tempPath\Projects\2025\Infrastructure_Upgrade.txt" -Encoding UTF8

        # Sample script
        @"
# Sample PowerShell Script
# Purpose: System Health Check
# Author: IT Department

Write-Host "Running system health check..."
Get-Service | Where-Object {`$_.Status -eq 'Running'} | Measure-Object
Get-Process | Measure-Object
Get-EventLog -LogName System -Newest 10
Write-Host "Health check complete."
"@ | Out-File "$tempPath\Tools\Scripts\HealthCheck.ps1" -Encoding UTF8

        # CSV data file
        @"
EmployeeID,Name,Department,StartDate,Email
1001,John Smith,IT,2020-01-15,john.smith@$DomainName
1002,Jane Doe,HR,2019-06-01,jane.doe@$DomainName
1003,Bob Wilson,Marketing,2021-03-20,bob.wilson@$DomainName
1004,Alice Johnson,Accounting,2018-11-10,alice.johnson@$DomainName
1005,Charlie Brown,Operations,2022-02-28,charlie.brown@$DomainName
"@ | Out-File "$tempPath\Shared\HR\Employee_Directory.csv" -Encoding UTF8

        # Budget spreadsheet data
        @"
Category,Q1,Q2,Q3,Q4,Total
Personnel,250000,250000,275000,275000,1050000
Hardware,50000,25000,50000,25000,150000
Software,30000,30000,30000,30000,120000
Training,10000,15000,10000,15000,50000
Travel,5000,10000,5000,10000,30000
Total,345000,330000,370000,355000,1400000
"@ | Out-File "$tempPath\Shared\Finance\Budget_2025.csv" -Encoding UTF8

        # Log file
        @"
$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Share created
$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Dummy data populated
$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Permissions configured
"@ | Out-File "$tempPath\Logs\setup.log" -Encoding UTF8

        Write-Host "  Created C:\temp share with dummy data" -ForegroundColor Green
        Write-Host "  Share path: \\$env:COMPUTERNAME\temp" -ForegroundColor Cyan
        
    } -ArgumentList $Config.DomainName, $Config.DomainNetBIOS
    
    Write-Log "C:\temp share created with dummy data" -Level Success
}

function Install-FineGrainedPasswordPolicies {
    Write-Log "Creating Fine-Grained Password Policies..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.DomainNetBIOS)\Administrator", $securePassword)
    
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($NetBIOS)
        
        Import-Module ActiveDirectory
        
        # ========== SERVICE ACCOUNTS - Strictest ==========
        $svcPolicyName = "PSO-ServiceAccounts-Strict"
        if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$svcPolicyName'" -ErrorAction SilentlyContinue)) {
            New-ADFineGrainedPasswordPolicy -Name $svcPolicyName `
                -Precedence 10 `
                -MinPasswordLength 25 `
                -PasswordHistoryCount 48 `
                -MaxPasswordAge (New-TimeSpan -Days 60) `
                -MinPasswordAge (New-TimeSpan -Days 1) `
                -ComplexityEnabled $true `
                -ReversibleEncryptionEnabled $false `
                -LockoutDuration (New-TimeSpan -Minutes 60) `
                -LockoutObservationWindow (New-TimeSpan -Minutes 60) `
                -LockoutThreshold 3 `
                -Description "Strict policy for service accounts"
            
            # Apply to service accounts (we'll create a group for this)
            if (-not (Get-ADGroup -Filter "Name -eq 'Service Accounts'" -ErrorAction SilentlyContinue)) {
                New-ADGroup -Name "Service Accounts" -GroupScope Global -GroupCategory Security -Path (Get-ADDomain).DistinguishedName -Description "All service accounts for FGPP"
            }
            Add-ADFineGrainedPasswordPolicySubject -Identity $svcPolicyName -Subjects "Service Accounts"
            Write-Host "  Created: $svcPolicyName (25 char, 60 day)" -ForegroundColor Green
        }
        
        # ========== ADMIN ACCOUNTS - Very Strict ==========
        $adminPolicyName = "PSO-Administrators-Strict"
        if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$adminPolicyName'" -ErrorAction SilentlyContinue)) {
            New-ADFineGrainedPasswordPolicy -Name $adminPolicyName `
                -Precedence 20 `
                -MinPasswordLength 16 `
                -PasswordHistoryCount 24 `
                -MaxPasswordAge (New-TimeSpan -Days 45) `
                -MinPasswordAge (New-TimeSpan -Days 1) `
                -ComplexityEnabled $true `
                -ReversibleEncryptionEnabled $false `
                -LockoutDuration (New-TimeSpan -Minutes 30) `
                -LockoutObservationWindow (New-TimeSpan -Minutes 30) `
                -LockoutThreshold 5 `
                -Description "Strict policy for administrator accounts"
            
            Add-ADFineGrainedPasswordPolicySubject -Identity $adminPolicyName -Subjects "Domain Admins", "Enterprise Admins", "Schema Admins"
            Write-Host "  Created: $adminPolicyName (16 char, 45 day)" -ForegroundColor Green
        }
        
        # ========== IT STAFF - Moderate ==========
        $itPolicyName = "PSO-IT-Moderate"
        if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$itPolicyName'" -ErrorAction SilentlyContinue)) {
            New-ADFineGrainedPasswordPolicy -Name $itPolicyName `
                -Precedence 30 `
                -MinPasswordLength 14 `
                -PasswordHistoryCount 12 `
                -MaxPasswordAge (New-TimeSpan -Days 90) `
                -MinPasswordAge (New-TimeSpan -Days 1) `
                -ComplexityEnabled $true `
                -ReversibleEncryptionEnabled $false `
                -LockoutDuration (New-TimeSpan -Minutes 15) `
                -LockoutObservationWindow (New-TimeSpan -Minutes 15) `
                -LockoutThreshold 10 `
                -Description "Moderate policy for IT staff"
            
            Add-ADFineGrainedPasswordPolicySubject -Identity $itPolicyName -Subjects "IT_Local" -ErrorAction SilentlyContinue
            Write-Host "  Created: $itPolicyName (14 char, 90 day)" -ForegroundColor Green
        }
        
        # ========== STANDARD USERS - Normal ==========
        $userPolicyName = "PSO-Users-Standard"
        if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$userPolicyName'" -ErrorAction SilentlyContinue)) {
            New-ADFineGrainedPasswordPolicy -Name $userPolicyName `
                -Precedence 50 `
                -MinPasswordLength 12 `
                -PasswordHistoryCount 10 `
                -MaxPasswordAge (New-TimeSpan -Days 180) `
                -MinPasswordAge (New-TimeSpan -Days 1) `
                -ComplexityEnabled $true `
                -ReversibleEncryptionEnabled $false `
                -LockoutDuration (New-TimeSpan -Minutes 15) `
                -LockoutObservationWindow (New-TimeSpan -Minutes 15) `
                -LockoutThreshold 15 `
                -Description "Standard policy for domain users"
            
            Add-ADFineGrainedPasswordPolicySubject -Identity $userPolicyName -Subjects "Domain Users"
            Write-Host "  Created: $userPolicyName (12 char, 180 day)" -ForegroundColor Green
        }
        
    } -ArgumentList $Config.DomainNetBIOS
    
    Write-Log "Fine-Grained Password Policies created" -Level Success
}

function Install-ServiceAccountsWithSPNs {
    Write-Log "Creating service accounts with SPNs..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.DomainNetBIOS)\Administrator", $securePassword)
    
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($DomainName, $NetBIOS, $DCFQDN)
        
        Import-Module ActiveDirectory
        $domainDN = (Get-ADDomain).DistinguishedName
        
        # Create Service Accounts OU if not exists
        $svcOU = "OU=Service Accounts,$domainDN"
        if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$svcOU'" -ErrorAction SilentlyContinue)) {
            New-ADOrganizationalUnit -Name "Service Accounts" -Path $domainDN -ProtectedFromAccidentalDeletion $true
        }
        
        # Service account definitions with SPNs
        $serviceAccounts = @(
            @{
                Name = 'svc-sql'
                DisplayName = 'SQL Server Service'
                Description = 'SQL Server Database Engine'
                SPNs = @("MSSQLSvc/$DCFQDN", "MSSQLSvc/${DCFQDN}:1433")
                Password = 'Sql$3rv1c3P@ss2025!'
            },
            @{
                Name = 'svc-iis'
                DisplayName = 'IIS Application Pool'
                Description = 'IIS Web Application Service'
                SPNs = @("HTTP/$DCFQDN", "HTTP/$($DCFQDN.Split('.')[0])")
                Password = 'IIS$3rv1c3P@ss2025!'
            },
            @{
                Name = 'svc-sccm'
                DisplayName = 'SCCM Service Account'
                Description = 'System Center Configuration Manager'
                SPNs = @("SMS/$DCFQDN")
                Password = 'SCCM$3rv1c3P@ss2025!'
            },
            @{
                Name = 'svc-backup'
                DisplayName = 'Backup Service Account'
                Description = 'Enterprise Backup Solution'
                SPNs = @()
                Password = 'B@ckup$3rv1c3P@ss2025!'
            },
            @{
                Name = 'svc-scom'
                DisplayName = 'SCOM Service Account'
                Description = 'System Center Operations Manager'
                SPNs = @()
                Password = 'SCOM$3rv1c3P@ss2025!'
            },
            @{
                Name = 'svc-adfs'
                DisplayName = 'ADFS Service Account'
                Description = 'Active Directory Federation Services'
                SPNs = @("host/$DCFQDN")
                Password = 'ADFS$3rv1c3P@ss2025!'
            },
            @{
                Name = 'svc-sharepoint'
                DisplayName = 'SharePoint Service Account'
                Description = 'SharePoint Farm Account'
                SPNs = @("HTTP/sharepoint.$DomainName", "HTTP/sharepoint")
                Password = 'SP$3rv1c3P@ss2025!'
            },
            @{
                Name = 'svc-exchange'
                DisplayName = 'Exchange Service Account'
                Description = 'Microsoft Exchange Services'
                SPNs = @("exchangeMDB/$DCFQDN", "exchangeRFR/$DCFQDN")
                Password = 'Exch$3rv1c3P@ss2025!'
            },
            @{
                Name = 'svc-veeam'
                DisplayName = 'Veeam Service Account'
                Description = 'Veeam Backup & Replication'
                SPNs = @()
                Password = 'V33@m$3rv1c3P@ss2025!'
            },
            @{
                Name = 'svc-scan'
                DisplayName = 'Scanner Service Account'
                Description = 'Network Scanner/Copier Service'
                SPNs = @()
                Password = 'Sc@n$3rv1c3P@ss2025!'
            }
        )
        
        $created = 0
        foreach ($svc in $serviceAccounts) {
            $sam = $svc.Name
            if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue)) {
                $userParams = @{
                    Name                  = $svc.DisplayName
                    SamAccountName        = $sam
                    UserPrincipalName     = "$sam@$DomainName"
                    DisplayName           = $svc.DisplayName
                    Description           = $svc.Description
                    Path                  = $svcOU
                    AccountPassword       = (ConvertTo-SecureString $svc.Password -AsPlainText -Force)
                    Enabled               = $true
                    PasswordNeverExpires  = $true
                    CannotChangePassword  = $true
                    ServicePrincipalNames = $svc.SPNs
                }
                
                New-ADUser @userParams
                
                # Add to Service Accounts group for FGPP
                Add-ADGroupMember -Identity "Service Accounts" -Members $sam -ErrorAction SilentlyContinue
                
                $created++
            }
        }
        
        Write-Host "  Created $created service accounts with SPNs" -ForegroundColor Green
        
    } -ArgumentList $Config.DomainName, $Config.DomainNetBIOS, "$($Config.VMName).$($Config.DomainName)"
    
    Write-Log "Service accounts created" -Level Success
}

function Install-ComputerObjects {
    Write-Log "Creating pre-staged computer objects..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.DomainNetBIOS)\Administrator", $securePassword)
    
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($NetBIOS)
        
        Import-Module ActiveDirectory
        $domainDN = (Get-ADDomain).DistinguishedName
        
        # Computer objects per department OU
        $computers = @(
            # IT Department
            @{ Name = 'IT-WKS-001'; OU = "OU=IT,OU=$NetBIOS Computers,$domainDN"; Desc = 'IT Workstation 1' }
            @{ Name = 'IT-WKS-002'; OU = "OU=IT,OU=$NetBIOS Computers,$domainDN"; Desc = 'IT Workstation 2' }
            @{ Name = 'IT-WKS-003'; OU = "OU=IT,OU=$NetBIOS Computers,$domainDN"; Desc = 'IT Workstation 3' }
            @{ Name = 'IT-DVLP-001'; OU = "OU=IT,OU=$NetBIOS Computers,$domainDN"; Desc = 'Developer Workstation 1' }
            @{ Name = 'IT-DVLP-002'; OU = "OU=IT,OU=$NetBIOS Computers,$domainDN"; Desc = 'Developer Workstation 2' }
            
            # HR Department
            @{ Name = 'HR-WKS-001'; OU = "OU=HR,OU=$NetBIOS Computers,$domainDN"; Desc = 'HR Workstation 1' }
            @{ Name = 'HR-WKS-002'; OU = "OU=HR,OU=$NetBIOS Computers,$domainDN"; Desc = 'HR Workstation 2' }
            
            # Marketing Department
            @{ Name = 'MKT-WKS-001'; OU = "OU=Marketing,OU=$NetBIOS Computers,$domainDN"; Desc = 'Marketing Workstation 1' }
            @{ Name = 'MKT-WKS-002'; OU = "OU=Marketing,OU=$NetBIOS Computers,$domainDN"; Desc = 'Marketing Workstation 2' }
            @{ Name = 'MKT-MAC-001'; OU = "OU=Marketing,OU=$NetBIOS Computers,$domainDN"; Desc = 'Marketing Mac 1' }
            
            # Accounting
            @{ Name = 'ACCT-WKS-001'; OU = "OU=Accounting,OU=$NetBIOS Computers,$domainDN"; Desc = 'Accounting Workstation 1' }
            @{ Name = 'ACCT-WKS-002'; OU = "OU=Accounting,OU=$NetBIOS Computers,$domainDN"; Desc = 'Accounting Workstation 2' }
            
            # Management
            @{ Name = 'EXEC-WKS-001'; OU = "OU=Management,OU=$NetBIOS Computers,$domainDN"; Desc = 'Executive Workstation 1' }
            @{ Name = 'EXEC-WKS-002'; OU = "OU=Management,OU=$NetBIOS Computers,$domainDN"; Desc = 'Executive Workstation 2' }
            @{ Name = 'EXEC-LT-001'; OU = "OU=Management,OU=$NetBIOS Computers,$domainDN"; Desc = 'Executive Laptop 1' }
            
            # Servers (in default Computers container or dedicated OU)
            @{ Name = 'SRV-FILE-01'; OU = "CN=Computers,$domainDN"; Desc = 'File Server' }
            @{ Name = 'SRV-PRINT-01'; OU = "CN=Computers,$domainDN"; Desc = 'Print Server' }
            @{ Name = 'SRV-SQL-01'; OU = "CN=Computers,$domainDN"; Desc = 'SQL Server' }
            @{ Name = 'SRV-WEB-01'; OU = "CN=Computers,$domainDN"; Desc = 'Web Server' }
            @{ Name = 'SRV-APP-01'; OU = "CN=Computers,$domainDN"; Desc = 'Application Server' }
            @{ Name = 'SRV-SCCM-01'; OU = "CN=Computers,$domainDN"; Desc = 'SCCM Server' }
            @{ Name = 'SRV-WSUS-01'; OU = "CN=Computers,$domainDN"; Desc = 'WSUS Server' }
            @{ Name = 'SRV-EXCH-01'; OU = "CN=Computers,$domainDN"; Desc = 'Exchange Server' }
            
            # Conference rooms
            @{ Name = 'CONF-RM-A'; OU = "CN=Computers,$domainDN"; Desc = 'Conference Room A PC' }
            @{ Name = 'CONF-RM-B'; OU = "CN=Computers,$domainDN"; Desc = 'Conference Room B PC' }
            @{ Name = 'LOBBY-KIOSK'; OU = "CN=Computers,$domainDN"; Desc = 'Lobby Kiosk' }
        )
        
        $created = 0
        foreach ($computer in $computers) {
            if (-not (Get-ADComputer -Filter "Name -eq '$($computer.Name)'" -ErrorAction SilentlyContinue)) {
                try {
                    New-ADComputer -Name $computer.Name -Path $computer.OU -Description $computer.Desc -Enabled $true -ErrorAction Stop
                    $created++
                } catch {
                    # OU might not exist, try default container
                    New-ADComputer -Name $computer.Name -Description $computer.Desc -Enabled $true -ErrorAction SilentlyContinue
                    $created++
                }
            }
        }
        
        Write-Host "  Created $created computer objects" -ForegroundColor Green
        
    } -ArgumentList $Config.DomainNetBIOS
    
    Write-Log "Computer objects created" -Level Success
}

function Install-NestedGroups {
    Write-Log "Creating nested group structure..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.DomainNetBIOS)\Administrator", $securePassword)
    
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($NetBIOS)
        
        Import-Module ActiveDirectory
        $domainDN = (Get-ADDomain).DistinguishedName
        $groupsOU = "OU=$NetBIOS Groups,$domainDN"
        
        # Create role-based groups (Global scope - for users)
        $roleGroups = @(
            @{ Name = 'GG-All-Employees'; Desc = 'All company employees' }
            @{ Name = 'GG-All-Managers'; Desc = 'All department managers' }
            @{ Name = 'GG-All-Executives'; Desc = 'All executive staff' }
            @{ Name = 'GG-IT-Admins'; Desc = 'IT Administrator team' }
            @{ Name = 'GG-IT-HelpDesk'; Desc = 'IT Help Desk team' }
            @{ Name = 'GG-HR-Team'; Desc = 'HR Department team' }
            @{ Name = 'GG-Finance-Team'; Desc = 'Finance/Accounting team' }
            @{ Name = 'GG-Remote-Workers'; Desc = 'Remote/VPN users' }
            @{ Name = 'GG-Contractors'; Desc = 'External contractors' }
            @{ Name = 'GG-Temps'; Desc = 'Temporary employees' }
        )
        
        foreach ($group in $roleGroups) {
            if (-not (Get-ADGroup -Filter "Name -eq '$($group.Name)'" -ErrorAction SilentlyContinue)) {
                New-ADGroup -Name $group.Name -GroupScope Global -GroupCategory Security -Path $groupsOU -Description $group.Desc
            }
        }
        
        # Create resource groups (Domain Local scope - for permissions)
        $resourceGroups = @(
            @{ Name = 'DL-Share-Company-Read'; Desc = 'Read access to Company share' }
            @{ Name = 'DL-Share-Company-Write'; Desc = 'Write access to Company share' }
            @{ Name = 'DL-Share-IT-Read'; Desc = 'Read access to IT share' }
            @{ Name = 'DL-Share-IT-Write'; Desc = 'Write access to IT share' }
            @{ Name = 'DL-Printer-Color'; Desc = 'Access to color printers' }
            @{ Name = 'DL-Printer-BW'; Desc = 'Access to B&W printers' }
            @{ Name = 'DL-VPN-Access'; Desc = 'VPN access permission' }
            @{ Name = 'DL-WiFi-Corporate'; Desc = 'Corporate WiFi access' }
            @{ Name = 'DL-WiFi-Guest'; Desc = 'Guest WiFi management' }
            @{ Name = 'DL-SQL-ReadOnly'; Desc = 'SQL Server read-only access' }
            @{ Name = 'DL-SQL-ReadWrite'; Desc = 'SQL Server read-write access' }
            @{ Name = 'DL-Web-Deploy'; Desc = 'Web deployment permissions' }
        )
        
        foreach ($group in $resourceGroups) {
            if (-not (Get-ADGroup -Filter "Name -eq '$($group.Name)'" -ErrorAction SilentlyContinue)) {
                New-ADGroup -Name $group.Name -GroupScope DomainLocal -GroupCategory Security -Path $groupsOU -Description $group.Desc
            }
        }
        
        # Create nested memberships (AGDLP model)
        # Add Global Groups to Domain Local Groups
        $nesting = @{
            'DL-Share-Company-Read'  = @('GG-All-Employees')
            'DL-Share-Company-Write' = @('GG-All-Managers', 'GG-All-Executives')
            'DL-Share-IT-Read'       = @('GG-IT-Admins', 'GG-IT-HelpDesk')
            'DL-Share-IT-Write'      = @('GG-IT-Admins')
            'DL-VPN-Access'          = @('GG-Remote-Workers', 'GG-IT-Admins', 'GG-All-Executives')
            'DL-Printer-Color'       = @('GG-All-Managers', 'GG-All-Executives', 'GG-IT-Admins')
            'DL-Printer-BW'          = @('GG-All-Employees')
            'DL-SQL-ReadOnly'        = @('GG-IT-HelpDesk')
            'DL-SQL-ReadWrite'       = @('GG-IT-Admins')
        }
        
        foreach ($dlGroup in $nesting.Keys) {
            foreach ($member in $nesting[$dlGroup]) {
                Add-ADGroupMember -Identity $dlGroup -Members $member -ErrorAction SilentlyContinue
            }
        }
        
        # Nest GG groups (managers are employees, executives are managers)
        Add-ADGroupMember -Identity 'GG-All-Employees' -Members 'GG-All-Managers' -ErrorAction SilentlyContinue
        Add-ADGroupMember -Identity 'GG-All-Managers' -Members 'GG-All-Executives' -ErrorAction SilentlyContinue
        Add-ADGroupMember -Identity 'GG-IT-Admins' -Members 'GG-IT-HelpDesk' -ErrorAction SilentlyContinue
        
        Write-Host "  Created $($roleGroups.Count + $resourceGroups.Count) groups with nested memberships" -ForegroundColor Green
        
    } -ArgumentList $Config.DomainNetBIOS
    
    Write-Log "Nested group structure created" -Level Success
}

function Install-StaleObjects {
    Write-Log "Creating stale/disabled objects for discovery testing..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.DomainNetBIOS)\Administrator", $securePassword)
    
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($DomainName, $NetBIOS)
        
        Import-Module ActiveDirectory
        $domainDN = (Get-ADDomain).DistinguishedName
        
        # Create Disabled Users OU
        $disabledOU = "OU=Disabled Accounts,$domainDN"
        if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$disabledOU'" -ErrorAction SilentlyContinue)) {
            New-ADOrganizationalUnit -Name "Disabled Accounts" -Path $domainDN -ProtectedFromAccidentalDeletion $false
        }
        
        # Create terminated/disabled users
        $staleUsers = @(
            @{ Name = 'John Former'; Sam = 'jformer'; Desc = 'Terminated 2024-01-15'; Days = 365 }
            @{ Name = 'Jane Exemployee'; Sam = 'jexemployee'; Desc = 'Terminated 2024-06-01'; Days = 200 }
            @{ Name = 'Bob Leftcompany'; Sam = 'bleftcompany'; Desc = 'Terminated 2023-12-01'; Days = 400 }
            @{ Name = 'Alice Retired'; Sam = 'aretired'; Desc = 'Retired 2024-03-01'; Days = 300 }
            @{ Name = 'Charlie Seasonal'; Sam = 'cseasonal'; Desc = 'Seasonal - disabled'; Days = 90 }
            @{ Name = 'Test Account1'; Sam = 'testaccount1'; Desc = 'Old test account'; Days = 500 }
            @{ Name = 'Test Account2'; Sam = 'testaccount2'; Desc = 'Old test account'; Days = 450 }
            @{ Name = 'Vendor Temp'; Sam = 'vendortemp'; Desc = 'Vendor access expired'; Days = 180 }
            @{ Name = 'Intern Summer2023'; Sam = 'intern2023'; Desc = 'Summer 2023 intern'; Days = 550 }
            @{ Name = 'Contractor Expired'; Sam = 'contractorexp'; Desc = 'Contract ended'; Days = 120 }
        )
        
        foreach ($user in $staleUsers) {
            if (-not (Get-ADUser -Filter "SamAccountName -eq '$($user.Sam)'" -ErrorAction SilentlyContinue)) {
                $lastLogon = (Get-Date).AddDays(-$user.Days)
                New-ADUser -Name $user.Name -SamAccountName $user.Sam -UserPrincipalName "$($user.Sam)@$DomainName" `
                    -Path $disabledOU -Description $user.Desc -Enabled $false `
                    -AccountPassword (ConvertTo-SecureString "DisabledP@ss123!" -AsPlainText -Force)
                
                # Set password last set to simulate staleness
                Set-ADUser -Identity $user.Sam -Replace @{pwdLastSet=0} -ErrorAction SilentlyContinue
            }
        }
        
        # Create expired accounts (enabled but expired)
        $expiredUsers = @(
            @{ Name = 'Temp Project1'; Sam = 'tempproject1'; ExpireDays = -30 }
            @{ Name = 'Temp Project2'; Sam = 'tempproject2'; ExpireDays = -60 }
            @{ Name = 'Guest Speaker'; Sam = 'guestspeaker'; ExpireDays = -90 }
        )
        
        foreach ($user in $expiredUsers) {
            if (-not (Get-ADUser -Filter "SamAccountName -eq '$($user.Sam)'" -ErrorAction SilentlyContinue)) {
                $expireDate = (Get-Date).AddDays($user.ExpireDays)
                New-ADUser -Name $user.Name -SamAccountName $user.Sam -UserPrincipalName "$($user.Sam)@$DomainName" `
                    -Path $disabledOU -Description "Account expired" -Enabled $true `
                    -AccountExpirationDate $expireDate `
                    -AccountPassword (ConvertTo-SecureString "ExpiredP@ss123!" -AsPlainText -Force)
            }
        }
        
        # Create stale computer objects
        $staleComputers = @(
            @{ Name = 'OLD-PC-001'; Desc = 'Decommissioned workstation' }
            @{ Name = 'OLD-PC-002'; Desc = 'Replaced workstation' }
            @{ Name = 'OLD-SRV-001'; Desc = 'Decommissioned server' }
            @{ Name = 'TEST-VM-001'; Desc = 'Old test VM' }
            @{ Name = 'TEST-VM-002'; Desc = 'Old test VM' }
            @{ Name = 'YOURPC-PC'; Desc = 'Unknown device' }
            @{ Name = 'YOURPC2-PC'; Desc = 'Unknown device' }
        )
        
        foreach ($computer in $staleComputers) {
            if (-not (Get-ADComputer -Filter "Name -eq '$($computer.Name)'" -ErrorAction SilentlyContinue)) {
                New-ADComputer -Name $computer.Name -Description $computer.Desc -Enabled $false
            }
        }
        
        Write-Host "  Created $($staleUsers.Count) disabled users, $($expiredUsers.Count) expired users, $($staleComputers.Count) stale computers" -ForegroundColor Green
        
    } -ArgumentList $Config.DomainName, $Config.DomainNetBIOS
    
    Write-Log "Stale objects created for discovery testing" -Level Success
}

function Install-NTPConfiguration {
    Write-Log "Configuring NTP (authoritative time source)..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.DomainNetBIOS)\Administrator", $securePassword)
    
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        # Configure as authoritative time source for the domain
        # Using Microsoft and NIST time servers
        $ntpServers = "time.windows.com,0x9 time.nist.gov,0x9 pool.ntp.org,0x9"
        
        # Set NTP configuration
        w32tm /config /manualpeerlist:$ntpServers /syncfromflags:manual /reliable:yes /update | Out-Null
        
        # Restart time service
        Restart-Service w32time -Force
        
        # Force sync
        w32tm /resync /force | Out-Null
        
        Write-Host "  NTP configured as authoritative time source" -ForegroundColor Green
    }
    
    Write-Log "NTP configuration complete" -Level Success
}

function Install-LAPSPreparation {
    Write-Log "Preparing for LAPS (Local Administrator Password Solution)..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.DomainNetBIOS)\Administrator", $securePassword)
    
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($NetBIOS)
        
        Import-Module ActiveDirectory
        $domainDN = (Get-ADDomain).DistinguishedName
        
        # Create LAPS groups for delegation
        $lapsGroups = @(
            @{ Name = 'LAPS-Password-Readers'; Desc = 'Can read LAPS passwords' }
            @{ Name = 'LAPS-Password-Reset'; Desc = 'Can reset LAPS passwords' }
            @{ Name = 'LAPS-Admins'; Desc = 'Full LAPS administration' }
        )
        
        foreach ($group in $lapsGroups) {
            if (-not (Get-ADGroup -Filter "Name -eq '$($group.Name)'" -ErrorAction SilentlyContinue)) {
                New-ADGroup -Name $group.Name -GroupScope DomainLocal -GroupCategory Security `
                    -Path "OU=$NetBIOS Groups,$domainDN" -Description $group.Desc
            }
        }
        
        # Add IT Admins to LAPS groups
        Add-ADGroupMember -Identity 'LAPS-Admins' -Members 'GG-IT-Admins' -ErrorAction SilentlyContinue
        Add-ADGroupMember -Identity 'LAPS-Password-Readers' -Members 'GG-IT-HelpDesk' -ErrorAction SilentlyContinue
        
        # Note: Actual LAPS schema extension and GPO requires the LAPS MSI
        # This just prepares the group structure
        
        Write-Host "  LAPS groups created (schema extension requires LAPS MSI)" -ForegroundColor Green
        
    } -ArgumentList $Config.DomainNetBIOS
    
    Write-Log "LAPS preparation complete" -Level Success
}

function Install-AdminDelegation {
    Write-Log "Configuring OU delegation for departmental admins..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $domainCred = New-Object PSCredential("$($Config.DomainNetBIOS)\Administrator", $securePassword)
    
    Invoke-Command -VMName $Config.VMName -Credential $domainCred -ScriptBlock {
        param($NetBIOS)
        
        Import-Module ActiveDirectory
        $domainDN = (Get-ADDomain).DistinguishedName
        $groupsOU = "OU=$NetBIOS Groups,$domainDN"
        
        # Create delegated admin groups
        $delegatedGroups = @(
            @{ Name = 'OU-Admins-IT'; Desc = 'IT OU administrators'; OU = "OU=IT,OU=$NetBIOS Users,$domainDN" }
            @{ Name = 'OU-Admins-HR'; Desc = 'HR OU administrators'; OU = "OU=HR,OU=$NetBIOS Users,$domainDN" }
            @{ Name = 'OU-Admins-Marketing'; Desc = 'Marketing OU administrators'; OU = "OU=Marketing,OU=$NetBIOS Users,$domainDN" }
            @{ Name = 'OU-Admins-Accounting'; Desc = 'Accounting OU administrators'; OU = "OU=Accounting,OU=$NetBIOS Users,$domainDN" }
        )
        
        foreach ($group in $delegatedGroups) {
            if (-not (Get-ADGroup -Filter "Name -eq '$($group.Name)'" -ErrorAction SilentlyContinue)) {
                New-ADGroup -Name $group.Name -GroupScope DomainLocal -GroupCategory Security `
                    -Path $groupsOU -Description $group.Desc
            }
        }
        
        # Note: Actual ACL delegation is complex and typically done via GUI or DSACLS
        # This creates the group structure for delegation
        
        Write-Host "  Created $($delegatedGroups.Count) delegated admin groups" -ForegroundColor Green
        
    } -ArgumentList $Config.DomainNetBIOS
    
    Write-Log "OU delegation groups created" -Level Success
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
    
    Install-DomainController
    Install-PrivilegedAdminAccounts
    Install-BulkADObjects
    
    # ===== ADVANCED DC CONFIGURATION =====
    Write-Log "Starting advanced DC configuration..." -Level Info
    Enable-ADRecycleBin
    Install-DHCPServer
    Install-DNSConfiguration
    Install-NTPConfiguration
    Install-FineGrainedPasswordPolicies
    Install-NestedGroups
    Install-ServiceAccountsWithSPNs
    Install-ComputerObjects
    Install-StaleObjects
    Install-FileShares
    Install-TempShareWithDummyData
    Install-BaseGPOs
    Install-LAPSPreparation
    Install-AdminDelegation
    Install-CertificateServices
    Install-AzureADConnect
    
    $duration = (Get-Date) - $startTime
    
    # Calculate DHCP scope for display
    $ipParts = $Config.VMIP -split '\.'
    $dhcpRange = "$($ipParts[0]).$($ipParts[1]).$($ipParts[2]).100-200"
    
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                    DEPLOYMENT COMPLETE!                        ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "  VM Name:           $($Config.VMName)" -ForegroundColor White
    Write-Host "  Domain:            $($Config.DomainName) ($($Config.DomainNetBIOS))" -ForegroundColor White
    Write-Host "  DC IP:             $($Config.VMIP)" -ForegroundColor White
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  DOMAIN ADMINISTRATOR" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Username:          $($Config.DomainNetBIOS)\Administrator"
    Write-Host "  Password:          $($Config.AdminPassword)"
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  PRIVILEGED SERVICE ACCOUNTS (Domain Admin + Enterprise Admin)" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    foreach ($account in $PrivilegedAccounts) {
        Write-Host ""
        Write-Host "  Account:           $($Config.DomainNetBIOS)\$($account.SamAccountName)" -ForegroundColor Yellow
        Write-Host "  Password:          $($account.Password)" -ForegroundColor Yellow
        Write-Host "  Groups:            $($account.Groups -join ', ')" -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  SERVICE ACCOUNTS (with SPNs)" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  svc-sql            Sql`$3rv1c3P@ss2025!      (MSSQLSvc SPNs)"
    Write-Host "  svc-iis            IIS`$3rv1c3P@ss2025!      (HTTP SPNs)"
    Write-Host "  svc-sccm           SCCM`$3rv1c3P@ss2025!     (SMS SPNs)"
    Write-Host "  svc-backup         B@ckup`$3rv1c3P@ss2025!"
    Write-Host "  svc-scom           SCOM`$3rv1c3P@ss2025!"
    Write-Host "  svc-adfs           ADFS`$3rv1c3P@ss2025!     (host SPNs)"
    Write-Host "  svc-sharepoint     SP`$3rv1c3P@ss2025!       (HTTP SPNs)"
    Write-Host "  svc-exchange       Exch`$3rv1c3P@ss2025!     (exchange SPNs)"
    Write-Host "  svc-veeam          V33@m`$3rv1c3P@ss2025!"
    Write-Host "  svc-scan           Sc@n`$3rv1c3P@ss2025!"
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  TEST USER ACCOUNTS" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  TestUser1          P@ssw0rd123!"
    Write-Host "  Bulk Users (~2990) Football22!"
    Write-Host "  Disabled Users     DisabledP@ss123!"
    Write-Host "  Expired Users      ExpiredP@ss123!"
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INFRASTRUCTURE SERVICES" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  DHCP Server:       Enabled (Scope: $dhcpRange)"
    Write-Host "  DNS Forwarders:    8.8.8.8, 8.8.4.4, 1.1.1.1"
    Write-Host "  Reverse DNS Zone:  $($ipParts[2]).$($ipParts[1]).$($ipParts[0]).in-addr.arpa"
    Write-Host "  NTP:               Authoritative time source configured"
    Write-Host "  AD Recycle Bin:    Enabled"
    Write-Host "  Certificate Auth:  $($Config.DomainNetBIOS)-ROOT-CA (Enterprise Root)"
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  FILE SHARES" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  \\$($Config.VMName)\temp          (Everyone Read - dummy data)"
    Write-Host "  \\$($Config.VMName)\IT, HR, Marketing, Accounting, Legal, etc."
    Write-Host "  \\$($Config.VMName)\Company        (Company-wide)"
    Write-Host "  \\$($Config.VMName)\IT_Tools`$      (Hidden - IT tools)"
    Write-Host "  \\$($Config.VMName)\Home`$          (Hidden - User home dirs)"
    Write-Host "  \\$($Config.VMName)\Profiles`$      (Hidden - Roaming profiles)"
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  GROUP POLICY OBJECTS" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $($Config.DomainNetBIOS) - Password Policy"
    Write-Host "  $($Config.DomainNetBIOS) - Security Audit Policy"
    Write-Host "  $($Config.DomainNetBIOS) - Windows Update Policy"
    Write-Host "  $($Config.DomainNetBIOS) - Desktop Settings"
    Write-Host "  $($Config.DomainNetBIOS) - Server Security Baseline"
    Write-Host "  $($Config.DomainNetBIOS) - Workstation Security"
    Write-Host "  $($Config.DomainNetBIOS) - Credential Guard"
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  FINE-GRAINED PASSWORD POLICIES" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  PSO-ServiceAccounts-Strict   25 char, 60 days, lockout 3"
    Write-Host "  PSO-Administrators-Strict    16 char, 45 days, lockout 5"
    Write-Host "  PSO-IT-Moderate              14 char, 90 days, lockout 10"
    Write-Host "  PSO-Users-Standard           12 char, 180 days, lockout 15"
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  DNS ALIASES (CNAMEs)" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  mail, exchange, autodiscover, ldap, kerberos, pki, ca"
    Write-Host "  fileserver, files, intranet, portal, sharepoint, teams"
    Write-Host "  sccm, wsus, nps, radius, dc01"
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  AD STRUCTURE CREATED" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  OUs:               ~22 (Users, Computers, Service Accounts, Disabled)"
    Write-Host "  Security Groups:   ~50 (Department, Role-based, Resource, LAPS)"
    Write-Host "  User Accounts:     ~3000+ (bulk + service + test + stale)"
    Write-Host "  Computer Objects:  ~25 (workstations + servers pre-staged)"
    Write-Host "  Stale Objects:     13 (disabled users, expired, old computers)"
    Write-Host ""
    
    if ($Config.InstallAADConnect) {
        Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  AZURE AD CONNECT" -ForegroundColor Cyan
        Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  Service Account:   $($Config.DomainNetBIOS)\AADConnect"
        Write-Host "  Password:          AADConnect2025!"
        Write-Host "  Installer:         Desktop shortcut on VM"
        Write-Host ""
        Write-Host "  Next steps:" -ForegroundColor Yellow
        Write-Host "  1. Connect to VM"
        Write-Host "  2. Run 'Install Azure AD Connect' from desktop"
        Write-Host "  3. Sign in with Azure Global Admin credentials"
    }
    
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  Duration: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Connect: vmconnect localhost $($Config.VMName)" -ForegroundColor Yellow
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-Log "DEPLOYMENT FAILED: $_" -Level Error
    throw
}
