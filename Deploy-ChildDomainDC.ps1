#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Deploys a Windows Server 2022 Child Domain Controller on Hyper-V.

.DESCRIPTION
    Deploys a child domain DC that joins an existing forest. Creates corp.parentdomain.com
    as a child domain under the parent forest root.

.PARAMETER SkipPrompts
    Use default configuration without interactive prompts.

.NOTES
    Author: Lab Automation Script
    Requires: Windows 11 with Hyper-V enabled, Administrator privileges
    Prerequisites: Parent domain DC must be running and accessible
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
    Write-Host "║       HYPER-V CHILD DOMAIN CONTROLLER DEPLOYMENT               ║" -ForegroundColor Cyan
    Write-Host "║              Joins Existing Forest as Child Domain             ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # Parent Domain Configuration
    Write-Host "── Parent Domain Configuration ──" -ForegroundColor Yellow
    Write-Host "  The child domain will be created under the parent forest" -ForegroundColor DarkGray
    Write-Host ""
    
    $parentDomain = Read-Host "  Parent Domain FQDN [ljpops.com]"
    if ([string]::IsNullOrWhiteSpace($parentDomain)) { $parentDomain = "ljpops.com" }
    $parentDomain = $parentDomain.ToLower()
    
    $parentDCIP = Read-Host "  Parent DC IP Address [192.168.0.10]"
    if ([string]::IsNullOrWhiteSpace($parentDCIP)) { $parentDCIP = "192.168.0.10" }
    
    # Get Parent DC VM Name for Hyper-V direct connection (required for DNS config)
    $defaultParentVMName = "uran"
    $parentVMName = Read-Host "  Parent DC Hyper-V VM Name [$defaultParentVMName]"
    if ([string]::IsNullOrWhiteSpace($parentVMName)) { $parentVMName = $defaultParentVMName }
    
    $parentAdminPassword = Read-Host "  Parent Domain Admin Password [LabAdmin2025!]"
    if ([string]::IsNullOrWhiteSpace($parentAdminPassword)) { $parentAdminPassword = "LabAdmin2025!" }
    
    # Child Domain Configuration
    Write-Host ""
    Write-Host "── Child Domain Configuration ──" -ForegroundColor Yellow
    
    $childPrefix = Read-Host "  Child Domain Prefix [corp]"
    if ([string]::IsNullOrWhiteSpace($childPrefix)) { $childPrefix = "corp" }
    $childPrefix = $childPrefix.ToLower()
    
    $childDomain = "$childPrefix.$parentDomain"
    Write-Host "  Child Domain FQDN: $childDomain" -ForegroundColor Green
    
    $childNetBIOS = Read-Host "  Child NetBIOS Name [CORP]"
    if ([string]::IsNullOrWhiteSpace($childNetBIOS)) { $childNetBIOS = "CORP" }
    $childNetBIOS = $childNetBIOS.ToUpper()
    
    # VM Configuration
    Write-Host ""
    Write-Host "── VM Configuration ──" -ForegroundColor Yellow
    
    $vmNameDefault = "$childPrefix-dc01"
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
    Write-Host "  Must be on same network as parent DC" -ForegroundColor DarkGray
    
    $vmIP = Read-Host "  Static IP Address [192.168.0.11]"
    if ([string]::IsNullOrWhiteSpace($vmIP)) { $vmIP = "192.168.0.11" }
    
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
    
    # Bulk AD Objects
    Write-Host ""
    Write-Host "── Bulk AD Object Creation ──" -ForegroundColor Yellow
    $installBulkAD = Read-Host "  Create OUs, Groups, and Users in child domain? (Y/n) [Y]"
    if ([string]::IsNullOrWhiteSpace($installBulkAD)) { $installBulkAD = "Y" }
    $installBulkAD = $installBulkAD.ToUpper() -eq "Y"
    
    # Storage Path
    Write-Host ""
    Write-Host "── Storage Location ──" -ForegroundColor Yellow
    $vmBasePath = Read-Host "  VM Storage Path [C:\Hyper-V_VMs]"
    if ([string]::IsNullOrWhiteSpace($vmBasePath)) { $vmBasePath = "C:\Hyper-V_VMs" }
    
    # Confirmation
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  CONFIGURATION SUMMARY" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Parent Domain:     $parentDomain (DC: $parentDCIP, VM: $parentVMName)"
    Write-Host "  Child Domain:      $childDomain ($childNetBIOS)"
    Write-Host "  VM Name:           $vmName"
    Write-Host "  Specs:             ${vmMemory}GB RAM, $vmCPU vCPUs, ${vmDisk}GB Disk"
    Write-Host "  IP Address:        $vmIP/$vmPrefix (GW: $vmGateway)"
    Write-Host "  Virtual Switch:    $switchName"
    Write-Host "  Bulk AD Objects:   $(if($installBulkAD){'Yes'}else{'No'})"
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
        # Parent Domain
        ParentDomain       = $parentDomain
        ParentDCIP         = $parentDCIP
        ParentVMName       = $parentVMName
        ParentAdminPassword = $parentAdminPassword
        ParentNetBIOS      = ($parentDomain -split '\.')[0].ToUpper()
        
        # Child Domain
        ChildDomain        = $childDomain
        ChildNetBIOS       = $childNetBIOS
        ChildPrefix        = $childPrefix
        AdminPassword      = $parentAdminPassword  # Use same password for simplicity
        SafeModePassword   = $parentAdminPassword
        
        # VM Config
        VMName             = $vmName
        VMMemoryGB         = $vmMemory
        VMProcessorCount   = $vmCPU
        VHDSizeGB          = $vmDisk
        SwitchName         = $switchName
        VMIP               = $vmIP
        VMPrefix           = $vmPrefix
        VMGateway          = $vmGateway
        VMDNS              = $parentDCIP  # DNS points to parent DC initially
        VMBasePath         = $vmBasePath
        InstallBulkAD      = $installBulkAD
        
        # ISO Config
        ISOFileName        = "Windows_Server_2022_Evaluation.iso"
        ISOUrl             = "https://software-static.download.prss.microsoft.com/sg/download/888969d5-f34g-4e03-ac9d-1f9786c66749/SERVER_EVAL_x64FRE_en-us.iso"
        ExpectedSHA256     = "3E4FA6D8507B554856FC9CA6079CC402DF11A8B79344871669F0251535255325"
    }
}

function Get-DefaultConfiguration {
    return @{
        ParentDomain       = "ljpops.com"
        ParentDCIP         = "192.168.0.10"
        ParentVMName       = "uran"
        ParentAdminPassword = "LabAdmin2025!"
        ParentNetBIOS      = "LJPOPS"
        ChildDomain        = "corp.ljpops.com"
        ChildNetBIOS       = "CORP"
        ChildPrefix        = "corp"
        AdminPassword      = "LabAdmin2025!"
        SafeModePassword   = "LabAdmin2025!"
        VMName             = "corp-dc01"
        VMMemoryGB         = 4
        VMProcessorCount   = 2
        VHDSizeGB          = 60
        SwitchName         = "LabSwitch"
        VMIP               = "192.168.0.11"
        VMPrefix           = 24
        VMGateway          = "192.168.0.1"
        VMDNS              = "192.168.0.10"
        VMBasePath         = "C:\Hyper-V_VMs"
        InstallBulkAD      = $true
        ISOFileName        = "Windows_Server_2022_Evaluation.iso"
        ISOUrl             = "https://software-static.download.prss.microsoft.com/sg/download/888969d5-f34g-4e03-ac9d-1f9786c66749/SERVER_EVAL_x64FRE_en-us.iso"
        ExpectedSHA256     = "3E4FA6D8507B554856FC9CA6079CC402DF11A8B79344871669F0251535255325"
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
# PRIVILEGED ADMIN ACCOUNTS FOR CHILD DOMAIN
# ============================================

$PrivilegedAccounts = @(
    @{
        SamAccountName    = 'corp-admin'
        Name              = 'Corp Domain Admin'
        GivenName         = 'Corp'
        Surname           = 'Admin'
        DisplayName       = 'Corp Domain Administrator'
        Description       = 'Child Domain Administrator'
        Password          = 'C0rp@dm1n#2025!'
        Groups            = @('Domain Admins')
    },
    @{
        SamAccountName    = 'svc-corp-backup'
        Name              = 'Corp Backup Service'
        GivenName         = 'Corp'
        Surname           = 'Backup'
        DisplayName       = 'Corp Backup Service Account'
        Description       = 'Backup service for child domain'
        Password          = 'C0rpB@ckup#2025!'
        Groups            = @('Domain Admins', 'Backup Operators')
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
    
    # Check Hyper-V
    $hyperv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
    if ($hyperv.State -ne 'Enabled') {
        throw "Hyper-V is not enabled. Run: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All"
    }
    
    # Check VMMS service
    $vmms = Get-Service -Name vmms -ErrorAction SilentlyContinue
    if ($vmms.Status -ne 'Running') {
        Write-Log "Starting Hyper-V Virtual Machine Management service..." -Level Warning
        Start-Service vmms -ErrorAction Stop
    }
    
    # Check disk space
    $drive = (Split-Path $Config.VMBasePath -Qualifier)
    $freeGB = [math]::Round((Get-PSDrive ($drive -replace ':','')).Free / 1GB, 2)
    $requiredGB = $Config.VHDSizeGB + 10
    if ($freeGB -lt $requiredGB) {
        throw "Insufficient disk space on $drive. Required: ${requiredGB}GB, Available: ${freeGB}GB"
    }
    
    # Test parent DC connectivity
    Write-Log "Testing connectivity to parent DC ($($Config.ParentDCIP))..."
    if (-not (Test-Connection -ComputerName $Config.ParentDCIP -Count 2 -Quiet)) {
        throw "Cannot reach parent DC at $($Config.ParentDCIP). Ensure parent DC is running."
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

function Install-ChildDomainController {
    Write-Log "Configuring Child Domain Controller..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $localCred = New-Object PSCredential("Administrator", $securePassword)
    
    # Wait for VM to be ready
    Wait-VMReady -VMName $Config.VMName -Credential $localCred -TimeoutMinutes 10 -Description "Windows Setup" | Out-Null
    
    Write-Log "Stabilizing services (15s)..."
    Start-Sleep -Seconds 15
    
    # Configure network - DNS points to parent DC
    Write-Log "Configuring network (DNS: $($Config.ParentDCIP))..."
    Invoke-Command -VMName $Config.VMName -Credential $localCred -ScriptBlock {
        param($IP, $Prefix, $Gateway, $DNS)
        $adapter = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
        
        # Remove existing IP config
        Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
        Remove-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
        
        # Set new IP
        New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $IP -PrefixLength $Prefix -DefaultGateway $Gateway | Out-Null
        
        # Set DNS to ONLY the parent DC - no fallback
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @($DNS)
        
        # Flush DNS cache
        Clear-DnsClientCache
        ipconfig /flushdns | Out-Null
        
        # Disable IPv6 to prevent any IPv6 DNS issues
        Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
        
        # Verify DNS is set correctly
        $dnsServers = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4
        Write-Host "  DNS configured: $($dnsServers.ServerAddresses -join ', ')" -ForegroundColor Cyan
        
    } -ArgumentList $Config.VMIP, $Config.VMPrefix, $Config.VMGateway, $Config.ParentDCIP
    
    # Wait for DNS settings to take effect
    Start-Sleep -Seconds 10
    
    # Test DNS resolution to parent domain - MUST resolve to parent DC IP
    Write-Log "Testing DNS resolution to parent domain..."
    
    $dnsTest = Invoke-Command -VMName $Config.VMName -Credential $localCred -ScriptBlock {
        param($ParentDomain, $ParentDCIP)
        
        $results = @{
            Success = $false
            ParentDCIP = $ParentDCIP
            Diagnostics = @()
        }
        
        # Flush DNS cache again
        Clear-DnsClientCache
        ipconfig /flushdns | Out-Null
        
        # Check current DNS server configuration
        $adapter = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
        $currentDNS = (Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses
        $results.Diagnostics += "Configured DNS servers: $($currentDNS -join ', ')"
        
        # Test basic connectivity to parent DC
        $pingTest = Test-Connection -ComputerName $ParentDCIP -Count 1 -Quiet
        $results.Diagnostics += "Ping to $ParentDCIP : $(if($pingTest){'SUCCESS'}else{'FAILED'})"
        
        if (-not $pingTest) {
            $results.Error = "Cannot ping parent DC at $ParentDCIP"
            return $results
        }
        
        # Test DNS port connectivity
        $dnsPort = Test-NetConnection -ComputerName $ParentDCIP -Port 53 -WarningAction SilentlyContinue
        $results.Diagnostics += "DNS port 53 on $ParentDCIP : $(if($dnsPort.TcpTestSucceeded){'OPEN'}else{'CLOSED'})"
        
        if (-not $dnsPort.TcpTestSucceeded) {
            $results.Error = "DNS port 53 is not accessible on parent DC. Is DNS service running?"
            return $results
        }
        
        # Try to resolve the parent domain using nslookup directly to parent DC
        $nslookupResult = & nslookup $ParentDomain $ParentDCIP 2>&1
        $results.Diagnostics += "nslookup output: $($nslookupResult -join ' | ')"
        
        # Try PowerShell DNS resolution explicitly to parent DC
        try {
            $resolved = Resolve-DnsName -Name $ParentDomain -Server $ParentDCIP -Type A -DnsOnly -ErrorAction Stop
            $resolvedIP = ($resolved | Where-Object { $_.Type -eq 'A' }).IPAddress | Select-Object -First 1
            $results.Diagnostics += "Resolve-DnsName result: $resolvedIP"
            
            # CRITICAL: Verify the resolved IP is the parent DC, not a public IP
            if ($resolvedIP -eq $ParentDCIP) {
                $results.Success = $true
                $results.ResolvedIP = $resolvedIP
                $results.Message = "Correctly resolved to parent DC"
            } elseif ($resolvedIP -like "192.168.*" -or $resolvedIP -like "10.*" -or $resolvedIP -like "172.16.*") {
                # Private IP but not parent DC - might be another DC
                $results.Success = $true
                $results.ResolvedIP = $resolvedIP
                $results.Message = "Resolved to private IP (may be another DC)"
            } else {
                # Public IP - this is WRONG
                $results.Success = $false
                $results.ResolvedIP = $resolvedIP
                $results.Error = "CRITICAL: Domain resolved to PUBLIC IP $resolvedIP instead of parent DC $ParentDCIP. The parent DC DNS is not authoritative for this domain!"
            }
        } catch {
            # Try SRV record lookup
            try {
                $srvRecord = "_ldap._tcp.dc._msdcs.$ParentDomain"
                $srvResult = Resolve-DnsName -Name $srvRecord -Server $ParentDCIP -Type SRV -DnsOnly -ErrorAction Stop
                $results.Success = $true
                $results.ResolvedIP = $srvResult.NameTarget
                $results.Message = "Resolved via SRV record"
                $results.Diagnostics += "SRV record found: $($srvResult.NameTarget)"
            } catch {
                $results.Error = "Cannot resolve $ParentDomain from parent DC: $_"
            }
        }
        
        return $results
    } -ArgumentList $Config.ParentDomain, $Config.ParentDCIP
    
    # Display diagnostics
    Write-Host ""
    Write-Host "  DNS Diagnostics:" -ForegroundColor Yellow
    foreach ($diag in $dnsTest.Diagnostics) {
        Write-Host "    $diag" -ForegroundColor DarkGray
    }
    Write-Host ""
    
    if (-not $dnsTest.Success) {
        Write-Host ""
        Write-Host "  ╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "  ║  DNS RESOLUTION FAILED - PARENT DC NOT AUTHORITATIVE          ║" -ForegroundColor Red
        Write-Host "  ╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        Write-Host ""
        Write-Host "  The parent DC ($($Config.ParentDCIP)) is not responding correctly for $($Config.ParentDomain)" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Please verify on the PARENT DC (uran):" -ForegroundColor Yellow
        Write-Host "    1. DNS Service is running:" -ForegroundColor White
        Write-Host "       Get-Service DNS" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "    2. DNS zone exists:" -ForegroundColor White
        Write-Host "       Get-DnsServerZone | Select ZoneName" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "    3. A record exists for the domain:" -ForegroundColor White
        Write-Host "       Get-DnsServerResourceRecord -ZoneName $($Config.ParentDomain) -RRType A" -ForegroundColor Cyan
        Write-Host ""
        throw "DNS resolution failed: $($dnsTest.Error)"
    }
    
    Write-Log "Parent domain DNS: $($dnsTest.ResolvedIP) ($($dnsTest.Message))" -Level Success
    
    # Install AD DS
    Write-Log "Installing AD Domain Services..."
    Invoke-Command -VMName $Config.VMName -Credential $localCred -ScriptBlock {
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -IncludeAllSubFeature | Out-Null
    }
    
    # Create credential for parent domain
    $parentCred = New-Object PSCredential("$($Config.ParentNetBIOS)\Administrator", $securePassword)
    
    # Promote as Child Domain DC
    Write-Log "Promoting to Child Domain Controller for '$($Config.ChildDomain)'..."
    Write-Log "  Parent Domain: $($Config.ParentDomain)"
    Write-Log "  Child Domain: $($Config.ChildDomain)"
    
    $secureSafeMode = ConvertTo-SecureString $Config.SafeModePassword -AsPlainText -Force
    
    Invoke-Command -VMName $Config.VMName -Credential $localCred -ScriptBlock {
        param($ChildDomain, $ParentDomain, $ChildNetBIOS, $SafePwd, $ParentCredUser, $ParentCredPwd)
        
        # Create parent domain credential inside the VM
        $secPwd = ConvertTo-SecureString $ParentCredPwd -AsPlainText -Force
        $parentCred = New-Object PSCredential($ParentCredUser, $secPwd)
        
        # Install as child domain
        Install-ADDSDomain `
            -DomainType ChildDomain `
            -NewDomainName ($ChildDomain -split '\.')[0] `
            -ParentDomainName $ParentDomain `
            -NewDomainNetbiosName $ChildNetBIOS `
            -SafeModeAdministratorPassword $SafePwd `
            -Credential $parentCred `
            -InstallDns `
            -CreateDnsDelegation `
            -NoRebootOnCompletion `
            -Force `
            -WarningAction SilentlyContinue | Out-Null
            
    } -ArgumentList $Config.ChildDomain, $Config.ParentDomain, $Config.ChildNetBIOS, $secureSafeMode, "$($Config.ParentNetBIOS)\Administrator", $Config.ParentAdminPassword
    
    Write-Log "Restarting VM..."
    Restart-VM -Name $Config.VMName -Force
    Start-Sleep -Seconds 30
    
    # Wait for child DC with child domain creds
    $childDomainCred = New-Object PSCredential("$($Config.ChildNetBIOS)\Administrator", $securePassword)
    
    $dcReady = $false
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $maxWaitMinutes = 15
    
    Write-Log "Waiting for Child Domain Controller services (timeout: ${maxWaitMinutes}m)..."
    
    # Wait for VM to respond first
    $vmResponsive = $false
    while (-not $vmResponsive -and $stopwatch.Elapsed.TotalMinutes -lt 5) {
        Start-Sleep -Seconds 10
        foreach ($cred in @($childDomainCred, $localCred)) {
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
        
        foreach ($cred in @($childDomainCred, $localCred)) {
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
                    Write-Log "Child Domain Controller operational: $($result.Domain)" -Level Success
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
            Invoke-Command -VMName $Config.VMName -Credential $childDomainCred -ScriptBlock {
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
    
    # CRITICAL: Verify and create DNS zones if missing
    # Sometimes Install-ADDSDomain doesn't properly create AD-integrated DNS zones
    Write-Log "Verifying DNS zones..."
    Invoke-Command -VMName $Config.VMName -Credential $childDomainCred -ScriptBlock {
        param($ChildDomain, $SelfIP, $ParentDCIP)
        
        Import-Module DnsServer -ErrorAction SilentlyContinue
        
        # Check if primary zone exists for child domain
        $primaryZone = Get-DnsServerZone -Name $ChildDomain -ErrorAction SilentlyContinue
        if (-not $primaryZone) {
            Write-Host "  WARNING: Primary DNS zone missing - creating..." -ForegroundColor Yellow
            Add-DnsServerPrimaryZone -Name $ChildDomain -ReplicationScope Domain -DynamicUpdate Secure -ErrorAction Stop
            Write-Host "  Created primary zone: $ChildDomain" -ForegroundColor Green
        } else {
            Write-Host "  Primary zone exists: $ChildDomain" -ForegroundColor Green
        }
        
        # For child domain, _msdcs records go in parent's _msdcs zone via delegation
        # But we should have our own DomainDnsZones
        
        # Ensure DNS client points to self first, then parent
        $adapter = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @($SelfIP, $ParentDCIP)
        
        # Clear caches and force re-registration
        Clear-DnsClientCache
        Clear-DnsServerCache -Force -ErrorAction SilentlyContinue
        
        # Register DC records
        ipconfig /registerdns | Out-Null
        Start-Sleep -Seconds 5
        nltest /dsregdns 2>&1 | Out-Null
        
        # Verify zone is queryable
        Start-Sleep -Seconds 5
        $testResolve = Resolve-DnsName -Name $ChildDomain -Type A -DnsOnly -ErrorAction SilentlyContinue
        if ($testResolve) {
            Write-Host "  DNS verification: $ChildDomain resolves correctly" -ForegroundColor Green
        } else {
            Write-Host "  DNS verification: May need additional time to propagate" -ForegroundColor Yellow
        }
        
    } -ArgumentList $Config.ChildDomain, $Config.VMIP, $Config.ParentDCIP
    
    Write-Log "DNS zones verified" -Level Success
    
    # Update DNS configuration - CRITICAL for cross-domain resolution
    Write-Log "Updating DNS configuration..."
    Invoke-Command -VMName $Config.VMName -Credential $childDomainCred -ScriptBlock {
        param($ParentDCIP, $SelfIP, $ParentDomain)
        
        # Set DNS servers: self as primary, parent DC as secondary
        $adapter = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @($SelfIP, $ParentDCIP)
        
        # Add conditional forwarder for parent domain - CRITICAL
        # Without this, parent domain resolves to public IP instead of internal DC
        $existingForwarder = Get-DnsServerZone -Name $ParentDomain -ErrorAction SilentlyContinue
        if (-not $existingForwarder) {
            Add-DnsServerConditionalForwarderZone -Name $ParentDomain -MasterServers $ParentDCIP -ReplicationScope Forest -ErrorAction SilentlyContinue
            Write-Host "  Added conditional forwarder: $ParentDomain -> $ParentDCIP" -ForegroundColor Green
        }
        
        # Also add forwarder for _msdcs zone of parent domain (for DC GUID resolution)
        $msdcsZone = "_msdcs.$ParentDomain"
        $existingMsdcs = Get-DnsServerZone -Name $msdcsZone -ErrorAction SilentlyContinue
        if (-not $existingMsdcs) {
            Add-DnsServerConditionalForwarderZone -Name $msdcsZone -MasterServers $ParentDCIP -ReplicationScope Forest -ErrorAction SilentlyContinue
            Write-Host "  Added conditional forwarder: $msdcsZone -> $ParentDCIP" -ForegroundColor Green
        }
        
        # Clear DNS cache to apply changes
        Clear-DnsClientCache
        Clear-DnsServerCache -Force -ErrorAction SilentlyContinue
        
        # Verify resolution works
        $testResolution = Resolve-DnsName -Name $ParentDomain -Type A -ErrorAction SilentlyContinue
        if ($testResolution.IPAddress -eq $ParentDCIP) {
            Write-Host "  DNS verification: $ParentDomain -> $ParentDCIP (Correct)" -ForegroundColor Green
        } else {
            Write-Host "  DNS verification: $ParentDomain resolved to $($testResolution.IPAddress) (May need manual fix)" -ForegroundColor Yellow
        }
        
    } -ArgumentList $Config.ParentDCIP, $Config.VMIP, $Config.ParentDomain
    
    # Disable auto-logon
    Invoke-Command -VMName $Config.VMName -Credential $childDomainCred -ScriptBlock {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "0" -ErrorAction SilentlyContinue
    }
    
    Write-Log "Child Domain Controller configured" -Level Success
}

function Configure-ParentDCDNS {
    Write-Log "Configuring DNS forwarders on parent DC ($($Config.ParentVMName))..."
    
    $securePassword = ConvertTo-SecureString $Config.ParentAdminPassword -AsPlainText -Force
    $parentCred = New-Object PSCredential("$($Config.ParentNetBIOS)\Administrator", $securePassword)
    
    try {
        Invoke-Command -VMName $Config.ParentVMName -Credential $parentCred -ScriptBlock {
            param($ChildDomain, $ChildDCIP)
            
            Import-Module DnsServer -ErrorAction SilentlyContinue
            
            # Add conditional forwarder for child domain
            $existingForwarder = Get-DnsServerZone -Name $ChildDomain -ErrorAction SilentlyContinue
            if (-not $existingForwarder) {
                Add-DnsServerConditionalForwarderZone -Name $ChildDomain -MasterServers $ChildDCIP -ErrorAction SilentlyContinue
                Write-Host "  Added forwarder on parent: $ChildDomain -> $ChildDCIP" -ForegroundColor Green
            } else {
                Write-Host "  Forwarder already exists: $ChildDomain" -ForegroundColor Cyan
            }
            
            # Add _msdcs zone forwarder for child domain (for DC GUID resolution)
            $msdcsZone = "_msdcs.$ChildDomain"
            $existingMsdcs = Get-DnsServerZone -Name $msdcsZone -ErrorAction SilentlyContinue
            if (-not $existingMsdcs) {
                Add-DnsServerConditionalForwarderZone -Name $msdcsZone -MasterServers $ChildDCIP -ErrorAction SilentlyContinue
                Write-Host "  Added forwarder on parent: $msdcsZone -> $ChildDCIP" -ForegroundColor Green
            } else {
                Write-Host "  Forwarder already exists: $msdcsZone" -ForegroundColor Cyan
            }
            
            # Clear DNS cache
            Clear-DnsServerCache -Force -ErrorAction SilentlyContinue
            
            # Verify resolution
            Start-Sleep -Seconds 2
            $testResolution = Resolve-DnsName -Name $ChildDomain -Type A -ErrorAction SilentlyContinue
            if ($testResolution) {
                Write-Host "  DNS verification: $ChildDomain resolved successfully" -ForegroundColor Green
            }
            
        } -ArgumentList $Config.ChildDomain, $Config.VMIP -ErrorAction Stop
        
        Write-Log "DNS forwarders configured on parent DC" -Level Success
    }
    catch {
        Write-Log "Could not configure DNS on parent DC: $_" -Level Warning
        Write-Log "You may need to manually add conditional forwarders on the parent DC" -Level Warning
        Write-Host ""
        Write-Host "  Manual fix on parent DC:" -ForegroundColor Yellow
        Write-Host "    Add-DnsServerConditionalForwarderZone -Name '$($Config.ChildDomain)' -MasterServers $($Config.VMIP)" -ForegroundColor Cyan
        Write-Host "    Add-DnsServerConditionalForwarderZone -Name '_msdcs.$($Config.ChildDomain)' -MasterServers $($Config.VMIP)" -ForegroundColor Cyan
        Write-Host ""
    }
}

function Install-PrivilegedAdminAccounts {
    Write-Log "Creating privileged admin accounts in child domain..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $childDomainCred = New-Object PSCredential("$($Config.ChildNetBIOS)\Administrator", $securePassword)
    $domainDN = "DC=$($Config.ChildDomain.Replace('.',',DC='))"
    
    foreach ($account in $PrivilegedAccounts) {
        Write-Log "Creating account: $($account.SamAccountName)..."
        
        $maxRetries = 3
        $retryCount = 0
        $success = $false
        
        while (-not $success -and $retryCount -lt $maxRetries) {
            $retryCount++
            try {
                Invoke-Command -VMName $Config.VMName -Credential $childDomainCred -ScriptBlock {
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
                } -ArgumentList $account, $domainDN, $Config.ChildDomain -ErrorAction Stop
                
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
    
    Write-Log "Creating bulk AD objects in child domain..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $childDomainCred = New-Object PSCredential("$($Config.ChildNetBIOS)\Administrator", $securePassword)
    $domainDN = "DC=$($Config.ChildDomain.Replace('.',',DC='))"
    
    # Create OUs
    Write-Log "Creating Organizational Units..."
    Invoke-Command -VMName $Config.VMName -Credential $childDomainCred -ScriptBlock {
        param($NetBIOS, $DomainDN)
        
        $adws = Get-Service ADWS -ErrorAction SilentlyContinue
        if ($adws.Status -ne 'Running') {
            Start-Service ADWS -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 10
        }
        
        Import-Module ActiveDirectory
        
        $ous = @(
            @{ Name = "$NetBIOS Users"; Path = $DomainDN }
            @{ Name = "$NetBIOS Computers"; Path = $DomainDN }
            @{ Name = "$NetBIOS Groups"; Path = $DomainDN }
            @{ Name = "Engineering"; Path = "OU=$NetBIOS Users,$DomainDN" }
            @{ Name = "Sales"; Path = "OU=$NetBIOS Users,$DomainDN" }
            @{ Name = "Support"; Path = "OU=$NetBIOS Users,$DomainDN" }
            @{ Name = "Finance"; Path = "OU=$NetBIOS Users,$DomainDN" }
            @{ Name = "Workstations"; Path = "OU=$NetBIOS Computers,$DomainDN" }
            @{ Name = "Servers"; Path = "OU=$NetBIOS Computers,$DomainDN" }
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
        
    } -ArgumentList $Config.ChildNetBIOS, $domainDN
    
    # Create Groups
    Write-Log "Creating Security Groups..."
    Invoke-Command -VMName $Config.VMName -Credential $childDomainCred -ScriptBlock {
        param($NetBIOS, $DomainDN)
        
        Import-Module ActiveDirectory
        
        $groups = @(
            @{ Name = "Engineering_Team"; Path = "OU=$NetBIOS Groups,$DomainDN"; Scope = "Global" }
            @{ Name = "Sales_Team"; Path = "OU=$NetBIOS Groups,$DomainDN"; Scope = "Global" }
            @{ Name = "Support_Team"; Path = "OU=$NetBIOS Groups,$DomainDN"; Scope = "Global" }
            @{ Name = "Finance_Team"; Path = "OU=$NetBIOS Groups,$DomainDN"; Scope = "Global" }
            @{ Name = "DL_Engineering_Folders"; Path = "OU=$NetBIOS Groups,$DomainDN"; Scope = "DomainLocal" }
            @{ Name = "DL_Sales_Folders"; Path = "OU=$NetBIOS Groups,$DomainDN"; Scope = "DomainLocal" }
            @{ Name = "DL_Finance_Folders"; Path = "OU=$NetBIOS Groups,$DomainDN"; Scope = "DomainLocal" }
            @{ Name = "All_Corp_Employees"; Path = "OU=$NetBIOS Groups,$DomainDN"; Scope = "Global" }
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
        
    } -ArgumentList $Config.ChildNetBIOS, $domainDN
    
    # Create Users
    Write-Log "Creating User Accounts..."
    Invoke-Command -VMName $Config.VMName -Credential $childDomainCred -ScriptBlock {
        param($NetBIOS, $DomainDN, $DomainName)
        
        Import-Module ActiveDirectory
        
        $users = @(
            @{ Sam = "eng.user1"; Name = "Engineer One"; GivenName = "Engineer"; Surname = "One"; Dept = "Engineering"; Title = "Software Engineer"; OU = "Engineering" }
            @{ Sam = "eng.user2"; Name = "Engineer Two"; GivenName = "Engineer"; Surname = "Two"; Dept = "Engineering"; Title = "Senior Developer"; OU = "Engineering" }
            @{ Sam = "eng.user3"; Name = "Engineer Three"; GivenName = "Engineer"; Surname = "Three"; Dept = "Engineering"; Title = "DevOps Engineer"; OU = "Engineering" }
            @{ Sam = "sales.user1"; Name = "Sales One"; GivenName = "Sales"; Surname = "One"; Dept = "Sales"; Title = "Account Executive"; OU = "Sales" }
            @{ Sam = "sales.user2"; Name = "Sales Two"; GivenName = "Sales"; Surname = "Two"; Dept = "Sales"; Title = "Sales Manager"; OU = "Sales" }
            @{ Sam = "support.user1"; Name = "Support One"; GivenName = "Support"; Surname = "One"; Dept = "Support"; Title = "Support Analyst"; OU = "Support" }
            @{ Sam = "support.user2"; Name = "Support Two"; GivenName = "Support"; Surname = "Two"; Dept = "Support"; Title = "Support Lead"; OU = "Support" }
            @{ Sam = "finance.user1"; Name = "Finance One"; GivenName = "Finance"; Surname = "One"; Dept = "Finance"; Title = "Financial Analyst"; OU = "Finance" }
            @{ Sam = "finance.user2"; Name = "Finance Two"; GivenName = "Finance"; Surname = "Two"; Dept = "Finance"; Title = "Controller"; OU = "Finance" }
            @{ Sam = "corp.manager"; Name = "Corp Manager"; GivenName = "Corp"; Surname = "Manager"; Dept = "Management"; Title = "Division Manager"; OU = "$NetBIOS Users" }
        )
        
        $created = 0
        foreach ($user in $users) {
            try {
                if (-not (Get-ADUser -Filter "SamAccountName -eq '$($user.Sam)'" -ErrorAction SilentlyContinue)) {
                    $path = if ($user.OU -eq "$NetBIOS Users") { "OU=$NetBIOS Users,$DomainDN" } else { "OU=$($user.OU),OU=$NetBIOS Users,$DomainDN" }
                    
                    New-ADUser -SamAccountName $user.Sam -Name $user.Name -GivenName $user.GivenName -Surname $user.Surname `
                        -UserPrincipalName "$($user.Sam)@$DomainName" -Path $path -Department $user.Dept -Title $user.Title `
                        -EmailAddress "$($user.Sam)@$DomainName" -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
                        -Enabled $true -PasswordNeverExpires $true
                    $created++
                }
            } catch {
                Write-Warning "Failed to create user $($user.Sam): $_"
            }
        }
        Write-Host "  Users created: $created" -ForegroundColor Cyan
        
        # Add users to groups
        Add-ADGroupMember -Identity "Engineering_Team" -Members "eng.user1","eng.user2","eng.user3" -ErrorAction SilentlyContinue
        Add-ADGroupMember -Identity "Sales_Team" -Members "sales.user1","sales.user2" -ErrorAction SilentlyContinue
        Add-ADGroupMember -Identity "Support_Team" -Members "support.user1","support.user2" -ErrorAction SilentlyContinue
        Add-ADGroupMember -Identity "Finance_Team" -Members "finance.user1","finance.user2" -ErrorAction SilentlyContinue
        
    } -ArgumentList $Config.ChildNetBIOS, $domainDN, $Config.ChildDomain
    
    Write-Log "Bulk AD object creation completed" -Level Success
}

function Install-TempShare {
    Write-Log "Creating C:\temp share with dummy data..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $childDomainCred = New-Object PSCredential("$($Config.ChildNetBIOS)\Administrator", $securePassword)
    
    Invoke-Command -VMName $Config.VMName -Credential $childDomainCred -ScriptBlock {
        param($DomainName)
        
        $tempPath = "C:\temp"
        New-Item -ItemType Directory -Path $tempPath -Force | Out-Null
        
        # Create share
        if (-not (Get-SmbShare -Name "temp" -ErrorAction SilentlyContinue)) {
            New-SmbShare -Name "temp" -Path $tempPath -FullAccess "Domain Admins" -ChangeAccess "Authenticated Users" -ReadAccess "Everyone" | Out-Null
        }
        
        # Create folders
        @("Documents", "Projects", "Engineering", "Sales", "Reports") | ForEach-Object {
            New-Item -ItemType Directory -Path (Join-Path $tempPath $_) -Force | Out-Null
        }
        
        # Create dummy files
        "Corp Division Shared Drive - $DomainName" | Out-File "$tempPath\README.txt" -Encoding UTF8
        "Engineering project files for Corp division" | Out-File "$tempPath\Engineering\README.txt" -Encoding UTF8
        "Sales materials for Corp division" | Out-File "$tempPath\Sales\README.txt" -Encoding UTF8
        
        @"
PROJECT STATUS - Corp Division
==============================
Date: $(Get-Date -Format 'yyyy-MM-dd')

Active Projects:
- Infrastructure Migration
- Application Modernization
- Security Enhancement

Contact: corp.manager@$DomainName
"@ | Out-File "$tempPath\Projects\status.txt" -Encoding UTF8
        
        Write-Host "  Created C:\temp share" -ForegroundColor Green
        
    } -ArgumentList $Config.ChildDomain
    
    Write-Log "C:\temp share created" -Level Success
}

function Verify-TrustRelationship {
    Write-Log "Verifying trust relationship with parent domain..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $childDomainCred = New-Object PSCredential("$($Config.ChildNetBIOS)\Administrator", $securePassword)
    
    $trustInfo = Invoke-Command -VMName $Config.VMName -Credential $childDomainCred -ScriptBlock {
        param($ParentDomain)
        
        Import-Module ActiveDirectory
        
        $results = @{
            Trusts = @()
            ParentDomainReachable = $false
            ForestInfo = $null
        }
        
        # Get trusts
        try {
            $trusts = Get-ADTrust -Filter * -ErrorAction Stop
            foreach ($trust in $trusts) {
                $results.Trusts += @{
                    Name = $trust.Name
                    Direction = $trust.Direction.ToString()
                    TrustType = $trust.TrustType.ToString()
                }
            }
        } catch {
            $results.TrustError = $_.Exception.Message
        }
        
        # Test parent domain
        try {
            $parentDC = Get-ADDomainController -DomainName $ParentDomain -Discover -ErrorAction Stop
            $results.ParentDomainReachable = $true
            $results.ParentDC = $parentDC.HostName
        } catch {
            $results.ParentError = $_.Exception.Message
        }
        
        # Get forest info
        try {
            $forest = Get-ADForest -ErrorAction Stop
            $results.ForestInfo = @{
                Name = $forest.Name
                ForestMode = $forest.ForestMode.ToString()
                Domains = $forest.Domains
                RootDomain = $forest.RootDomain
            }
        } catch {
            $results.ForestError = $_.Exception.Message
        }
        
        return $results
        
    } -ArgumentList $Config.ParentDomain
    
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  TRUST & FOREST VERIFICATION" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    if ($trustInfo.ForestInfo) {
        Write-Host "  Forest Name:       $($trustInfo.ForestInfo.Name)" -ForegroundColor Green
        Write-Host "  Root Domain:       $($trustInfo.ForestInfo.RootDomain)"
        Write-Host "  Domains:           $($trustInfo.ForestInfo.Domains -join ', ')"
    }
    
    Write-Host ""
    Write-Host "  Parent DC:         $(if($trustInfo.ParentDomainReachable){"$($trustInfo.ParentDC) (Reachable)"}else{'NOT REACHABLE'})" -ForegroundColor $(if($trustInfo.ParentDomainReachable){'Green'}else{'Red'})
    
    if ($trustInfo.Trusts.Count -gt 0) {
        Write-Host ""
        Write-Host "  Trust Relationships:" -ForegroundColor Yellow
        foreach ($trust in $trustInfo.Trusts) {
            Write-Host "    - $($trust.Name): $($trust.Direction) ($($trust.TrustType))"
        }
    }
    
    Write-Host ""
    
    Write-Log "Trust verification complete" -Level Success
}

function Verify-PostDeploymentHealth {
    Write-Log "Running post-deployment health checks and DNS verification..."
    
    $securePassword = ConvertTo-SecureString $Config.AdminPassword -AsPlainText -Force
    $childDomainCred = New-Object PSCredential("$($Config.ChildNetBIOS)\Administrator", $securePassword)
    
    $healthResults = Invoke-Command -VMName $Config.VMName -Credential $childDomainCred -ScriptBlock {
        param($ParentDomain, $ParentDCIP, $ChildDomain, $SelfIP)
        
        $results = @{
            DNSServers = @()
            DNSFixed = $false
            SelfResolution = $null
            GuidResolution = $null
            ParentResolution = $null
            ParentDCResolution = $null
            ReplicationStatus = $null
            SysvolReady = $false
        }
        
        # CRITICAL: Ensure DNS client points to self first, then parent
        $adapter = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
        $currentDNS = (Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses
        
        $needsFix = $false
        if ($currentDNS.Count -lt 2) { $needsFix = $true }
        elseif ($currentDNS[0] -ne $SelfIP) { $needsFix = $true }
        elseif ($currentDNS -notcontains $ParentDCIP) { $needsFix = $true }
        
        if ($needsFix) {
            Write-Host "  Fixing DNS client configuration..." -ForegroundColor Yellow
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @($SelfIP, $ParentDCIP)
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
            $selfResolve = Resolve-DnsName -Name "$env:COMPUTERNAME.$ChildDomain" -Type A -DnsOnly -ErrorAction Stop
            $results.SelfResolution = $selfResolve.IPAddress | Select-Object -First 1
        } catch {
            $results.SelfResolution = "FAILED"
        }
        
        # Test DC GUID resolution (critical for dcdiag)
        try {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            $dcGuid = (Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction SilentlyContinue).InvocationId.Guid
            if ($dcGuid) {
                # For child domain, GUID record is in parent's _msdcs zone
                $parentDomainRoot = ($ChildDomain -split '\.', 2)[1]  # Get parent domain from child FQDN
                $guidRecord = "$dcGuid._msdcs.$parentDomainRoot"
                $guidResolve = Resolve-DnsName -Name $guidRecord -Type CNAME -DnsOnly -ErrorAction SilentlyContinue
                if ($guidResolve) {
                    $results.GuidResolution = "OK"
                } else {
                    $results.GuidResolution = "MISSING"
                    nltest /dsregdns 2>&1 | Out-Null
                }
            }
        } catch {
            $results.GuidResolution = "UNKNOWN"
        }
        
        # Test parent domain resolution
        try {
            $parentResolve = Resolve-DnsName -Name $ParentDomain -Type A -DnsOnly -ErrorAction Stop
            $results.ParentResolution = $parentResolve.IPAddress | Select-Object -First 1
        } catch {
            $results.ParentResolution = "FAILED"
        }
        
        # Test parent DC hostname resolution
        $parentDCName = (Resolve-DnsName -Name $ParentDCIP -Type PTR -ErrorAction SilentlyContinue).NameHost
        if ($parentDCName) {
            try {
                $dcResolve = Resolve-DnsName -Name $parentDCName -Type A -DnsOnly -ErrorAction Stop
                $results.ParentDCResolution = "$parentDCName -> $($dcResolve.IPAddress)"
            } catch {
                $results.ParentDCResolution = "FAILED"
            }
        }
        
        # Force replication
        try {
            repadmin /syncall /AdeP 2>&1 | Out-Null
            $results.ReplicationStatus = "Initiated"
        } catch {
            $results.ReplicationStatus = "Failed to initiate"
        }
        
        # Check SYSVOL
        $results.SysvolReady = Test-Path "\\$ChildDomain\SYSVOL\$ChildDomain\Policies"
        
        return $results
        
    } -ArgumentList $Config.ParentDomain, $Config.ParentDCIP, $Config.ChildDomain, $Config.VMIP
    
    # Display results
    Write-Host ""
    Write-Host "  Post-Deployment Health Check:" -ForegroundColor Cyan
    Write-Host "    DNS Servers:        $($healthResults.DNSServers -join ', ')" -ForegroundColor $(if($healthResults.DNSServers.Count -ge 2){'Green'}else{'Yellow'})
    if ($healthResults.DNSFixed) {
        Write-Host "    DNS Config:         Fixed (was misconfigured)" -ForegroundColor Yellow
    }
    Write-Host "    Self Resolution:    $($healthResults.SelfResolution)" -ForegroundColor $(if($healthResults.SelfResolution -eq $Config.VMIP){'Green'}else{'Red'})
    Write-Host "    DC GUID Record:     $($healthResults.GuidResolution)" -ForegroundColor $(if($healthResults.GuidResolution -eq 'OK'){'Green'}else{'Yellow'})
    Write-Host "    Parent Resolution:  $($Config.ParentDomain) -> $($healthResults.ParentResolution)" -ForegroundColor $(if($healthResults.ParentResolution -eq $Config.ParentDCIP){'Green'}else{'Red'})
    if ($healthResults.ParentDCResolution) {
        Write-Host "    Parent DC:          $($healthResults.ParentDCResolution)" -ForegroundColor Green
    }
    Write-Host "    Replication:        $($healthResults.ReplicationStatus)" -ForegroundColor Green
    Write-Host "    SYSVOL Ready:       $($healthResults.SysvolReady)" -ForegroundColor $(if($healthResults.SysvolReady){'Green'}else{'Yellow'})
    Write-Host ""
    
    if ($healthResults.SelfResolution -ne $Config.VMIP -or $healthResults.GuidResolution -ne 'OK') {
        Write-Log "WARNING: DNS resolution issues detected. Running additional DNS repair..." -Level Warning
        
        Invoke-Command -VMName $Config.VMName -Credential $childDomainCred -ScriptBlock {
            Restart-Service DNS -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 10
            ipconfig /registerdns
            nltest /dsregdns 2>&1 | Out-Null
            Write-Host "  DNS repair completed - please verify with dcdiag" -ForegroundColor Yellow
        }
    } elseif ($healthResults.ParentResolution -ne $Config.ParentDCIP) {
        Write-Log "WARNING: Parent domain resolution incorrect. You may need to manually verify DNS." -Level Warning
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
    
    Install-ChildDomainController
    Verify-PostDeploymentHealth
    Configure-ParentDCDNS
    Install-PrivilegedAdminAccounts
    Install-BulkADObjects
    Install-TempShare
    Verify-TrustRelationship
    
    $duration = (Get-Date) - $startTime
    
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║              CHILD DOMAIN DEPLOYMENT COMPLETE!                 ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "  VM Name:           $($Config.VMName)" -ForegroundColor White
    Write-Host "  Child Domain:      $($Config.ChildDomain) ($($Config.ChildNetBIOS))" -ForegroundColor White
    Write-Host "  Parent Domain:     $($Config.ParentDomain)" -ForegroundColor White
    Write-Host "  DC IP:             $($Config.VMIP)" -ForegroundColor White
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  DOMAIN HIERARCHY" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $($Config.ParentDomain) (Forest Root)"
    Write-Host "    └── $($Config.ChildDomain) (Child Domain) ← NEW"
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  CREDENTIALS" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Child Domain Admin:"
    Write-Host "    $($Config.ChildNetBIOS)\Administrator     $($Config.AdminPassword)"
    Write-Host ""
    Write-Host "  Child Domain Accounts:" -ForegroundColor Yellow
    foreach ($account in $PrivilegedAccounts) {
        Write-Host "    $($Config.ChildNetBIOS)\$($account.SamAccountName)"
        Write-Host "      Password: $($account.Password)"
    }
    Write-Host ""
    Write-Host "  Test Users:        P@ssw0rd123!"
    Write-Host "    eng.user1, eng.user2, eng.user3"
    Write-Host "    sales.user1, sales.user2"
    Write-Host "    support.user1, support.user2"
    Write-Host "    finance.user1, finance.user2"
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  CROSS-DOMAIN ACCESS" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Users in $($Config.ParentDomain) can access $($Config.ChildDomain) resources"
    Write-Host "  Users in $($Config.ChildDomain) can access $($Config.ParentDomain) resources"
    Write-Host "  Enterprise Admins from parent have full access"
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  FILE SHARES" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  \\$($Config.VMName)\temp     (Everyone Read)"
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
    Write-Host ""
    Write-Host "  Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Ensure parent DC ($($Config.ParentDCIP)) is running"
    Write-Host "  2. Verify network connectivity between VMs"
    Write-Host "  3. Check that parent domain credentials are correct"
    Write-Host ""
    throw
}
