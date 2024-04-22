function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if (-not (Test-Admin)) {
    # Re-launch the script with administrator rights
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $args"
    Start-Process powershell -ArgumentList $arguments -Verb RunAs
    exit
}


$info = New-Object PSObject

# Computer Name
$computerName = $env:COMPUTERNAME
$info | Add-Member -Type NoteProperty -Name "ComputerName" -Value $computerName

# hardware components information
$cpu = Get-WmiObject -Query "Select * from Win32_Processor" | Select-Object Name, NumberOfCores, MaxClockSpeed
$ram = Get-WmiObject -Query "Select * from Win32_PhysicalMemory"
$disk = Get-WmiObject -Query "Select * from Win32_DiskDrive"
$tpm = Get-WmiObject -Namespace "ROOT\CIMV2\Security\MicrosoftTpm" -Query "Select * from Win32_Tpm"
$graphics = Get-WmiObject -Query "Select * from Win32_VideoController"

# supported processor
$intelUrl = "https://raw.githubusercontent.com/rcmaehl/WhyNotWin11/main/includes/SupportedProcessorsIntel.txt"
$amdUrl = "https://raw.githubusercontent.com/rcmaehl/WhyNotWin11/main/includes/SupportedProcessorsAMD.txt"
$supportedIntelProcessors = (Invoke-WebRequest -Uri $intelUrl).Content -split "`r?`n"
$supportedAmdProcessors = (Invoke-WebRequest -Uri $amdUrl).Content -split "`r?`n"
$supportedProcessors = $supportedIntelProcessors + $supportedAmdProcessors
$cpu = Get-WmiObject -Query "Select * from Win32_Processor" | Select-Object Name, NumberOfCores, MaxClockSpeed
$cpuName = $cpu.Name
$processorFound = $supportedProcessors | Where-Object {
    $normalizedCpuName = $cpuName -replace '\s+', ' ' -replace '[^\w\s]', ''
    $normalizedPattern = $_ -replace '\s+', ' ' -replace '[^\w\s]', ''
    $normalizedCpuName -match [regex]::Escape($normalizedPattern)
}
$cpuStatus = if ($processorFound -and $cpu.NumberOfCores -ge 2 -and $cpu.MaxClockSpeed -ge 1000) {
    "Meets requirements: $($cpu.Name), $($cpu.NumberOfCores) cores at $($cpu.MaxClockSpeed) MHz"
} else {
    "Does not meet requirements: $($cpu.Name), $($cpu.NumberOfCores) cores at $($cpu.MaxClockSpeed) MHz"
}
$info | Add-Member -Type NoteProperty -Name "CPU" -Value $cpuStatus

# RAM check
$totalRam = ($ram.Capacity | Measure-Object -Sum).Sum / 1GB
$ramStatus = if ($totalRam -ge 4) { "Meets requirements: ${totalRam} GB" } else { "Does not meet requirements: ${totalRam} GB" }
$info | Add-Member -Type NoteProperty -Name "RAM" -Value $ramStatus

# Storage check
$totalDisk = ($disk.Size | Measure-Object -Sum).Sum / 1GB
$diskStatus = if ($totalDisk -ge 64) { "Meets requirements: ${totalDisk} GB" } else { "Does not meet requirements: ${totalDisk} GB" }
$info | Add-Member -Type NoteProperty -Name "Storage" -Value $diskStatus

# System firmware check
try {
    $secureBootEnabled = Confirm-SecureBootUEFI
    $firmwareStatus = if ($secureBootEnabled) {
        "Secure Boot is enabled."
    } else {
        "Secure Boot is disabled."
    }
} catch {
    $firmwareStatus = "Secure Boot status could not be determined or Secure Boot is not supported on this system."
}
$info | Add-Member -Type NoteProperty -Name "SystemFirmware" -Value $firmwareStatus

# TPM check
if ($tpm) {
    $isEnabled = if ($tpm.IsEnabled_InitialValue) { "Enabled" } else { "Disabled" }
    $versionInfo = $tpm.SpecVersion.Split(",")[0].Trim()  # Get the major version part
    $meetsRequirements = if ($versionInfo -eq "2.0") { "Meets requirements" } else { "Does not meet requirements" }
    $tpmStatus = "$($meetsRequirements): TPM Version: $($tpm.SpecVersion), Status: $isEnabled"
} else {
    $tpmStatus = "TPM not present or not enabled"
}
$info | Add-Member -Type NoteProperty -Name "TPM" -Value $tpmStatus

# Graphics card check
$graphicsStatus = foreach ($gpu in $graphics) {
    "Graphics Card: $($gpu.Caption)"
}
$info | Add-Member -Type NoteProperty -Name "GraphicsCard" -Value $graphicsStatus

# Domain check
$computerSystem = Get-WmiObject -Class Win32_ComputerSystem
$domainStatus = if ($computerSystem.PartOfDomain) {
    "Joined to Domain: $($computerSystem.Domain)"
} else {
    "Not joined to any domain"
}
$info | Add-Member -Type NoteProperty -Name "DomainStatus" -Value $domainStatus

# Installed Applications
$apps = @("Sentinel Agent", "Rapid7", "Cisco Secure Client","Cisco AnyConnect Secure Mobility Client"
foreach ($app in $apps) {
    $appQuery = Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE Name LIKE '%$app%'"
    $appStatus = if ($appQuery) { "Installed" } else { "Not Installed" }
    $info | Add-Member -Type NoteProperty -Name $app -Value $appStatus
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
function Get-SaveFilePath {
    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    $dialog.Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*"
    $dialog.FileName = "$computerName"

    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return $dialog.FileName
    }
    else {
        return $null
    }
}
$savePath = Get-SaveFilePath
if ($savePath -ne $null) {
    $jsonData = $info | ConvertTo-Json
    Set-Content -Path $savePath -Value $jsonData
    Write-Output "System information exported to $savePath"
} else {
    Write-Output "No file path selected, operation cancelled."
}
