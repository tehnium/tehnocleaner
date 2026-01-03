<#
.SYNOPSIS
    System Cleaner PowerShell Script
.DESCRIPTION
    Performs comprehensive system cleaning including:
    - System files cleanup
    - Browser cache cleaning (Edge, Chrome, Firefox, Brave)
    - Windows Update cleanup
    - Telemetry and tracking disabling
    - Unnecessary services disabling
    - Windows Apps removal
    - OneDrive removal
.NOTES
    Version: 1.4
    Author: tehnium
    Run as Administrator for full functionality
#>

# Require admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator!" -ForegroundColor Red
    Start-Sleep 3
    exit
}

# Set execution policy temporarily
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# UI Settings
$Host.UI.RawUI.WindowTitle = "System Cleaner PowerShell v1.4"
$ProgressPreference = 'SilentlyContinue'

# Clear screen and display header
Clear-Host
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "           SYSTEM CLEANER POWERSHELL         " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "Please wait while system information is gathered..."
Write-Host ""

# 1. Display System Information
function Get-SystemInfo {
    Write-Host "=== SYSTEM INFORMATION ===" -ForegroundColor Green
    $os = Get-CimInstance Win32_OperatingSystem
    $cpu = Get-CimInstance Win32_Processor
    $memory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | ForEach-Object {[math]::Round(($_.Sum / 1GB), 2)}
    Write-Host "OS Name: $($os.Caption)"
    Write-Host "OS Version: $($os.Version)"
    Write-Host "System Type: $($os.OSArchitecture)"
    Write-Host "CPU: $($cpu.Name)"
    Write-Host "Total Physical Memory: $memory GB"
    Write-Host ""
}
Get-SystemInfo

# 2. Main Cleaning Functions

function Invoke-SystemCleanup {
    Write-Host "=== SYSTEM CLEANUP ===" -ForegroundColor Green
    # Clean Windows Update cache
    Write-Host "Cleaning Windows Update cache..."
    Stop-Service -Name wuauserv -Force
    Remove-Item -Path "$env:windir\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv
    # Clean temporary files
    Write-Host "Cleaning temporary files..."
    Remove-Item -Path "$env:windir\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:windir\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:windir\Logs\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:windir\Debug\*" -Recurse -Force -ErrorAction SilentlyContinue
    # Clean system files
    Write-Host "Cleaning system files..."
    @(
        "$env:windir\WindowsUpdate.log",
        "$env:windir\*.dmp",
        "$env:windir\*.tmp",
        "$env:windir\*.log"
    ) | ForEach-Object {
        if (Test-Path $_) { Remove-Item $_ -Force -ErrorAction SilentlyContinue }
    }
    # Clean user temp files for all users
    Write-Host "Cleaning user temp files..."
    Get-ChildItem "C:\Users" | ForEach-Object {
        $userPath = $_.FullName
        @(
            "$userPath\AppData\Local\Temp\*",
            "$userPath\AppData\Local\Microsoft\Windows\INetCache\*",
            "$userPath\AppData\Local\Microsoft\Windows\Temporary Internet Files\*",
            "$userPath\AppData\Local\Microsoft\Windows\Explorer\*",
            "$userPath\AppData\Local\Microsoft\Windows\Burn\*",
            "$userPath\AppData\Local\IconCache.db"
        ) | ForEach-Object {
            if (Test-Path $_) { Remove-Item $_ -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    # Run DISM cleanup
    Write-Host "Running DISM cleanup..."
    Start-Process -FilePath "Dism.exe" -ArgumentList "/online /Cleanup-Image /StartComponentCleanup" -Wait -NoNewWindow
    Start-Process -FilePath "Dism.exe" -ArgumentList "/online /Cleanup-Image /StartComponentCleanup /ResetBase" -Wait -NoNewWindow
    Start-Process -FilePath "Dism.exe" -ArgumentList "/online /Cleanup-Image /SPSuperseded" -Wait -NoNewWindow
    # Run Disk Cleanup
    Write-Host "Running Disk Cleanup..."
    $cleanmgr = "$env:SystemRoot\System32\cleanmgr.exe"
    if (Test-Path $cleanmgr) {
        $cleanupTypes = @(
            "Active Setup Temp Folders",
            "Content Indexer Cleaner",
            "Internet Cache Files",
            "Memory Dump Files",
            "Offline Files",
            "Previous Installations",
            "Recycle Bin",
            "Service Pack Cleanup",
            "Setup Log Files",
            "System error memory dump files",
            "Temporary Files",
            "Temporary Setup Files",
            "Thumbnail Cache",
            "Upgrade Discarded Files",
            "Windows Error Reporting Archive Files",
            "Windows Error Reporting Queue Files",
            "Windows Upgrade Log Files"
        )
        foreach ($type in $cleanupTypes) {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$type"
            if (Test-Path $regPath) {
                Set-ItemProperty -Path $regPath -Name "StateFlags0011" -Type DWord -Value 2 -Force
            }
        }
        Start-Process -FilePath $cleanmgr -ArgumentList "/sagerun:11" -Wait -NoNewWindow
    }
    # Clear Event Logs
    Write-Host "Clearing Event Logs..."
    wevtutil el | ForEach-Object { wevtutil cl $_ }
    # Clear System Restore Points
    Write-Host "Clearing System Restore Points..."
    if (Get-Command -Name vssadmin -ErrorAction SilentlyContinue) {
        vssadmin Delete Shadows /For=C: /All /Quiet
    }
}

function Clear-BrowserCaches {
    Write-Host "=== BROWSER CACHE CLEANUP ===" -ForegroundColor Green
    Get-ChildItem "C:\Users" | ForEach-Object {
        $user = $_.Name
        $userPath = $_.FullName
        # Microsoft Edge
        $edgePaths = @(
            "$userPath\AppData\Local\Microsoft\Edge\User Data\Default\Cache",
            "$userPath\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache",
            "$userPath\AppData\Local\Microsoft\Edge\User Data\Default\GPUCache",
            "$userPath\AppData\Local\Microsoft\Edge\User Data\Default\Media Cache"
        )
        # Google Chrome
        $chromePaths = @(
            "$userPath\AppData\Local\Google\Chrome\User Data\Default\Cache",
            "$userPath\AppData\Local\Google\Chrome\User Data\Default\Code Cache",
            "$userPath\AppData\Local\Google\Chrome\User Data\Default\GPUCache",
            "$userPath\AppData\Local\Google\Chrome\User Data\Default\Media Cache"
        )
        # Mozilla Firefox
        $firefoxPaths = @(
            "$userPath\AppData\Local\Mozilla\Firefox\Profiles\*.default-release\cache2",
            "$userPath\AppData\Local\Mozilla\Firefox\Profiles\*.default-release\thumbnails",
            "$userPath\AppData\Local\Mozilla\Firefox\Profiles\*.default-release\startupCache"
        )
        # Brave Browser
        $bravePaths = @(
            "$userPath\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Cache",
            "$userPath\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Code Cache",
            "$userPath\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\GPUCache",
            "$userPath\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Media Cache"
        )
        Write-Host "Cleaning browser caches for user: $user"
        # Clean all browser paths
        $allPaths = $edgePaths + $chromePaths + $firefoxPaths + $bravePaths
        foreach ($path in $allPaths) {
            if (Test-Path $_) {
                try {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                    Write-Host "Cleaned: $path" -ForegroundColor DarkGray
                } catch {
                    Write-Host "Error cleaning $path : $_" -ForegroundColor Yellow
                }
            }
        }
    }
}

function Disable-TelemetryServices {
    Write-Host "=== DISABLING TELEMETRY SERVICES ===" -ForegroundColor Green
    # Disable services
    $services = @(
        "DiagTrack",
        "dmwappushservice",
        "diagnosticshub.standardcollector.service",
        "WMPNetworkSvc",
        "WSearch"
    )
    foreach ($service in $services) {
        try {
            Stop-Service -Name $service -Force -ErrorAction Stop
            Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
            Write-Host "Disabled service: $service" -ForegroundColor DarkGray
        } catch {
            Write-Host "Error disabling $service : $_" -ForegroundColor Yellow
        }
    }
    # Disable scheduled tasks
    $tasks = @(
        "Microsoft Compatibility Appraiser",
        "ProgramDataUpdater",
        "Consolidator",
        "KernelCeipTask",
        "UsbCeip",
        "Microsoft-Windows-DiskDiagnosticDataCollector",
        "Sqm-Tasks",
        "FamilySafetyUpload",
        "OfficeTelemetryAgentLogOn",
        "OfficeTelemetryAgentFallBack"
    )
    foreach ($task in $tasks) {
        try {
            Disable-ScheduledTask -TaskName $task -ErrorAction Stop | Out-Null
            Write-Host "Disabled task: $task" -ForegroundColor DarkGray
        } catch {
            Write-Host "Error disabling task $task : $_" -ForegroundColor Yellow
        }
    }
    # Disable telemetry via registry
    Write-Host "Disabling telemetry via registry..."
    $regSettings = @(
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name="Enabled"; Value=0; Type="DWord"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"; Value=0; Type="DWord"},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name="AllowTelemetry"; Value=0; Type="DWord"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name="AITEnable"; Value=0; Type="DWord"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name="DisableUAR"; Value=1; Type="DWord"},
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener"; Name="Start"; Value=0; Type="DWord"},
        @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost"; Name="EnableWebContentEvaluation"; Value=0; Type="DWord"},
        @{Path="HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"; Name="value"; Value=0; Type="DWord"},
        @{Path="HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"; Name="value"; Value=0; Type="DWord"}
    )
    foreach ($setting in $regSettings) {
        try {
            if (-not (Test-Path $setting.Path)) {
                New-Item -Path $setting.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $setting.Type -Force
        } catch {
            Write-Host "Error setting registry value $($setting.Path)\$($setting.Name) : $_" -ForegroundColor Yellow
        }
    }
}

function Remove-WindowsApps {
    Write-Host "=== REMOVING WINDOWS APPS ===" -ForegroundColor Green
    $appsToRemove = @(
        "*3DBuilder*",
        "*Getstarted*",
        "*WindowsAlarms*",
        "*WindowsCamera*",
        "*bing*",
        "*MicrosoftOfficeHub*",
        "*OneNote*",
        "*people*",
        "*WindowsPhone*",
        "*photos*",
        "*SkypeApp*",
        "*solit*",
        "*WindowsSoundRecorder*",
        "*windowscommunicationsapps*",
        "*zune*",
        "*Sway*",
        "*CommsPhone*",
        "*ConnectivityStore*",
        "*Microsoft.Messaging*",
        "*Facebook*",
        "*Twitter*",
        "*Drawboard PDF*"
    )
    foreach ($app in $appsToRemove) {
        try {
            Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction Stop
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -Like $app | Remove-AppxProvisionedPackage -Online -ErrorAction Stop
            Write-Host "Removed app: $app" -ForegroundColor DarkGray
        } catch {
            Write-Host "Error removing app $app : $_" -ForegroundColor Yellow
        }
    }
}

function Remove-OneDrive {
    Write-Host "=== REMOVING ONEDRIVE ===" -ForegroundColor Green
    try {
        # Kill OneDrive process
        Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
        # Uninstall OneDrive
        if (Test-Path "$env:SystemRoot\SysWOW64\OneDriveSetup.exe") {
            Start-Process -FilePath "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait -NoNewWindow
        }
        # Remove OneDrive folders
        $foldersToRemove = @(
            "$env:USERPROFILE\OneDrive",
            "$env:LOCALAPPDATA\Microsoft\OneDrive",
            "$env:PROGRAMDATA\Microsoft OneDrive",
            "C:\OneDriveTemp"
        )
        foreach ($folder in $foldersToRemove) {
            if (Test-Path $folder) {
                Remove-Item -Path $folder -Recurse -Force -ErrorAction Stop
            }
        }
        # Remove from Explorer sidebar
        $registryPaths = @(
            "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}",
            "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        )
        foreach ($regPath in $registryPaths) {
            if (Test-Path $regPath) {
                Set-ItemProperty -Path $regPath -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Force
            }
        }
        Write-Host "OneDrive has been successfully removed." -ForegroundColor Green
        # Restart Explorer
        Stop-Process -Name "explorer" -Force
        Start-Process "explorer.exe"
    } catch {
        Write-Host "Error removing OneDrive: $_" -ForegroundColor Red
    }
}

# NEW FUNCTION: Clean C:\ safely without affecting system folders
function Clean-RootDrive {
    Write-Host "=== CLEANING ROOT DRIVE (C:\) ===" -ForegroundColor Green

    # Directorii candidați pentru curățare (siguri)
    $foldersToDelete = @(
        "$env:SystemDrive\Temp",
        "$env:SystemDrive\TempFiles",
        "$env:SystemDrive\Cache",
        "$env:SystemDrive\Logs",
        "$env:SystemDrive\Debug",
        "$env:SystemDrive\CrashDumps",
        "$env:SystemDrive\Install_Temp",
        "$env:SystemDrive\AppData",
        "$env:SystemDrive\Downloaded Installers"
    )

    foreach ($folder in $foldersToDelete) {
        if (Test-Path $folder) {
            try {
                Remove-Item -Path $folder -Recurse -Force -ErrorAction Stop
                Write-Host "Deleted folder: $folder" -ForegroundColor DarkGray
            } catch {
                Write-Host "Error deleting $folder : $_" -ForegroundColor Yellow
            }
        }
    }

    # Extensii de fișiere suspecte de șters (ex: .tmp, .log, .bak etc.)
    $extensionsToDelete = @("*.tmp", "*.log", "*.bak", "*.old", "*.swp", "*.dmp", "*.crash", "*.cache")

    # Parcurgem C:\ pentru fișiere temporare
    foreach ($ext in $extensionsToDelete) {
        try {
            Get-ChildItem -Path "$env:SystemDrive\" -Filter $ext -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
                $_.FullName -notmatch "^$env:SystemDrive\\Windows" -and
                $_.FullName -notmatch "^$env:SystemDrive\\Program Files" -and
                $_.FullName -notmatch "^$env:SystemDrive\\Program Files (x86)" -and
                $_.FullName -notmatch "^$env:SystemDrive\\Users"
            } | ForEach-Object {
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                Write-Host "Deleted file: $($_.FullName)" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host "Error searching for $ext files: $_" -ForegroundColor Yellow
        }
    }

    Write-Host "Root drive cleanup completed." -ForegroundColor Green
}

# 3. Execute all cleaning functions
Invoke-SystemCleanup
Clear-BrowserCaches
Disable-TelemetryServices
Remove-WindowsApps
Remove-OneDrive
Clean-RootDrive

# 4. Completion
Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   SYSTEM CLEANUP COMPLETED SUCCESSFULLY!   " -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""
# Prompt to restart
$restart = Read-Host "Do you want to restart your computer now? (Y/N)"
if ($restart -eq "Y" -or $restart -eq "y") {
    Write-Host "Restarting computer in 5 seconds..." -ForegroundColor Yellow
    Start-Sleep 5
    Restart-Computer -Force
} else {
    Write-Host "Please restart your computer when convenient to complete the cleanup." -ForegroundColor Yellow
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
