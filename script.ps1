# Set output encoding to UTF-8
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Color definitions (compatible with PowerShell 5.1 and 7.x)
$ESC = [char]27
$RED = "$ESC[31m"
$GREEN = "$ESC[32m"
$YELLOW = "$ESC[33m"
$BLUE = "$ESC[34m"
$NC = "$ESC[0m"

# Try to resize terminal window to 120x40 (columns x rows) on startup
# Silently ignore failures to avoid affecting main script flow
function Try-ResizeTerminalWindow {
    param(
        [int]$Columns = 120,
        [int]$Rows = 40
    )

    # Method 1: Adjust via PowerShell Host RawUI (traditional console, ConEmu, etc.)
    try {
        $rawUi = $null
        if ($Host -and $Host.UI -and $Host.UI.RawUI) {
            $rawUi = $Host.UI.RawUI
        }

        if ($rawUi) {
            try {
                # BufferSize must be >= WindowSize, otherwise exception will be thrown
                $bufferSize = $rawUi.BufferSize
                $newBufferSize = New-Object System.Management.Automation.Host.Size (
                    ([Math]::Max($bufferSize.Width, $Columns)),
                    ([Math]::Max($bufferSize.Height, $Rows))
                )
                $rawUi.BufferSize = $newBufferSize
            } catch {
                # Silently ignore
            }

            try {
                $rawUi.WindowSize = New-Object System.Management.Automation.Host.Size ($Columns, $Rows)
            } catch {
                # Silently ignore
            }
        }
    } catch {
        # Silently ignore
    }

    # Method 2: Try again via ANSI escape sequences (Windows Terminal, etc.)
    try {
        if (-not [Console]::IsOutputRedirected) {
            $escChar = [char]27
            [Console]::Out.Write("$escChar[8;${Rows};${Columns}t")
        }
    } catch {
        # Silently ignore
    }
}

Try-ResizeTerminalWindow -Columns 120 -Rows 40

# Path resolution: Prioritize .NET for system directories to avoid path issues from missing environment variables
function Get-FolderPathSafe {
    param(
        [Parameter(Mandatory = $true)][System.Environment+SpecialFolder]$SpecialFolder,
        [Parameter(Mandatory = $true)][string]$EnvVarName,
        [Parameter(Mandatory = $true)][string]$FallbackRelative,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $path = [Environment]::GetFolderPath($SpecialFolder)
    if ([string]::IsNullOrWhiteSpace($path)) {
        $envValue = [Environment]::GetEnvironmentVariable($EnvVarName)
        if (-not [string]::IsNullOrWhiteSpace($envValue)) {
            $path = $envValue
        }
    }
    if ([string]::IsNullOrWhiteSpace($path)) {
        $userProfile = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile)
        if ([string]::IsNullOrWhiteSpace($userProfile)) {
            $userProfile = [Environment]::GetEnvironmentVariable("USERPROFILE")
        }
        if (-not [string]::IsNullOrWhiteSpace($userProfile)) {
            $path = Join-Path $userProfile $FallbackRelative
        }
    }
    if ([string]::IsNullOrWhiteSpace($path)) {
        Write-Host "$YELLOW⚠️  [Path]$NC $Label cannot be resolved, will try other methods"
    } else {
        Write-Host "$BLUEℹ️  [Path]$NC ${Label}: $path"
    }
    return $path
}

function Initialize-CursorPaths {
    Write-Host "$BLUEℹ️  [Path]$NC Starting to resolve Cursor related paths..."
    $global:CursorAppDataRoot = Get-FolderPathSafe `
        -SpecialFolder ([System.Environment+SpecialFolder]::ApplicationData) `
        -EnvVarName "APPDATA" `
        -FallbackRelative "AppData\Roaming" `
        -Label "Roaming AppData"
    $global:CursorLocalAppDataRoot = Get-FolderPathSafe `
        -SpecialFolder ([System.Environment+SpecialFolder]::LocalApplicationData) `
        -EnvVarName "LOCALAPPDATA" `
        -FallbackRelative "AppData\Local" `
        -Label "Local AppData"
    $global:CursorUserProfileRoot = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile)
    if ([string]::IsNullOrWhiteSpace($global:CursorUserProfileRoot)) {
        $global:CursorUserProfileRoot = [Environment]::GetEnvironmentVariable("USERPROFILE")
    }
    if (-not [string]::IsNullOrWhiteSpace($global:CursorUserProfileRoot)) {
        Write-Host "$BLUEℹ️  [Path]$NC User directory: $global:CursorUserProfileRoot"
    }
    $global:CursorAppDataDir = if ($global:CursorAppDataRoot) { Join-Path $global:CursorAppDataRoot "Cursor" } else { $null }
    $global:CursorLocalAppDataDir = if ($global:CursorLocalAppDataRoot) { Join-Path $global:CursorLocalAppDataRoot "Cursor" } else { $null }
    $global:CursorStorageDir = if ($global:CursorAppDataDir) { Join-Path $global:CursorAppDataDir "User\globalStorage" } else { $null }
    $global:CursorStorageFile = if ($global:CursorStorageDir) { Join-Path $global:CursorStorageDir "storage.json" } else { $null }
    $global:CursorBackupDir = if ($global:CursorStorageDir) { Join-Path $global:CursorStorageDir "backups" } else { $null }

    if ($global:CursorStorageDir -and -not (Test-Path $global:CursorStorageDir)) {
        Write-Host "$YELLOW⚠️  [Path]$NC Global configuration directory doesn't exist: $global:CursorStorageDir"
    }
    if ($global:CursorStorageFile) {
        if (Test-Path $global:CursorStorageFile) {
            Write-Host "$GREEN✅ [Path]$NC Found configuration file: $global:CursorStorageFile"
        } else {
            Write-Host "$YELLOW⚠️  [Path]$NC Configuration file doesn't exist: $global:CursorStorageFile"
        }
    }
}

function Normalize-CursorInstallCandidate {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }
    $candidate = $Path.Trim().Trim('"')
    if (Test-Path $candidate -PathType Leaf) {
        $candidate = Split-Path -Parent $candidate
    }
    return $candidate
}

function Test-CursorInstallPath {
    param([string]$Path)
    $candidate = Normalize-CursorInstallCandidate -Path $Path
    if (-not $candidate) {
        return $false
    }
    $exePath = Join-Path $candidate "Cursor.exe"
    return (Test-Path $exePath)
}

function Get-CursorInstallPathFromRegistry {
    $results = @()
    $uninstallKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($key in $uninstallKeys) {
        try {
            $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                if (-not $item.DisplayName -or $item.DisplayName -notlike "*Cursor*") {
                    continue
                }
                $candidate = $null
                if ($item.InstallLocation) {
                    $candidate = $item.InstallLocation
                } elseif ($item.DisplayIcon) {
                    $candidate = $item.DisplayIcon.Split(',')[0].Trim('"')
                } elseif ($item.UninstallString) {
                    $candidate = $item.UninstallString.Split(' ')[0].Trim('"')
                }
                if ($candidate) {
                    $results += $candidate
                }
            }
        } catch {
            Write-Host "$YELLOW⚠️  [Path]$NC Failed to read registry: $key"
        }
    }
    return $results | Where-Object { $_ } | Select-Object -Unique
}

function Request-CursorInstallPathFromUser {
    Write-Host "$YELLOW💡 [Hint]$NC Automatic detection failed, you can manually select Cursor installation directory (containing Cursor.exe)"
    $selectedPath = $null
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = "Please select Cursor installation directory (containing Cursor.exe)"
        $dialog.ShowNewFolderButton = $false
        if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $selectedPath = $dialog.SelectedPath
        }
    } catch {
        Write-Host "$YELLOW⚠️  [Hint]$NC Unable to open selection window, will use command line input"
    }
    if (-not $selectedPath) {
        $manualInput = Read-Host "Please enter Cursor installation directory (containing Cursor.exe), or press Enter to cancel"
        if (-not [string]::IsNullOrWhiteSpace($manualInput)) {
            $selectedPath = $manualInput
        }
    }
    if ($selectedPath) {
        $normalized = Normalize-CursorInstallCandidate -Path $selectedPath
        if ($normalized -and (Test-CursorInstallPath -Path $normalized)) {
            Write-Host "$GREEN✅ [Found]$NC Manually specified installation path: $normalized"
            return $normalized
        }
        Write-Host "$RED❌ [Error]$NC Manual path is invalid: $selectedPath"
    }
    return $null
}

function Resolve-CursorInstallPath {
    param([switch]$AllowPrompt)
    if ($global:CursorInstallPath -and (Test-CursorInstallPath -Path $global:CursorInstallPath)) {
        return $global:CursorInstallPath
    }

    Write-Host "$BLUE🔎 [Path]$NC Detecting Cursor installation directory..."
    $candidates = @()
    if ($global:CursorLocalAppDataRoot) {
        $candidates += (Join-Path $global:CursorLocalAppDataRoot "Programs\Cursor")
    }
    $programFiles = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFiles)
    if ($programFiles) {
        $candidates += (Join-Path $programFiles "Cursor")
    }
    $programFilesX86 = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFilesX86)
    if ($programFilesX86) {
        $candidates += (Join-Path $programFilesX86 "Cursor")
    }

    $regCandidates = @(Get-CursorInstallPathFromRegistry)
    if ($regCandidates.Count -gt 0) {
        Write-Host "$BLUEℹ️  [Path]$NC Found candidate paths from registry: $($regCandidates -join '; ')"
        $candidates += $regCandidates
    }

    $fixedDrives = [IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' }
    foreach ($drive in $fixedDrives) {
        $root = $drive.RootDirectory.FullName
        $candidates += (Join-Path $root "Program Files\Cursor")
        $candidates += (Join-Path $root "Program Files (x86)\Cursor")
        $candidates += (Join-Path $root "Cursor")
    }

    $candidates = $candidates | Where-Object { $_ } | Select-Object -Unique
    $totalCandidates = $candidates.Count
    for ($i = 0; $i -lt $totalCandidates; $i++) {
        $candidate = Normalize-CursorInstallCandidate -Path $candidates[$i]
        $attempt = $i + 1
        if (-not $candidate) {
            continue
        }
        Write-Host "$BLUE⏳ [Path]$NC ($attempt/$totalCandidates) Trying installation path: $candidate"
        if (Test-CursorInstallPath -Path $candidate) {
            $global:CursorInstallPath = $candidate
            Write-Host "$GREEN✅ [Found]$NC Found Cursor installation path: $candidate"
            return $candidate
        }
    }

    if ($AllowPrompt) {
        $manualPath = Request-CursorInstallPathFromUser
        if ($manualPath) {
            $global:CursorInstallPath = $manualPath
            return $manualPath
        }
    }

    Write-Host "$RED❌ [Error]$NC Cursor application installation path not found"
    Write-Host "$YELLOW💡 [Hint]$NC Please confirm Cursor is correctly installed or manually specify path"
    return $null
}

# Configuration file paths (use global variables after initialization)
Initialize-CursorPaths
$STORAGE_FILE = $global:CursorStorageFile
$BACKUP_DIR = $global:CursorBackupDir

# PowerShell native method to generate random string
function Generate-RandomString {
    param([int]$Length)
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    $result = ""
    for ($i = 0; $i -lt $Length; $i++) {
        $result += $chars[(Get-Random -Maximum $chars.Length)]
    }
    return $result
}

# 🔍 Simple JavaScript brace matching (for locating function boundaries within limited segments)
function Find-JsMatchingBraceEnd {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][int]$OpenBraceIndex,
        [int]$MaxScan = 20000
    )

    if ($OpenBraceIndex -lt 0 -or $OpenBraceIndex -ge $Text.Length) {
        return -1
    }

    $limit = [Math]::Min($Text.Length, $OpenBraceIndex + $MaxScan)

    $depth = 1
    $inSingle = $false
    $inDouble = $false
    $inTemplate = $false
    $inLineComment = $false
    $inBlockComment = $false
    $escape = $false

    for ($i = $OpenBraceIndex + 1; $i -lt $limit; $i++) {
        $ch = $Text[$i]
        $next = if ($i + 1 -lt $limit) { $Text[$i + 1] } else { [char]0 }

        if ($inLineComment) {
            if ($ch -eq "`n") { $inLineComment = $false }
            continue
        }
        if ($inBlockComment) {
            if ($ch -eq '*' -and $next -eq '/') { $inBlockComment = $false; $i++; continue }
            continue
        }

        if ($inSingle) {
            if ($escape) { $escape = $false; continue }
            if ($ch -eq '\') { $escape = $true; continue }
            if ($ch -eq "'") { $inSingle = $false }
            continue
        }
        if ($inDouble) {
            if ($escape) { $escape = $false; continue }
            if ($ch -eq '\') { $escape = $true; continue }
            if ($ch -eq '"') { $inDouble = $false }
            continue
        }
        if ($inTemplate) {
            if ($escape) { $escape = $false; continue }
            if ($ch -eq '\') { $escape = $true; continue }
            if ($ch -eq '`') { $inTemplate = $false }
            continue
        }

        # Comment detection
        if ($ch -eq '/' -and $next -eq '/') { $inLineComment = $true; $i++; continue }
        if ($ch -eq '/' -and $next -eq '*') { $inBlockComment = $true; $i++; continue }

        # Strings/template strings
        if ($ch -eq "'") { $inSingle = $true; continue }
        if ($ch -eq '"') { $inDouble = $true; continue }
        if ($ch -eq '`') { $inTemplate = $true; continue }

        # Brace depth
        if ($ch -eq '{') { $depth++; continue }
        if ($ch -eq '}') {
            $depth--
            if ($depth -eq 0) { return $i }
        }
    }

    return -1
}

# 🔧 Modify Cursor core JS files to implement device identification bypass (enhanced triple solution)
function Modify-CursorJSFiles {
    Write-Host ""
    Write-Host "$BLUE🔧 [Core Modification]$NC Starting to modify Cursor core JS files for device identification bypass..."
    Write-Host "$BLUE💡 [Solution]$NC Using enhanced triple solution: placeholder replacement + b6 fixed-point rewrite + Loader Stub + External Hook"
    Write-Host ""

    # Windows Cursor application path
    $cursorAppPath = Resolve-CursorInstallPath -AllowPrompt
    if (-not $cursorAppPath) {
        return $false
    }

    # Generate or reuse device identifiers
    $useConfigIds = $false
    if ($global:CursorIds -and $global:CursorIds.machineId -and $global:CursorIds.macMachineId -and $global:CursorIds.devDeviceId -and $global:CursorIds.sqmId) {
        $machineId = [string]$global:CursorIds.machineId
        $macMachineId = [string]$global:CursorIds.macMachineId
        $deviceId = [string]$global:CursorIds.devDeviceId
        $sqmId = [string]$global:CursorIds.sqmId
        $machineGuid = if ($global:CursorIds.machineGuid) { [string]$global:CursorIds.machineGuid } else { [System.Guid]::NewGuid().ToString().ToLower() }
        $sessionId = if ($global:CursorIds.sessionId) { [string]$global:CursorIds.sessionId } else { [System.Guid]::NewGuid().ToString().ToLower() }
        $firstSessionDateValue = if ($global:CursorIds.firstSessionDate) {
            $rawFirstSessionDate = $global:CursorIds.firstSessionDate
            if ($rawFirstSessionDate -is [DateTime]) {
                $rawFirstSessionDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            } elseif ($rawFirstSessionDate -is [DateTimeOffset]) {
                $rawFirstSessionDate.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            } else {
                [string]$rawFirstSessionDate
            }
        } else {
            (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        }
        $macAddress = if ($global:CursorIds.macAddress) { [string]$global:CursorIds.macAddress } else { "00:11:22:33:44:55" }
        $useConfigIds = $true
    } else {
        $randomBytes = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
        $rng.GetBytes($randomBytes)
        $machineId = [System.BitConverter]::ToString($randomBytes) -replace '-',''
        $rng.Dispose()
        $deviceId = [System.Guid]::NewGuid().ToString().ToLower()
        $randomBytes2 = New-Object byte[] 32
        $rng2 = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
        $rng2.GetBytes($randomBytes2)
        $macMachineId = [System.BitConverter]::ToString($randomBytes2) -replace '-',''
        $rng2.Dispose()
        $sqmId = "{" + [System.Guid]::NewGuid().ToString().ToUpper() + "}"
        $machineGuid = [System.Guid]::NewGuid().ToString().ToLower()
        $sessionId = [System.Guid]::NewGuid().ToString().ToLower()
        $firstSessionDateValue = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $macAddress = "00:11:22:33:44:55"
    }

    if ($useConfigIds) {
        Write-Host "$GREEN🔑 [Ready]$NC Using device identifiers from configuration"
    } else {
        Write-Host "$GREEN🔑 [Generated]$NC Generated new device identifiers"
    }
    Write-Host "   machineId: $($machineId.Substring(0,16))..."
    Write-Host "   machineGuid: $($machineGuid.Substring(0,16))..."
    Write-Host "   deviceId: $($deviceId.Substring(0,16))..."
    Write-Host "   macMachineId: $($macMachineId.Substring(0,16))..."
    Write-Host "   sqmId: $sqmId"

    # Save ID configuration to user directory
    $idsConfigPath = "$env:USERPROFILE\.cursor_ids.json"
    if (Test-Path $idsConfigPath) {
        Remove-Item -Path $idsConfigPath -Force
        Write-Host "$YELLOW🗑️  [Cleanup]$NC Deleted old ID configuration file"
    }
    $idsConfig = @{
        machineId = $machineId
        machineGuid = $machineGuid
        macMachineId = $macMachineId
        devDeviceId = $deviceId
        sqmId = $sqmId
        macAddress = $macAddress
        sessionId = $sessionId
        firstSessionDate = $firstSessionDateValue
        createdAt = $firstSessionDateValue
    }
    $idsConfig | ConvertTo-Json | Set-Content -Path $idsConfigPath -Encoding UTF8
    Write-Host "$GREEN💾 [Saved]$NC New ID configuration saved to: $idsConfigPath"

    # Deploy external Hook file
    $hookTargetPath = "$env:USERPROFILE\.cursor_hook.js"
    $hookSourceCandidates = @()
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $hookSourceCandidates += (Join-Path $PSScriptRoot "..\hook\cursor_hook.js")
    } elseif ($MyInvocation.MyCommand.Path) {
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        if (-not [string]::IsNullOrWhiteSpace($scriptDir)) {
            $hookSourceCandidates += (Join-Path $scriptDir "..\hook\cursor_hook.js")
        }
    }
    $cwdPath = $null
    try { $cwdPath = (Get-Location).Path } catch { $cwdPath = $null }
    if (-not [string]::IsNullOrWhiteSpace($cwdPath)) {
        $hookSourceCandidates += (Join-Path $cwdPath "scripts\hook\cursor_hook.js")
    }
    $hookSourcePath = $hookSourceCandidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    $hookDownloadUrls = @(
        "https://wget.la/https://raw.githubusercontent.com/yuaotian/go-cursor-help/refs/heads/master/scripts/hook/cursor_hook.js",
        "https://down.npee.cn/?https://raw.githubusercontent.com/yuaotian/go-cursor-help/refs/heads/master/scripts/hook/cursor_hook.js",
        "https://xget.xi-xu.me/gh/yuaotian/go-cursor-help/refs/heads/master/scripts/hook/cursor_hook.js",
        "https://gh-proxy.com/https://raw.githubusercontent.com/yuaotian/go-cursor-help/refs/heads/master/scripts/hook/cursor_hook.js",
        "https://gh.chjina.com/https://raw.githubusercontent.com/yuaotian/go-cursor-help/refs/heads/master/scripts/hook/cursor_hook.js"
    )
    if ($env:CURSOR_HOOK_DOWNLOAD_URLS) {
        $hookDownloadUrls = $env:CURSOR_HOOK_DOWNLOAD_URLS -split '\s*,\s*' | Where-Object { $_ }
        Write-Host "$BLUEℹ️  [Hook]$NC Detected custom download node list, will use it first"
    }
    if ($hookSourcePath) {
        try {
            Copy-Item -Path $hookSourcePath -Destination $hookTargetPath -Force
            Write-Host "$GREEN✅ [Hook]$NC External Hook deployed: $hookTargetPath"
        } catch {
            Write-Host "$YELLOW⚠️  [Hook]$NC Local Hook copy failed, trying online download..."
        }
    }
    if (-not (Test-Path $hookTargetPath)) {
        Write-Host "$BLUEℹ️  [Hook]$NC Downloading external Hook for device identification interception..."
        $originalProgressPreference = $ProgressPreference
        $ProgressPreference = 'Continue'
        try {
            if ($hookDownloadUrls.Count -eq 0) {
                Write-Host "$YELLOW⚠️  [Hook]$NC Download node list empty, skipping online download"
            } else {
                $totalUrls = $hookDownloadUrls.Count
                for ($i = 0; $i -lt $totalUrls; $i++) {
                    $url = $hookDownloadUrls[$i]
                    $attempt = $i + 1
                    Write-Host "$BLUE⏳ [Hook]$NC ($attempt/$totalUrls) Current download node: $url"
                    try {
                        Invoke-WebRequest -Uri $url -OutFile $hookTargetPath -UseBasicParsing -ErrorAction Stop
                        Write-Host "$GREEN✅ [Hook]$NC External Hook downloaded online: $hookTargetPath"
                        break
                    } catch {
                        Write-Host "$YELLOW⚠️  [Hook]$NC External Hook download failed: $url"
                        if (Test-Path $hookTargetPath) {
                            Remove-Item -Path $hookTargetPath -Force
                        }
                    }
                }
            }
        } finally {
            $ProgressPreference = $originalProgressPreference
        }
        if (-not (Test-Path $hookTargetPath)) {
            Write-Host "$YELLOW⚠️  [Hook]$NC All external Hook downloads failed"
        }
    }

    # Target JS file list
    $jsFiles = @(
        "$cursorAppPath\resources\app\out\main.js",
        "$cursorAppPath\resources\app\out\vs\code\electron-utility\sharedProcess\sharedProcessMain.js"
    )

    $modifiedCount = 0

    # Close Cursor processes
    Write-Host "$BLUE🔄 [Closing]$NC Closing Cursor processes for file modification..."
    Stop-AllCursorProcesses -MaxRetries 3 -WaitSeconds 3 | Out-Null

    # Create backup directory
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupPath = "$cursorAppPath\resources\app\out\backups"

    Write-Host "$BLUE💾 [Backup]$NC Creating Cursor JS file backups..."
    try {
        New-Item -ItemType Directory -Path $backupPath -Force | Out-Null

        $originalBackup = "$backupPath\main.js.original"

        foreach ($file in $jsFiles) {
            if (-not (Test-Path $file)) {
                Write-Host "$YELLOW⚠️  [Warning]$NC File doesn't exist: $(Split-Path $file -Leaf)"
                continue
            }

            $fileName = Split-Path $file -Leaf
            $fileOriginalBackup = "$backupPath\$fileName.original"

            if (-not (Test-Path $fileOriginalBackup)) {
                $content = Get-Content $file -Raw -ErrorAction SilentlyContinue
                if ($content -and $content -match "__cursor_patched__") {
                    Write-Host "$YELLOW⚠️  [Warning]$NC File has been modified but no original backup, will use current version as base"
                }
                Copy-Item $file $fileOriginalBackup -Force
                Write-Host "$GREEN✅ [Backup]$NC Original backup created successfully: $fileName"
            } else {
                Write-Host "$BLUE🔄 [Restore]$NC Restoring from original backup: $fileName"
                Copy-Item $fileOriginalBackup $file -Force
            }
        }

        foreach ($file in $jsFiles) {
            if (Test-Path $file) {
                $fileName = Split-Path $file -Leaf
                Copy-Item $file "$backupPath\$fileName.backup_$timestamp" -Force
            }
        }
        Write-Host "$GREEN✅ [Backup]$NC Timestamp backup created successfully: $backupPath"
    } catch {
        Write-Host "$RED❌ [Error]$NC Failed to create backup: $($_.Exception.Message)"
        return $false
    }

    # Modify JS files
    Write-Host "$BLUE🔧 [Modifying]$NC Starting to modify JS files (using device identifiers)..."

    foreach ($file in $jsFiles) {
        if (-not (Test-Path $file)) {
            Write-Host "$YELLOW⚠️  [Skipping]$NC File doesn't exist: $(Split-Path $file -Leaf)"
            continue
        }

        Write-Host "$BLUE📝 [Processing]$NC Processing: $(Split-Path $file -Leaf)"

        try {
            $content = Get-Content $file -Raw -Encoding UTF8
            $replaced = $false
            $replacedB6 = $false

            # ========== Method A: someValue placeholder replacement ==========
            if (-not $firstSessionDateValue) {
                $firstSessionDateValue = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            }

            $placeholders = @(
                @{ Name = 'someValue.machineId';         Value = [string]$machineId },
                @{ Name = 'someValue.macMachineId';      Value = [string]$macMachineId },
                @{ Name = 'someValue.devDeviceId';       Value = [string]$deviceId },
                @{ Name = 'someValue.sqmId';             Value = [string]$sqmId },
                @{ Name = 'someValue.sessionId';         Value = [string]$sessionId },
                @{ Name = 'someValue.firstSessionDate';  Value = [string]$firstSessionDateValue }
            )

            foreach ($ph in $placeholders) {
                $name = $ph.Name
                $jsonValue = ($ph.Value | ConvertTo-Json -Compress)

                $changed = $false

                $doubleLiteral = '"' + $name + '"'
                if ($content.Contains($doubleLiteral)) {
                    $content = $content.Replace($doubleLiteral, $jsonValue)
                    $changed = $true
                }
                $singleLiteral = "'" + $name + "'"
                if ($content.Contains($singleLiteral)) {
                    $content = $content.Replace($singleLiteral, $jsonValue)
                    $changed = $true
                }

                if (-not $changed -and $content.Contains($name)) {
                    $content = $content.Replace($name, $jsonValue)
                    $changed = $true
                }

                if ($changed) {
                    Write-Host "   $GREEN✓$NC [Solution A] Replaced $name"
                    $replaced = $true
                }
            }

            # ========== Method B: b6 fixed-point rewrite ==========
            if ((Split-Path $file -Leaf) -eq "main.js") {
                try {
                    $moduleMarker = "out-build/vs/base/node/id.js"
                    $markerIndex = $content.IndexOf($moduleMarker)
                    if ($markerIndex -lt 0) {
                        throw "id.js module marker not found"
                    }

                    $windowLen = [Math]::Min($content.Length - $markerIndex, 200000)
                    $windowText = $content.Substring($markerIndex, $windowLen)

                    $hashRegex = [regex]::new('createHash\(["'']sha256["'']\)')
                    $hashMatches = $hashRegex.Matches($windowText)
                    Write-Host "   $BLUEℹ️  $NC [Solution B Diagnostic] id.js offset=$markerIndex | sha256 createHash hits=$($hashMatches.Count)"
                    $patched = $false
                    $diagLines = @()
                    $candidateNo = 0

                    foreach ($hm in $hashMatches) {
                        $candidateNo++
                        $hashPos = $hm.Index
                        $funcStart = $windowText.LastIndexOf("async function", $hashPos)
                        if ($funcStart -lt 0) {
                            if ($candidateNo -le 3) { $diagLines += "Candidate #${candidateNo}: async function start not found" }
                            continue
                        }

                        $openBrace = $windowText.IndexOf("{", $funcStart)
                        if ($openBrace -lt 0) {
                            if ($candidateNo -le 3) { $diagLines += "Candidate #${candidateNo}: function opening brace not found" }
                            continue
                        }

                        $endBrace = Find-JsMatchingBraceEnd -Text $windowText -OpenBraceIndex $openBrace -MaxScan 20000
                        if ($endBrace -lt 0) {
                            if ($candidateNo -le 3) { $diagLines += "Candidate #${candidateNo}: Brace pairing failed" }
                            continue
                        }

                        $funcText = $windowText.Substring($funcStart, $endBrace - $funcStart + 1)
                        if ($funcText.Length -gt 8000) {
                            if ($candidateNo -le 3) { $diagLines += "Candidate #${candidateNo}: Function body too long len=$($funcText.Length), skipped" }
                            continue
                        }

                        $sig = [regex]::Match($funcText, '^async function (\w+)\((\w+)\)')
                        if (-not $sig.Success) {
                            if ($candidateNo -le 3) { $diagLines += "Candidate #${candidateNo}: Failed to parse function signature" }
                            continue
                        }
                        $fn = $sig.Groups[1].Value
                        $param = $sig.Groups[2].Value

                        $hasDigest = ($funcText -match '\.digest\(["'']hex["'']\)')
                        $hasReturn = ($funcText -match ('return\s+' + [regex]::Escape($param) + '\?\w+:\w+\}'))
                        if ($candidateNo -le 3) {
                            $diagLines += "Candidate #${candidateNo}: $fn($param) len=$($funcText.Length) digest=$hasDigest return=$hasReturn"
                        }
                        if (-not $hasDigest) { continue }
                        if (-not $hasReturn) { continue }

                        $replacement = "async function $fn($param){return $param?'$machineGuid':'$machineId';}"
                        $absStart = $markerIndex + $funcStart
                        $absEnd = $markerIndex + $endBrace
                        $content = $content.Substring(0, $absStart) + $replacement + $content.Substring($absEnd + 1)

                        Write-Host "   $BLUEℹ️  $NC [Solution B Diagnostic] Hit candidate #${candidateNo}: $fn($param) len=$($funcText.Length)"
                        Write-Host "   $GREEN✓$NC [Solution B] Rewrote $fn($param) machine code source function"
                        $replacedB6 = $true
                        $patched = $true
                        break
                    }

                    if (-not $patched) {
                        Write-Host "   $YELLOW⚠️  $NC [Solution B] Machine code source function features not located, skipping"
                        foreach ($d in ($diagLines | Select-Object -First 3)) {
                            Write-Host "      $BLUEℹ️  $NC [Solution B Diagnostic] $d"
                        }
                    }
                } catch {
                    Write-Host "   $YELLOW⚠️  $NC [Solution B] Location failed, skipping: $($_.Exception.Message)"
                }
            }

            # ========== Method C: Loader Stub injection ==========
            $injectCode = @"
// ========== Cursor Hook Loader Start ==========
;(async function(){/*__cursor_patched__*/
'use strict';
if (globalThis.__cursor_hook_loaded__) return;
globalThis.__cursor_hook_loaded__ = true;

try {
    var fsMod = await import('fs');
    var pathMod = await import('path');
    var osMod = await import('os');
    var urlMod = await import('url');

    var fs = fsMod && (fsMod.default || fsMod);
    var path = pathMod && (pathMod.default || pathMod);
    var os = osMod && (osMod.default || osMod);
    var url = urlMod && (urlMod.default || urlMod);

    if (fs && path && os && url && typeof url.pathToFileURL === 'function') {
        var hookPath = path.join(os.homedir(), '.cursor_hook.js');
        if (typeof fs.existsSync === 'function' && fs.existsSync(hookPath)) {
            await import(url.pathToFileURL(hookPath).href);
        }
    }
} catch (e) {
}
})();
// ========== Cursor Hook Loader End ==========

"@

            if ($content -match "__cursor_patched__") {
                Write-Host "   $YELLOW⚠️  $NC [Solution C] Detected existing injection marker, skipping duplicate injection"
            } elseif ($content -match '(\*/\s*\n)') {
                $replacement = '$1' + $injectCode
                $content = [regex]::Replace($content, '(\*/\s*\n)', $replacement, 1)
                Write-Host "   $GREEN✓$NC [Solution C] Loader Stub injected (after copyright notice, first time only)"
            } else {
                $content = $injectCode + $content
                Write-Host "   $GREEN✓$NC [Solution C] Loader Stub injected (file beginning)"
            }

            $patchedCount = ([regex]::Matches($content, "__cursor_patched__")).Count
            if ($patchedCount -gt 1) {
                throw "Detected duplicate injection markers: $patchedCount"
            }

            Set-Content -Path $file -Value $content -Encoding UTF8 -NoNewline

            $summaryParts = @()
            if ($replaced) { $summaryParts += "someValue replacement" }
            if ($replacedB6) { $summaryParts += "b6 fixed-point rewrite" }
            $summaryParts += "Hook loader"
            $summaryText = ($summaryParts -join " + ")
            Write-Host "$GREEN✅ [Success]$NC Enhanced solution modification successful ($summaryText)"
            $modifiedCount++

        } catch {
            Write-Host "$RED❌ [Error]$NC Failed to modify file: $($_.Exception.Message)"
            $fileName = Split-Path $file -Leaf
            $backupFile = "$backupPath\$fileName.original"
            if (Test-Path $backupFile) {
                Copy-Item $backupFile $file -Force
                Write-Host "$YELLOW🔄 [Restored]$NC File restored from backup"
            }
        }
    }

    if ($modifiedCount -gt 0) {
        Write-Host ""
        Write-Host "$GREEN🎉 [Complete]$NC Successfully modified $modifiedCount JS files"
        Write-Host "$BLUE💾 [Backup]$NC Original file backup location: $backupPath"
        Write-Host "$BLUE💡 [Explanation]$NC Using enhanced triple solution:"
        Write-Host "   • Solution A: someValue placeholder replacement"
        Write-Host "   • Solution B: b6 fixed-point rewrite"
        Write-Host "   • Solution C: Loader Stub + External Hook"
        Write-Host "$BLUE📁 [Configuration]$NC ID configuration file: $idsConfigPath"
        return $true
    } else {
        Write-Host "$RED❌ [Failed]$NC No files successfully modified"
        return $false
    }
}

# 🚀 Cursor trial protection delete folders function
function Remove-CursorTrialFolders {
    Write-Host ""
    Write-Host "$GREEN🎯 [Core Function]$NC Executing Cursor trial protection folder deletion..."
    Write-Host "$BLUE📋 [Explanation]$NC This function will delete specified Cursor-related folders to reset trial status"
    Write-Host ""

    $foldersToDelete = @()

    $adminPaths = @(
        "C:\Users\Administrator\.cursor",
        "C:\Users\Administrator\AppData\Roaming\Cursor"
    )

    $currentUserPaths = @()
    $userProfileRoot = if ($global:CursorUserProfileRoot) { $global:CursorUserProfileRoot } else { [Environment]::GetEnvironmentVariable("USERPROFILE") }
    if ($userProfileRoot) {
        $currentUserPaths += (Join-Path $userProfileRoot ".cursor")
    }
    if ($global:CursorAppDataDir) {
        $currentUserPaths += $global:CursorAppDataDir
    }

    $foldersToDelete += $adminPaths
    $foldersToDelete += $currentUserPaths

    Write-Host "$BLUE📂 [Detecting]$NC Will check the following folders:"
    foreach ($folder in $foldersToDelete) {
        Write-Host "   📁 $folder"
    }
    Write-Host ""

    $deletedCount = 0
    $skippedCount = 0
    $errorCount = 0

    foreach ($folder in $foldersToDelete) {
        Write-Host "$BLUE🔍 [Checking]$NC Checking folder: $folder"

        if (Test-Path $folder) {
            try {
                Write-Host "$YELLOW⚠️  [Warning]$NC Folder exists, deleting..."
                Remove-Item -Path $folder -Recurse -Force -ErrorAction Stop
                Write-Host "$GREEN✅ [Success]$NC Deleted folder: $folder"
                $deletedCount++
            }
            catch {
                Write-Host "$RED❌ [Error]$NC Failed to delete folder: $folder"
                Write-Host "$RED💥 [Details]$NC Error: $($_.Exception.Message)"
                $errorCount++
            }
        } else {
            Write-Host "$YELLOW⏭️  [Skipping]$NC Folder doesn't exist: $folder"
            $skippedCount++
        }
        Write-Host ""
    }

    Write-Host "$GREEN📊 [Statistics]$NC Operation completion statistics:"
    Write-Host "   ✅ Successfully deleted: $deletedCount folders"
    Write-Host "   ⏭️  Skipped: $skippedCount folders"
    Write-Host "   ❌ Deletion failed: $errorCount folders"
    Write-Host ""

    if ($deletedCount -gt 0) {
        Write-Host "$GREEN🎉 [Complete]$NC Cursor trial protection folder deletion complete!"

        Write-Host "$BLUE🔧 [Fixing]$NC Pre-creating necessary directory structure to avoid permission issues..."

        $cursorAppData = $global:CursorAppDataDir
        $cursorLocalAppData = $global:CursorLocalAppDataDir
        $cursorUserProfile = if ($userProfileRoot) { Join-Path $userProfileRoot ".cursor" } else { "$env:USERPROFILE\.cursor" }

        try {
            if ($cursorAppData -and -not (Test-Path $cursorAppData)) {
                New-Item -ItemType Directory -Path $cursorAppData -Force | Out-Null
            }
            if ($cursorUserProfile -and -not (Test-Path $cursorUserProfile)) {
                New-Item -ItemType Directory -Path $cursorUserProfile -Force | Out-Null
            }
            Write-Host "$GREEN✅ [Complete]$NC Directory structure pre-creation complete"
        } catch {
            Write-Host "$YELLOW⚠️  [Warning]$NC Issues during directory pre-creation: $($_.Exception.Message)"
        }
    } else {
        Write-Host "$YELLOW🤔 [Hint]$NC No folders found to delete, may have been cleaned already"
    }
    Write-Host ""
}

# 🔄 Restart Cursor and wait for configuration file generation
function Restart-CursorAndWait {
    Write-Host ""
    Write-Host "$GREEN🔄 [Restarting]$NC Restarting Cursor to regenerate configuration file..."

    if (-not $global:CursorProcessInfo) {
        Write-Host "$RED❌ [Error]$NC No Cursor process information found, cannot restart"
        return $false
    }

    $cursorPath = $global:CursorProcessInfo.Path

    if ($cursorPath -is [array]) {
        $cursorPath = $cursorPath[0]
    }

    if ([string]::IsNullOrEmpty($cursorPath)) {
        Write-Host "$RED❌ [Error]$NC Cursor path is empty"
        return $false
    }

    Write-Host "$BLUE📍 [Path]$NC Using path: $cursorPath"

    if (-not (Test-Path $cursorPath)) {
        Write-Host "$RED❌ [Error]$NC Cursor executable doesn't exist: $cursorPath"

        $installPath = Resolve-CursorInstallPath -AllowPrompt
        $foundPath = if ($installPath) { Join-Path $installPath "Cursor.exe" } else { $null }
        if ($foundPath -and (Test-Path $foundPath)) {
            Write-Host "$GREEN💡 [Found]$NC Using alternative path: $foundPath"
        } else {
            $foundPath = $null
        }

        if (-not $foundPath) {
            Write-Host "$RED❌ [Error]$NC Cannot find valid Cursor executable"
            return $false
        }

        $cursorPath = $foundPath
    }

    try {
        Write-Host "$GREEN🚀 [Starting]$NC Starting Cursor..."
        $process = Start-Process -FilePath $cursorPath -PassThru -WindowStyle Hidden

        Write-Host "$YELLOW⏳ [Waiting]$NC Waiting 20 seconds for Cursor to fully start and generate configuration file..."
        Start-Sleep -Seconds 20

        $configPath = $STORAGE_FILE
        if (-not $configPath) {
            Write-Host "$RED❌ [Error]$NC Cannot resolve configuration file path"
            return $false
        }
        $maxWait = 45
        $waited = 0

        while (-not (Test-Path $configPath) -and $waited -lt $maxWait) {
            Write-Host "$YELLOW⏳ [Waiting]$NC Waiting for configuration file generation... ($waited/$maxWait seconds)"
            Start-Sleep -Seconds 1
            $waited++
        }

        if (Test-Path $configPath) {
            Write-Host "$GREEN✅ [Success]$NC Configuration file generated: $configPath"

            Write-Host "$YELLOW⏳ [Waiting]$NC Waiting 5 seconds to ensure configuration file is completely written..."
            Start-Sleep -Seconds 5
        } else {
            Write-Host "$YELLOW⚠️  [Warning]$NC Configuration file not generated within expected time"
            Write-Host "$BLUE💡 [Hint]$NC May need to manually start Cursor once to generate configuration file"
        }

        Write-Host "$YELLOW🔄 [Closing]$NC Closing Cursor for configuration modification..."
        if ($process -and -not $process.HasExited) {
            $process.Kill()
            $process.WaitForExit(5000)
        }

        Get-Process -Name "Cursor" -ErrorAction SilentlyContinue | Stop-Process -Force
        Get-Process -Name "cursor" -ErrorAction SilentlyContinue | Stop-Process -Force

        Write-Host "$GREEN✅ [Complete]$NC Cursor restart process complete"
        return $true

    } catch {
        Write-Host "$RED❌ [Error]$NC Failed to restart Cursor: $($_.Exception.Message)"
        Write-Host "$BLUE💡 [Debug]$NC Error details: $($_.Exception.GetType().FullName)"
        return $false
    }
}

# 🔒 Force close all Cursor processes
function Stop-AllCursorProcesses {
    param(
        [int]$MaxRetries = 3,
        [int]$WaitSeconds = 5
    )

    Write-Host "$BLUE🔒 [Process Check]$NC Checking and closing all Cursor-related processes..."

    $cursorProcessNames = @(
        "Cursor",
        "cursor",
        "Cursor Helper",
        "Cursor Helper (GPU)",
        "Cursor Helper (Plugin)",
        "Cursor Helper (Renderer)",
        "CursorUpdater"
    )

    for ($retry = 1; $retry -le $MaxRetries; $retry++) {
        Write-Host "$BLUE🔍 [Checking]$NC Process check $retry/$MaxRetries..."

        $foundProcesses = @()
        foreach ($processName in $cursorProcessNames) {
            $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
            if ($processes) {
                $foundProcesses += $processes
                Write-Host "$YELLOW⚠️  [Found]$NC Process: $processName (PID: $($processes.Id -join ', '))"
            }
        }

        if ($foundProcesses.Count -eq 0) {
            Write-Host "$GREEN✅ [Success]$NC All Cursor processes closed"
            return $true
        }

        Write-Host "$YELLOW🔄 [Closing]$NC Closing $($foundProcesses.Count) Cursor processes..."

        foreach ($process in $foundProcesses) {
            try {
                $process.CloseMainWindow() | Out-Null
                Write-Host "$BLUE  • Graceful close: $($process.ProcessName) (PID: $($process.Id))$NC"
            } catch {
                Write-Host "$YELLOW  • Graceful close failed: $($process.ProcessName)$NC"
            }
        }

        Start-Sleep -Seconds 3

        foreach ($processName in $cursorProcessNames) {
            $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
            if ($processes) {
                foreach ($process in $processes) {
                    try {
                        Stop-Process -Id $process.Id -Force
                        Write-Host "$RED  • Force terminate: $($process.ProcessName) (PID: $($process.Id))$NC"
                    } catch {
                        Write-Host "$RED  • Force terminate failed: $($process.ProcessName)$NC"
                    }
                }
            }
        }

        if ($retry -lt $MaxRetries) {
            Write-Host "$YELLOW⏳ [Waiting]$NC Waiting $WaitSeconds seconds before re-checking..."
            Start-Sleep -Seconds $WaitSeconds
        }
    }

    Write-Host "$RED❌ [Failed]$NC After $MaxRetries attempts, Cursor processes still running"
    return $false
}

# 🔐 Check file permissions and lock status
function Test-FileAccessibility {
    param(
        [string]$FilePath
    )

    Write-Host "$BLUE🔐 [Permission Check]$NC Checking file access permissions: $(Split-Path $FilePath -Leaf)"

    if (-not (Test-Path $FilePath)) {
        Write-Host "$RED❌ [Error]$NC File doesn't exist"
        return $false
    }

    try {
        $fileStream = [System.IO.File]::Open($FilePath, 'Open', 'ReadWrite', 'None')
        $fileStream.Close()
        Write-Host "$GREEN✅ [Permissions]$NC File is readable/writable, not locked"
        return $true
    } catch [System.IO.IOException] {
        Write-Host "$RED❌ [Locked]$NC File locked by another process: $($_.Exception.Message)"
        return $false
    } catch [System.UnauthorizedAccessException] {
        Write-Host "$YELLOW⚠️  [Permissions]$NC File permissions restricted, trying to modify permissions..."

        try {
            $file = Get-Item $FilePath
            if ($file.IsReadOnly) {
                $file.IsReadOnly = $false
                Write-Host "$GREEN✅ [Fixed]$NC Removed read-only attribute"
            }

            $fileStream = [System.IO.File]::Open($FilePath, 'Open', 'ReadWrite', 'None')
            $fileStream.Close()
            Write-Host "$GREEN✅ [Permissions]$NC Permission fix successful"
            return $true
        } catch {
            Write-Host "$RED❌ [Permissions]$NC Cannot fix permissions: $($_.Exception.Message)"
            return $false
        }
    } catch {
        Write-Host "$RED❌ [Error]$NC Unknown error: $($_.Exception.Message)"
        return $false
    }
}

# 🧹 Cursor initialization cleanup function
function Invoke-CursorInitialization {
    Write-Host ""
    Write-Host "$GREEN🧹 [Initialization]$NC Executing Cursor initialization cleanup..."
    $BASE_PATH = if ($global:CursorAppDataDir) { Join-Path $global:CursorAppDataDir "User" } else { $null }
    if (-not $BASE_PATH) {
        Write-Host "$RED❌ [Error]$NC Cannot resolve Cursor user directory, initialization cleanup terminated"
        return
    }

    $filesToDelete = @(
        (Join-Path -Path $BASE_PATH -ChildPath "globalStorage\state.vscdb"),
        (Join-Path -Path $BASE_PATH -ChildPath "globalStorage\state.vscdb.backup")
    )

    $folderToCleanContents = Join-Path -Path $BASE_PATH -ChildPath "History"
    $folderToDeleteCompletely = Join-Path -Path $BASE_PATH -ChildPath "workspaceStorage"

    Write-Host "$BLUE🔍 [Debug]$NC Base path: $BASE_PATH"

    foreach ($file in $filesToDelete) {
        Write-Host "$BLUE🔍 [Checking]$NC Checking file: $file"
        if (Test-Path $file) {
            try {
                Remove-Item -Path $file -Force -ErrorAction Stop
                Write-Host "$GREEN✅ [Success]$NC Deleted file: $file"
            }
            catch {
                Write-Host "$RED❌ [Error]$NC Failed to delete file $file: $($_.Exception.Message)"
            }
        } else {
            Write-Host "$YELLOW⚠️  [Skipping]$NC File doesn't exist, skipping deletion: $file"
        }
    }

    Write-Host "$BLUE🔍 [Checking]$NC Checking folder to clear: $folderToCleanContents"
    if (Test-Path $folderToCleanContents) {
        try {
            Get-ChildItem -Path $folderToCleanContents -Recurse | Remove-Item -Force -Recurse -ErrorAction Stop
            Write-Host "$GREEN✅ [Success]$NC Cleared folder contents: $folderToCleanContents"
        }
        catch {
            Write-Host "$RED❌ [Error]$NC Failed to clear folder $folderToCleanContents: $($_.Exception.Message)"
        }
    } else {
        Write-Host "$YELLOW⚠️  [Skipping]$NC Folder doesn't exist, skipping clear: $folderToCleanContents"
    }

    Write-Host "$BLUE🔍 [Checking]$NC Checking folder to delete: $folderToDeleteCompletely"
    if (Test-Path $folderToDeleteCompletely) {
        try {
            Remove-Item -Path $folderToDeleteCompletely -Recurse -Force -ErrorAction Stop
            Write-Host "$GREEN✅ [Success]$NC Deleted folder: $folderToDeleteCompletely"
        }
        catch {
            Write-Host "$RED❌ [Error]$NC Failed to delete folder $folderToDeleteCompletely: $($_.Exception.Message)"
        }
    } else {
        Write-Host "$YELLOW⚠️  [Skipping]$NC Folder doesn't exist, skipping deletion: $folderToDeleteCompletely"
    }

    Write-Host "$GREEN✅ [Complete]$NC Cursor initialization cleanup complete"
    Write-Host ""
}

# 🔧 Modify system registry MachineGuid
function Update-MachineGuid {
    try {
        Write-Host "$BLUE🔧 [Registry]$NC Modifying system registry MachineGuid..."

        $registryPath = "HKLM:\SOFTWARE\Microsoft\Cryptography"
        if (-not (Test-Path $registryPath)) {
            Write-Host "$YELLOW⚠️  [Warning]$NC Registry path doesn't exist: $registryPath, creating..."
            New-Item -Path $registryPath -Force | Out-Null
            Write-Host "$GREEN✅ [Info]$NC Registry path created successfully"
        }

        $originalGuid = ""
        try {
            $currentGuid = Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction SilentlyContinue
            if ($currentGuid) {
                $originalGuid = $currentGuid.MachineGuid
                Write-Host "$GREEN✅ [Info]$NC Current registry value:"
                Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
                Write-Host "    MachineGuid    REG_SZ    $originalGuid"
            } else {
                Write-Host "$YELLOW⚠️  [Warning]$NC MachineGuid value doesn't exist, will create new value"
            }
        } catch {
            Write-Host "$YELLOW⚠️  [Warning]$NC Failed to read registry: $($_.Exception.Message)"
            Write-Host "$YELLOW⚠️  [Warning]$NC Will try to create new MachineGuid value"
        }

        $backupFile = $null
        if ($originalGuid) {
            $backupFile = "$BACKUP_DIR\MachineGuid_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
            Write-Host "$BLUE💾 [Backup]$NC Backing up registry..."
            $backupResult = Start-Process "reg.exe" -ArgumentList "export", "`"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography`"", "`"$backupFile`"" -NoNewWindow -Wait -PassThru

            if ($backupResult.ExitCode -eq 0) {
                Write-Host "$GREEN✅ [Backup]$NC Registry key backed up to: $backupFile"
            } else {
                Write-Host "$YELLOW⚠️  [Warning]$NC Backup creation failed, continuing..."
                $backupFile = $null
            }
        }

        $newGuid = [System.Guid]::NewGuid().ToString()
        Write-Host "$BLUE🔄 [Generating]$NC New MachineGuid: $newGuid"

        Set-ItemProperty -Path $registryPath -Name MachineGuid -Value $newGuid -Force -ErrorAction Stop

        $verifyGuid = (Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction Stop).MachineGuid
        if ($verifyGuid -ne $newGuid) {
            throw "Registry verification failed: Updated value ($verifyGuid) doesn't match expected value ($newGuid)"
        }

        Write-Host "$GREEN✅ [Success]$NC Registry update successful:"
        Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
        Write-Host "    MachineGuid    REG_SZ    $newGuid"
        return $true
    }
    catch {
        Write-Host "$RED❌ [Error]$NC Registry operation failed: $($_.Exception.Message)"

        if ($backupFile -and (Test-Path $backupFile)) {
            Write-Host "$YELLOW🔄 [Restoring]$NC Restoring from backup..."
            $restoreResult = Start-Process "reg.exe" -ArgumentList "import", "`"$backupFile`"" -NoNewWindow -Wait -PassThru

            if ($restoreResult.ExitCode -eq 0) {
                Write-Host "$GREEN✅ [Restore Success]$NC Original registry value restored"
            } else {
                Write-Host "$RED❌ [Error]$NC Restore failed, please manually import backup file: $backupFile"
            }
        } else {
            Write-Host "$YELLOW⚠️  [Warning]$NC No backup file found or backup creation failed, cannot auto-restore"
        }

        return $false
    }
}

# 🚫 Disable Cursor auto-update
function Disable-CursorAutoUpdate {
    Write-Host ""
    Write-Host "$BLUE🚫 [Disable Updates]$NC Trying to disable Cursor auto-update..."

    $cursorAppPath = Resolve-CursorInstallPath -AllowPrompt
    if (-not $cursorAppPath) {
        Write-Host "$YELLOW⚠️  [Warning]$NC Cursor installation path not found, skipping disable updates"
        return $false
    }

    $updateFiles = @()
    $updateFiles += "$cursorAppPath\resources\app-update.yml"
    $updateFiles += "$cursorAppPath\resources\app\update-config.json"
    if ($global:CursorAppDataDir) {
        $updateFiles += (Join-Path $global:CursorAppDataDir "update-config.json")
        $updateFiles += (Join-Path $global:CursorAppDataDir "settings.json")
    }
    $updateFiles = $updateFiles | Where-Object { $_ }

    foreach ($file in $updateFiles) {
        if (-not (Test-Path $file)) { continue }

        try {
            Copy-Item $file "$file.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')" -Force
        } catch {
            Write-Host "$YELLOW⚠️  [Warning]$NC Backup failed: $file"
        }

        if ($file -like "*.yml") {
            Set-Content -Path $file -Value "# update disabled by script $(Get-Date)" -Encoding UTF8
            Write-Host "$GREEN✅ [Complete]$NC Processed update configuration: $file"
            continue
        }

        if ($file -like "*update-config.json") {
            $config = @{ autoCheck = $false; autoDownload = $false }
            $config | ConvertTo-Json -Depth 5 | Set-Content -Path $file -Encoding UTF8
            Write-Host "$GREEN✅ [Complete]$NC Processed update configuration: $file"
            continue
        }

        if ($file -like "*settings.json") {
            try {
                $settings = Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
            } catch {
                $settings = @{}
            }
            if ($settings -is [hashtable]) {
                $settings["update.mode"] = "none"
            } else {
                $settings | Add-Member -MemberType NoteProperty -Name "update.mode" -Value "none" -Force
            }
            $settings | ConvertTo-Json -Depth 10 | Set-Content -Path $file -Encoding UTF8
            Write-Host "$GREEN✅ [Complete]$NC Processed update configuration: $file"
            continue
        }
    }

    $updaterCandidates = @()
    $updaterCandidates += "$cursorAppPath\Update.exe"
    if ($global:CursorLocalAppDataDir) {
        $updaterCandidates += (Join-Path $global:CursorLocalAppDataDir "Update.exe")
    }
    $updaterCandidates += "$cursorAppPath\CursorUpdater.exe"
    $updaterCandidates = $updaterCandidates | Where-Object { $_ }

    foreach ($updater in $updaterCandidates) {
        if (-not (Test-Path $updater)) { continue }
        $backup = "$updater.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        try {
            Move-Item -Path $updater -Destination $backup -Force
            Write-Host "$GREEN✅ [Complete]$NC Disabled updater: $updater"
        } catch {
            Write-Host "$YELLOW⚠️  [Warning]$NC Updater disable failed: $updater"
        }
    }

    return $true
}

# Check configuration file and environment
function Test-CursorEnvironment {
    param(
        [string]$Mode = "FULL"
    )

    Write-Host ""
    Write-Host "$BLUE🔍 [Environment Check]$NC Checking Cursor environment..."

    $configPath = $STORAGE_FILE
    $cursorAppData = $global:CursorAppDataDir
    $issues = @()

    if (-not $configPath) {
        $issues += "Cannot resolve configuration file path"
    } elseif (-not (Test-Path $configPath)) {
        $issues += "Configuration file doesn't exist: $configPath"
    } else {
        try {
            $content = Get-Content $configPath -Raw -Encoding UTF8 -ErrorAction Stop
            $config = $content | ConvertFrom-Json -ErrorAction Stop
            Write-Host "$GREEN✅ [Check]$NC Configuration file format correct"
        } catch {
            $issues += "Configuration file format error: $($_.Exception.Message)"
        }
    }

    if (-not $cursorAppData -or -not (Test-Path $cursorAppData)) {
        $issues += "Cursor application data directory doesn't exist: $cursorAppData"
    }

    $cursorPaths = @()
    $installPath = Resolve-CursorInstallPath
    if ($installPath) {
        $cursorPaths = @(Join-Path $installPath "Cursor.exe")
    }

    $cursorFound = $false
    foreach ($path in $cursorPaths) {
        if (Test-Path $path) {
            Write-Host "$GREEN✅ [Check]$NC Found Cursor installation: $path"
            $cursorFound = $true
            break
        }
    }

    if (-not $cursorFound) {
        $issues += "Cursor installation not found, please confirm Cursor is correctly installed"
    }

    if ($issues.Count -eq 0) {
        Write-Host "$GREEN✅ [Environment Check]$NC All checks passed"
        return @{ Success = $true; Issues = @() }
    } else {
        Write-Host "$RED❌ [Environment Check]$NC Found $($issues.Count) issues:"
        foreach ($issue in $issues) {
            Write-Host "$RED  • ${issue}$NC"
        }
        return @{ Success = $false; Issues = $issues }
    }
}

# 🛠️ Modify machine code configuration
function Modify-MachineCodeConfig {
    param(
        [string]$Mode = "FULL"
    )

    Write-Host ""
    Write-Host "$GREEN🛠️  [Configuration]$NC Modifying machine code configuration..."

    $configPath = $STORAGE_FILE
    if (-not $configPath) {
        Write-Host "$RED❌ [Error]$NC Cannot resolve configuration file path"
        return $false
    }

    if (-not (Test-Path $configPath)) {
        Write-Host "$RED❌ [Error]$NC Configuration file doesn't exist: $configPath"
        Write-Host ""
        Write-Host "$YELLOW💡 [Solution]$NC Try the following steps:"
        Write-Host "$BLUE  1️⃣  Manually start Cursor application$NC"
        Write-Host "$BLUE  2️⃣  Wait for Cursor to fully load (about 30 seconds)$NC"
        Write-Host "$BLUE  3️⃣  Close Cursor application$NC"
        Write-Host "$BLUE  4️⃣  Re-run this script$NC"
        Write-Host ""
        Write-Host "$YELLOW⚠️  [Alternative]$NC If problem persists:"
        Write-Host "$BLUE  • Select script's 'Reset Environment + Modify Machine Code' option$NC"
        Write-Host "$BLUE  • That option will automatically generate configuration file$NC"
        Write-Host ""

        $userChoice = Read-Host "Try to start Cursor now to generate configuration file? (y/n)"
        if ($userChoice -match "^(y|yes)$") {
            Write-Host "$BLUE🚀 [Trying]$NC Trying to start Cursor..."
            return Start-CursorToGenerateConfig
        }

        return $false
    }

    if ($Mode -eq "MODIFY_ONLY") {
        Write-Host "$BLUE🔒 [Safety Check]$NC Even in modify-only mode, need to ensure all Cursor processes are completely closed"
        if (-not (Stop-AllCursorProcesses -MaxRetries 3 -WaitSeconds 3)) {
            Write-Host "$RED❌ [Error]$NC Cannot close all Cursor processes, modification may fail"
            $userChoice = Read-Host "Force continue? (y/n)"
            if ($userChoice -notmatch "^(y|yes)$") {
                return $false
            }
        }
    }

    if (-not (Test-FileAccessibility -FilePath $configPath)) {
        Write-Host "$RED❌ [Error]$NC Cannot access configuration file, may be locked or insufficient permissions"
        return $false
    }

    try {
        Write-Host "$BLUE🔍 [Verifying]$NC Checking configuration file format..."
        $originalContent = Get-Content $configPath -Raw -Encoding UTF8 -ErrorAction Stop
        $config = $originalContent | ConvertFrom-Json -ErrorAction Stop
        Write-Host "$GREEN✅ [Verify]$NC Configuration file format correct"

        Write-Host "$BLUE📋 [Current Configuration]$NC Checking existing telemetry properties:"
        $telemetryProperties = @('telemetry.machineId', 'telemetry.macMachineId', 'telemetry.devDeviceId', 'telemetry.sqmId')
        foreach ($prop in $telemetryProperties) {
            if ($config.PSObject.Properties[$prop]) {
                $value = $config.$prop
                $displayValue = if ($value.Length -gt 20) { "$($value.Substring(0,20))..." } else { $value }
                Write-Host "$GREEN  ✓ ${prop}$NC = $displayValue"
            } else {
                Write-Host "$YELLOW  - ${prop}$NC (doesn't exist, will create)"
            }
        }
        Write-Host ""
    } catch {
        Write-Host "$RED❌ [Error]$NC Configuration file format error: $($_.Exception.Message)"
        Write-Host "$YELLOW💡 [Suggestion]$NC Configuration file may be corrupted, suggest selecting 'Reset Environment + Modify Machine Code' option"
        return $false
    }

    $maxRetries = 3
    $retryCount = 0

    while ($retryCount -lt $maxRetries) {
        $retryCount++
        Write-Host ""
        Write-Host "$BLUE🔄 [Attempt]$NC Attempt $retryCount/$maxRetries..."

        try {
            Write-Host "$BLUE⏳ [Progress]$NC 1/6 - Generating new device identifiers..."

            $MAC_MACHINE_ID = [System.Guid]::NewGuid().ToString()
            $UUID = [System.Guid]::NewGuid().ToString()
            $prefixBytes = [System.Text.Encoding]::UTF8.GetBytes("auth0|user_")
            $prefixHex = -join ($prefixBytes | ForEach-Object { '{0:x2}' -f $_ })
            $randomBytes = New-Object byte[] 32
            $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
            $rng.GetBytes($randomBytes)
            $randomPart = [System.BitConverter]::ToString($randomBytes) -replace '-',''
            $rng.Dispose()
            $MACHINE_ID = "${prefixHex}${randomPart}"
            $SQM_ID = "{$([System.Guid]::NewGuid().ToString().ToUpper())}"
            $SERVICE_MACHINE_ID = [System.Guid]::NewGuid().ToString()
            $FIRST_SESSION_DATE = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            $SESSION_ID = [System.Guid]::NewGuid().ToString()

            $global:CursorIds = @{
                machineId        = $MACHINE_ID
                macMachineId     = $MAC_MACHINE_ID
                devDeviceId      = $UUID
                sqmId            = $SQM_ID
                firstSessionDate = $FIRST_SESSION_DATE
                sessionId        = $SESSION_ID
                macAddress       = "00:11:22:33:44:55"
            }

            Write-Host "$GREEN✅ [Progress]$NC 1/7 - Device identifiers generation complete"

            Write-Host "$BLUE⏳ [Progress]$NC 2/7 - Creating backup directory..."

            $backupDir = $BACKUP_DIR
            if (-not $backupDir) {
                throw "Cannot resolve backup directory path"
            }
            if (-not (Test-Path $backupDir)) {
                New-Item -ItemType Directory -Path $backupDir -Force -ErrorAction Stop | Out-Null
            }

            $backupName = "storage.json.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')_retry$retryCount"
            $backupPath = "$backupDir\$backupName"

            Write-Host "$BLUE⏳ [Progress]$NC 3/7 - Backing up original configuration..."
            Copy-Item $configPath $backupPath -ErrorAction Stop

            if (Test-Path $backupPath) {
                $backupSize = (Get-Item $backupPath).Length
                $originalSize = (Get-Item $configPath).Length
                if ($backupSize -eq $originalSize) {
                    Write-Host "$GREEN✅ [Progress]$NC 3/7 - Configuration backup successful: $backupName"
                } else {
                    Write-Host "$YELLOW⚠️  [Warning]$NC Backup file size mismatch, but continuing"
                }
            } else {
                throw "Backup file creation failed"
            }

            Write-Host "$BLUE⏳ [Progress]$NC 4/7 - Reading original configuration to memory..."

            $originalContent = Get-Content $configPath -Raw -Encoding UTF8 -ErrorAction Stop
            $config = $originalContent | ConvertFrom-Json -ErrorAction Stop

            Write-Host "$BLUE⏳ [Progress]$NC 5/7 - Updating configuration in memory..."

            $propertiesToUpdate = @{
                'telemetry.machineId' = $MACHINE_ID
                'telemetry.macMachineId' = $MAC_MACHINE_ID
                'telemetry.devDeviceId' = $UUID
                'telemetry.sqmId' = $SQM_ID
                'storage.serviceMachineId' = $SERVICE_MACHINE_ID
                'telemetry.firstSessionDate' = $FIRST_SESSION_DATE
            }

            foreach ($property in $propertiesToUpdate.GetEnumerator()) {
                $key = $property.Key
                $value = $property.Value

                if ($config.PSObject.Properties[$key]) {
                    $config.$key = $value
                    Write-Host "$BLUE  ✓ Update property: ${key}$NC"
                } else {
                    $config | Add-Member -MemberType NoteProperty -Name $key -Value $value -Force
                    Write-Host "$BLUE  + Add property: ${key}$NC"
                }
            }

            Write-Host "$BLUE⏳ [Progress]$NC 6/7 - Atomic writing new configuration file..."

            $tempPath = "$configPath.tmp"
            $updatedJson = $config | ConvertTo-Json -Depth 10

            [System.IO.File]::WriteAllText($tempPath, $updatedJson, [System.Text.Encoding]::UTF8)

            $tempContent = Get-Content $tempPath -Raw -Encoding UTF8 -ErrorAction Stop
            $tempConfig = $tempContent | ConvertFrom-Json -ErrorAction Stop

            $toComparableString = {
                param([object]$v)
                if ($null -eq $v) { return $null }
                if ($v -is [DateTime]) { return $v.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
                if ($v -is [DateTimeOffset]) { return $v.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
                return [string]$v
            }

            $tempVerificationPassed = $true
            foreach ($property in $propertiesToUpdate.GetEnumerator()) {
                $key = $property.Key
                $expectedValue = $property.Value
                $actualValue = $tempConfig.$key

                $expectedComparable = & $toComparableString $expectedValue
                $actualComparable = & $toComparableString $actualValue

                if ($actualComparable -ne $expectedComparable) {
                    $tempVerificationPassed = $false
                    Write-Host "$RED  ✗ Temporary file verification failed: ${key}$NC"
                    $expectedType = if ($null -eq $expectedValue) { '<null>' } else { $expectedValue.GetType().FullName }
                    $actualType = if ($null -eq $actualValue) { '<null>' } else { $actualValue.GetType().FullName }
                    Write-Host "$YELLOW    [Debug] Type: expected=${expectedType}; actual=${actualType}$NC"
                    Write-Host "$YELLOW    [Debug] Value: expected=${expectedComparable}; actual=${actualComparable}$NC"
                    break
                }
            }

            if (-not $tempVerificationPassed) {
                Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
                throw "Temporary file verification failed"
            }

            Remove-Item $configPath -Force
            Move-Item $tempPath $configPath

            $file = Get-Item $configPath
            $file.IsReadOnly = $false

            Write-Host "$BLUE⏳ [Progress]$NC 7/7 - Verifying new configuration file..."

            $verifyContent = Get-Content $configPath -Raw -Encoding UTF8 -ErrorAction Stop
            $verifyConfig = $verifyContent | ConvertFrom-Json -ErrorAction Stop

            $verificationPassed = $true
            $verificationResults = @()

            foreach ($property in $propertiesToUpdate.GetEnumerator()) {
                $key = $property.Key
                $expectedValue = $property.Value
                $actualValue = $verifyConfig.$key

                $expectedComparable = & $toComparableString $expectedValue
                $actualComparable = & $toComparableString $actualValue

                if ($actualComparable -eq $expectedComparable) {
                    $verificationResults += "✓ ${key}: Verification passed"
                } else {
                    $expectedType = if ($null -eq $expectedValue) { '<null>' } else { $expectedValue.GetType().FullName }
                    $actualType = if ($null -eq $actualValue) { '<null>' } else { $actualValue.GetType().FullName }
                    $verificationResults += "✗ ${key}: Verification failed (expected type: ${expectedType}, actual type: ${actualType}; expected: ${expectedComparable}, actual: ${actualComparable})"
                    $verificationPassed = $false
                }
            }

            Write-Host "$BLUE📋 [Verification Details]$NC"
            foreach ($result in $verificationResults) {
                Write-Host "   $result"
            }

            if ($verificationPassed) {
                Write-Host "$GREEN✅ [Success]$NC Attempt $retryCount modification successful!"
                Write-Host ""
                Write-Host "$GREEN🎉 [Complete]$NC Machine code configuration modification complete!"
                Write-Host "$BLUE📋 [Details]$NC Updated the following identifiers:"
                Write-Host "   🔹 machineId: $MACHINE_ID"
                Write-Host "   🔹 macMachineId: $MAC_MACHINE_ID"
                Write-Host "   🔹 devDeviceId: $UUID"
                Write-Host "   🔹 sqmId: $SQM_ID"
                Write-Host "   🔹 serviceMachineId: $SERVICE_MACHINE_ID"
                Write-Host "   🔹 firstSessionDate: $FIRST_SESSION_DATE"
                Write-Host ""
                Write-Host "$GREEN💾 [Backup]$NC Original configuration backed up to: $backupName"

                Write-Host "$BLUE🔧 [machineid]$NC Modifying machineid file..."
                $machineIdFilePath = if ($global:CursorAppDataDir) { Join-Path $global:CursorAppDataDir "machineid" } else { $null }
                if (-not $machineIdFilePath) {
                    Write-Host "$YELLOW⚠️  [machineid]$NC Cannot resolve machineid file path, skipping modification"
                } else {
                    try {
                        if (Test-Path $machineIdFilePath) {
                            $machineIdBackup = "$backupDir\machineid.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                            Copy-Item $machineIdFilePath $machineIdBackup -Force
                            Write-Host "$GREEN💾 [Backup]$NC machineid file backed up: $machineIdBackup"
                        }
                        [System.IO.File]::WriteAllText($machineIdFilePath, $SERVICE_MACHINE_ID, [System.Text.Encoding]::UTF8)
                        Write-Host "$GREEN✅ [machineid]$NC machineid file modified successfully: $SERVICE_MACHINE_ID"

                        $machineIdFile = Get-Item $machineIdFilePath
                        $machineIdFile.IsReadOnly = $true
                        Write-Host "$GREEN🔒 [Protection]$NC machineid file set to read-only"
                    } catch {
                        Write-Host "$YELLOW⚠️  [machineid]$NC machineid file modification failed: $($_.Exception.Message)"
                        Write-Host "$BLUE💡 [Hint]$NC Can manually modify file: $machineIdFilePath"
                    }
                }

                Write-Host "$BLUE🔧 [updaterId]$NC Modifying .updaterId file..."
                $updaterIdFilePath = if ($global:CursorAppDataDir) { Join-Path $global:CursorAppDataDir ".updaterId" } else { $null }
                if (-not $updaterIdFilePath) {
                    Write-Host "$YELLOW⚠️  [updaterId]$NC Cannot resolve .updaterId file path, skipping modification"
                } else {
                    try {
                        if (Test-Path $updaterIdFilePath) {
                            $updaterIdBackup = "$backupDir\.updaterId.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                            Copy-Item $updaterIdFilePath $updaterIdBackup -Force
                            Write-Host "$GREEN💾 [Backup]$NC .updaterId file backed up: $updaterIdBackup"
                        }
                        $newUpdaterId = [System.Guid]::NewGuid().ToString()
                        [System.IO.File]::WriteAllText($updaterIdFilePath, $newUpdaterId, [System.Text.Encoding]::UTF8)
                        Write-Host "$GREEN✅ [updaterId]$NC .updaterId file modified successfully: $newUpdaterId"

                        $updaterIdFile = Get-Item $updaterIdFilePath
                        $updaterIdFile.IsReadOnly = $true
                        Write-Host "$GREEN🔒 [Protection]$NC .updaterId file set to read-only"
                    } catch {
                        Write-Host "$YELLOW⚠️  [updaterId]$NC .updaterId file modification failed: $($_.Exception.Message)"
                        Write-Host "$BLUE💡 [Hint]$NC Can manually modify file: $updaterIdFilePath"
                    }
                }

                Write-Host "$BLUE🔒 [Protection]$NC Setting configuration file protection..."
                try {
                    $configFile = Get-Item $configPath
                    $configFile.IsReadOnly = $true
                    Write-Host "$GREEN✅ [Protection]$NC Configuration file set to read-only, preventing Cursor from overwriting modifications"
                    Write-Host "$BLUE💡 [Hint]$NC File path: $configPath"
                } catch {
                    Write-Host "$YELLOW⚠️  [Protection]$NC Failed to set read-only attribute: $($_.Exception.Message)"
                    Write-Host "$BLUE💡 [Suggestion]$NC Can manually right-click file → Properties → Check 'Read-only'"
                }
                Write-Host "$BLUE 🔒 [Security]$NC Recommended to restart Cursor to ensure configuration takes effect"
                return $true
            } else {
                Write-Host "$RED❌ [Failed]$NC Attempt $retryCount verification failed"
                if ($retryCount -lt $maxRetries) {
                    Write-Host "$BLUE🔄 [Restoring]$NC Restoring backup, preparing retry..."
                    Copy-Item $backupPath $configPath -Force
                    Start-Sleep -Seconds 2
                    continue
                } else {
                    Write-Host "$RED❌ [Final Failure]$NC All retries failed, restoring original configuration"
                    Copy-Item $backupPath $configPath -Force
                    return $false
                }
            }

        } catch {
            Write-Host "$RED❌ [Exception]$NC Attempt $retryCount exception: $($_.Exception.Message)"
            Write-Host "$BLUE💡 [Debug Info]$NC Error type: $($_.Exception.GetType().FullName)"

            if (Test-Path "$configPath.tmp") {
                Remove-Item "$configPath.tmp" -Force -ErrorAction SilentlyContinue
            }

            if ($retryCount -lt $maxRetries) {
                Write-Host "$BLUE🔄 [Restoring]$NC Restoring backup, preparing retry..."
                if (Test-Path $backupPath) {
                    Copy-Item $backupPath $configPath -Force
                }
                Start-Sleep -Seconds 3
                continue
            } else {
                Write-Host "$RED❌ [Final Failure]$NC All retries failed"
                if (Test-Path $backupPath) {
                    Write-Host "$BLUE🔄 [Restoring]$NC Restoring backup configuration..."
                    try {
                        Copy-Item $backupPath $configPath -Force
                        Write-Host "$GREEN✅ [Restored]$NC Original configuration restored"
                    } catch {
                        Write-Host "$RED❌ [Error]$NC Backup restoration failed: $($_.Exception.Message)"
                    }
                }
                return $false
            }
        }
    }

    Write-Host "$RED❌ [Final Failure]$NC After $maxRetries attempts, still cannot complete modification"
    return $false
}

# Start Cursor to generate configuration file
function Start-CursorToGenerateConfig {
    Write-Host "$BLUE🚀 [Starting]$NC Trying to start Cursor to generate configuration file..."

    $installPath = Resolve-CursorInstallPath -AllowPrompt
    $cursorPath = if ($installPath) { Join-Path $installPath "Cursor.exe" } else { $null }

    if (-not $cursorPath) {
        Write-Host "$RED❌ [Error]$NC Cursor installation not found, please confirm Cursor is correctly installed"
        return $false
    }

    try {
        Write-Host "$BLUE📍 [Path]$NC Using Cursor path: $cursorPath"

        $process = Start-Process -FilePath $cursorPath -PassThru -WindowStyle Normal
        Write-Host "$GREEN🚀 [Started]$NC Cursor started, PID: $($process.Id)"

        Write-Host "$YELLOW⏳ [Waiting]$NC Please wait for Cursor to fully load (about 30 seconds)..."
        Write-Host "$BLUE💡 [Hint]$NC You can manually close Cursor after it fully loads"

        $configPath = $STORAGE_FILE
        if (-not $configPath) {
            Write-Host "$RED❌ [Error]$NC Cannot resolve configuration file path"
            return $false
        }
        $maxWait = 60
        $waited = 0

        while (-not (Test-Path $configPath) -and $waited -lt $maxWait) {
            Start-Sleep -Seconds 2
            $waited += 2
            if ($waited % 10 -eq 0) {
                Write-Host "$YELLOW⏳ [Waiting]$NC Waiting for configuration file generation... ($waited/$maxWait seconds)"
            }
        }

        if (Test-Path $configPath) {
            Write-Host "$GREEN✅ [Success]$NC Configuration file generated!"
            Write-Host "$BLUE💡 [Hint]$NC Now you can close Cursor and re-run the script"
            return $true
        } else {
            Write-Host "$YELLOW⚠️  [Timeout]$NC Configuration file not generated within expected time"
            Write-Host "$BLUE💡 [Suggestion]$NC Please manually operate Cursor to trigger configuration generation"
            return $false
        }

    } catch {
        Write-Host "$RED❌ [Error]$NC Failed to start Cursor: $($_.Exception.Message)"
        return $false
    }
}

# Check administrator privileges
function Test-Administrator {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($user)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Host "$RED[Error]$NC Please run this script as Administrator"
    Write-Host "Right-click the script and select 'Run as Administrator'"
    Read-Host "Press Enter to exit"
    exit 1
}

# Display Logo
Clear-Host
Write-Host @"

    ██████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗ 
   ██╔════╝██║   ██║██╔══██╗██╔════╝██╔═══██╗██╔══██╗
   ██║     ██║   ██║██████╔╝███████╗██║   ██║██████╔╝
   ██║     ██║   ██║██╔══██╗╚════██║██║   ██║██╔══██╗
   ╚██████╗╚██████╔╝██║  ██║███████║╚██████╔╝██║  ██║
    ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝

"@
Write-Host "$BLUE================================$NC"
Write-Host "$GREEN🚀   Cursor Trial Protection Deletion Tool          $NC"
Write-Host "$YELLOW📱  Follow公众号【煎饼果子卷AI】 $NC"
Write-Host "$YELLOW🤝  Join for more Cursor tips and AI knowledge (script free, follow公众号 to join group for more tips and experts)  $NC"
Write-Host "$YELLOW💡  [Important] This tool is free, if helpful, please follow公众号【煎饼果子卷AI】  $NC"
Write-Host ""
Write-Host "$YELLOW⚡  [Small Ad] Cursor official成品号：Unlimited ♾️ ¥1050 | 7-day周卡 $100 ¥210 | 7-day周卡 $500 ¥1050 | 7-day周卡 $1000 ¥2450 | All 7-day warranty | ，WeChat：JavaRookie666  $NC"
Write-Host "$BLUE================================$NC"

# 🎯 User selection menu
Write-Host ""
Write-Host "$GREEN🎯 [Select Mode]$NC Please select the operation you want to perform:"
Write-Host ""
Write-Host "$BLUE  1️⃣  Modify machine code only$NC"
Write-Host "$YELLOW      • Execute machine code modification function$NC"
Write-Host "$YELLOW      • Execute injecting破解JS code to core files$NC"
Write-Host "$YELLOW      • Skip folder deletion/environment reset steps$NC"
Write-Host "$YELLOW      • Preserve existing Cursor configuration and data$NC"
Write-Host ""
Write-Host "$BLUE  2️⃣  Reset environment + modify machine code$NC"
Write-Host "$RED      • Execute complete environment reset (delete Cursor folders)$NC"
Write-Host "$RED      • ⚠️  Configuration will be lost, please backup$NC"
Write-Host "$YELLOW      • Follow machine code modification$NC"
Write-Host "$YELLOW      • Execute injecting破解JS code to core files$NC"
Write-Host "$YELLOW      • This is equivalent to current full script behavior$NC"
Write-Host ""

do {
    $userChoice = Read-Host "Enter selection (1 or 2)"
    if ($userChoice -eq "1") {
        Write-Host "$GREEN✅ [Selected]$NC You selected: Modify machine code only"
        $executeMode = "MODIFY_ONLY"
        break
    } elseif ($userChoice -eq "2") {
        Write-Host "$GREEN✅ [Selected]$NC You selected: Reset environment + modify machine code"
        Write-Host "$RED⚠️  [Important Warning]$NC This operation will delete all Cursor configuration files!"
        $confirmReset = Read-Host "Confirm complete reset? (enter yes to confirm, any other key to cancel)"
        if ($confirmReset -eq "yes") {
            $executeMode = "RESET_AND_MODIFY"
            break
        } else {
            Write-Host "$YELLOW👋 [Cancelled]$NC User cancelled reset operation"
            continue
        }
    } else {
        Write-Host "$RED❌ [Error]$NC Invalid selection, please enter 1 or 2"
    }
} while ($true)

Write-Host ""

if ($executeMode -eq "MODIFY_ONLY") {
    Write-Host "$GREEN📋 [Execution Flow]$NC Modify machine code only mode will execute as follows:"
    Write-Host "$BLUE  1️⃣  Detect Cursor configuration file$NC"
    Write-Host "$BLUE  2️⃣  Backup existing configuration file$NC"
    Write-Host "$BLUE  3️⃣  Modify machine code configuration$NC"
    Write-Host "$BLUE  4️⃣  Display operation completion information$NC"
    Write-Host ""
    Write-Host "$YELLOW⚠️  [Notes]$NC"
    Write-Host "$YELLOW  • Won't delete any folders or reset environment$NC"
    Write-Host "$YELLOW  • Preserve all existing configuration and data$NC"
    Write-Host "$YELLOW  • Original configuration file automatically backed up$NC"
} else {
    Write-Host "$GREEN📋 [Execution Flow]$NC Reset environment + modify machine code mode will execute as follows:"
    Write-Host "$BLUE  1️⃣  Detect and close Cursor processes$NC"
    Write-Host "$BLUE  2️⃣  Save Cursor program path information$NC"
    Write-Host "$BLUE  3️⃣  Delete specified Cursor trial-related folders$NC"
    Write-Host "$BLUE      📁 C:\Users\Administrator\.cursor$NC"
    Write-Host "$BLUE      📁 C:\Users\Administrator\AppData\Roaming\Cursor$NC"
    Write-Host "$BLUE      📁 C:\Users\%USERNAME%\.cursor$NC"
    Write-Host "$BLUE      📁 C:\Users\%USERNAME%\AppData\Roaming\Cursor$NC"
    Write-Host "$BLUE  3.5️⃣ Pre-create necessary directory structure to avoid permission issues$NC"
    Write-Host "$BLUE  4️⃣  Restart Cursor to generate new configuration file$NC"
    Write-Host "$BLUE  5️⃣  Wait for configuration file generation (max 45 seconds)$NC"
    Write-Host "$BLUE  6️⃣  Close Cursor processes$NC"
    Write-Host "$BLUE  7️⃣  Modify newly generated machine code configuration file$NC"
    Write-Host "$BLUE  8️⃣  Display operation completion statistics$NC"
    Write-Host ""
    Write-Host "$YELLOW⚠️  [Notes]$NC"
    Write-Host "$YELLOW  • Don't manually operate Cursor during script execution$NC"
    Write-Host "$YELLOW  • Recommended to close all Cursor windows before execution$NC"
    Write-Host "$YELLOW  • Need to restart Cursor after execution$NC"
    Write-Host "$YELLOW  • Original configuration files automatically backed up to backups folder$NC"
}
Write-Host ""

Write-Host "$GREEN🤔 [Confirmation]$NC Please confirm you understand the above execution flow"
$confirmation = Read-Host "Continue execution? (enter y or yes to continue, any other key to exit)"
if ($confirmation -notmatch "^(y|yes)$") {
    Write-Host "$YELLOW👋 [Exit]$NC User cancelled execution, script exiting"
    Read-Host "Press Enter to exit"
    exit 0
}
Write-Host "$GREEN✅ [Confirmed]$NC User confirmed to continue"
Write-Host ""

function Get-CursorVersion {
    try {
        $installPath = Resolve-CursorInstallPath
        $packagePath = if ($installPath) { Join-Path $installPath "resources\app\package.json" } else { $null }
        if ($packagePath -and (Test-Path $packagePath)) {
            $packageJson = Get-Content $packagePath -Raw | ConvertFrom-Json
            if ($packageJson.version) {
                Write-Host "$GREEN[Info]$NC Currently installed Cursor version: v$($packageJson.version)"
                return $packageJson.version
            }
        }

        $altPath = if ($global:CursorLocalAppDataRoot) { Join-Path $global:CursorLocalAppDataRoot "cursor\resources\app\package.json" } else { $null }
        if ($altPath -and (Test-Path $altPath)) {
            $packageJson = Get-Content $altPath -Raw | ConvertFrom-Json
            if ($packageJson.version) {
                Write-Host "$GREEN[Info]$NC Currently installed Cursor version: v$($packageJson.version)"
                return $packageJson.version
            }
        }

        Write-Host "$YELLOW[Warning]$NC Cannot detect Cursor version"
        Write-Host "$YELLOW[Hint]$NC Please ensure Cursor is correctly installed"
        return $null
    }
    catch {
        Write-Host "$RED[Error]$NC Failed to get Cursor version: $_"
        return $null
    }
}

$cursorVersion = Get-CursorVersion
Write-Host ""

Write-Host "$YELLOW💡 [Important]$NC Latest 1.0.x version already supported"

Write-Host ""

Write-Host "$GREEN🔍 [Checking]$NC Checking Cursor processes..."

function Get-ProcessDetails {
    param($processName)
    Write-Host "$BLUE🔍 [Debug]$NC Getting $processName process details:"
    Get-WmiObject Win32_Process -Filter "name='$processName'" |
        Select-Object ProcessId, ExecutablePath, CommandLine |
        Format-List
}

$MAX_RETRIES = 5
$WAIT_TIME = 1

function Close-CursorProcessAndSaveInfo {
    param($processName)

    $global:CursorProcessInfo = $null

    $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($processes) {
        Write-Host "$YELLOW⚠️  [Warning]$NC Found $processName running"

        $firstProcess = if ($processes -is [array]) { $processes[0] } else { $processes }
        $processPath = $firstProcess.Path

        if ($processPath -is [array]) {
            $processPath = $processPath[0]
        }

        $global:CursorProcessInfo = @{
            ProcessName = $firstProcess.ProcessName
            Path = $processPath
            StartTime = $firstProcess.StartTime
        }
        Write-Host "$GREEN💾 [Saved]$NC Saved process information: $($global:CursorProcessInfo.Path)"

        Get-ProcessDetails $processName

        Write-Host "$YELLOW🔄 [Operation]$NC Trying to close $processName..."
        Stop-Process -Name $processName -Force

        $retryCount = 0
        while ($retryCount -lt $MAX_RETRIES) {
            $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
            if (-not $process) { break }

            $retryCount++
            if ($retryCount -ge $MAX_RETRIES) {
                Write-Host "$RED❌ [Error]$NC After $MAX_RETRIES attempts, still cannot close $processName"
                Get-ProcessDetails $processName
                Write-Host "$RED💥 [Error]$NC Please manually close process and retry"
                Read-Host "Press Enter to exit"
                exit 1
            }
            Write-Host "$YELLOW⏳ [Waiting]$NC Waiting for process to close, attempt $retryCount/$MAX_RETRIES..."
            Start-Sleep -Seconds $WAIT_TIME
        }
        Write-Host "$GREEN✅ [Success]$NC $processName successfully closed"
    } else {
        Write-Host "$BLUE💡 [Hint]$NC No $processName process running"
        $installPath = Resolve-CursorInstallPath
        $candidatePath = if ($installPath) { Join-Path $installPath "Cursor.exe" } else { $null }
        if ($candidatePath -and (Test-Path $candidatePath)) {
            $global:CursorProcessInfo = @{
                ProcessName = "Cursor"
                Path = $candidatePath
                StartTime = $null
            }
            Write-Host "$GREEN💾 [Found]$NC Found Cursor installation path: $candidatePath"
        }

        if (-not $global:CursorProcessInfo) {
            Write-Host "$YELLOW⚠️  [Warning]$NC Cursor installation path not found, will use default path"
            $defaultInstallPath = if ($global:CursorLocalAppDataRoot) { Join-Path $global:CursorLocalAppDataRoot "Programs\cursor\Cursor.exe" } else { "$env:LOCALAPPDATA\Programs\cursor\Cursor.exe" }
            $global:CursorProcessInfo = @{
                ProcessName = "Cursor"
                Path = $defaultInstallPath
                StartTime = $null
            }
        }
    }
}

if (-not $BACKUP_DIR) {
    Write-Host "$YELLOW⚠️  [Warning]$NC Cannot resolve backup directory path, skipping creation"
} elseif (-not (Test-Path $BACKUP_DIR)) {
    try {
        New-Item -ItemType Directory -Path $BACKUP_DIR -Force | Out-Null
        Write-Host "$GREEN✅ [Backup Directory]$NC Backup directory created successfully: $BACKUP_DIR"
    } catch {
        Write-Host "$YELLOW⚠️  [Warning]$NC Backup directory creation failed: $($_.Exception.Message)"
    }
}

if ($executeMode -eq "MODIFY_ONLY") {
    Write-Host "$GREEN🚀 [Starting]$NC Starting execute modify machine code only function..."

    $envCheck = Test-CursorEnvironment -Mode "MODIFY_ONLY"
    if (-not $envCheck.Success) {
        Write-Host ""
        Write-Host "$RED❌ [Environment Check Failed]$NC Cannot continue, found the following issues:"
        foreach ($issue in $envCheck.Issues) {
            Write-Host "$RED  • ${issue}$NC"
        }
        Write-Host ""
        Write-Host "$YELLOW💡 [Suggestion]$NC Please select the following operations:"
        Write-Host "$BLUE  1️⃣  Select 'Reset environment + modify machine code' option (recommended)$NC"
        Write-Host "$BLUE  2️⃣  Manually start Cursor once, then re-run script$NC"
        Write-Host "$BLUE  3️⃣  Check if Cursor is correctly installed$NC"
        Write-Host ""
        Read-Host "Press Enter to exit"
        exit 1
    }

    $configSuccess = Modify-MachineCodeConfig -Mode "MODIFY_ONLY"

    if ($configSuccess) {
        Write-Host ""
        Write-Host "$GREEN🎉 [Configuration File]$NC Machine code configuration file modification complete!"

        Write-Host "$BLUE🔧 [Registry]$NC Modifying system registry..."
        $registrySuccess = Update-MachineGuid

        Write-Host ""
        Write-Host "$BLUE🔧 [Device Identification Bypass]$NC Executing JavaScript injection function..."
        Write-Host "$BLUE💡 [Explanation]$NC This function will directly modify Cursor core JS files for deeper device identification bypass"
        $jsSuccess = Modify-CursorJSFiles

        if ($registrySuccess) {
            Write-Host "$GREEN✅ [Registry]$NC System registry modification successful"

            if ($jsSuccess) {
                Write-Host "$GREEN✅ [JavaScript Injection]$NC JavaScript injection function executed successfully"
                Write-Host ""
                Write-Host "$GREEN🎉 [Complete]$NC All machine code modifications complete (enhanced version)!"
                Write-Host "$BLUE📋 [Details]$NC Completed the following modifications:"
                Write-Host "$GREEN  ✓ Cursor configuration file (storage.json)$NC"
                Write-Host "$GREEN  ✓ System registry (MachineGuid)$NC"
                Write-Host "$GREEN  ✓ JavaScript core injection (device identification bypass)$NC"
            } else {
                Write-Host "$YELLOW⚠️  [JavaScript Injection]$NC JavaScript injection function failed, but other functions successful"
                Write-Host ""
                Write-Host "$GREEN🎉 [Complete]$NC All machine code modifications complete!"
                Write-Host "$BLUE📋 [Details]$NC Completed the following modifications:"
                Write-Host "$GREEN  ✓ Cursor configuration file (storage.json)$NC"
                Write-Host "$GREEN  ✓ System registry (MachineGuid)$NC"
                Write-Host "$YELLOW  ⚠ JavaScript core injection (partial failure)$NC"
            }

            Write-Host "$BLUE🔒 [Protection]$NC Setting configuration file protection..."
            try {
                $configPath = $STORAGE_FILE
                if (-not $configPath) {
                    throw "Cannot resolve configuration file path"
                }
                $configFile = Get-Item $configPath
                $configFile.IsReadOnly = $true
                Write-Host "$GREEN✅ [Protection]$NC Configuration file set to read-only, preventing Cursor from overwriting modifications"
                Write-Host "$BLUE💡 [Hint]$NC File path: $configPath"
            } catch {
                Write-Host "$YELLOW⚠️  [Protection]$NC Failed to set read-only attribute: $($_.Exception.Message)"
                Write-Host "$BLUE💡 [Suggestion]$NC Can manually right-click file → Properties → Check 'Read-only'"
            }
        } else {
            Write-Host "$YELLOW⚠️  [Registry]$NC Registry modification failed, but configuration file modification successful"

            if ($jsSuccess) {
                Write-Host "$GREEN✅ [JavaScript Injection]$NC JavaScript injection function executed successfully"
                Write-Host ""
                Write-Host "$YELLOW🎉 [Partial Complete]$NC Configuration file and JavaScript injection complete, registry modification failed"
                Write-Host "$BLUE💡 [Suggestion]$NC May need administrator permissions to modify registry"
                Write-Host "$BLUE📋 [Details]$NC Completed the following modifications:"
                Write-Host "$GREEN  ✓ Cursor configuration file (storage.json)$NC"
                Write-Host "$YELLOW  ⚠ System registry (MachineGuid) - failed$NC"
                Write-Host "$GREEN  ✓ JavaScript core injection (device identification bypass)$NC"
            } else {
                Write-Host "$YELLOW⚠️  [JavaScript Injection]$NC JavaScript injection function failed"
                Write-Host ""
                Write-Host "$YELLOW🎉 [Partial Complete]$NC Configuration file modification complete, registry and JavaScript injection failed"
                Write-Host "$BLUE💡 [Suggestion]$NC May need administrator permissions to modify registry"
            }

            Write-Host "$BLUE🔒 [Protection]$NC Setting configuration file protection..."
            try {
                $configPath = $STORAGE_FILE
                if (-not $configPath) {
                    throw "Cannot resolve configuration file path"
                }
                $configFile = Get-Item $configPath
                $configFile.IsReadOnly = $true
                Write-Host "$GREEN✅ [Protection]$NC Configuration file set to read-only, preventing Cursor from overwriting modifications"
                Write-Host "$BLUE💡 [Hint]$NC File path: $configPath"
            } catch {
                Write-Host "$YELLOW⚠️  [Protection]$NC Failed to set read-only attribute: $($_.Exception.Message)"
                Write-Host "$BLUE💡 [Suggestion]$NC Can manually right-click file → Properties → Check 'Read-only'"
            }
        }

        Write-Host ""
        Write-Host "$BLUE🚫 [Disable Updates]$NC Disabling Cursor auto-update..."
        if (Disable-CursorAutoUpdate) {
            Write-Host "$GREEN✅ [Disable Updates]$NC Auto-update processed"
        } else {
            Write-Host "$YELLOW⚠️  [Disable Updates]$NC Unable to confirm disable updates, may need manual processing"
        }

        Write-Host "$BLUE💡 [Hint]$NC Now can start Cursor using new machine code configuration"
    } else {
        Write-Host ""
        Write-Host "$RED❌ [Failed]$NC Machine code modification failed!"
        Write-Host "$YELLOW💡 [Suggestion]$NC Try 'Reset environment + modify machine code' option"
    }
} else {
    Write-Host "$GREEN🚀 [Starting]$NC Starting execute reset environment + modify machine code function..."

    Close-CursorProcessAndSaveInfo "Cursor"
    if (-not $global:CursorProcessInfo) {
        Close-CursorProcessAndSaveInfo "cursor"
    }

    Write-Host ""
    Write-Host "$RED🚨 [Important Warning]$NC ============================================"
    Write-Host "$YELLOW⚠️  [Risk Control Reminder]$NC Cursor risk control mechanism is very strict!"
    Write-Host "$YELLOW⚠️  [Must Delete]$NC Must completely delete specified folders, no残留 settings allowed"
    Write-Host "$YELLOW⚠️  [Trial Protection]$NC Only thorough cleanup can effectively prevent trial Pro status loss"
    Write-Host "$RED🚨 [Important Warning]$NC ============================================"
    Write-Host ""

    Write-Host "$GREEN🚀 [Starting]$NC Starting execute core function..."
    Remove-CursorTrialFolders

    Restart-CursorAndWait

    $configSuccess = Modify-MachineCodeConfig
    
    Invoke-CursorInitialization

    if ($configSuccess) {
        Write-Host ""
        Write-Host "$GREEN🎉 [Configuration File]$NC Machine code configuration file modification complete!"

        Write-Host "$BLUE🔧 [Registry]$NC Modifying system registry..."
        $registrySuccess = Update-MachineGuid

        Write-Host ""
        Write-Host "$BLUE🔧 [Device Identification Bypass]$NC Executing JavaScript injection function..."
        Write-Host "$BLUE💡 [Explanation]$NC This function will directly modify Cursor core JS files for deeper device identification bypass"
        $jsSuccess = Modify-CursorJSFiles

        if ($registrySuccess) {
            Write-Host "$GREEN✅ [Registry]$NC System registry modification successful"

            if ($jsSuccess) {
                Write-Host "$GREEN✅ [JavaScript Injection]$NC JavaScript injection function executed successfully"
                Write-Host ""
                Write-Host "$GREEN🎉 [Complete]$NC All operations complete (enhanced version)!"
                Write-Host "$BLUE📋 [Details]$NC Completed the following operations:"
                Write-Host "$GREEN  ✓ Delete Cursor trial-related folders$NC"
                Write-Host "$GREEN  ✓ Cursor initialization cleanup$NC"
                Write-Host "$GREEN  ✓ Regenerate configuration file$NC"
                Write-Host "$GREEN  ✓ Modify machine code configuration$NC"
                Write-Host "$GREEN  ✓ Modify system registry$NC"
                Write-Host "$GREEN  ✓ JavaScript core injection (device identification bypass)$NC"
            } else {
                Write-Host "$YELLOW⚠️  [JavaScript Injection]$NC JavaScript injection function failed, but other functions successful"
                Write-Host ""
                Write-Host "$GREEN🎉 [Complete]$NC All operations complete!"
                Write-Host "$BLUE📋 [Details]$NC Completed the following operations:"
                Write-Host "$GREEN  ✓ Delete Cursor trial-related folders$NC"
                Write-Host "$GREEN  ✓ Cursor initialization cleanup$NC"
                Write-Host "$GREEN  ✓ Regenerate configuration file$NC"
                Write-Host "$GREEN  ✓ Modify machine code configuration$NC"
                Write-Host "$GREEN  ✓ Modify system registry$NC"
                Write-Host "$YELLOW  ⚠ JavaScript core injection (partial failure)$NC"
            }

            Write-Host "$BLUE🔒 [Protection]$NC Setting configuration file protection..."
            try {
                $configPath = $STORAGE_FILE
                if (-not $configPath) {
                    throw "Cannot resolve configuration file path"
                }
                $configFile = Get-Item $configPath
                $configFile.IsReadOnly = $true
                Write-Host "$GREEN✅ [Protection]$NC Configuration file set to read-only, preventing Cursor from overwriting modifications"
                Write-Host "$BLUE💡 [Hint]$NC File path: $configPath"
            } catch {
                Write-Host "$YELLOW⚠️  [Protection]$NC Failed to set read-only attribute: $($_.Exception.Message)"
                Write-Host "$BLUE💡 [Suggestion]$NC Can manually right-click file → Properties → Check 'Read-only'"
            }
        } else {
            Write-Host "$YELLOW⚠️  [Registry]$NC Registry modification failed, but other operations successful"

            if ($jsSuccess) {
                Write-Host "$GREEN✅ [JavaScript Injection]$NC JavaScript injection function executed successfully"
                Write-Host ""
                Write-Host "$YELLOW🎉 [Partial Complete]$NC Most operations complete, registry modification failed"
                Write-Host "$BLUE💡 [Suggestion]$NC May need administrator permissions to modify registry"
                Write-Host "$BLUE📋 [Details]$NC Completed the following operations:"
                Write-Host "$GREEN  ✓ Delete Cursor trial-related folders$NC"
                Write-Host "$GREEN  ✓ Cursor initialization cleanup$NC"
                Write-Host "$GREEN  ✓ Regenerate configuration file$NC"
                Write-Host "$GREEN  ✓ Modify machine code configuration$NC"
                Write-Host "$YELLOW  ⚠ Modify system registry - failed$NC"
                Write-Host "$GREEN  ✓ JavaScript core injection (device identification bypass)$NC"
            } else {
                Write-Host "$YELLOW⚠️  [JavaScript Injection]$NC JavaScript injection function failed"
                Write-Host ""
                Write-Host "$YELLOW🎉 [Partial Complete]$NC Most operations complete, registry and JavaScript injection failed"
                Write-Host "$BLUE💡 [Suggestion]$NC May need administrator permissions to modify registry"
            }

            Write-Host "$BLUE🔒 [Protection]$NC Setting configuration file protection..."
            try {
                $configPath = $STORAGE_FILE
                if (-not $configPath) {
                    throw "Cannot resolve configuration file path"
                }
                $configFile = Get-Item $configPath
                $configFile.IsReadOnly = $true
                Write-Host "$GREEN✅ [Protection]$NC Configuration file set to read-only, preventing Cursor from overwriting modifications"
                Write-Host "$BLUE💡 [Hint]$NC File path: $configPath"
            } catch {
                Write-Host "$YELLOW⚠️  [Protection]$NC Failed to set read-only attribute: $($_.Exception.Message)"
                Write-Host "$BLUE💡 [Suggestion]$NC Can manually right-click file → Properties → Check 'Read-only'"
            }
        }

        Write-Host ""
        Write-Host "$BLUE🚫 [Disable Updates]$NC Disabling Cursor auto-update..."
        if (Disable-CursorAutoUpdate) {
            Write-Host "$GREEN✅ [Disable Updates]$NC Auto-update processed"
        } else {
            Write-Host "$YELLOW⚠️  [Disable Updates]$NC Unable to confirm disable updates, may need manual processing"
        }
    } else {
        Write-Host ""
        Write-Host "$RED❌ [Failed]$NC Machine code configuration modification failed!"
        Write-Host "$YELLOW💡 [Suggestion]$NC Check error information and retry"
    }
}

Write-Host ""
Write-Host "$GREEN================================$NC"
Write-Host "$YELLOW📱  Follow公众号【煎饼果子卷AI】join for more Cursor tips and AI knowledge (script free, follow公众号 to join group for more tips and experts)  $NC"
Write-Host "$YELLOW⚡   [Small Ad] Cursor official成品号：Unlimited ♾️ ¥1050 | 7-day周卡 $100 ¥210 | 7-day周卡 $500 ¥1050 | 7-day周卡 $1000 ¥2450 | All 7-day warranty | ，WeChat：JavaRookie666  $NC"
Write-Host "$GREEN================================$NC"
Write-Host ""

Write-Host "$GREEN🎉 [Script Complete]$NC Thank you for using Cursor machine code modification tool!"
Write-Host "$BLUE💡 [Hint]$NC If issues, refer to公众号 or re-run script"
Write-Host ""
Read-Host "Press Enter to exit"
exit 0