# GitHub Repo Security Scanner — Windows PowerShell Installer
# Run: powershell -ExecutionPolicy Bypass -File install.ps1

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  GitHub Repo Security Scanner" -ForegroundColor Cyan
Write-Host "  Windows PowerShell Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$InstallDir = "$env:USERPROFILE\.repo-scanner"
$BinDir = "$InstallDir\bin"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\scans" | Out-Null

function Install-IfMissing($name, $installBlock) {
    if (Get-Command $name -ErrorAction SilentlyContinue) {
        Write-Host "  [OK] $name already installed" -ForegroundColor Green
    } else {
        Write-Host "  Installing $name..." -ForegroundColor Yellow
        & $installBlock
        Write-Host "  [OK] $name installed" -ForegroundColor Green
    }
}

function Download-Binary($name, $url, $outName) {
    $out = "$BinDir\$outName"
    if (-not (Test-Path $out)) {
        Write-Host "  Downloading $name..." -ForegroundColor Yellow
        try {
            Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
            Write-Host "  [OK] $name downloaded" -ForegroundColor Green
        } catch {
            Write-Host "  [WARN] Could not download $name - $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [OK] $name already present" -ForegroundColor Green
    }
}

function Download-Zip($name, $url, $exeName) {
    if (-not (Test-Path "$BinDir\$exeName")) {
        Write-Host "  Downloading $name..." -ForegroundColor Yellow
        $tmp = "$env:TEMP\$name.zip"
        try {
            Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
            Expand-Archive -Path $tmp -DestinationPath $BinDir -Force
            Remove-Item $tmp -Force
            Write-Host "  [OK] $name installed" -ForegroundColor Green
        } catch {
            Write-Host "  [WARN] Could not install $name - $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [OK] $name already present" -ForegroundColor Green
    }
}

# ── Git ───────────────────────────────────────────────────────
Install-IfMissing "git" {
    winget install --id Git.Git -e --source winget --silent
}

# ── Bun ───────────────────────────────────────────────────────
Install-IfMissing "bun" {
    irm bun.sh/install.ps1 | iex
    $env:PATH = "$env:USERPROFILE\.bun\bin;$env:PATH"
}

# ── GitHub CLI ────────────────────────────────────────────────
Install-IfMissing "gh" {
    winget install --id GitHub.cli -e --source winget --silent
}

# ── Python ────────────────────────────────────────────────────
Install-IfMissing "python" {
    winget install --id Python.Python.3.12 -e --source winget --silent
    $env:PATH = "$env:LOCALAPPDATA\Programs\Python\Python312;$env:LOCALAPPDATA\Programs\Python\Python312\Scripts;$env:PATH"
}

# ── pip-based tools ───────────────────────────────────────────
Write-Host ""
Write-Host "Installing Python-based tools..." -ForegroundColor Yellow

foreach ($pkg in @("semgrep", "guarddog")) {
    Install-IfMissing $pkg {
        pip install $pkg --quiet
    }
}

# ── Binary tools ──────────────────────────────────────────────
Write-Host ""
Write-Host "Installing binary security tools..." -ForegroundColor Yellow

# Scorecard
Download-Binary "scorecard" `
    "https://github.com/ossf/scorecard/releases/latest/download/scorecard_windows_amd64.exe" `
    "scorecard.exe"

# OSV-Scanner
Download-Binary "osv-scanner" `
    "https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_windows_amd64.exe" `
    "osv-scanner.exe"

# Gitleaks
Download-Zip "gitleaks" `
    "https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_8.18.0_windows_x64.zip" `
    "gitleaks.exe"

# Grype
Download-Zip "grype" `
    "https://github.com/anchore/grype/releases/latest/download/grype_windows_amd64.zip" `
    "grype.exe"

# TruffleHog
Download-Zip "trufflehog" `
    "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_windows_amd64.zip" `
    "trufflehog.exe"

# Syft
Download-Zip "syft" `
    "https://github.com/anchore/syft/releases/latest/download/syft_windows_amd64.zip" `
    "syft.exe"

# ── Copy scanner ──────────────────────────────────────────────
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Copy-Item "$ScriptDir\..\scanner\scan.ts" "$InstallDir\scan.ts" -Force

# ── Create repo-scan.ps1 wrapper ──────────────────────────────
$wrapper = @"
`$env:PATH = "$BinDir;`$env:USERPROFILE\.bun\bin;`$env:PATH"
`$bun = if (Get-Command bun -ErrorAction SilentlyContinue) { "bun" } else { "`$env:USERPROFILE\.bun\bin\bun.exe" }
& `$bun run "$InstallDir\scan.ts" @args
"@
$wrapper | Out-File "$InstallDir\repo-scan.ps1" -Encoding UTF8

# Also create a .bat for cmd.exe users
@"
@echo off
powershell -ExecutionPolicy Bypass -File "%USERPROFILE%\.repo-scanner\repo-scan.ps1" %*
"@ | Out-File "$InstallDir\repo-scan.bat" -Encoding ASCII

# ── Add to PATH ───────────────────────────────────────────────
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($currentPath -notlike "*\.repo-scanner\bin*") {
    [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$BinDir", "User")
}
if ($currentPath -notlike "*\.repo-scanner*") {
    [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$InstallDir", "User")
}

# ── GitHub auth check ─────────────────────────────────────────
Write-Host ""
$ghStatus = gh auth status 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] GitHub CLI authenticated" -ForegroundColor Green
} else {
    Write-Host "[ACTION REQUIRED] Run: gh auth login" -ForegroundColor Yellow
    Write-Host "  (Free GitHub account is fine - needed for Scorecard scans)" -ForegroundColor Yellow
}

# ── Done ──────────────────────────────────────────────────────
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Open a NEW PowerShell window, then run:" -ForegroundColor Cyan
Write-Host "  repo-scan https://github.com/owner/repo" -ForegroundColor White
Write-Host "  repo-scan https://github.com/owner/repo --quick" -ForegroundColor White
Write-Host "  repo-scan https://github.com/owner/repo --json" -ForegroundColor White
Write-Host ""
Write-Host "Scan results saved to: $InstallDir\scans\" -ForegroundColor Gray
Write-Host ""
