@echo off
setlocal EnableDelayedExpansion

echo.
echo ========================================
echo   GitHub Repo Security Scanner
echo   Windows Installer
echo ========================================
echo.

:: Check for admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] Not running as Administrator. Some installs may fail.
    echo Right-click install.bat and choose "Run as administrator" for best results.
    echo.
    pause
)

:: ── 1. Check winget ──────────────────────────────────────────
where winget >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] winget not found.
    echo winget comes with Windows 10 1809+ and Windows 11.
    echo Install it from: https://aka.ms/getwinget
    echo Then re-run this installer.
    pause
    exit /b 1
)
echo [OK] winget found

:: ── 2. Git ───────────────────────────────────────────────────
where git >nul 2>&1
if %errorLevel% neq 0 (
    echo Installing Git...
    winget install --id Git.Git -e --source winget --silent
    :: Refresh PATH
    set "PATH=%PATH%;C:\Program Files\Git\bin;C:\Program Files\Git\cmd"
) else (
    echo [OK] Git already installed
)

:: ── 3. GitHub CLI ─────────────────────────────────────────────
where gh >nul 2>&1
if %errorLevel% neq 0 (
    echo Installing GitHub CLI...
    winget install --id GitHub.cli -e --source winget --silent
) else (
    echo [OK] GitHub CLI already installed
)

:: ── 4. Bun ───────────────────────────────────────────────────
where bun >nul 2>&1
if %errorLevel% neq 0 (
    echo Installing Bun...
    powershell -ExecutionPolicy Bypass -Command "irm bun.sh/install.ps1 | iex"
    set "PATH=%PATH%;%USERPROFILE%\.bun\bin"
) else (
    echo [OK] Bun already installed
)

:: ── 5. Python (for GuardDog) ──────────────────────────────────
where python >nul 2>&1
if %errorLevel% neq 0 (
    echo Installing Python...
    winget install --id Python.Python.3.12 -e --source winget --silent
    set "PATH=%PATH%;%LOCALAPPDATA%\Programs\Python\Python312;%LOCALAPPDATA%\Programs\Python\Python312\Scripts"
) else (
    echo [OK] Python already installed
)

:: ── 6. Security tools via winget ─────────────────────────────
echo.
echo Installing security scanning tools...

:: Gitleaks
where gitleaks >nul 2>&1
if %errorLevel% neq 0 (
    echo   Installing Gitleaks...
    winget install --id zricethezav.gitleaks -e --source winget --silent 2>nul
    if %errorLevel% neq 0 (
        echo   [NOTE] Gitleaks not in winget. Downloading directly...
        powershell -Command "& { $url = 'https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_windows_x64.zip'; $out = '%TEMP%\gitleaks.zip'; Invoke-WebRequest -Uri $url -OutFile $out; Expand-Archive -Path $out -DestinationPath '%USERPROFILE%\.repo-scanner\bin' -Force }"
    )
) else (
    echo   [OK] Gitleaks already installed
)

:: Semgrep (via pip)
where semgrep >nul 2>&1
if %errorLevel% neq 0 (
    echo   Installing Semgrep...
    pip install semgrep --quiet
) else (
    echo   [OK] Semgrep already installed
)

:: OSV-Scanner
where osv-scanner >nul 2>&1
if %errorLevel% neq 0 (
    echo   Installing OSV-Scanner...
    winget install --id Google.OSVScanner -e --source winget --silent 2>nul
    if %errorLevel% neq 0 (
        echo   Downloading OSV-Scanner directly...
        powershell -Command "& { $url = 'https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_windows_amd64.exe'; Invoke-WebRequest -Uri $url -OutFile '%USERPROFILE%\.repo-scanner\bin\osv-scanner.exe' }"
    )
) else (
    echo   [OK] OSV-Scanner already installed
)

:: Grype
where grype >nul 2>&1
if %errorLevel% neq 0 (
    echo   Installing Grype...
    powershell -Command "& { $url = 'https://raw.githubusercontent.com/anchore/grype/main/install.sh'; $script = (Invoke-WebRequest -Uri $url).Content; $script | powershell }" 2>nul
    if %errorLevel% neq 0 (
        echo   Downloading Grype directly...
        powershell -Command "& { $url = 'https://github.com/anchore/grype/releases/latest/download/grype_windows_amd64.zip'; $out = '%TEMP%\grype.zip'; Invoke-WebRequest -Uri $url -OutFile $out; Expand-Archive -Path $out -DestinationPath '%USERPROFILE%\.repo-scanner\bin' -Force }"
    )
) else (
    echo   [OK] Grype already installed
)

:: TruffleHog
where trufflehog >nul 2>&1
if %errorLevel% neq 0 (
    echo   Installing TruffleHog...
    pip install trufflehog --quiet 2>nul
    if %errorLevel% neq 0 (
        powershell -Command "& { $url = 'https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_windows_amd64.tar.gz'; $out = '%TEMP%\trufflehog.tar.gz'; Invoke-WebRequest -Uri $url -OutFile $out }"
        echo   [NOTE] TruffleHog tar.gz downloaded to %TEMP% - extract manually if needed
    )
) else (
    echo   [OK] TruffleHog already installed
)

:: GuardDog
where guarddog >nul 2>&1
if %errorLevel% neq 0 (
    echo   Installing GuardDog...
    pip install guarddog --quiet
) else (
    echo   [OK] GuardDog already installed
)

:: ── 7. Scorecard (Go-based, direct download) ──────────────────
where scorecard >nul 2>&1
if %errorLevel% neq 0 (
    echo   Installing OpenSSF Scorecard...
    powershell -Command "& { $url = 'https://github.com/ossf/scorecard/releases/latest/download/scorecard_windows_amd64.exe'; Invoke-WebRequest -Uri $url -OutFile '%USERPROFILE%\.repo-scanner\bin\scorecard.exe' }"
    echo   [OK] Scorecard downloaded to %%USERPROFILE%%\.repo-scanner\bin
) else (
    echo   [OK] Scorecard already installed
)

:: ── 8. Install scanner ────────────────────────────────────────
set "INSTALL_DIR=%USERPROFILE%\.repo-scanner"
if not exist "%INSTALL_DIR%\bin" mkdir "%INSTALL_DIR%\bin"
if not exist "%INSTALL_DIR%\scans" mkdir "%INSTALL_DIR%\scans"

:: Copy scan.ts
set "SCRIPT_DIR=%~dp0"
copy /Y "%SCRIPT_DIR%..\scanner\scan.ts" "%INSTALL_DIR%\scan.ts" >nul

:: Create repo-scan.bat wrapper
(
echo @echo off
echo set "BUN=%USERPROFILE%\.bun\bin\bun.exe"
echo set "SCANNER=%USERPROFILE%\.repo-scanner\scan.ts"
echo set "PATH=%USERPROFILE%\.repo-scanner\bin;%USERPROFILE%\.bun\bin;%%PATH%%"
echo if not exist "%%BUN%%" set "BUN=bun"
echo "%%BUN%%" run "%%SCANNER%%" %%*
) > "%INSTALL_DIR%\repo-scan.bat"

:: Add to user PATH via registry
powershell -Command "& { $path = [Environment]::GetEnvironmentVariable('PATH','User'); if ($path -notlike '*\.repo-scanner\bin*') { [Environment]::SetEnvironmentVariable('PATH', $path + ';%INSTALL_DIR%\bin', 'User') } }"
powershell -Command "& { $path = [Environment]::GetEnvironmentVariable('PATH','User'); if ($path -notlike '*\.repo-scanner*') { [Environment]::SetEnvironmentVariable('PATH', $path + ';%INSTALL_DIR%', 'User') } }"

:: ── 9. GitHub auth reminder ───────────────────────────────────
echo.
gh auth status >nul 2>&1
if %errorLevel% neq 0 (
    echo [ACTION REQUIRED] GitHub CLI not authenticated.
    echo Run this after installation: gh auth login
    echo (Free GitHub account is fine - needed for Scorecard scans)
) else (
    echo [OK] GitHub CLI authenticated
)

:: ── Done ──────────────────────────────────────────────────────
echo.
echo ========================================
echo   Installation complete!
echo ========================================
echo.
echo Usage (open a NEW Command Prompt window first):
echo   repo-scan https://github.com/owner/repo
echo   repo-scan https://github.com/owner/repo --quick
echo   repo-scan https://github.com/owner/repo --json
echo.
echo Scan results saved to: %USERPROFILE%\.repo-scanner\scans\
echo.
pause
