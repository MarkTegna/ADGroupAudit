# AD Group Audit - Build Script
# Author: Mark Oldham
# Builds a single-file Windows executable using PyInstaller

$ErrorActionPreference = "Stop"

# Read version from version.py
$versionFile = "ad_group_audit\version.py"
$versionLine = Get-Content $versionFile | Select-String '__version__\s*='
$version = ($versionLine -replace '.*"(.*)".*', '$1').Trim()

Write-Host "Building AD Group Audit v$version"
Write-Host "================================="

# Clean previous builds
if (Test-Path "build") { Remove-Item -Recurse -Force "build" -ErrorAction SilentlyContinue }
if (Test-Path "dist") {
    # Remove individual files first, then try the folder
    Get-ChildItem "dist" -Recurse -File | Remove-Item -Force -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force "dist" -ErrorAction SilentlyContinue
}

# Run PyInstaller - main audit tool
Write-Host "Running PyInstaller (ad-group-audit)..."
python -m PyInstaller --onefile `
    --name "ad-group-audit" `
    --add-data "ad_group_audit.ini;." `
    --hidden-import "pyodbc" `
    --hidden-import "ldap3" `
    ad_group_audit\main.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "PyInstaller build failed (ad-group-audit)!"
    exit 1
}

# Run PyInstaller - DC replication checker
Write-Host "Running PyInstaller (dc-repl-check)..."
python -m PyInstaller --onefile `
    --name "dc-repl-check" `
    --add-data "ad_group_audit.ini;." `
    --hidden-import "ldap3" `
    ad_group_audit\dc_repl_check.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "PyInstaller build failed (dc-repl-check)!"
    exit 1
}

# Create distribution directory
$distDir = "dist\ad-group-audit-$version"
New-Item -ItemType Directory -Path $distDir -Force | Out-Null

# Copy files to distribution
Copy-Item "dist\ad-group-audit.exe" "$distDir\"
Copy-Item "dist\dc-repl-check.exe" "$distDir\"

# Create default INI if it doesn't exist
if (-not (Test-Path "ad_group_audit.ini")) {
    python -c "from ad_group_audit.config_manager import ConfigManager; ConfigManager('ad_group_audit.ini').create_default()"
}
Copy-Item "ad_group_audit.ini" "$distDir\"

# Copy README if it exists
if (Test-Path "README.md") {
    Copy-Item "README.md" "$distDir\"
}

# Create zip
$zipName = "ad-group-audit-$version.zip"
Write-Host "Creating $zipName..."
Compress-Archive -Path "$distDir\*" -DestinationPath "dist\$zipName" -Force

Write-Host ""
Write-Host "Build complete!"
Write-Host "  Executable: dist\ad-group-audit.exe"
Write-Host "  Distribution: dist\$zipName"
