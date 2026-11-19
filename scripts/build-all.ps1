$ErrorActionPreference = "Stop"
$env:PATH = "$env:USERPROFILE\.cargo\bin;" + $env:PATH

Write-Host "[1/3] Building guard-helper (netguard-guard.exe)..." -ForegroundColor Cyan
cargo build -p guard-helper --release

$targetBin = "src-tauri\binaries\netguard-guard-x86_64-pc-windows-msvc.exe"
Copy-Item "target\release\netguard-guard.exe" $targetBin -Force

Write-Host "[2/3] Building frontend..." -ForegroundColor Cyan
npm run build

Write-Host "[3/3] Building Tauri v2 desktop app..." -ForegroundColor Cyan
npx tauri build --config src-tauri/tauri.release.json
