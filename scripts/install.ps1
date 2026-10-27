# Windows entry point. Teate itself runs inside Ubuntu on WSL2.
[CmdletBinding()]
param(
    [switch]$All,
    [switch]$DryRun,
    [string]$Distribution = "Ubuntu-24.04"
)
$ErrorActionPreference = "Stop"

if ($Distribution -notmatch '^Ubuntu(-[0-9]+\.[0-9]+)?$') {
    throw "Choose an Ubuntu WSL distribution, for example Ubuntu-24.04."
}
if ($DryRun) {
    Write-Host "Ensure WSL2 and $Distribution exist (may require administrator approval/restart)."
    Write-Host "Inside WSL: copy the public Teate source to ~/teate if absent; run bash scripts/install.sh$(if ($All) { ' --all' })."
    Write-Host 'Dry run only. No changes made.'
    exit 0
}
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw "WSL is unavailable. Enable WSL2 on a supported Windows 10/11 installation: https://learn.microsoft.com/windows/wsl/install"
}

$distros = (& wsl.exe --list --quiet 2>$null) -replace "`0", ""
if ($LASTEXITCODE -ne 0 -or $Distribution -notin @($distros | ForEach-Object { $_.Trim() })) {
    & wsl.exe --install --distribution $Distribution --no-launch
    if ($LASTEXITCODE -ne 0) {
        throw "WSL setup needs administrator access or a Windows restart. Complete setup and run this command again."
    }
    Write-Host "Start $Distribution, create its Linux user, and restart Windows if requested. Then run this installer again."
    exit 1
}
$kernel = & wsl.exe --distribution $Distribution -- uname -r
if ($LASTEXITCODE -ne 0 -or ($kernel -join '') -notmatch '(?i)WSL2') {
    throw "WSL2 is required. Run: wsl --set-version $Distribution 2 ; then rerun this installer."
}

$root = Split-Path -Parent $PSScriptRoot
$linuxRoot = & wsl.exe --distribution $Distribution -- wslpath -a $root
if ($LASTEXITCODE -ne 0) { throw "Could not map the Teate folder into WSL." }
$linuxRoot = ($linuxRoot -join "`n").Trim()
if ($linuxRoot -match "[`r`n]") { throw "Unsupported source path." }

# Pass paths as argv, never interpolate them into shell code. Keep Linux installs
# and operational state in the Linux home, not in a shared Windows directory.
$prepare = @'
set -eu
umask 077
src=$1
dst="$HOME/teate"
if [ ! -e "$dst" ]; then
  mkdir "$dst"
  for name in teate scripts tests docs .gitignore README.md AGENTS.md LICENSE SECURITY.md CONTRIBUTING.md; do
    if [ -e "$src/$name" ]; then cp -R "$src/$name" "$dst/"; fi
  done
  mkdir "$dst/config"
  for name in example.json ci.example.json policy.json; do
    if [ -f "$src/config/$name" ]; then cp "$src/config/$name" "$dst/config/"; fi
  done
fi
if [ ! -f "$dst/scripts/install.sh" ]; then
  echo '~/teate already exists but is not a Teate installation; move it or use an existing Teate checkout.' >&2
  exit 2
fi
if [ "$2" = '--all' ]; then
  exec bash "$dst/scripts/install.sh" --all
else
  exec bash "$dst/scripts/install.sh"
fi
'@
$profile = if ($All) { "--all" } else { "scan" }
# A script file avoids Windows PowerShell 5.1's native argv quote rewriting.
$temporary = [System.IO.Path]::GetTempFileName()
try {
    [System.IO.File]::WriteAllText($temporary, ($prepare -replace "`r`n", "`n"), (New-Object System.Text.UTF8Encoding($false)))
    $linuxScript = & wsl.exe --distribution $Distribution -- wslpath -a $temporary
    if ($LASTEXITCODE -ne 0) { throw "Could not map the temporary installer into WSL." }
    & wsl.exe --distribution $Distribution -- bash ($linuxScript -join "`n").Trim() $linuxRoot $profile
    if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed. Fix the reported issue and rerun." }
} finally {
    Remove-Item -LiteralPath $temporary -Force
}
Write-Host "Ready. Run: wsl -d $Distribution"
Write-Host 'Then: cd ~/teate && source .teate/env.sh'
