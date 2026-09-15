param(
    [string]$VpsHost = "201.24.52.171",
    [string]$SshUser = "root",
    [string]$IdentityFile = "$HOME\.ssh\gost_probe",
    [int]$LocalPort = 13128,
    [int]$RemotePort = 13129
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $IdentityFile)) {
    throw "SSH key not found: $IdentityFile"
}

$probe = Test-NetConnection -ComputerName $VpsHost -Port 22 -WarningAction SilentlyContinue
if (-not $probe.TcpTestSucceeded) {
    throw "TCP $VpsHost`:22 is unavailable. The script will not change sshd or use another port."
}

$forward = "127.0.0.1:$LocalPort`:127.0.0.1:$RemotePort"
Write-Host "Opening 127.0.0.1:$LocalPort -> $VpsHost -> 127.0.0.1:$RemotePort"
Write-Host "Keep this window open; press Ctrl+C to stop the forward."

& ssh.exe `
    -i $IdentityFile `
    -N `
    -L $forward `
    -o ExitOnForwardFailure=yes `
    -o ServerAliveInterval=30 `
    -o ServerAliveCountMax=3 `
    "$SshUser@$VpsHost"

if ($LASTEXITCODE -ne 0) {
    throw "ssh.exe exited with code $LASTEXITCODE"
}
