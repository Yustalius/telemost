param(
    [string]$VpsHost = "201.24.52.171",
    [string]$SshUser = "root",
    [string]$IdentityFile = "$HOME\.ssh\gost_probe",
    [int]$LocalProxyPort = 13128,
    [int]$RemoteProxyPort = 13129,
    [int]$PacPort = 13127,
    [string]$StartUrl = "https://retest-agent.apps.yd-m6-kt66.vimpelcom.ru/",
    [string]$ProfileDir = "$env:LOCALAPPDATA\TelemostCorpEdge"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $IdentityFile)) {
    throw "SSH key not found: $IdentityFile"
}
$edgeCandidates = @(
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
)
$edge = $edgeCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $edge) {
    throw "Microsoft Edge not found"
}
$probe = Test-NetConnection -ComputerName $VpsHost -Port 22 -WarningAction SilentlyContinue
if (-not $probe.TcpTestSucceeded) {
    throw "TCP $VpsHost`:22 is unavailable"
}

$forward = "127.0.0.1:$LocalProxyPort`:127.0.0.1:$RemoteProxyPort"
$sshArgs = @(
    "-i", $IdentityFile,
    "-N",
    "-L", $forward,
    "-o", "ExitOnForwardFailure=yes",
    "-o", "ServerAliveInterval=30",
    "-o", "ServerAliveCountMax=3",
    "$SshUser@$VpsHost"
)
$ssh = Start-Process -FilePath "ssh.exe" -ArgumentList $sshArgs -PassThru -WindowStyle Hidden
$pacJob = $null
try {
    $deadline = (Get-Date).AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 250
        if ($ssh.HasExited) {
            throw "ssh.exe exited with code $($ssh.ExitCode)"
        }
        $ready = Test-NetConnection -ComputerName 127.0.0.1 -Port $LocalProxyPort -WarningAction SilentlyContinue
    } while (-not $ready.TcpTestSucceeded -and (Get-Date) -lt $deadline)
    if (-not $ready.TcpTestSucceeded) {
        throw "SSH forward did not listen on 127.0.0.1:$LocalProxyPort"
    }

    $pac = @"
function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if (host == "beeline.ru" || dnsDomainIs(host, ".beeline.ru") ||
      host == "vimpelcom.ru" || dnsDomainIs(host, ".vimpelcom.ru")) {
    return "PROXY 127.0.0.1:$LocalProxyPort";
  }
  return "DIRECT";
}
"@
    $pacJob = Start-Job -ArgumentList $PacPort, $pac -ScriptBlock {
        param($Port, $PacBody)
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        try {
            while ($true) {
                $client = $listener.AcceptTcpClient()
                try {
                    $stream = $client.GetStream()
                    $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::ASCII, $false, 1024, $true)
                    while (($line = $reader.ReadLine()) -ne "" -and $null -ne $line) {}
                    $body = [System.Text.Encoding]::UTF8.GetBytes($PacBody)
                    $header = "HTTP/1.1 200 OK`r`nContent-Type: application/x-ns-proxy-autoconfig`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n"
                    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
                    $stream.Write($headerBytes, 0, $headerBytes.Length)
                    $stream.Write($body, 0, $body.Length)
                    $stream.Flush()
                } finally {
                    $client.Dispose()
                }
            }
        } finally {
            $listener.Stop()
        }
    }
    $pacDeadline = (Get-Date).AddSeconds(10)
    do {
        Start-Sleep -Milliseconds 200
        $pacReady = Test-NetConnection -ComputerName 127.0.0.1 -Port $PacPort -WarningAction SilentlyContinue
    } while (-not $pacReady.TcpTestSucceeded -and (Get-Date) -lt $pacDeadline)
    if (-not $pacReady.TcpTestSucceeded) {
        throw "PAC server did not listen on 127.0.0.1:$PacPort"
    }

    New-Item -ItemType Directory -Force -Path $ProfileDir | Out-Null
    Write-Host "Edge profile: $ProfileDir"
    Write-Host "Only beeline.ru, vimpelcom.ru and their subdomains use the reverse proxy."
    $edgeArgs = @(
        "--user-data-dir=$ProfileDir",
        "--proxy-pac-url=http://127.0.0.1:$PacPort/proxy.pac",
        "--no-first-run",
        "--new-window",
        $StartUrl
    )
    $edgeProcess = Start-Process -FilePath $edge -ArgumentList $edgeArgs -PassThru
    Wait-Process -Id $edgeProcess.Id
} finally {
    if ($pacJob) {
        Stop-Job -Job $pacJob -ErrorAction SilentlyContinue
        Remove-Job -Job $pacJob -Force -ErrorAction SilentlyContinue
    }
    if ($ssh -and -not $ssh.HasExited) {
        Stop-Process -Id $ssh.Id -Force -ErrorAction SilentlyContinue
    }
}
