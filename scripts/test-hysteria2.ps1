#Requires -Version 7.0
param([string]$HysteriaPath)
$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $HysteriaPath) {
    if (-not $IsWindows) { throw 'Supply -HysteriaPath for a non-Windows host.' }
    $directory = Join-Path $workspace 'target/oracles/hysteria-v2.6.4'
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $HysteriaPath = Join-Path $directory 'hysteria.exe'
    if (-not (Test-Path -LiteralPath $HysteriaPath)) {
        Invoke-WebRequest 'https://github.com/HyNetworks/hysteria/releases/download/app/v2.6.4/hysteria-windows-amd64.exe' -OutFile $HysteriaPath
    }
    if ((Get-FileHash -LiteralPath $HysteriaPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne '02bb3681c28789132989de8d13ac3cbf3de7127a75967d4b9595f557216ca8bc') {
        throw 'Official Hysteria v2.6.4 checksum mismatch.'
    }
}
$previous = $env:HYSTERIA_BIN
Push-Location $workspace
try {
    $env:HYSTERIA_BIN = (Resolve-Path -LiteralPath $HysteriaPath).Path
    cargo test -p meta-protocol --locked --offline --test hysteria2_interop -- --ignored --nocapture
    if ($LASTEXITCODE -ne 0) { throw 'Hysteria 2 interoperability failed.' }
} finally {
    $env:HYSTERIA_BIN = $previous
    Pop-Location
}
