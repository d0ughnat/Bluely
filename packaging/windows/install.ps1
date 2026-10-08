param()

$ErrorActionPreference = 'Stop'
$base = 'https://github.com/d0ughnat/Bluely/releases/latest/download'
$folder = Join-Path $env:TEMP ('BluelyInstall-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $folder | Out-Null
$installer = Join-Path $folder 'Bluely-Setup-x64.exe'
$checksum = Join-Path $folder 'Bluely-Setup-x64.exe.sha256'

try {
    Write-Host 'Downloading Bluely for Windows...'
    Invoke-WebRequest -Uri "$base/Bluely-Setup-x64.exe" -OutFile $installer -UseBasicParsing
    Invoke-WebRequest -Uri "$base/Bluely-Setup-x64.exe.sha256" -OutFile $checksum -UseBasicParsing
    $expected = ((Get-Content -LiteralPath $checksum -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
    if ($expected -notmatch '^[a-f0-9]{64}$') {
        throw 'The published checksum is invalid.'
    }
    $actual = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw 'The installer checksum does not match the published checksum.'
    }

    Write-Host 'Starting Bluely setup. Approve the Windows administrator prompt to continue.'
    $process = Start-Process -FilePath $installer -Verb RunAs -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) {
        throw "Bluely setup exited with code $($process.ExitCode)."
    }
    $app = Join-Path $env:ProgramFiles 'Bluely\Bluely.exe'
    if (Test-Path -LiteralPath $app -PathType Leaf) {
        Start-Process -FilePath $app
        Write-Host 'Bluely is installed and running.'
    } else {
        Write-Host 'Bluely is installed. Open it from the Start menu.'
    }
    if ($process.ExitCode -eq 3010) {
        Write-Host 'Restart Windows to complete setup.'
    }
} finally {
    Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue
}
