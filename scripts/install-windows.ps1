#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$Listen = '',
    [string]$InstallDirectory = "$env:ProgramFiles\SpamGate",
    [string]$DataDirectory = "$env:ProgramData\SpamGate"
)
$ErrorActionPreference = 'Stop'
$ServiceName = 'SpamGate'
$SourceExe = Join-Path $PSScriptRoot 'spamgate.exe'
$TargetExe = Join-Path $InstallDirectory 'spamgate.exe'
$LogPath = Join-Path $DataDirectory 'spamgate.log'
$Metadata = Join-Path $DataDirectory 'install.json'

if (-not (Test-Path -LiteralPath $SourceExe -PathType Leaf)) {
    throw "Missing SpamGate binary: $SourceExe"
}
$Version = & $SourceExe -version
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($Version)) {
    throw 'SpamGate binary version check failed.'
}
if ([string]::IsNullOrEmpty($Listen)) {
    if (Test-Path -LiteralPath $Metadata -PathType Leaf) {
        $Listen = (Get-Content -LiteralPath $Metadata -Raw | ConvertFrom-Json).listen
    } else {
        $Listen = '127.0.0.1:38470'
    }
}
if ($Listen -notmatch '^[a-zA-Z0-9.:[\]_-]+$' -or $Listen -notmatch ':') {
    throw 'Invalid -Listen. Supply a listener such as 127.0.0.1:38470 or 192.168.1.10:38470.'
}
if ($InstallDirectory.Contains('"') -or $DataDirectory.Contains('"')) {
    throw 'Installation directory paths must not contain quotation marks.'
}

New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $DataDirectory -Force | Out-Null

# SYSTEM and Administrators: full access; LocalService: modify permissions.
# The one-time claim key is written to a log readable only by these principals.
& icacls.exe $DataDirectory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)M' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict SpamGate data directory ACL.' }

$Existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $Existing -and $Existing.Status -ne 'Stopped') {
    Stop-Service -Name $ServiceName -ErrorAction Stop
    (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
$TempExe = Join-Path $InstallDirectory 'spamgate.exe.new'
Copy-Item -LiteralPath $SourceExe -Destination $TempExe -Force
Move-Item -LiteralPath $TempExe -Destination $TargetExe -Force
$BinaryPath = '"{0}" -data "{1}" -listen "{2}" -log-file "{3}"' -f $TargetExe, $DataDirectory, $Listen, $LogPath
if ($null -eq $Existing) {
    New-Service -Name $ServiceName -BinaryPathName $BinaryPath -DisplayName 'SpamGate Mail Filtering' -StartupType Automatic | Out-Null
} else {
    & sc.exe config $ServiceName binPath= $BinaryPath start= auto | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not update SpamGate Windows service command line.' }
}
& sc.exe config $ServiceName obj= 'NT AUTHORITY\LocalService' password= '' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not set LocalService account.' }
& sc.exe failure $ServiceName reset= 86400 actions= 'restart/5000/restart/15000/none/0' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not configure service recovery.' }
@{listen=$Listen;version="$Version"} | ConvertTo-Json | Set-Content -LiteralPath $Metadata -Encoding UTF8
Start-Service -Name $ServiceName
(Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
Write-Host "SpamGate $Version installed as Windows service $ServiceName."
Write-Host "Console: http://$Listen"
Write-Host "Setup key and logs: $LogPath (administrator access required)"
Write-Host "Persistent data: $DataDirectory (preserved on upgrade)"
Write-Host "Status: Get-Service SpamGate"
