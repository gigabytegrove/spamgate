#Requires -RunAsAdministrator
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$Existing = Get-Service -Name SpamGate -ErrorAction SilentlyContinue
if ($null -ne $Existing) {
    if ($Existing.Status -ne 'Stopped') {
        Stop-Service -Name SpamGate
        (Get-Service SpamGate).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    & sc.exe delete SpamGate | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not delete SpamGate service.' }
}
$Exe = Join-Path $env:ProgramFiles 'SpamGate\spamgate.exe'
if (Test-Path -LiteralPath $Exe -PathType Leaf) { Remove-Item -LiteralPath $Exe -Force }
Write-Host 'SpamGate service and executable removed.'
Write-Host "Mail history, logs, and configuration are retained in $env:ProgramData\SpamGate."
Write-Host 'This script never deletes user data.'
