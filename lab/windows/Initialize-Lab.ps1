#requires -RunAsAdministrator
# Run only inside the disposable Windows lab VM, using 64-bit Windows PowerShell.
[CmdletBinding()]
param([switch]$AcknowledgeLabOnly)
$ErrorActionPreference = 'Stop'
if (-not $AcknowledgeLabOnly) { throw 'Supply -AcknowledgeLabOnly inside the disposable lab VM.' }
if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell.' }
if ($PSVersionTable.PSEdition -ne 'Desktop') { throw 'Use Windows PowerShell 5.1, not PowerShell 7, for these Windows-only scripts.' }
$base = 'C:\DVL'
New-Item -ItemType Directory -Force -Path "$base\runs", "$base\baseline", "$base\tools" | Out-Null
$backup = "$base\baseline\audit-policy-before.csv"
if (-not (Test-Path $backup)) {
    & auditpol.exe /backup /file:$backup
    if ($LASTEXITCODE -ne 0) { throw 'Could not back up audit policy.' }
}
# Subcategory names below assume an English-language Windows image.
foreach ($subcategory in @('User Account Management', 'Security Group Management')) {
    & auditpol.exe /set "/subcategory:$subcategory" /success:enable /failure:enable
    if ($LASTEXITCODE -ne 0) { throw "Could not enable $subcategory. Check auditpol /list /subcategory:*" }
}
& auditpol.exe /get /category:*
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber, CsName |
    ConvertTo-Json | Set-Content "$base\baseline\host.json" -Encoding UTF8
Get-Date -Format o
Write-Host 'Save setup screenshot: audit subcategories enabled and host name. No credentials.'
