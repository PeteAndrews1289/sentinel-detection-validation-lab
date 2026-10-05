#requires -RunAsAdministrator
<#
Run ONLY on the disposable Windows lab VM. Does not turn off antivirus or clear logs.
All test accounts are disabled, have random passwords, and are removed in finally.
Task and Run-key test actions are a harmless cmd.exe /c exit 0.
Use -PauseForScreenshot to inspect state before cleanup. Do not reboot/sign out then.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('ps_positive','ps_negative','task_positive','task_negative',
        'admin_positive','admin_negative','runkey_positive','runkey_negative',
        'decode_positive','decode_negative','chain_positive','chain_negative')]
    [string]$Case,
    [switch]$AcknowledgeLabOnly,
    [switch]$PauseForScreenshot
)
$ErrorActionPreference = 'Stop'
if (-not $AcknowledgeLabOnly) { throw 'Supply -AcknowledgeLabOnly inside the disposable lab VM.' }
if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell.' }
if ($PSVersionTable.PSEdition -ne 'Desktop') { throw 'Use Windows PowerShell 5.1, not PowerShell 7, for these Windows-only scripts.' }
if (-not (Get-Service Sysmon64 -ErrorAction SilentlyContinue)) { throw 'Install Sysmon64 first.' }
if (-not (Test-Path 'C:\DVL\baseline\audit-policy-before.csv')) { throw 'Run Initialize-Lab.ps1 first.' }

$runId = [Guid]::NewGuid().ToString('N').Substring(0,12)
$runDir = "C:\DVL\runs\$runId"
New-Item -ItemType Directory -Force -Path $runDir | Out-Null
$started = [DateTime]::UtcNow
$manifest = [ordered]@{
    schema_version=1; run_id=$runId; case_id=$Case; computer=$env:COMPUTERNAME
    started_utc=$started.ToString('o'); ended_utc=$null
    execution_ok=$false; cleanup_ok=$false; anchor=$runId
    expected_rule_ids=@(); telemetry_requirements=@(); error=$null; cleanup_errors=@()
}
$localUser=$null; $taskName=$null; $registryPath=$null; $registryName=$null

function Invoke-Native {
    param([string]$Exe, [string[]]$Arguments, [int[]]$AllowedExitCodes=@(0))
    $oldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $Exe @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $oldPreference }
    $output | ForEach-Object { Write-Host ([string]$_) }
    Write-Host "Exit code: $code"
    if ($AllowedExitCodes -notcontains $code) { throw "$Exe returned unexpected exit code $code" }
}
function Require-Telemetry {
    param([string]$Family, [int]$Id, [string]$Image='')
    $script:manifest.telemetry_requirements += @{
        source_family=$Family; event_id=$Id; image_suffix=$Image
    }
}
function New-DisabledLabUser {
    $name = "dvl$runId"
    if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) { throw 'Unexpected account name collision.' }
    $bytes = New-Object byte[] 24
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $secret = ConvertTo-SecureString ('Aa1!' + [Convert]::ToBase64String($bytes)) -AsPlainText -Force
    $script:localUser = New-LocalUser -Name $name -Password $secret -Disabled -Description "DVL disposable $runId"
    $secret = $null
    $script:manifest.anchor = $script:localUser.SID.Value
    Write-Host "Created DISABLED lab account: $name / SID $($script:localUser.SID.Value)"
    Require-Telemetry 'SecurityEvent' 4720
}

Start-Transcript -Path "$runDir\execution-transcript.txt" | Out-Null
try {
    Write-Host "DVL run $runId | case $Case | host $env:COMPUTERNAME | UTC $($started.ToString('o'))"
    switch ($Case) {
        'ps_positive' {
            $payload = "Write-Output 'DVL harmless encoded message $runId'"
            $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
            $manifest.anchor=$encoded
            $manifest.expected_rule_ids=@('DVL-001')
            Require-Telemetry 'Sysmon' 1 '\powershell.exe'
            Invoke-Native "$PSHOME\powershell.exe" @('-NoProfile','-NonInteractive','-EncodedCommand',$encoded)
        }
        'ps_negative' {
            Require-Telemetry 'Sysmon' 1 '\powershell.exe'
            Invoke-Native "$PSHOME\powershell.exe" @('-NoProfile','-NonInteractive','-Command',"Write-Output 'DVL plain message $runId'")
        }
        'task_positive' {
            $taskName="DVL_$runId"
            $manifest.expected_rule_ids=@('DVL-002')
            Require-Telemetry 'Sysmon' 1 '\schtasks.exe'
            Invoke-Native "$env:SystemRoot\System32\schtasks.exe" @('/Create','/TN',$taskName,'/SC','ONSTART','/RU','SYSTEM','/TR',"$env:SystemRoot\System32\cmd.exe /c exit 0")
            Get-ScheduledTask -TaskName $taskName -ErrorAction Stop | Format-List TaskName,State,Actions
            Write-Host 'Task registration verified. No task execution is claimed; do not reboot.'
        }
        'task_negative' {
            # A unique nonexistent task name makes this query traceable without creating a task.
            $name="DVL_absent_$runId"
            Require-Telemetry 'Sysmon' 1 '\schtasks.exe'
            Invoke-Native "$env:SystemRoot\System32\schtasks.exe" @('/Query','/TN',$name) @(1)
            Write-Host 'Exit code 1 is expected: a lookup of a nonexistent task, not task creation.'
        }
        'admin_positive' {
            New-DisabledLabUser
            $group = Get-LocalGroup -SID 'S-1-5-32-544'
            Add-LocalGroupMember -Group $group -Member $localUser
            $member = Get-LocalGroupMember -Group $group | Where-Object { $_.SID.Value -eq $localUser.SID.Value }
            if (-not $member) { throw 'Administrator membership read-back failed.' }
            $member | Format-Table Name,SID
            $manifest.expected_rule_ids=@('DVL-003','DVL-006')
            Require-Telemetry 'SecurityEvent' 4732
        }
        'admin_negative' {
            New-DisabledLabUser
            $group=Get-LocalGroup -SID 'S-1-5-32-545'
            Add-LocalGroupMember -Group $group -Member $localUser
            $member=Get-LocalGroupMember -Group $group | Where-Object { $_.SID.Value -eq $localUser.SID.Value }
            if (-not $member) { throw 'Users membership read-back failed.' }
            $member | Format-Table Name,SID
            Require-Telemetry 'SecurityEvent' 4732
        }
        'runkey_positive' {
            $registryPath='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
            $registryName="DVL_$runId"
            if (-not (Test-Path -LiteralPath $registryPath -ErrorAction Stop)) { New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null }
            New-ItemProperty -Path $registryPath -Name $registryName -PropertyType String -Value "$env:SystemRoot\System32\cmd.exe /c exit 0" | Out-Null
            Get-ItemPropertyValue -Path $registryPath -Name $registryName
            Write-Host 'Run value written; no sign-in/autostart execution is claimed. Do not sign out.'
            $manifest.expected_rule_ids=@('DVL-004')
            Require-Telemetry 'Sysmon' 13
        }
        'runkey_negative' {
            $registryPath='HKCU:\Software\DVL\Settings'
            $registryName="DVL_$runId"
            if (-not (Test-Path -LiteralPath $registryPath -ErrorAction Stop)) { New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null }
            New-ItemProperty -Path $registryPath -Name $registryName -PropertyType String -Value "Harmless setting $runId" | Out-Null
            Get-ItemPropertyValue -Path $registryPath -Name $registryName
            Require-Telemetry 'Sysmon' 13
        }
        'decode_positive' {
            $plain="DVL harmless text $runId"
            [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($plain)) | Set-Content "$runDir\input.b64" -Encoding Ascii
            Invoke-Native "$env:SystemRoot\System32\certutil.exe" @('-decode',"$runDir\input.b64","$runDir\decoded.txt")
            $decoded=[IO.File]::ReadAllText("$runDir\decoded.txt")
            if ($decoded -ne $plain) { throw 'Decoded file read-back did not equal input.' }
            Write-Host "Verified decoded content: $decoded"
            $manifest.expected_rule_ids=@('DVL-005')
            Require-Telemetry 'Sysmon' 1 '\certutil.exe'
        }
        'decode_negative' {
            "DVL hash-only file $runId" | Set-Content "$runDir\input.txt" -Encoding Ascii
            Invoke-Native "$env:SystemRoot\System32\certutil.exe" @('-hashfile',"$runDir\input.txt",'SHA256')
            Require-Telemetry 'Sysmon' 1 '\certutil.exe'
        }
        'chain_positive' {
            New-DisabledLabUser
            $group=Get-LocalGroup -SID 'S-1-5-32-544'
            Add-LocalGroupMember -Group $group -Member $localUser
            $member=Get-LocalGroupMember -Group $group | Where-Object { $_.SID.Value -eq $localUser.SID.Value }
            if (-not $member) { throw 'Administrator membership read-back failed.' }
            $member | Format-Table Name,SID
            $manifest.expected_rule_ids=@('DVL-003','DVL-006')
            Require-Telemetry 'SecurityEvent' 4732
        }
        'chain_negative' {
            New-DisabledLabUser
            Write-Host 'Account exists but no administrator membership was added.'
        }
    }
    $manifest.execution_ok=$true
    Write-Host "EXECUTION VERIFIED. Anchor: $($manifest.anchor)"
    if ($PauseForScreenshot) {
        [void](Read-Host 'Take 01-execution and 02-local-event screenshots now. Do not reboot/sign out. Enter to clean up')
    }
} catch {
    $manifest.error=$_.Exception.Message
    Write-Warning "EXECUTION FAILURE: $($manifest.error)"
} finally {
    $manifest.ended_utc=[DateTime]::UtcNow.ToString('o')
    $cleanupErrors=@()
    if ($localUser) {
        try {
            # Remove membership first so the 4733 reversal can also be inspected.
            foreach ($sid in @('S-1-5-32-544','S-1-5-32-545')) {
                $g=Get-LocalGroup -SID $sid
                if (Get-LocalGroupMember -Group $g | Where-Object {$_.SID.Value -eq $localUser.SID.Value}) {
                    Remove-LocalGroupMember -Group $g -Member $localUser
                }
            }
            Remove-LocalUser -Name $localUser.Name
            if (Get-LocalUser -Name $localUser.Name -ErrorAction SilentlyContinue) { throw 'Account still exists.' }
        } catch { $cleanupErrors += $_.Exception.Message }
    }
    if ($taskName) {
        try {
            if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            }
            if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'Task still exists.' }
        } catch { $cleanupErrors += $_.Exception.Message }
    }
    if ($registryPath -and $registryName) {
        try {
            Remove-ItemProperty -Path $registryPath -Name $registryName -ErrorAction SilentlyContinue
            if (Get-ItemProperty -Path $registryPath -Name $registryName -ErrorAction SilentlyContinue) { throw 'Registry value still exists.' }
        } catch { $cleanupErrors += $_.Exception.Message }
    }
    $manifest.cleanup_errors=$cleanupErrors
    $manifest.cleanup_ok=($cleanupErrors.Count -eq 0)
    $manifest | ConvertTo-Json -Depth 8 | Set-Content "$runDir\manifest.json" -Encoding UTF8
    Write-Host "Cleanup verified: $($manifest.cleanup_ok). Evidence: $runDir"
    if ($cleanupErrors.Count) { Write-Warning ($cleanupErrors -join '; ') }
    Stop-Transcript | Out-Null
}

# Preserve real local XML, including cleanup events. These are PRIVATE until reviewed.
# This is not a claim that all required records were present; inspect the relevant events.
$endLocal=Get-Date
foreach ($spec in @(@('Microsoft-Windows-Sysmon/Operational','sysmon'),@('Security','security'))) {
    $logName=$spec[0]; $stem=$spec[1]
    try {
        $records=@(Get-WinEvent -FilterHashtable @{LogName=$logName; StartTime=$started.ToLocalTime(); EndTime=$endLocal} -ErrorAction Stop)
        $xml='<Events>' + (($records | ForEach-Object {$_.ToXml()}) -join "`r`n") + '</Events>'
        $xml | Set-Content "$runDir\$stem-events.xml" -Encoding UTF8
        $records | Select-Object TimeCreated,Id,RecordId,ProviderName,MachineName |
            Export-Csv "$runDir\$stem-index.csv" -NoTypeInformation
    } catch {
        $_.Exception.Message | Set-Content "$runDir\$stem-export-error.txt" -Encoding UTF8
    }
}
$hashPath = Join-Path $runDir 'file-hashes.csv'
$evidenceFiles = @(Get-ChildItem -LiteralPath $runDir -File -ErrorAction Stop | Where-Object { $_.FullName -ne $hashPath })
$hashRows = @(Get-FileHash -LiteralPath $evidenceFiles.FullName -Algorithm SHA256 -ErrorAction Stop)
$hashRows | Select-Object Path,Hash | Export-Csv -LiteralPath $hashPath -NoTypeInformation -ErrorAction Stop
Get-Content "$runDir\manifest.json"
if (-not $manifest.execution_ok -or -not $manifest.cleanup_ok) { exit 1 }

