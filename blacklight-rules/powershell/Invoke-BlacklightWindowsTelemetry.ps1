[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet('Audit', 'Apply', 'Rollback')]
    [string]$Mode = 'Audit',
    [ValidateSet('HighValue', 'AllRoots')]
    [string]$Coverage = 'HighValue',
    [string]$StatePath = (Join-Path $env:ProgramData 'Blacklight\windows-telemetry-state.json'),
    [switch]$IncludeFailures,
    [long]$MinimumSecurityLogBytes = 0
)

$ErrorActionPreference = 'Stop'
$fileSystemGuid = '{0CCE921D-69AE-11D9-BED3-505054503030}'
$auditPolicyChangeGuid = '{0CCE922F-69AE-11D9-BED3-505054503030}'
$schemaVersion = 'blacklight.windows-telemetry-state.v2'
$legacyOverrideValueName = 'SCENoApplyLegacyAuditPolicy'
$legacyOverrideKeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$readAuditRights = [System.Security.AccessControl.FileSystemRights]::ReadData -bor
    [System.Security.AccessControl.FileSystemRights]::ListDirectory -bor
    [System.Security.AccessControl.FileSystemRights]::ReadAttributes -bor
    [System.Security.AccessControl.FileSystemRights]::ReadExtendedAttributes -bor
    [System.Security.AccessControl.FileSystemRights]::ReadPermissions

function Test-IsAdministrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-WindowsHost {
    if ($env:OS -ne 'Windows_NT') {
        throw 'This utility supports Windows hosts only.'
    }
}

function Assert-ElevatedSession {
    param([Parameter(Mandatory = $true)][string]$SelectedMode)
    if (-not (Test-IsAdministrator)) {
        throw "$SelectedMode mode requires an elevated PowerShell session. Start PowerShell with 'Run as administrator', then run the command again. Audit mode is safe to run without elevation, but its results can be incomplete."
    }
}

function Get-CurrentUserHomeRoot {
    if ([string]::IsNullOrWhiteSpace($env:USERPROFILE) -or -not (Test-Path -LiteralPath $env:USERPROFILE -PathType Container)) {
        throw 'USERPROFILE must identify the current user profile directory.'
    }
    (Resolve-Path -LiteralPath $env:USERPROFILE).Path
}

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$FailurePrefix
    )
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $FilePath @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }
    if ($exitCode -ne 0) {
        $prefix = if ($FailurePrefix) { $FailurePrefix } else { Split-Path -Leaf $FilePath }
        throw "${prefix} failed with exit code ${exitCode}: $($output -join ' ')"
    }
    [pscustomobject]@{ ExitCode = $exitCode; Output = $output -join [Environment]::NewLine }
}

function Invoke-AuditPol {
    param([Parameter(Mandatory = $true)][string[]]$Arguments, [switch]$AllowFailure)
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& (Join-Path $env:SystemRoot 'System32\auditpol.exe') @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }
    if ($exitCode -ne 0 -and -not $AllowFailure) {
        throw "auditpol failed with exit code ${exitCode}: $($output -join ' ')"
    }
    [pscustomobject]@{ ExitCode = $exitCode; Output = $output -join [Environment]::NewLine }
}

function Invoke-Wevtutil {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    Invoke-NativeCommand -FilePath (Join-Path $env:SystemRoot 'System32\wevtutil.exe') -Arguments $Arguments -FailurePrefix 'wevtutil'
}

function Get-TargetDefinitions {
    param([string]$SelectedCoverage)
    if ($SelectedCoverage -eq 'AllRoots') {
        return @(
            @{ Tool = 'codex'; RelativePath = '.codex' },
            @{ Tool = 'claude_code'; RelativePath = '.claude' },
            @{ Tool = 'claude_code'; RelativePath = '.claude.json' },
            @{ Tool = 'cursor'; RelativePath = '.cursor' },
            @{ Tool = 'antigravity_cli'; RelativePath = '.gemini\antigravity-cli' }
        )
    }
    @(
        @{ Tool = 'codex'; RelativePath = '.codex\auth.json' },
        @{ Tool = 'codex'; RelativePath = '.codex\.sandbox-secrets\sandbox_users.json' },
        @{ Tool = 'codex'; RelativePath = '.codex\config.toml' },
        @{ Tool = 'codex'; RelativePath = '.codex\rules\default.rules' },
        @{ Tool = 'codex'; RelativePath = '.codex\session_index.jsonl' },
        @{ Tool = 'claude_code'; RelativePath = '.claude\.credentials.json' },
        @{ Tool = 'claude_code'; RelativePath = '.claude\settings.json' },
        @{ Tool = 'claude_code'; RelativePath = '.claude.json' },
        @{ Tool = 'cursor'; RelativePath = '.cursor\cli-config.json' },
        @{ Tool = 'cursor'; RelativePath = '.cursor\mcp.json' },
        @{ Tool = 'cursor'; RelativePath = '.cursor\prompt_history.json' },
        @{ Tool = 'cursor'; RelativePath = '.cursor\ai-tracking\ai-code-tracking.db' },
        @{ Tool = 'antigravity_cli'; RelativePath = '.gemini\antigravity-cli\settings.json' },
        @{ Tool = 'antigravity_cli'; RelativePath = '.gemini\antigravity-cli\mcp_config.json' },
        @{ Tool = 'antigravity_cli'; RelativePath = '.gemini\antigravity-cli\conversation_summaries.db' }
    )
}

function Get-TargetPaths {
    param([string]$HomeRoot, [string]$SelectedCoverage)
    $definitions = Get-TargetDefinitions -SelectedCoverage $SelectedCoverage
    @($definitions | ForEach-Object {
        [pscustomobject]@{
            Tool = $_.Tool
            HomeRoot = $HomeRoot
            Path = Join-Path -Path $HomeRoot -ChildPath $_.RelativePath
        }
    })
}

function Test-BlacklightReadAuditRule {
    param(
        $Rule,
        [switch]$RequireFailure
    )
    try {
        $sid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        return $false
    }
    $hasSuccess = (([int]$Rule.AuditFlags -band [int][System.Security.AccessControl.AuditFlags]::Success) -ne 0)
    $hasFailure = (([int]$Rule.AuditFlags -band [int][System.Security.AccessControl.AuditFlags]::Failure) -ne 0)
    $hasReadRights = (([long]$Rule.FileSystemRights -band [long]$readAuditRights) -eq [long]$readAuditRights)
    if ($sid -ne 'S-1-1-0' -or -not $hasSuccess -or -not $hasReadRights) {
        return $false
    }
    if ($RequireFailure -and -not $hasFailure) {
        return $false
    }
    $true
}

function Get-SaclState {
    param([string]$LiteralPath)
    $item = Get-Item -LiteralPath $LiteralPath -Force
    $acl = Get-Acl -LiteralPath $LiteralPath -Audit
    [pscustomobject]@{
        Path = $item.FullName
        IsDirectory = $item.PSIsContainer
        Sddl = $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Audit)
        BlacklightAuditAceCount = @($acl.Audit | Where-Object { Test-BlacklightReadAuditRule -Rule $_ }).Count
    }
}

function Add-ReadAuditRule {
    param([string]$LiteralPath, [bool]$AuditFailures)
    $item = Get-Item -LiteralPath $LiteralPath -Force
    $acl = Get-Acl -LiteralPath $LiteralPath -Audit
    $inheritance = if ($item.PSIsContainer) {
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else { [System.Security.AccessControl.InheritanceFlags]::None }
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $flags = [System.Security.AccessControl.AuditFlags]::Success
    if ($AuditFailures) { $flags = $flags -bor [System.Security.AccessControl.AuditFlags]::Failure }
    $everyone = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
    $rule = [System.Security.AccessControl.FileSystemAuditRule]::new($everyone, $readAuditRights, $inheritance, $propagation, $flags)

    $alreadyPresent = @($acl.Audit | Where-Object {
        Test-BlacklightReadAuditRule -Rule $_ -RequireFailure:$AuditFailures
    }).Count -gt 0
    if (-not $alreadyPresent) {
        $acl.AddAuditRule($rule)
        Set-Acl -LiteralPath $LiteralPath -AclObject $acl
    }
}

function Restore-SaclState {
    param($Entry)
    if (-not (Test-Path -LiteralPath $Entry.Path)) { return }
    $security = if ($Entry.IsDirectory) {
        [System.Security.AccessControl.DirectorySecurity]::new()
    } else {
        [System.Security.AccessControl.FileSecurity]::new()
    }
    $security.SetSecurityDescriptorSddlForm([string]$Entry.Sddl, [System.Security.AccessControl.AccessControlSections]::Audit)
    Set-Acl -LiteralPath $Entry.Path -AclObject $security
}

function Get-LegacyAuditPolicyOverride {
    try {
        return [int](Get-ItemProperty -LiteralPath $legacyOverrideKeyPath -Name $legacyOverrideValueName -ErrorAction Stop).$legacyOverrideValueName
    }
    catch {
        return $null
    }
}

function Set-LegacyAuditPolicyOverride {
    param($PriorValue)
    if ($null -eq $PriorValue) {
        Remove-ItemProperty -LiteralPath $legacyOverrideKeyPath -Name $legacyOverrideValueName -ErrorAction SilentlyContinue
        return
    }
    New-ItemProperty -LiteralPath $legacyOverrideKeyPath -Name $legacyOverrideValueName -PropertyType DWord -Value ([int]$PriorValue) -Force | Out-Null
}

function Enable-LegacyAuditPolicyOverride {
    $prior = Get-LegacyAuditPolicyOverride
    if ($prior -ne 1) {
        New-ItemProperty -LiteralPath $legacyOverrideKeyPath -Name $legacyOverrideValueName -PropertyType DWord -Value 1 -Force | Out-Null
    }
    $prior
}

function Protect-AdminOnlyPath {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [switch]$Directory
    )
    if (-not (Test-Path -LiteralPath $LiteralPath)) { return }
    $identitySystem = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $identityAdmins = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $inheritance = if ($Directory) {
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $security = if ($Directory) {
        [System.Security.AccessControl.DirectorySecurity]::new()
    } else {
        [System.Security.AccessControl.FileSecurity]::new()
    }
    $security.SetAccessRuleProtection($true, $false)
    $security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($identitySystem, $rights, $inheritance, $propagation, [System.Security.AccessControl.AccessControlType]::Allow))
    $security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($identityAdmins, $rights, $inheritance, $propagation, [System.Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath $LiteralPath -AclObject $security
}

function Remove-TelemetryStateFiles {
    param(
        [Parameter(Mandatory = $true)][string]$JsonPath,
        [string]$AuditPolicyBackupPath
    )
    if ($AuditPolicyBackupPath -and (Test-Path -LiteralPath $AuditPolicyBackupPath)) {
        Remove-Item -LiteralPath $AuditPolicyBackupPath -Force
    }
    if (Test-Path -LiteralPath $JsonPath) {
        Remove-Item -LiteralPath $JsonPath -Force
    }
}

function Restore-TelemetryState {
    param(
        [Parameter(Mandatory = $true)]$SavedState,
        [switch]$LeaveStateFilesOnFailure
    )
    try {
        Invoke-AuditPol -Arguments @('/restore', "/file:$($SavedState.AuditPolicyBackup)") | Out-Null
        foreach ($entry in @($SavedState.Paths)) {
            Restore-SaclState -Entry $entry
        }
        if ($SavedState.SecurityLogMaximumSizeBytes -gt 0) {
            Invoke-Wevtutil -Arguments @('sl', 'Security', "/ms:$($SavedState.SecurityLogMaximumSizeBytes)") | Out-Null
        }
        if ($SavedState.PSObject.Properties.Name -contains 'LegacyAuditPolicyOverride') {
            Set-LegacyAuditPolicyOverride -PriorValue $SavedState.LegacyAuditPolicyOverride
        }
    }
    catch {
        if ($LeaveStateFilesOnFailure) {
            throw "Rollback failed and state files were left in place for retry. Fix the error, then run Rollback again. $($_.Exception.Message)"
        }
        throw
    }
}

function Get-TelemetryAudit {
    param([object[]]$Targets)
    $isAdministrator = Test-IsAdministrator
    $fileSystemPolicy = Invoke-AuditPol -Arguments @('/get', "/subcategory:$fileSystemGuid", '/r') -AllowFailure
    $policyChange = Invoke-AuditPol -Arguments @('/get', "/subcategory:$auditPolicyChangeGuid", '/r') -AllowFailure
    $securityLog = $null
    $securityLogError = $null
    try { $securityLog = Get-WinEvent -ListLog Security -ErrorAction Stop }
    catch { $securityLogError = $_.Exception.Message }
    $legacyOverride = Get-LegacyAuditPolicyOverride

    if (-not $isAdministrator) {
        Write-Warning 'Audit mode is running without elevation. Apply and Rollback are blocked, and Security-log or SACL results may be incomplete. Start PowerShell with Run as administrator for a complete check.'
    }
    if ($fileSystemPolicy.ExitCode -ne 0 -or $policyChange.ExitCode -ne 0) {
        Write-Warning 'One or more advanced audit-policy queries failed. Do not treat this audit result as proof that recording is configured.'
    }
    if ($securityLogError) {
        Write-Warning "The Security log could not be inspected: $securityLogError"
    }
    if ($legacyOverride -ne 1) {
        Write-Warning 'SCENoApplyLegacyAuditPolicy is not enabled. Advanced subcategory settings may be ignored until Apply enables the override (or Group Policy sets it).'
    }

    [pscustomobject]@{
        RecordType = 'TelemetryPrerequisites'
        Mode = $Mode
        IsAdministrator = $isAdministrator
        CanApplyOrRollback = $isAdministrator
        AuditResultMayBeIncomplete = (-not $isAdministrator) -or $fileSystemPolicy.ExitCode -ne 0 -or $policyChange.ExitCode -ne 0 -or $null -ne $securityLogError
        FileSystemAuditPolicyExitCode = $fileSystemPolicy.ExitCode
        FileSystemAuditPolicy = $fileSystemPolicy.Output
        AuditPolicyChangeExitCode = $policyChange.ExitCode
        AuditPolicyChange = $policyChange.Output
        LegacyPolicyOverrideEnabled = if ($null -eq $legacyOverride) { $null } else { [int]$legacyOverride -eq 1 }
        SecurityLogEnabled = if ($securityLog) { $securityLog.IsEnabled } else { $null }
        SecurityLogMode = if ($securityLog) { $securityLog.LogMode.ToString() } else { $null }
        SecurityLogMaximumSizeBytes = if ($securityLog) { $securityLog.MaximumSizeInBytes } else { $null }
        SecurityLogReadError = $securityLogError
        SecurityLogMeetsRequestedMinimum = if ($securityLog -and $MinimumSecurityLogBytes -gt 0) { $securityLog.MaximumSizeInBytes -ge $MinimumSecurityLogBytes } else { $null }
        GroupPolicyCaveat = 'Domain or local Group Policy can overwrite local advanced audit policy. Verify the effective policy after policy refresh.'
    }

    foreach ($target in $Targets) {
        $exists = Test-Path -LiteralPath $target.Path
        $sacl = $null
        $saclError = $null
        if ($exists) {
            try { $sacl = Get-SaclState -LiteralPath $target.Path }
            catch { $saclError = $_.Exception.Message }
        }
        [pscustomobject]@{
            RecordType = 'Target'
            Mode = $Mode
            Tool = $target.Tool
            HomeRoot = $target.HomeRoot
            Path = $target.Path
            Exists = $exists
            SaclReadable = $null -ne $sacl
            SaclReadError = $saclError
            ReadAuditAcePresent = if ($sacl) { $sacl.BlacklightAuditAceCount -gt 0 } else { $false }
            MatchingEveryoneAuditAceCount = if ($sacl) { $sacl.BlacklightAuditAceCount } else { 0 }
        }
    }
}

Assert-WindowsHost
$homeRoot = Get-CurrentUserHomeRoot
$targets = @(Get-TargetPaths -HomeRoot $homeRoot -SelectedCoverage $Coverage)

if ($Mode -eq 'Audit') {
    Get-TelemetryAudit -Targets $targets
    return
}

Assert-ElevatedSession -SelectedMode $Mode

if ($Mode -eq 'Apply') {
    if (Test-Path -LiteralPath $StatePath) {
        throw "State path already exists; choose a new -StatePath or roll back the recorded state: $StatePath"
    }
    $existingTargets = @($targets | Where-Object { Test-Path -LiteralPath $_.Path })
    if ($existingTargets.Count -eq 0) {
        throw "No selected Blacklight targets exist under '$homeRoot'. No policy or SACL changes were made. Run Audit mode to review the selected coverage, or create the target before applying telemetry."
    }
    $stateDirectory = Split-Path -Parent $StatePath
    if (-not $stateDirectory) { $stateDirectory = (Get-Location).Path }
    $auditPolicyBackup = "$StatePath.auditpol.csv"
    $createdStateDirectory = $false
    $securityLog = Get-WinEvent -ListLog Security -ErrorAction Stop
    $saclState = @($existingTargets | ForEach-Object { Get-SaclState -LiteralPath $_.Path })

    if ($PSCmdlet.ShouldProcess('Windows advanced audit policy and selected Blacklight paths', 'Enable Blacklight read telemetry')) {
        if (-not (Test-Path -LiteralPath $stateDirectory)) {
            New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
            $createdStateDirectory = $true
        }
        if ($createdStateDirectory) {
            Protect-AdminOnlyPath -LiteralPath $stateDirectory -Directory
        }

        Invoke-AuditPol -Arguments @('/backup', "/file:$auditPolicyBackup") | Out-Null
        Protect-AdminOnlyPath -LiteralPath $auditPolicyBackup

        $priorLegacyOverride = Get-LegacyAuditPolicyOverride
        $state = [ordered]@{
            SchemaVersion = $schemaVersion
            CapturedAtUtc = [DateTime]::UtcNow.ToString('o')
            Coverage = $Coverage
            IncludeFailures = [bool]$IncludeFailures
            AuditPolicyBackup = $auditPolicyBackup
            SecurityLogMaximumSizeBytes = $securityLog.MaximumSizeInBytes
            LegacyAuditPolicyOverride = $priorLegacyOverride
            Paths = $saclState
        }
        $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $StatePath -Encoding UTF8

        try {
            Protect-AdminOnlyPath -LiteralPath $StatePath
            Enable-LegacyAuditPolicyOverride | Out-Null
            $failureSetting = if ($IncludeFailures) { 'enable' } else { 'disable' }
            Invoke-AuditPol -Arguments @('/set', "/subcategory:$fileSystemGuid", '/success:enable', "/failure:$failureSetting") | Out-Null
            Invoke-AuditPol -Arguments @('/set', "/subcategory:$auditPolicyChangeGuid", '/success:enable', "/failure:$failureSetting") | Out-Null
            foreach ($target in $existingTargets) {
                Add-ReadAuditRule -LiteralPath $target.Path -AuditFailures ([bool]$IncludeFailures)
            }
            if ($MinimumSecurityLogBytes -gt 0 -and $securityLog.MaximumSizeInBytes -lt $MinimumSecurityLogBytes) {
                Invoke-Wevtutil -Arguments @('sl', 'Security', "/ms:$MinimumSecurityLogBytes") | Out-Null
            }
        }
        catch {
            $applyError = $_
            try {
                $savedState = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
                Restore-TelemetryState -SavedState $savedState
                Remove-TelemetryStateFiles -JsonPath $StatePath -AuditPolicyBackupPath $auditPolicyBackup
            }
            catch {
                throw "Apply failed and automatic rollback also failed. State files remain at '$StatePath'. Run Rollback after fixing the error. Apply error: $($applyError.Exception.Message) Rollback error: $($_.Exception.Message)"
            }
            throw "Apply failed; changes were rolled back automatically. $($applyError.Exception.Message)"
        }
    }
    Get-TelemetryAudit -Targets $targets
    return
}

if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
    throw "Rollback state file was not found: $StatePath"
}
$savedState = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
if ($savedState.SchemaVersion -ne $schemaVersion) {
    throw "Unsupported state schema: $($savedState.SchemaVersion). This script expects $schemaVersion. Roll back with the script version that created the state, or remove the state files manually after restoring audit policy from the recorded backup."
}
if ([string]::IsNullOrWhiteSpace([string]$savedState.AuditPolicyBackup) -or -not (Test-Path -LiteralPath $savedState.AuditPolicyBackup -PathType Leaf)) {
    throw "The audit-policy backup recorded in the rollback state is missing: $($savedState.AuditPolicyBackup). No changes were made."
}

$rollbackCoverage = [string]$savedState.Coverage
if ([string]::IsNullOrWhiteSpace($rollbackCoverage)) { $rollbackCoverage = $Coverage }
$rollbackTargets = @(Get-TargetPaths -HomeRoot $homeRoot -SelectedCoverage $rollbackCoverage)
$auditPolicyBackupPath = [string]$savedState.AuditPolicyBackup

if ($PSCmdlet.ShouldProcess('Windows advanced audit policy and selected Blacklight paths', 'Restore pre-Blacklight telemetry state')) {
    Restore-TelemetryState -SavedState $savedState -LeaveStateFilesOnFailure
    Remove-TelemetryStateFiles -JsonPath $StatePath -AuditPolicyBackupPath $auditPolicyBackupPath
    Write-Host "Rollback complete. State files removed; you can Apply again using -StatePath '$StatePath'."
}
Get-TelemetryAudit -Targets $rollbackTargets
