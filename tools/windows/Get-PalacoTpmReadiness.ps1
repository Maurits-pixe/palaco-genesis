#requires -Version 5.1
<#
.SYNOPSIS
Read-only Windows/TPM prerequisites report for PALACO offline backend engineering.
.DESCRIPTION
Does not initialize/clear TPM, create keys, change policy, enable a service,
contact the network or authorize execution. JSON contains no device identity.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest

function Resolve-PalacoTpmReadiness {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Observation)

    $requiredBooleans = @(
        'IsWindows', 'TpmPresent', 'TpmReady', 'TpmEnabled', 'TpmActivated',
        'LockedOut', 'RestartPending'
    )
    $unknown = @()
    foreach ($name in $requiredBooleans) {
        if (-not $Observation.ContainsKey($name) -or
            $Observation[$name] -isnot [bool]) {
            $unknown += $name
        }
    }
    if (-not $Observation.ContainsKey('WindowsBuild') -or
        $Observation['WindowsBuild'] -isnot [int]) {
        $unknown += 'WindowsBuild'
    }
    if (-not $Observation.ContainsKey('TpmSpecVersion') -or
        $Observation['TpmSpecVersion'] -isnot [string] -or
        [string]::IsNullOrWhiteSpace($Observation['TpmSpecVersion'])) {
        $unknown += 'TpmSpecVersion'
    }

    $issues = @()
    $state = 'HOLD_INCOMPLETE_EVIDENCE'
    if ($Observation.ContainsKey('IsWindows') -and
        $Observation['IsWindows'] -is [bool] -and
        -not $Observation['IsWindows']) {
        $state = 'HOLD_UNSUPPORTED_HOST'
        $issues += 'WINDOWS_REQUIRED'
    }
    elseif ($unknown.Count -eq 0) {
        if ($Observation['WindowsBuild'] -lt 19041) { $issues += 'WINDOWS_BUILD_BELOW_TARGET' }
        if (-not $Observation['TpmPresent']) { $issues += 'TPM_NOT_PRESENT' }
        if (-not $Observation['TpmReady']) { $issues += 'TPM_NOT_READY' }
        if (-not $Observation['TpmEnabled']) { $issues += 'TPM_NOT_ENABLED' }
        if (-not $Observation['TpmActivated']) { $issues += 'TPM_NOT_ACTIVATED' }
        if ($Observation['LockedOut']) { $issues += 'TPM_LOCKED_OUT' }
        if ($Observation['RestartPending']) { $issues += 'RESTART_PENDING' }
        if ($Observation['TpmSpecVersion'] -notmatch '^2\.0(?:\s*,|\s*$)') {
            $issues += 'TPM_2_0_NOT_OBSERVED'
        }
        $state = if ($issues.Count -eq 0) {
            'PREREQUISITES_OBSERVED'
        } else {
            'HOLD_PREREQUISITES'
        }
    }

    [pscustomobject][ordered]@{
        Schema = 'palaco.windows-tpm-readiness.v1'
        DiagnosticOnly = $true
        PrerequisiteState = $state
        MissingOrInvalidEvidence = @($unknown)
        Issues = @($issues)
        BackendState = 'NOT_IMPLEMENTED'
        AntiRollbackVerified = $false
        RuntimeAuthorized = $false
    }
}

function Get-PalacoBooleanProperty {
    param([object]$Object, [string]$Name)
    if ($null -ne $Object) {
        $property = $Object.PSObject.Properties[$Name]
        if ($null -ne $property -and $property.Value -is [bool]) {
            return $property.Value
        }
    }
    return $null
}

function Get-PalacoTpmObservation {
    [CmdletBinding()]
    param()
    $observation = @{
        IsWindows = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
        WindowsBuild = $null
        TpmPresent = $null
        TpmReady = $null
        TpmEnabled = $null
        TpmActivated = $null
        LockedOut = $null
        RestartPending = $null
        TpmSpecVersion = $null
    }
    if (-not $observation.IsWindows) { return $observation }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $build = 0
        if ([int]::TryParse([string]$os.BuildNumber, [ref]$build)) {
            $observation.WindowsBuild = $build
        }
    } catch {
        # Read failure remains UNKNOWN; no raw error/device details are emitted.
    }
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        foreach ($name in @('TpmPresent', 'TpmReady', 'TpmEnabled', 'TpmActivated',
                            'LockedOut', 'RestartPending')) {
            $observation[$name] = Get-PalacoBooleanProperty -Object $tpm -Name $name
        }
    } catch {
        # Missing module/permission/TPM never implies readiness.
    }
    try {
        $tpmInfo = Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftTpm' `
            -ClassName Win32_Tpm -ErrorAction Stop
        if ($null -ne $tpmInfo -and $tpmInfo.SpecVersion -is [string]) {
            $observation.TpmSpecVersion = $tpmInfo.SpecVersion.Trim()
        }
    } catch {
        # Do not infer TPM 2.0 from TpmReady alone.
    }
    return $observation
}

if ($MyInvocation.InvocationName -ne '.') {
    $observation = Get-PalacoTpmObservation
    $result = Resolve-PalacoTpmReadiness -Observation $observation
    $report = [ordered]@{
        ObservedAtUtc = [DateTime]::UtcNow.ToString('o')
        ObservationTimeTrusted = $false
        Assessment = $result
        Observation = $observation
    }
    $report | ConvertTo-Json -Depth 5
}
