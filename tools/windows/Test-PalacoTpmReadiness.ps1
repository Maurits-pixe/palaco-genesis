#requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Get-PalacoTpmReadiness.ps1')

function Assert-Equal($Actual, $Expected, [string]$Name) {
    if ($Actual -cne $Expected) { throw "FAIL: $Name; expected $Expected; got $Actual" }
}
function New-Fixture {
    @{
        IsWindows = $true
        WindowsBuild = 22631
        TpmPresent = $true
        TpmReady = $true
        TpmEnabled = $true
        TpmActivated = $true
        LockedOut = $false
        RestartPending = $false
        TpmSpecVersion = '2.0, 0, 1.59'
    }
}
$passed = 0
$ready = Resolve-PalacoTpmReadiness -Observation (New-Fixture)
Assert-Equal $ready.PrerequisiteState 'PREREQUISITES_OBSERVED' 'complete fixture'
Assert-Equal $ready.BackendState 'NOT_IMPLEMENTED' 'no backend inference'
Assert-Equal $ready.RuntimeAuthorized $false 'no runtime authority'
Assert-Equal $ready.AntiRollbackVerified $false 'no rollback proof'
$passed++

foreach ($field in (New-Fixture).Keys) {
    $fixture = New-Fixture
    $fixture.Remove($field)
    $result = Resolve-PalacoTpmReadiness -Observation $fixture
    Assert-Equal $result.PrerequisiteState 'HOLD_INCOMPLETE_EVIDENCE' "missing $field"
    $passed++
}
foreach ($field in @('TpmPresent', 'TpmReady', 'TpmEnabled', 'TpmActivated')) {
    $fixture = New-Fixture
    $fixture[$field] = $false
    Assert-Equal (Resolve-PalacoTpmReadiness $fixture).PrerequisiteState `
        'HOLD_PREREQUISITES' "false $field"
    $fixture[$field] = 'true'
    Assert-Equal (Resolve-PalacoTpmReadiness $fixture).PrerequisiteState `
        'HOLD_INCOMPLETE_EVIDENCE' "string $field"
    $passed += 2
}
foreach ($field in @('LockedOut', 'RestartPending')) {
    $fixture = New-Fixture
    $fixture[$field] = $true
    Assert-Equal (Resolve-PalacoTpmReadiness $fixture).PrerequisiteState `
        'HOLD_PREREQUISITES' "blocking $field"
    $passed++
}
foreach ($version in @('1.2', '12.0', '2.01', '2.0garbage')) {
    $fixture = New-Fixture
    $fixture.TpmSpecVersion = $version
    Assert-Equal (Resolve-PalacoTpmReadiness $fixture).PrerequisiteState `
        'HOLD_PREREQUISITES' "unsupported spec $version"
    $passed++
}
$fixture = New-Fixture
$fixture.WindowsBuild = 19040
Assert-Equal (Resolve-PalacoTpmReadiness $fixture).PrerequisiteState `
    'HOLD_PREREQUISITES' 'below minimum build'
$passed++
$fixture = New-Fixture
$fixture.IsWindows = $false
Assert-Equal (Resolve-PalacoTpmReadiness $fixture).PrerequisiteState `
    'HOLD_UNSUPPORTED_HOST' 'non-Windows'
$passed++

# A failed/missing probe leaves nulls; it must never pass the pure classifier.
$fixture = New-Fixture
$fixture.TpmReady = $null
Assert-Equal (Resolve-PalacoTpmReadiness $fixture).PrerequisiteState `
    'HOLD_INCOMPLETE_EVIDENCE' 'probe failure'
$passed++

# Execute the actual read-only entry point in a fresh process and validate JSON.
$executable = (Get-Process -Id $PID).Path
$json = & $executable -NoProfile -NonInteractive -File `
    (Join-Path $PSScriptRoot 'Get-PalacoTpmReadiness.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Diagnostic process failed' }
$report = ($json -join [Environment]::NewLine) | ConvertFrom-Json
Assert-Equal $report.Assessment.Schema 'palaco.windows-tpm-readiness.v1' 'JSON schema'
Assert-Equal $report.Assessment.DiagnosticOnly $true 'diagnostic only'
Assert-Equal $report.Assessment.RuntimeAuthorized $false 'live probe no authority'
Assert-Equal $report.Assessment.AntiRollbackVerified $false 'live probe no rollback proof'
$passed++
Write-Output "PASS: $passed readiness scenarios; live probe is diagnostic, not TPM backend verification."
