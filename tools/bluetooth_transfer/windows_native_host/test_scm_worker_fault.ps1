# PALACO v6.0: intentional SCM worker failure on a disposable Windows runner.
# Temporary service, fault marker and incident evidence are ALWAYS removed.
$ErrorActionPreference = "Stop"
if ($env:GITHUB_ACTIONS -ne "true" -or $env:RUNNER_ENVIRONMENT -ne "github-hosted") {
    throw "CI fault injection is forbidden outside GitHub-hosted runners"
}
$serviceName = "PALACO-BT-Diagnostic-HOLD"
$project = "tools/bluetooth_transfer/windows_native_host"
$bin = Join-Path (Resolve-Path ".").Path "$project/bin/Release/net8.0-windows"
$exe = Join-Path $bin "Palaco.Bluetooth.NativeHost.exe"
$marker = Join-Path $bin "palaco-ci-fault.marker"
$evidence = Join-Path $bin "palaco-ci-incident.json"
$receipt = Join-Path $bin "palaco-ci-incident-receipt.txt"
$created = $false
$markerCreated = $false

function Sc([string[]]$Arguments) {
    $out = & sc.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "SCM action $($Arguments[0]) failed (exit $LASTEXITCODE): $out"
    }
}
try {
    if (-not (Test-Path -LiteralPath $exe)) { throw "Missing diagnostic executable" }
    if ((Test-Path -LiteralPath $marker) -or (Test-Path -LiteralPath $evidence) -or
        (Test-Path -LiteralPath $receipt)) {
        throw "Refusing stale CI marker or evidence"
    }
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        throw "Refusing existing SCM service"
    }
    [IO.File]::WriteAllText($marker, "PALACO-CI-ONLY-HOLD-DENY")
    $markerCreated = $true
    $binary = '"' + $exe + '" --service-ci-fault'
    Sc -Arguments @("create", $serviceName, "binPath=", $binary,
                    "start=", "demand", "obj=", "LocalSystem")
    $created = $true
    Sc -Arguments @("sidtype", $serviceName, "unrestricted")
    Sc -Arguments @("failure", $serviceName, "reset=", "0",
                    "actions=", "none/0")
    Sc -Arguments @("start", $serviceName)

    # Unexpected worker completion must make SCM leave RUNNING without a retry.
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    $observedRunning = $false
    do {
        $state = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        if ($state.State -eq "Running") { $observedRunning = $true }
        if ($observedRunning -and $state.State -eq "Stopped") { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not $observedRunning -or $state.State -ne "Stopped") {
        throw "SCM failed to stop after intentional worker fault"
    }
    Start-Sleep -Milliseconds 1200
    $final = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($final.State -ne "Stopped" -or [int]$final.ProcessId -ne 0) {
        throw "SCM unexpectedly restarted after injected fault"
    }
    if (-not (Test-Path -LiteralPath $evidence)) {
        throw "Missing incident evidence after worker fault"
    }
    $record = Get-Content -LiteralPath $evidence -Raw | ConvertFrom-Json
    if ($record.protocol -ne "PALACO-BT-CI-INCIDENT-V1" -or
        $record.incident -ne "WORKER_FAULTED" -or
        $record.decision -ne "HOLD" -or
        $record.authorization -ne "DENY" -or
        $record.independent_signature -ne $false -or
        $record.native_security_verified -ne $false) {
        throw "Incident evidence violates HOLD/DENY or provenance policy"
    }
    $canonical = "PALACO-BT-CI-INCIDENT-V1|WORKER_FAULTED|HOLD|DENY"
    $expected = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::ASCII.GetBytes($canonical))).ToLowerInvariant()
    if ($record.canonical_sha256 -cne $expected) {
        throw "Incident evidence checksum invalid"
    }
    # Different process / implementation verifies original C# evidence as
    # strict JSON, enforces one-time local receipt and rejects replay.
    $verifier = "tools/bluetooth_transfer/verify_scm_ci_incident.py"
    python $verifier --evidence $evidence --receipt $receipt
    if ($LASTEXITCODE -ne 0) { throw "Independent CI incident verification failed" }
    python $verifier --evidence $evidence --receipt $receipt
    if ($LASTEXITCODE -eq 0) { throw "Replay of incident was accepted" }
    if (-not (Test-Path -LiteralPath $receipt)) {
        throw "Independent receipt missing"
    }
    Write-Output "Independent CI incident verification PASS (original validated, replay denied; unsigned)"
    Write-Output "Windows SCM injected worker failure PASS (STOPPED, no restart, fixed HOLD/DENY evidence, SHA-256 verified)"
}
finally {
    if ($created) {
        $current = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($current -and $current.Status.ToString() -ne "Stopped") {
            & sc.exe stop $serviceName 2>&1 | Out-Null
            Start-Sleep -Seconds 1
        }
        & sc.exe delete $serviceName 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to delete fault-test service" }
    }
    if ($markerCreated) { Remove-Item -LiteralPath $marker -Force -ErrorAction Stop }
    if (Test-Path -LiteralPath $evidence) {
        Remove-Item -LiteralPath $evidence -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $receipt) {
        Remove-Item -LiteralPath $receipt -Force -ErrorAction Stop
    }
}
