# GitHub-hosted ephemeral Windows runner only.
# Creates a deny-only diagnostic SCM service and deletes it in finally.
# NEVER use on a developer, customer or production Windows machine.
$ErrorActionPreference = "Stop"
if ($env:GITHUB_ACTIONS -ne "true" -or $env:RUNNER_ENVIRONMENT -ne "github-hosted") {
    throw "SCM lifecycle probe is restricted to disposable GitHub-hosted runners"
}
$serviceName = "PALACO-BT-Diagnostic-HOLD"
$project = "tools/bluetooth_transfer/windows_native_host"
$exe = Join-Path (Resolve-Path ".").Path "$project/bin/Release/net8.0-windows/Palaco.Bluetooth.NativeHost.exe"
$created = $false

function Invoke-Sc([string[]]$arguments) {
    $out = & sc.exe @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "SCM operation failed: $($arguments[0]) (exit $LASTEXITCODE): $out"
    }
}
function Await-ServiceStatus([string]$desired, [int]$seconds) {
    $expiry = [DateTime]::UtcNow.AddSeconds($seconds)
    do {
        $svc = Get-Service -Name $serviceName -ErrorAction Stop
        if ($svc.Status.ToString() -eq $desired) { return }
        Start-Sleep -Milliseconds 400
    } while ([DateTime]::UtcNow -lt $expiry)
    throw "SCM did not reach state $desired"
}
try {
    if (-not (Test-Path -LiteralPath $exe)) { throw "Windows host executable missing" }
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        throw "Refusing to touch existing SCM service"
    }
    # The installed image is local to this disposable CI runner and remains
    # explicitly configured for manual start, no network/BLE/TPM capability.
    $binary = '"' + $exe + '" --service'
    Invoke-Sc -arguments @("create", $serviceName, "binPath=", $binary, "start=", "demand", "obj=", "LocalSystem")
    $created = $true
    Invoke-Sc -arguments @("sidtype", $serviceName, "unrestricted")

    foreach ($cycle in 1..2) {
        Invoke-Sc -arguments @("start", $serviceName)
        Await-ServiceStatus "Running" 15
        $state = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        if ($null -eq $state -or $state.ProcessId -le 0 -or $state.StartMode -ne "Manual") {
            throw "SCM identity/lifecycle observation invalid"
        }
        # No ALLOW path is exercised. This tests SCM state, not true hardware
        # attestation or client token policy under the service account.
        Invoke-Sc -arguments @("stop", $serviceName)
        Await-ServiceStatus "Stopped" 15
    }
    Write-Output "Windows SCM lifecycle PASS (ephemeral runner; SID enabled; two start/stop cycles; HOLD/DENY)"
}
finally {
    if ($created) {
        $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status.ToString() -ne "Stopped") {
            & sc.exe stop $serviceName 2>&1 | Out-Null
            try { Await-ServiceStatus "Stopped" 10 } catch { }
        }
        & sc.exe delete $serviceName 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to delete disposable SCM service" }
    }
}
