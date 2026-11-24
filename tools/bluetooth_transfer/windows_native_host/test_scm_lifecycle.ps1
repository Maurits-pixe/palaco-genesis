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
        # Running is not sufficient: verify the worker opened the expected
        # diagnostic pipe and its service process remains alive. Do not
        # confuse an absent pipe or a timeout with Windows ACCESS_DENIED.
        $pidAtStart = [int]$state.ProcessId
        $pipeSeen = $false
        $expiry = [DateTime]::UtcNow.AddSeconds(8)
        do {
            $namedPipes = @(Get-ChildItem -LiteralPath '\\\\.\\pipe\\' -ErrorAction Stop)
            $pipeSeen = @($namedPipes | Where-Object {
                $_.Name -eq "PALACO-BT-NATIVE-DIAGNOSTIC-V1"
            }).Count -eq 1
            if (-not $pipeSeen) { Start-Sleep -Milliseconds 250 }
        } while (-not $pipeSeen -and [DateTime]::UtcNow -lt $expiry)
        if (-not $pipeSeen) { throw "Service worker did not expose diagnostic pipe" }
        Start-Sleep -Milliseconds 600
        $health = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        if ($null -eq $health -or [int]$health.ProcessId -ne $pidAtStart -or
            $health.State -ne "Running" -or
            $null -eq (Get-Process -Id $pidAtStart -ErrorAction SilentlyContinue)) {
            throw "Service process changed or stopped unexpectedly"
        }
        # Execute an actual non-System connection while the SCM-owned pipe
        # exists; the test only accepts Windows ACCESS_DENIED.
        dotnet run --no-build --configuration Release --project "$project/Palaco.Bluetooth.NativeHost.csproj" -- --ipc-scm-client-denial-test
        if ($LASTEXITCODE -ne 0) { throw "SCM diagnostic caller was not conclusively denied" }
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
