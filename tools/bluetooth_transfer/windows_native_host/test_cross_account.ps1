# Windows CI only: ephemeral non-admin account for actual ACL denial test.
# No service install, no elevation, no production account changes.
# Must run on a disposable GitHub-hosted Windows runner with local-admin rights.
$ErrorActionPreference = "Stop"
$name = "palacobt" + ([Guid]::NewGuid().ToString("N").Substring(0, 8))
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$rawPassword = [Convert]::ToBase64String($bytes) + "aA1!"
$secret = ConvertTo-SecureString $rawPassword -AsPlainText -Force
$created = $false
try {
    New-LocalUser -Name $name -Password $secret -Description "PALACO disposable CI ACL negative test" -ErrorAction Stop | Out-Null
    $created = $true
    $env:PALACO_TEST_USER = $name
    $env:PALACO_TEST_PASSWORD = $rawPassword
    dotnet run --no-build --configuration Release --project tools/bluetooth_transfer/windows_native_host/Palaco.Bluetooth.NativeHost.csproj -- --ipc-cross-account-test
    if ($LASTEXITCODE -ne 0) { throw "Windows cross-account IPC negative test failed" }
}
finally {
    Remove-Item Env:PALACO_TEST_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:PALACO_TEST_USER -ErrorAction SilentlyContinue
    $rawPassword = $null
    $secret.Dispose()
    if ($created) { Remove-LocalUser -Name $name -ErrorAction Stop }
}
