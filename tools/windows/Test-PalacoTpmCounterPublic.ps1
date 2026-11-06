#requires -Version 5.1
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -Path (Join-Path $PSScriptRoot 'PalacoTpmCounterPublic.cs')
function Assert-True([bool]$Condition, [string]$Label) {
    if (-not $Condition) { throw "FAIL: $Label" }
}
function Assert-Rejected([scriptblock]$Action, [string]$Label) {
    $rejected = $false
    try { $null = & $Action } catch { $rejected = $true }
    Assert-True $rejected $Label
}
[uint32]$index = 0x01500020
[byte[]]$publicArea = @(0x01,0x50,0,0x20, 0,0x0b, 0,0,0,0x10, 0,0, 0,8)
function New-Name([byte[]]$Area) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return [byte[]](@(0,0x0b) + $sha.ComputeHash($Area)) } finally { $sha.Dispose() }
}
[byte[]]$name = New-Name $publicArea
[byte[]]$frame = @(0x80,1, 0,0,0,62, 0,0,0,0, 0,14) + $publicArea + @(0,34) + $name
$reader = [Palaco.WindowsTpm.CounterPublicReader]
$command = $reader::BuildReadPublic($index)
Assert-True (([BitConverter]::ToString($command)) -ceq '80-01-00-00-00-0E-00-00-01-69-01-50-00-20') 'only NV_ReadPublic command'
$result = $reader::ParseReadPublic($frame, $index, $name)
Assert-True ($result.NvIndex -eq $index) 'matching index'
Assert-True (-not $result.AntiRollbackVerified) 'no antirollback promotion'
Assert-True (-not $result.RuntimeAuthorized) 'no authority promotion'
$count = 2
for ($length = 0; $length -lt $frame.Length; $length++) {
    $truncated = New-Object byte[] $length
    [Array]::Copy($frame, $truncated, $length)
    Assert-Rejected { $reader::ParseReadPublic($truncated, $index, $name) } "truncated $length"
    $count++
}
foreach ($offset in @(0,1,5,9,10,13,17,21,23,25,27,29,40,61)) {
    [byte[]]$corrupt = $frame.Clone()
    $corrupt[$offset] = $corrupt[$offset] -bxor 1
    Assert-Rejected { $reader::ParseReadPublic($corrupt, $index, $name) } "mutation $offset"
    $count++
}
[byte[]]$wrongName = $name.Clone()
$wrongName[10] = $wrongName[10] -bxor 1
Assert-Rejected { $reader::ParseReadPublic($frame, $index, $wrongName) } 'different independent pin'
Assert-Rejected { $reader::ParseReadPublic($frame, ($index + 1), $name) } 'different index'
Assert-Rejected { $reader::ParseReadPublic((New-Object byte[] 4097), $index, $name) } 'oversize'
Assert-Rejected { $reader::BuildReadPublic(0x81000000) } 'not an NV handle'
Assert-Rejected { $reader::Read(0x81000000, $name) } 'invalid input before native call'
$count += 5
foreach ($change in @(9,13)) {
    [byte[]]$altered = $publicArea.Clone()
    $altered[$change] = if ($change -eq 9) { 0 } else { 7 }
    [byte[]]$changedName = New-Name $altered
    [byte[]]$changedFrame = @(0x80,1, 0,0,0,62, 0,0,0,0, 0,14) + $altered + @(0,34) + $changedName
    Assert-Rejected { $reader::ParseReadPublic($changedFrame, $index, $changedName) } 'non-counter or non-eight-byte data'
    $count++
}
# Also accept the valid 32-byte SHA-256 authorization policy layout.
[byte[]]$withPolicy = @($publicArea[0..9]) + @(0,32) + (New-Object byte[] 32) + @(0,8)
[byte[]]$policyName = New-Name $withPolicy
[byte[]]$policyFrame = @(0x80,1, 0,0,0,94, 0,0,0,0, 0,46) + $withPolicy + @(0,34) + $policyName
$null = $reader::ParseReadPublic($policyFrame, $index, $policyName)
$count++
Write-Output "PASS: $count TPM NV public codec cases; native hardware read NOT EXECUTED."
