#requires -Version 5.1
# Read public metadata of an EXISTING independently pinned TPM 2.0 NV counter.
# Never defines, increments, clears or undefines a counter. No counter value read.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][uint32]$NvIndex,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^000[bB][0-9a-fA-F]{64}$')][string]$ExpectedNvName
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not ('Palaco.WindowsTpm.CounterPublicReader' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'PalacoTpmCounterPublic.cs')
}
[byte[]]$name = New-Object byte[] 34
for ($i = 0; $i -lt 34; $i++) {
    $name[$i] = [Convert]::ToByte($ExpectedNvName.Substring(2 * $i, 2), 16)
}
$observation = [Palaco.WindowsTpm.CounterPublicReader]::Read($NvIndex, $name)
[ordered]@{
    Schema = 'palaco.windows-tpm-counter-public.v1'
    DiagnosticOnly = $true
    PublicAreaMatchesPinnedName = $true
    NvIndex = ('0x{0:x8}' -f $observation.NvIndex)
    NameHex = $observation.NameHex
    Attributes = ('0x{0:x8}' -f $observation.Attributes)
    CounterValueObserved = $false
    AntiRollbackVerified = $false
    RuntimeAuthorized = $false
} | ConvertTo-Json
