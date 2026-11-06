# ORCH-059 — Windows TPM prerequisite observation

DERIVED diagnostic implementation on ORCH-058. User selected Windows PC with TPM as the offline target. The unfinished Unix-client proposal was not opened as a PR or integrated; this slice targets Windows prerequisites instead.

Get-PalacoTpmReadiness.ps1 is read-only and works without downloading modules. It collects IsWindows, Win32_OperatingSystem.BuildNumber, Get-Tpm boolean fields and Win32_Tpm.SpecVersion. It does not initialize/clear TPM, create keys, change registry/policy/execution policy, enable services or make network requests. It emits JSON to stdout without computer name, user, serial number, key material or raw exception text. ObservedAtUtc is explicitly not trusted time.

Classification requires correctly typed complete evidence: Windows build >=19041 (engineering target threshold, not a claim about Windows lifecycle/support), TPM present/ready/enabled/activated, not locked out, no restart pending, and TPM spec 2.0. Unknown, failed or malformed observations stay HOLD. PREREQUISITES_OBSERVED means only that these reported fields satisfy this classifier. BackendState always NOT_IMPLEMENTED, AntiRollbackVerified and RuntimeAuthorized always false. No inference about CNG key eligibility, attestation, secure boot, TPM NV counter policy, firmware provenance, durable compare-exchange or rollback resistance is made.

Run locally from Windows PowerShell 5.1 or PowerShell 7:

```powershell
powershell.exe -NoProfile -File .\tools\windows\Get-PalacoTpmReadiness.ps1
```

Use a normal shell first. Permission/module failures remain incomplete evidence; the script never self-elevates or alters execution policy. If local policy blocks scripts, preserve that control and use the organization's approved script-execution process. Output can be redirected to a user-selected JSON file if desired. Share the JSON to guide hardware-specific implementation; it contains basic build/TPM state but no device identity by design.

Tests cover each missing field, false prerequisites, string-for-boolean mistakes, locked/restart states, unsupported spec versions/builds, unsupported host, null probe evidence and a fresh-process live JSON smoke test. CI runs on Windows with Windows PowerShell and pwsh. CI fixture/live-runner results do not establish the user's TPM state or implement a TPM-backed storage backend. No hardware provisioning or runtime activation occurs.

AI-review through three lenses: TRIAS — diagnostics cannot grant authority or modify TPM state; ORACLE — complete observations are required and all hardware/anti-rollback claims remain unverified; MENTOR — one standalone read-only script produces a useful report without asking the user to install dependencies. Dissent: actual user-device evidence and the TPM backend are still missing, so production anti-rollback remains HOLD.

Next transition: inspect the target-machine report, choose the Windows TPM storage/key/NV design and its authorization/recovery policy, then implement and test that concrete backend. TPM signing or sealing alone is not a monotonic rollback defense. Existing independent human review and GO-13 gates remain before merge/activation. Exact-head CI evidence belongs in the PR.
