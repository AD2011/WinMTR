# Regression test for CLI Ctrl+C shutdown (see README.md in this folder).
#
# Verifies that WinMTR.exe, launched from an interactive shell inside a
# pseudoconsole (the same input path as Windows Terminal and SSH), exits on a
# single Ctrl+C (0x03) even though the shell does not wait for a
# Windows-subsystem executable and keeps reading console input concurrently.
#
# Usage (after building Release x64):
#   powershell -File tests\ctrlc\run-test.ps1                # PowerShell host
#   powershell -File tests\ctrlc\run-test.ps1 -Mode cmdshell # cmd.exe host
#   powershell -File tests\ctrlc\run-test.ps1 -TargetArgs '1.1.1.1 -n -w 3' -Settle 10   # natural exit check
#
# Exit code 0 = PASS. 1 = Ctrl+C ignored (the bug). 2 = setup problem
# (note: with a -w/-c bounded run, "target exited before Ctrl+C" is the
# expected PASS signal for natural completion).
param(
    [ValidateSet('shell', 'cmdshell', 'direct')]
    [string]$Mode = 'shell',
    [string]$TargetExe = '',
    [string]$TargetArgs = '1.1.1.1 -n',
    [int]$Settle = 5,
    [int]$Presses = 3
)
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $TargetExe) {
    $TargetExe = [IO.Path]::GetFullPath((Join-Path $here '..\..\src\Release_x64\WinMTR.exe'))
}
if (-not (Test-Path $TargetExe)) {
    Write-Error "Target binary not found: $TargetExe (build Release x64 first)"
    exit 2
}

# Build the harness on demand with the .NET Framework compiler (always present).
$harness = Join-Path $here 'CtrlCTest.exe'
$source = Join-Path $here 'CtrlCTest.cs'
if (-not (Test-Path $harness) -or (Get-Item $source).LastWriteTime -gt (Get-Item $harness).LastWriteTime) {
    & "$env:windir\Microsoft.NET\Framework64\v4.0.30319\csc.exe" -nologo "-out:$harness" $source
    if ($LASTEXITCODE -ne 0) { Write-Error 'Failed to compile CtrlCTest.cs'; exit 2 }
}

# The harness must run in its own real console: under a pipe-stdio host,
# Windows duplicates the pipe handles into console-subsystem children even
# with bInheritHandles=FALSE, which breaks the pseudoconsole scenario.
Remove-Item (Join-Path $here 'harness.log') -ErrorAction SilentlyContinue
$argList = @($Mode, ('"' + $TargetExe + '"'), ('"' + $TargetArgs + '"'), $Settle, $Presses)
$p = Start-Process -FilePath $harness -ArgumentList $argList -WindowStyle Hidden -Wait -PassThru
Get-Content (Join-Path $here 'harness.log') -ErrorAction SilentlyContinue
Write-Output ("VERDICT_EXITCODE=" + $p.ExitCode + " (0=PASS ctrl+c exits, 1=FAIL still running, 2=setup error)")
exit $p.ExitCode
