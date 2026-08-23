# CLI Ctrl+C regression test

WinMTR is a Windows-subsystem executable that also runs a live CLI mode. That
combination has a non-obvious consequence: an interactive shell (PowerShell,
cmd) does **not** wait for a Windows-subsystem process. The shell returns to
its prompt immediately and keeps a blocking console read pending on the
**same shared console input buffer** for the whole trace.

## The bug this locks down

With `ENABLE_PROCESSED_INPUT` cleared, Ctrl+C is only a queued `0x03`
`KEY_EVENT` — and the shell's blocking read (PSReadLine) consumes it before
WinMTR's poll ever runs, then resets the console input mode. Result: Ctrl+C
appeared completely dead in CLI mode; users had to kill the terminal.

The fix (in `WinMTRDialog.cpp`) forces `ENABLE_PROCESSED_INPUT` **on** and
re-asserts it every poll. With processed input on, conhost never queues the
key: it broadcasts `CTRL_C_EVENT` to every process attached to the console —
which the shell cannot steal — and `CliConsoleHandler` fires. This works
identically for local terminals and SSH, because both Windows Terminal and
sshd deliver input through ConPTY/conhost, where the same input-mode rules
apply.

## What the harness does

`CtrlCTest.cs` creates a real pseudoconsole (`CreatePseudoConsole`), starts an
interactive shell inside it, types the WinMTR command line, sends literal
`0x03` bytes through the ConPTY input pipe (byte-identical to what SSH sends,
equivalent to what Windows Terminal sends), and asserts that the WinMTR
process exits. It also checks the shell is still responsive afterwards.

## Running it

Build Release x64 first, then:

```powershell
powershell -File tests\ctrlc\run-test.ps1                 # PowerShell host (the case that used to fail)
powershell -File tests\ctrlc\run-test.ps1 -Mode cmdshell  # cmd.exe host
powershell -File tests\ctrlc\run-test.ps1 -TargetArgs '1.1.1.1 -n -w 3' -Settle 10  # natural completion
```

Exit code 0 = pass, 1 = Ctrl+C ignored (the original bug). For the natural
completion variant, `FAIL(setup): target exited before Ctrl+C was sent` is the
expected (passing) outcome — it proves bounded runs still end on their own.

Notes:

- The runner uses `Start-Process` so the harness gets its own real console;
  under pipe-stdio hosts (CI runners, agent shells) Windows duplicates pipe
  std handles into console children, which silently breaks the scenario.
- First run after a rebuild can be slowed by Defender scanning the fresh
  binary; the harness waits up to 30 s for the target to appear.
- `direct` mode (no shell) is **not** meaningful for WinMTR: a GUI-subsystem
  exe gets no console from the pseudoconsole attribute and would attach to the
  harness's own console instead.
