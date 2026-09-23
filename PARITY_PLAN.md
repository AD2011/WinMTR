# WinMTR ↔ Linux mtr Feature-Parity Plan

Living document. Any agent or developer picking this up: read this file top to
bottom, then check the **Status tracker** at the end for what is done and what
is next. Update the tracker as you land work.

Companion context: `DEVELOPMENT_HANDOFF.md` (gitignored, local) covers the
CLI/console architecture history, including the Ctrl+C saga.

**ARCHITECTURE CHANGE (2026-08-27): WinMTR is now a `/SUBSYSTEM:CONSOLE`
binary** (with `/ENTRY:WinMainCRTStartup` so MFC still boots through WinMain —
see `src/WinMTR.vcxproj`). Rationale: as a Windows-subsystem exe the shell
never waited for CLI runs and kept a competing blocking read on the shared
console, which made the interactive keys (q/d/r/o/p/h) unfixable — the shell
stole the keystrokes before WinMTR's poll ran (Ctrl+C only worked because
processed-input ON makes conhost broadcast CTRL_C_EVENT, which no reader can
steal). As a console-subsystem exe the shell waits like it does for real
`mtr`, WinMTR owns console input exclusively, and the old prompt-underlay
artifact is gone. Tradeoff: double-clicking the GUI briefly flashes a console
window (released immediately via `FreeConsole` in `HideOwnedConsoleWindow`),
and launching the GUI from a terminal now blocks that shell until the GUI
closes (use `start WinMTR.exe`). All CLI input handling lives in
`PollCliInput` in `src/WinMTRDialog.cpp`; the redundant Ctrl+C layers
(handler + 0x03 drain + processed-input re-assert) are kept for edge launches.
Regression test: `tests/ctrlc/run-test.ps1` (also drives the interactive keys
via `-KeyByte`).

## Goal

Bring the WinMTR CLI to functional parity with Linux `mtr` (0.95), in three
priority tiers:

1. **P1 — Probe engine**: TCP SYN (`-T`), UDP (`-u`), target port (`-P`).
   SCTP is a documented non-goal (see below).
2. **P2 — Everything else** in mtr that is missing (flags, stats, output
   formats, interactive keys beyond the basics).
3. **P3 — GUI**: expose the new probe modes and stats in the MFC GUI.

Plus one immediate fix: the interactive keys shown in the CLI header
(`Keys: Help Display-mode Restart-statistics Order-of-fields quit`) were
display-only; they must actually work.

## Empirical constraints (verified on this machine, 2026-08-27)

These were measured with throwaway probes (`RawSockProbe.cs`, `TraceProbe.cs`
— scratchpad only, not in repo). Do not re-litigate them without re-testing:

| Capability | Non-elevated | Elevated |
|---|---|---|
| `IcmpSendEcho2` ICMP trace (current engine) | works | works |
| Create + bind raw ICMP/ICMPv6 socket | bind **succeeds** | succeeds |
| **Receive** ICMP TTL-exceeded on raw socket | **nothing arrives** (silent) | expected to work (standard approach of tracetcp/nmap; verify once elevated) |
| UDP socket with `IP_TTL=n`, `sendto` | works (packet leaves) | works |
| TCP socket with `IP_TTL=n`, non-blocking `connect` (SYN with our TTL) | works | works |
| Full TCP connect to dest (final-hop detection) | works | works |
| Raw **TCP** send (craft own SYN) | blocked by Windows since XP SP2 — **never possible**, don't try | same |
| SCTP socket (proto 132) | `WSAEPROTONOSUPPORT` — no Windows SCTP stack | same |

Consequences:

- TCP/UDP trace modes **require Administrator** (for the raw ICMP listener
  that captures TTL-exceeded and unreachable errors). Detect and fail with a
  clear message when not elevated. This mirrors mtr needing root/setuid.
- TCP SYN mode must use the OS stack: non-blocking `connect()` on a socket
  with `IP_TTL` set — NOT raw packet crafting. Intermediate hops answer with
  ICMP TTL-exceeded (matched to the probe by the embedded source port);
  final hop is detected by the connect completing (SYN-ACK) or being refused
  (RST), both of which the socket reports directly.
- UDP mode: `sendto` on a TTL-limited UDP socket. Intermediate hops: ICMP
  TTL-exceeded. Final hop: ICMP port-unreachable (type 3 code 3 / v6 type 1
  code 4) from the destination.
- SCTP (`mtr` has it on Linux): **non-goal on Windows**. No native stack;
  would require a kernel driver or usrsctp + raw IP (also blocked). `-S`
  should print "SCTP is not supported on Windows" and exit 1.
- Testing caveat: the agent tool shell is network-sandboxed. Anything that
  needs real network must run **detached** (`Start-Process`), which is what
  `tests/ctrlc/run-test.ps1` already does. Assert on process behavior/log
  files, not on captured stdout of the sandboxed shell.

## Architecture

### Current engine (ICMP)

`src/WinMTRNet.cpp` — `DoTrace()` spawns one thread per TTL (`TraceThread` /
`TraceThread6`), each looping `IcmpSendEcho2`/`Icmp6SendEcho2` with
`IPINFO.Ttl = hop`. Stats flow through `AddXmit` → (`UpdateRTT` +
`AddReturned` + `SetAddr`) | `SetErrorName`, all mutex-guarded on
`s_nethost host[MAX_HOPS]`. The CLI renderer (`BuildCliScreen` in
`WinMTRDialog.cpp`) and the GUI both read the same accessors, so **new probe
modes only need to feed the same stats calls** and everything downstream
(display, StDev, final report, GUI) works unchanged.

### P1 probe engine design (TCP/UDP)

New mode dispatch in `WinMTRNet::DoTrace`: when `probeMode != PROBE_ICMP`,
run `DoTraceSocket()` instead of the ICMP thread spawn. Same
one-thread-per-TTL model to keep the stats machinery identical:

- **Shared ICMP listener thread** owns one raw ICMP (or ICMPv6) socket bound
  to the outbound interface (found via UDP connect + `getsockname`). It
  parses incoming ICMP: type 11 (TTL exceeded) and type 3 (unreachable),
  extracts the embedded original IP header + first 8 transport bytes, reads
  the **source port** and looks it up in the pending-probe table to find
  which hop sent that probe; records gateway address + RTT and signals the
  hop's event.
- **Pending-probe table**: `MAX_HOPS` slots (one per TTL thread, sequential
  probes per hop, so one outstanding probe per slot), each holding
  `{srcPort, sendTick (QueryPerformanceCounter), event, result}` under the
  existing `ghMutex`.
- **TCP prober thread (per TTL)**, each cycle: fresh `SOCK_STREAM` socket,
  `IP_TTL = hop`, bind ephemeral (to learn srcPort), non-blocking
  `connect(dest, targetPort)`; register in table; wait on
  `WaitForSingleObject(event, ECHO_REPLY_TIMEOUT)` OR socket completion
  (`select` writability/except). Outcomes:
  - listener signaled → intermediate hop (gateway addr + RTT)
  - connect completed or `WSAECONNREFUSED` → destination reached:
    `SetAddr(hop, dest)`, RTT = connect time
  - timeout → `SetErrorName(hop, IP_REQ_TIMED_OUT)`
  Close socket (closing a half-open connect sends RST cleanup for free).
- **UDP prober thread (per TTL)**, each cycle: fresh UDP socket,
  `IP_TTL = hop`, bind ephemeral, `sendto(dest, port)` where port =
  `targetPort` if `-P` given else classic `33434`; payload `pingsize` bytes.
  Outcomes: TTL-exceeded → intermediate; port-unreachable *from dest* →
  destination reached; timeout → lost.
- **Elevation gate**: raw socket creation/bind failure, or (belt and braces)
  `CheckTokenMembership(WinBuiltinAdministratorsSid)` false → abort trace
  with "TCP/UDP trace modes require Administrator privileges. Re-run from an
  elevated terminal." before entering the alt screen.
- IPv4 first. IPv6 (`ICMPV6`, `IPV6_UNICAST_HOPS`, inner 40-byte header
  parse) is stage 2 of P1 — same listener structure.

CLI flags: `-T/--tcp`, `-u/--udp`, `-P/--port N`. mtr defaults: TCP port 80;
UDP uses classic 33434 unless `-P`. GUI stays ICMP-only until P3.

### Interactive keys (the immediate fix)

`PollCliStopRequest` already drains `ReadConsoleInput` for Ctrl+C. Generalize:
`PollCliKey()` returns the next interesting key char while preserving the
Ctrl+C counter path (console handler + 0x03 drain). Keys (mtr bindings):

- `q` — quit (same graceful path as Ctrl+C)
- `h` / `?` — help screen on the alt screen; any key returns
- `d` — cycle display mode: 0 = statistics, 1 = packet history strip-chart
  (needs a per-hop ring buffer of recent probe results in `s_nethost`;
  `AddXmit` appends an in-flight slot, `UpdateRTT` fills it, timeout leaves
  it lost)
- `r` — restart statistics: new `WinMTRNet::ResetStatistics()` zeroing
  counters (`xmit/returned/total/m2/last/best/worst` + history) but keeping
  `addr/name/asn` so the display doesn't blank out
- `o` — cycle field-order presets (custom `-o` string is P2)
- `p` — pause display (probing continues); any key resumes

Keep in mind the console model: keys arrive interleaved with the shell's own
reads. `ENABLE_PROCESSED_INPUT` stays ON (Ctrl+C depends on it) and the
`ENABLE_ECHO_INPUT|ENABLE_LINE_INPUT` clears are what let single keypresses
reach `ReadConsoleInput` without Enter.

## P2 — remaining mtr parity (medium priority)

Ordered by value/effort. Each is independent; tick them off in the tracker.

1. **True report mode**: `-r` currently just forces the live CLI. Make `-r`
   with `-c N` run quietly (no alt screen) and print only the final table —
   exact `mtr -r` semantics. ~10 lines: skip `BeginCliScreenSession`/render
   loop, wait for cycles, print final report. (Final-report-on-exit already
   exists.)
2. **JSON/CSV/XML output**: `--json`, `--csv`, `--xml` formatters over the
   same accessors used by `BuildCliScreen`. Highest scripting value.
3. **First/max TTL**: `-f N` first TTL (skip spawning threads below N),
   `-m N` max TTL (cap thread spawn; replaces the hardcoded `MAX_HOPS=30`
   ceiling as the effective limit).
4. **Timeouts as flags**: `-Z` probe timeout (replace compile-time
   `ECHO_REPLY_TIMEOUT`), `-G` grace period.
5. **Custom field order**: `-o "LSNABWV"` flag + interactive `o` prompt.
   Field letters (mtr): L=Loss% S=Snt N=Last A=Avg B=Best W=Wrst V=StDev
   R=Recv (D=Drop J=Jitter when added).
6. **Jitter + Gmean columns**: interarrival jitter (last/avg/max) and
   geometric mean; extend `s_nethost` accumulators like the StDev work.
7. **`-b`**: show hostname *and* IP per hop.
8. **ToS/DSCP `-Q`**, payload pattern `-B`, source address bind `-a`.
9. **`-U` max unknown hops**, `-x` extra resolution toggles.
10. **MPLS decoding `-e`**: parse RFC 4950 extensions from the raw ICMP
    listener (P1 gives us the raw packets; the ICMP-echo path can't see them
    — document that `-e` needs `-T`/`-u`).
11. **Multiple targets / `-F` file** — architectural (multiple `WinMTRNet`
    instances); do last.
12. **`-n` refinement**: display-toggle at runtime (`n` key) — needs storing
    both name and IP per hop (cheap once `-b` lands).

Non-goals (Windows platform limits — do not attempt):
- SCTP mode (no stack).
- Raw-crafted TCP probes (blocked by the OS since XP SP2).
- Sub-millisecond RTT in ICMP mode (`IcmpSendEcho2` returns whole ms). The
  P1 socket engine uses `QueryPerformanceCounter` and *can* do 0.1 ms
  precision — match mtr's tenths formatting there.

## P3 — GUI (last priority)

1. Probe-mode selector (ICMP/TCP/UDP) + port field in the options dialog;
   wire to the same `probeMode`/`targetPort` members. Elevation notice when
   TCP/UDP selected without admin (relaunch-elevated button ideally).
2. StDev (+ Jitter when it lands) columns in the results list and in
   copy/export text/HTML.
3. Optional: per-hop history sparkline in the list control (owner-draw cell).

The GUI reads the same `WinMTRNet` accessors, so P1/P2 plumbing carries over;
the work is dialog resources + column wiring in `WinMTRDialog.cpp` /
`WinMTR.rc`.

## Build & test

Build (from repo root):

```powershell
& 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe' src\WinMTR.sln /t:Build /p:Configuration=Release /p:Platform=x64 /m
```

Tests:

- `tests/ctrlc/run-test.ps1` — ConPTY harness. Verifies Ctrl+C exit; also
  takes `-KeyByte N` to send an arbitrary key instead of 0x03 (e.g. `-KeyByte
  113` = `q`) — use it for every interactive-key regression.
- Probe modes: must be tested **elevated, detached, in a real console**.
  Non-elevated error path: `WinMTR.exe 1.1.1.1 -T` from a normal shell must
  print the elevation error and exit 1 (no alt screen entered).
- Elevated verification (human, once per engine change):
  `WinMTR.exe 1.1.1.1 -T -P 443 -c 5` and `WinMTR.exe 1.1.1.1 -u -c 5` from
  an Administrator terminal; expect the same hop list as ICMP mode (hop 3 on
  this network never answers — that's the network, not a bug).

## Status tracker

Update this table as work lands. "Agent notes" = anything the next person
needs that isn't obvious from the diff.

| # | Item | Tier | Status | Agent notes |
|---|------|------|--------|-------------|
| 0a | Interactive keys: q, h/?, d, r, o, p | P0 | **DONE** (2026-08-27) | Keys live in `PollCliInput`/`RunCliTrace` (WinMTRDialog.cpp); history ring in `s_nethost.hist`; `ResetStatistics()` in WinMTRNet. Tested via harness `-KeyByte` (q/d/o/h verified; r is trivial logic). |
| 0b | Harness `-KeyByte` param | P0 | **DONE** (2026-08-27) | `tests/ctrlc/CtrlCTest.cs` + `run-test.ps1`. |
| 0c | `/SUBSYSTEM:CONSOLE` flip | P0 | **DONE** (2026-08-27) | Prerequisite for 0a — see the architecture-change note at the top. GUI double-click smoke-tested OK; console flash is expected. CLI exit codes: 0 success / 1 refused-failed. |
| 0d | `-c` completion robust to stalled hops | P0 | **DONE** (2026-08-27) | Cycle count is now max xmit across hops, not hop 0's. Found via a VPN whose gateway wedges TTL=1 ICMP echoes so hop 1's prober stalls (environmental — IcmpSendEcho2 stops returning; worth revisiting if it recurs off-VPN). |
| 1a | CLI flags `-T`, `-u`, `-P`, SCTP refusal | P1 | **DONE** (2026-08-27) | Parsed in `WinMTRMain.cpp`; stored on dialog (`probeMode`, `targetPort`). `-S`/`--sctp` prints non-support error, exit. |
| 1b | Elevation gate + clear error | P1 | **DONE** (2026-08-27) | `RequireElevationForSocketProbes()` in WinMTRMain.cpp; checked before alt screen. |
| 1c | Raw ICMP listener + pending-probe table | P1 | **DONE** (2026-08-27) | `WinMTRNet.cpp`: `IcmpListenerThread`, `probeTable[MAX_HOPS]`. IPv4 only. |
| 1d | TCP SYN prober (IPv4) | P1 | **DONE** (2026-08-27) | `TcpProbeThread`. Fresh socket per probe; final hop via connect/RST. **Needs elevated human verification.** |
| 1e | UDP prober (IPv4) | P1 | **DONE** (2026-08-27) | `UdpProbeThread`. Default port 33434, `-P` overrides. **Needs elevated human verification.** |
| 1f | IPv6 for TCP/UDP modes | P1 | TODO | Same listener structure; ICMPv6 types 3 (hop limit) / 1 (unreachable); inner header fixed 40 bytes. |
| 2.1 | True `-r` report mode | P2 | TODO | See P2 list. |
| 2.2 | `--json` / `--csv` / `--xml` | P2 | TODO | |
| 2.3 | `-f` / `-m` TTL bounds | P2 | TODO | |
| 2.4 | `-Z` / `-G` timeouts | P2 | TODO | |
| 2.5 | `-o` field order (flag + prompt) | P2 | TODO | Presets already cycle via `o` key. |
| 2.6 | Jitter / Gmean columns | P2 | TODO | |
| 2.7 | `-b` host+IP display | P2 | TODO | |
| 2.8 | `-Q` ToS, `-B` pattern, `-a` source bind | P2 | TODO | |
| 2.9 | `-U` max unknown hops | P2 | TODO | |
| 2.10 | MPLS `-e` (TCP/UDP modes only) | P2 | TODO | |
| 2.11 | Multi-target / `-F` | P2 | TODO | Big; do last. |
| 3.1 | GUI probe-mode + port UI | P3 | TODO | |
| 3.2 | GUI StDev/Jitter columns + exports | P3 | TODO | |
| 3.3 | GUI history sparkline | P3 | TODO | Optional. |
