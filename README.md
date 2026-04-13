WinMTR 2.0
==========

WinMTR 2.0 is a lightweight Windows network diagnostic tool that combines traceroute-style path discovery with continuous ping statistics.

This version adds a practical command-line experience similar to Linux `mtr`, per-hop ASN lookup, IPv4/IPv6 selection, and a native Windows GUI with system-following dark mode.

## Features

- Live CLI mode by default when a target host is passed on the command line
- In-place terminal refresh with `Ctrl+C` stop support
- Optional bounded runs with cycle or duration limits
- Per-hop ASN lookup in CLI, copied text reports, and exported reports
- IPv4 and IPv6 selection with `-4` and `-6`
- GUI mode for classic WinMTR usage
- Native Windows light/dark appearance for the GUI
- Text and HTML export support

## Requirements

- Windows 7 or newer
- Visual Studio with C++ and MFC support for local builds
- A modern Windows SDK and C++ toolset

## CLI Usage

WinMTR runs in CLI mode whenever you launch it from a terminal with a target host. Use `--gui` only when you explicitly want the desktop GUI.

```text
WinMTR.exe google.com
WinMTR.exe bgp.tools -4
WinMTR.exe bgp.tools -6
WinMTR.exe --numeric example.com
WinMTR.exe --report-cycles 10 1.1.1.1
WinMTR.exe --report-seconds 30 --numeric example.com
WinMTR.exe --gui example.com
```

Supported options:

- `-h`, `--help`: show help
- `-g`, `--gui`: force GUI mode
- `-r`, `--report`: run in CLI live-report mode
- `-c`, `--report-cycles <count>`: stop after a fixed number of cycles
- `-w`, `--report-seconds <seconds>`: stop after a fixed duration
- `-i`, `--interval <seconds>`: set probe interval
- `-s`, `--size <bytes>`: set ICMP payload size
- `-n`, `--numeric`: disable reverse DNS lookups
- `-4`, `--ipv4`: force IPv4
- `-6`, `--ipv6`: force IPv6

## GUI Usage

Launching `WinMTR.exe` without command-line arguments opens the GUI directly without showing a console window.

The GUI follows the Windows app light/dark setting where supported, including the main controls, status bar, and results table header.

Use this form if you want to open the GUI with a pre-filled target from a terminal:

```text
WinMTR.exe --gui example.com
```

## Build

Open `src\WinMTR.sln` in Visual Studio, or build from a Developer PowerShell:

```powershell
MSBuild.exe src\WinMTR.sln /t:Build /p:Configuration=Release /p:Platform=x64
```

The release binary is written to:

```text
src\Release_x64\WinMTR.exe
```

## Credits

- [mtr](https://github.com/traviscross/mtr) by Travis Cross and contributors
- [WinMTR Official](https://github.com/WinMTR/WinMTR-Official), the Windows port by Dragos Manac
- [WinMTR Redux](https://github.com/White-Tiger/WinMTR), with IPv6 support extended by White-Tiger

## License

WinMTR 2.0 is distributed under the GNU General Public License version 2. See [LICENSE](LICENSE).
