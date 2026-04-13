WinMTR 2.0
==========

WinMTR 2.0 is a Windows network diagnostic tool that combines traceroute-style path discovery with continuous ping statistics.

CLI examples:

    WinMTR.exe google.com
    WinMTR.exe bgp.tools -4
    WinMTR.exe bgp.tools -6
    WinMTR.exe --numeric example.com
    WinMTR.exe --report-cycles 10 1.1.1.1
    WinMTR.exe --report-seconds 30 example.com
    WinMTR.exe --gui example.com

Run `WinMTR.exe --help` for all CLI options.

Launching `WinMTR.exe` without arguments opens the GUI.

Credits:

    mtr by Travis Cross and contributors:
    https://github.com/traviscross/mtr

    WinMTR Official, the Windows port by Dragos Manac:
    https://github.com/WinMTR/WinMTR-Official

    WinMTR Redux, with IPv6 support extended by White-Tiger:
    https://github.com/White-Tiger/WinMTR

License:

    GNU General Public License version 2.
