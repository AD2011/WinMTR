// CtrlCTest: ConPTY harness that reproduces "Ctrl+C does not exit WinMTR CLI".
// Spawns a shell (or the target directly) inside a pseudoconsole, launches the
// target, sends 0x03 bytes through the ConPTY input pipe (exactly what Windows
// Terminal / SSH deliver), and asserts the target process exits.
// Exit code 0 = target exited after Ctrl+C (PASS). 1 = still running (FAIL).
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

static class CtrlCTest
{
    [StructLayout(LayoutKind.Sequential)]
    struct COORD { public short X; public short Y; }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
        public int dwX; public int dwY; public int dwXSize; public int dwYSize;
        public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute;
        public int dwFlags; public short wShowWindow; public short cbReserved2;
        public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFOEX { public STARTUPINFO StartupInfo; public IntPtr lpAttributeList; }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CreatePipe(out SafeFileHandle hReadPipe, out SafeFileHandle hWritePipe, IntPtr lpPipeAttributes, int nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern int CreatePseudoConsole(COORD size, SafeFileHandle hInput, SafeFileHandle hOutput, uint dwFlags, out IntPtr phPC);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern void ClosePseudoConsole(IntPtr hPC);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    static readonly IntPtr PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = (IntPtr)0x00020016;

    static FileStream ptyIn;
    static StringBuilder captured = new StringBuilder();
    static object capturedLock = new object();
    static StreamWriter logFile;

    static void Log(string msg)
    {
        string line = "[harness " + DateTime.Now.ToString("HH:mm:ss.fff") + "] " + msg;
        Console.WriteLine(line);
        if (logFile != null) { logFile.WriteLine(line); logFile.Flush(); }
    }

    static void SendText(string s)
    {
        byte[] b = Encoding.UTF8.GetBytes(s);
        ptyIn.Write(b, 0, b.Length);
        ptyIn.Flush();
    }

    static int Main(string[] args)
    {
        // usage: CtrlCTest.exe <shell|direct> <targetExe> <targetArgs> [settleSec] [ctrlCPresses]
        logFile = new StreamWriter(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "harness.log"), false);
        if (args.Length < 3) { Log("usage: CtrlCTest <shell|direct> <targetExe> <targetArgs> [settleSec] [presses]"); return 2; }
        string mode = args[0];
        string targetExe = args[1];
        string targetArgs = args[2];
        int settleSec = args.Length > 3 ? int.Parse(args[3]) : 5;
        int presses = args.Length > 4 ? int.Parse(args[4]) : 3;
        string targetName = Path.GetFileNameWithoutExtension(targetExe);

        // 1. pipes + pseudoconsole
        SafeFileHandle inRead, inWrite, outRead, outWrite;
        if (!CreatePipe(out inRead, out inWrite, IntPtr.Zero, 0)) { Log("CreatePipe(in) failed"); return 2; }
        if (!CreatePipe(out outRead, out outWrite, IntPtr.Zero, 0)) { Log("CreatePipe(out) failed"); return 2; }

        COORD size; size.X = 120; size.Y = 30;
        IntPtr hPC;
        int hr = CreatePseudoConsole(size, inRead, outWrite, 0, out hPC);
        if (hr != 0) { Log("CreatePseudoConsole failed hr=0x" + hr.ToString("X8")); return 2; }

        ptyIn = new FileStream(inWrite, FileAccess.Write);
        FileStream ptyOut = new FileStream(outRead, FileAccess.Read);

        // 2. drain output continuously so the pty never stalls
        Thread drain = new Thread(delegate()
        {
            byte[] buf = new byte[8192];
            try
            {
                while (true)
                {
                    int n = ptyOut.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    lock (capturedLock) { captured.Append(Encoding.UTF8.GetString(buf, 0, n)); }
                }
            }
            catch (Exception) { }
        });
        drain.IsBackground = true;
        drain.Start();

        // 3. spawn the root process attached to the pseudoconsole
        IntPtr attrSize = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attrSize);
        IntPtr attrList = Marshal.AllocHGlobal(attrSize);
        if (!InitializeProcThreadAttributeList(attrList, 1, 0, ref attrSize)) { Log("InitializeProcThreadAttributeList failed"); return 2; }
        if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, hPC, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
        { Log("UpdateProcThreadAttribute failed"); return 2; }

        STARTUPINFOEX siEx = new STARTUPINFOEX();
        siEx.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
        siEx.lpAttributeList = attrList;

        string rootCmd;
        if (mode == "shell")
            rootCmd = "powershell.exe -NoProfile -NoLogo";
        else if (mode == "cmdshell")
            rootCmd = "cmd.exe";
        else
            rootCmd = "\"" + targetExe + "\" " + targetArgs;
        bool isShell = (mode == "shell" || mode == "cmdshell");

        PROCESS_INFORMATION pi;
        if (!CreateProcess(null, rootCmd, IntPtr.Zero, IntPtr.Zero, false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref siEx, out pi))
        { Log("CreateProcess failed err=" + Marshal.GetLastWin32Error()); return 2; }
        Log("root process started pid=" + pi.dwProcessId + " cmd=" + rootCmd);

        Process target = null;
        DateTime harnessStart = DateTime.Now;

        try
        {
            if (isShell)
            {
                Thread.Sleep(4000); // let the shell prompt come up
                string cmd = mode == "shell"
                    ? "& '" + targetExe + "' " + targetArgs + "\r"
                    : "\"" + targetExe + "\" " + targetArgs + "\r";
                Log("typing command into shell: " + cmd.TrimEnd('\r'));
                SendText(cmd);
            }

            // 4. find the target process
            for (int i = 0; i < 120 && target == null; i++)
            {
                Process[] procs = Process.GetProcessesByName(targetName);
                foreach (Process p in procs)
                {
                    try { if (p.StartTime >= harnessStart.AddSeconds(-2)) { target = p; break; } }
                    catch (Exception) { }
                }
                if (target == null) Thread.Sleep(250);
            }
            if (target == null) { Log("FAIL: target process never appeared"); DumpTail(); return 2; }
            Log("target " + targetName + " pid=" + target.Id + " running; settling " + settleSec + "s");

            Thread.Sleep(settleSec * 1000);
            if (target.HasExited) { Log("FAIL(setup): target exited before Ctrl+C was sent"); DumpTail(); return 2; }

            // 5. hammer Ctrl+C like the user did
            bool exited = false;
            for (int i = 0; i < presses && !exited; i++)
            {
                Log("sending 0x03 (press " + (i + 1) + "/" + presses + ")");
                ptyIn.WriteByte(0x03);
                ptyIn.Flush();
                exited = target.WaitForExit(3000);
            }
            if (!exited) exited = target.WaitForExit(5000);

            if (exited)
            {
                Log("PASS: target exited after Ctrl+C");
                if (isShell)
                {
                    // is the shell still usable afterwards?
                    Thread.Sleep(500);
                    SendText("echo POST_EXIT_SHELL_OK\r");
                    Thread.Sleep(2000);
                    string text;
                    lock (capturedLock) { text = captured.ToString(); }
                    int firstIdx = text.IndexOf("POST_EXIT_SHELL_OK");
                    bool echoed = firstIdx >= 0 && text.IndexOf("POST_EXIT_SHELL_OK", firstIdx + 1) >= 0;
                    Log(echoed ? "PASS: shell responsive after exit" : "WARN: shell did not echo after exit");
                }
                DumpTail();
                return 0;
            }
            Log("FAIL: target still running after " + presses + " Ctrl+C presses + 5s grace -> killing it");
            DumpTail();
            try { target.Kill(); } catch (Exception) { }
            return 1;
        }
        finally
        {
            try { if (isShell) SendText("exit\r"); } catch (Exception) { }
            Thread.Sleep(500);
            try { if (target != null && !target.HasExited) target.Kill(); } catch (Exception) { }
            try { Process root = Process.GetProcessById(pi.dwProcessId); root.Kill(); } catch (Exception) { }
            ClosePseudoConsole(hPC);
        }
    }

    static void DumpTail()
    {
        string text;
        lock (capturedLock) { text = captured.ToString(); }
        string file = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "pty-output.log");
        File.WriteAllText(file, text);
        int show = Math.Min(600, text.Length);
        Log("--- last " + show + " chars of pty output (full log: " + file + ") ---");
        Console.WriteLine(text.Substring(text.Length - show).Replace("\x1b", "<ESC>"));
        Log("--- end pty output ---");
    }
}
