//*****************************************************************************
// FILE:            WinMTRMain.cpp
//
//
// HISTORY:
//
//
//    -- versions 0.8
//
// - 01.18.2002 - Store LRU hosts in registry (v0.8)
// - 05.08.2001 - Replace edit box with combo box which hold last entered hostnames.
//				  Fixed a memory leak which caused program to crash after a long
//				  time running. (v0.7)
// - 11.27.2000 - Added resizing support and flat buttons. (v0.6)
// - 11.26.2000 - Added copy data to clipboard and posibility to save data to file as text or HTML.(v0.5)
// - 08.03.2000 - added double-click on hostname for detailed information (v0.4)
// - 08.02.2000 - fix icmp error codes handling. (v0.3)
// - 08.01.2000 - support for full command-line parameter specification (v0.2)
// - 07.30.2000 - support for command-line host specification
//					by Silviu Simen (ssimen@ubisoft.ro) (v0.1b)
// - 07.28.2000 - first release (v0.1)
//*****************************************************************************

#include "WinMTRGlobal.h"
#include "WinMTRMain.h"
#include "WinMTRDialog.h"
#include "WinMTRHelp.h"
#include <algorithm>
#include <iostream>
#include <set>
#include <sstream>
#include <vector>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

WinMTRMain WinMTR;

//*****************************************************************************
// BEGIN_MESSAGE_MAP
//
//
//*****************************************************************************
BEGIN_MESSAGE_MAP(WinMTRMain, CWinApp)
	ON_COMMAND(ID_HELP, CWinApp::OnHelp)
END_MESSAGE_MAP()

//*****************************************************************************
// WinMTRMain::WinMTRMain
//
//
//*****************************************************************************
WinMTRMain::WinMTRMain()
{
}

//*****************************************************************************
// WinMTRMain::InitInstance
//
//
//*****************************************************************************
BOOL WinMTRMain::InitInstance()
{
	INITCOMMONCONTROLSEX icex = {
		sizeof(INITCOMMONCONTROLSEX),
		ICC_STANDARD_CLASSES | ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_LINK_CLASS
	};
	InitCommonControlsEx(&icex);
	if(!AfxSocketInit()) {
		AfxMessageBox(IDP_SOCKETS_INIT_FAILED);
		return FALSE;
	}
	
	AfxEnableControlContainer();
	
	
	WinMTRDialog mtrDialog;
	m_pMainWnd = &mtrDialog;

	WinMTRCommandLineOptions options;
	std::vector<char> cmdBuffer;
	if(strlen(m_lpCmdLine)) {
		size_t len = strlen(m_lpCmdLine);
		cmdBuffer.resize(len + 2, '\0');
		memcpy(&cmdBuffer[0], m_lpCmdLine, len);
		cmdBuffer[len] = ' ';
		if(!ParseCommandLineParams(&cmdBuffer[0], &mtrDialog, options)) {
			return FALSE;
		}
	}

	if(options.showHelp) {
		if(SetupConsole()) {
			PrintHelp();
		}
		return FALSE;
	}

	if(options.cliMode) {
		RunCliMode(options, &mtrDialog);
		return FALSE;
	}

	HideOwnedConsoleWindow();
	mtrDialog.DoModal();

	
	return FALSE;
}


//*****************************************************************************
// WinMTRMain::ParseCommandLineParams
//
//
//*****************************************************************************
bool WinMTRMain::ParseCommandLineParams(LPTSTR cmd, WinMTRDialog* wmtrdlg, WinMTRCommandLineOptions& options)
{
	char value[1024];
	std::string host_name = "";
	bool hasAnyCliArguments = strlen(cmd) > 1;
	
	if(GetParamValue(cmd, "help",'h', NULL)) {
		options.showHelp = true;
		return true;
	}
	
	if(GetHostNameParamValue(cmd, host_name)) {
		wmtrdlg->SetHostName(host_name.c_str());
		options.hostName = host_name;
	}
	if(GetParamValue(cmd, "interval",'i', value)) {
		wmtrdlg->SetInterval((float)atof(value));
		wmtrdlg->hasIntervalFromCmdLine = true;
	}
	if(GetParamValue(cmd, "size",'s', value)) {
		wmtrdlg->SetPingSize((WORD)atoi(value));
		wmtrdlg->hasPingsizeFromCmdLine = true;
	}
	if(GetParamValue(cmd, "maxLRU",'m', value)) {
		wmtrdlg->SetMaxLRU(atoi(value));
		wmtrdlg->hasMaxLRUFromCmdLine = true;
	}
	if(GetParamValue(cmd, "numeric",'n', NULL)) {
		wmtrdlg->SetUseDNS(FALSE);
		wmtrdlg->hasUseDNSFromCmdLine = true;
	}
	if(GetParamValue(cmd, "ipv6",'6', NULL)) {
		wmtrdlg->hasUseIPv6FromCmdLine=true;
		wmtrdlg->useIPv6=1;
	}
	if(GetParamValue(cmd, "ipv4",'4', NULL)) {
		wmtrdlg->hasUseIPv6FromCmdLine=true;
		wmtrdlg->useIPv6=0;
	}
	if(GetParamValue(cmd, "gui", 'g', NULL)) {
		options.forceGui = true;
	}
	if(GetParamValue(cmd, "report", 'r', NULL)) {
		options.cliMode = true;
	}
	if(GetParamValue(cmd, "report-cycles", 'c', value)) {
		options.cliMode = true;
		options.reportCycles = max(1, atoi(value));
	}
	if(GetParamValue(cmd, "report-seconds", 'w', value)) {
		options.cliMode = true;
		options.reportDurationSeconds = max(1, atoi(value));
	}
	if(!options.forceGui && hasAnyCliArguments) {
		options.cliMode = true;
	}
	return true;
}

bool WinMTRMain::RunCliMode(const WinMTRCommandLineOptions& options, WinMTRDialog* wmtrdlg)
{
	if(!SetupConsole()) return false;
	if(options.hostName.empty()) {
		WriteConsoleText("No host specified.\n\n");
		PrintHelp();
		return false;
	}
	if(!wmtrdlg->wmtrnet->initialized) {
		WriteConsoleText("WinMTR network initialization failed.\n");
		return false;
	}
	return wmtrdlg->RunCliTrace(options.hostName.c_str(), options.reportCycles, options.reportDurationSeconds) != 0;
}

void WinMTRMain::HideOwnedConsoleWindow() const
{
	HWND consoleWindow = GetConsoleWindow();
	if(!consoleWindow) return;

	DWORD processIds[8] = {0};
	DWORD count = GetConsoleProcessList(processIds, sizeof(processIds) / sizeof(processIds[0]));
	if(count <= 1) {
		ShowWindow(consoleWindow, SW_HIDE);
	}
}

bool WinMTRMain::SetupConsole() const
{
	HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
	if(output != NULL && output != INVALID_HANDLE_VALUE) return true;

	if(!AttachConsole(ATTACH_PARENT_PROCESS) && GetLastError() != ERROR_ACCESS_DENIED) {
		if(!AllocConsole()) {
			return false;
		}
	}

	HANDLE conOut = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if(conOut != INVALID_HANDLE_VALUE) {
		SetStdHandle(STD_OUTPUT_HANDLE, conOut);
		SetStdHandle(STD_ERROR_HANDLE, conOut);
	}

	HANDLE conIn = CreateFileA("CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if(conIn != INVALID_HANDLE_VALUE) {
		SetStdHandle(STD_INPUT_HANDLE, conIn);
	}

	output = GetStdHandle(STD_OUTPUT_HANDLE);
	return output != NULL && output != INVALID_HANDLE_VALUE;
}

void WinMTRMain::WriteConsoleText(const char* text) const
{
	if(!text || !*text) return;
	HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
	if(output == INVALID_HANDLE_VALUE || output == NULL) return;

	DWORD written = 0;
	WriteFile(output, text, (DWORD)strlen(text), &written, NULL);
}

void WinMTRMain::PrintHelp() const
{
	std::ostringstream help;
	help << "WinMTR 2.0 command line usage:\n";
	help << "  WinMTR.exe [options] host\n\n";
	help << "Options:\n";
	help << "  -h, --help               Show this help text.\n";
	help << "  -g, --gui                Force the GUI even when a host is provided.\n";
	help << "  -r, --report             Run without the GUI in live terminal mode.\n";
	help << "  -c, --report-cycles N    Stop after N report intervals.\n";
	help << "  -w, --report-seconds N   Stop after N seconds.\n";
	help << "  -i, --interval SECONDS   Probe interval.\n";
	help << "  -s, --size BYTES         ICMP payload size.\n";
	help << "  -n, --numeric            Do not perform reverse DNS lookups.\n";
	help << "  -4, --ipv4               Force IPv4.\n";
	help << "  -6, --ipv6               Force IPv6.\n\n";
	help << "CLI mode refreshes continuously until Ctrl+C by default.\n";
	help << "CLI reports include per-hop ASN lookup when available.\n";
	WriteConsoleText(help.str().c_str());
}

//*****************************************************************************
// WinMTRMain::GetParamValue
//
//
//*****************************************************************************
int WinMTRMain::GetParamValue(LPTSTR cmd, char* param, char sparam, char* value)
{
	char* p;
	
	char p_long[1024];
	char p_short[1024];
	
	sprintf(p_long,"--%s ", param);
	p_short[0] = '\0';
	if(sparam)
		sprintf(p_short,"-%c ", sparam);
	
	if((p=strstr(cmd, p_long))) ;
	else if(sparam)
		p=strstr(cmd, p_short);
	else
		p = NULL;
		
	if(p == NULL)
		return 0;
		
	if(!value)
		return 1;
		
	while(*p && *p!=' ')
		p++;
	while(*p==' ') p++;
	
	int i = 0;
	while(*p && *p!=' ')
		value[i++] = *p++;
	value[i]='\0';
	
	return 1;
}

//*****************************************************************************
// WinMTRMain::GetHostNameParamValue
//
//
//*****************************************************************************
int WinMTRMain::GetHostNameParamValue(LPTSTR cmd, std::string& host_name)
{
	std::vector<std::string> args;
	std::string current;
	bool inQuotes = false;
	for(size_t i = 0; cmd[i]; ++i) {
		char ch = cmd[i];
		if(ch == '"') {
			inQuotes = !inQuotes;
			continue;
		}
		if(!inQuotes && isspace((unsigned char)ch)) {
			if(!current.empty()) {
				args.push_back(current);
				current.clear();
			}
			continue;
		}
		current.push_back(ch);
	}
	if(!current.empty()) {
		args.push_back(current);
	}

	static const std::set<std::string> valueOptions = {
		"-i", "--interval",
		"-s", "--size",
		"-m", "--maxLRU",
		"-c", "--report-cycles",
		"-w", "--report-seconds"
	};

	for(size_t i = 0; i < args.size(); ++i) {
		const std::string& arg = args[i];
		if(arg.empty()) continue;
		if(arg[0] != '-') {
			host_name = arg;
			return 1;
		}
		if(valueOptions.find(arg) != valueOptions.end()) {
			++i;
		}
	}

	return 0;
}
