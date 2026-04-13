//*****************************************************************************
// FILE:            WinMTRDialog.cpp
//
//
//*****************************************************************************

#include "WinMTRGlobal.h"
#include "WinMTRDialog.h"
#include "WinMTROptions.h"
#include "WinMTRProperties.h"
#include "WinMTRNet.h"
#include <iomanip>
#include <iostream>
#include <string>
#include <sstream>

#ifdef _DEBUG
#	define TRACE_MSG(msg)									\
	{														\
	std::ostringstream dbg_msg(std::ostringstream::out);	\
	dbg_msg << msg << std::endl;							\
	OutputDebugString(dbg_msg.str().c_str());				\
	}
#	define new DEBUG_NEW
#	undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#else
#	define TRACE_MSG(msg)
#endif

void PingThread(void* p);
unsigned WINAPI CliTraceThread(void* p);

static int GetSockaddrLength(const sockaddr* addr)
{
	if(!addr) return 0;
	return addr->sa_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
}

static std::string HtmlEscape(const char* value)
{
	std::string source = value ? value : "";
	std::string escaped;
	for(size_t i = 0; i < source.length(); ++i) {
		switch(source[i]) {
		case '&': escaped += "&amp;"; break;
		case '<': escaped += "&lt;"; break;
		case '>': escaped += "&gt;"; break;
		case '"': escaped += "&quot;"; break;
		default: escaped.push_back(source[i]); break;
		}
	}
	return escaped;
}

static std::string PadCell(const std::string& value, size_t width, bool rightAlign = false)
{
	if(width == 0) return "";
	std::string text = value;
	if(text.length() > width) {
		text = text.substr(0, width);
	}
	if(text.length() < width) {
		size_t padding = width - text.length();
		if(rightAlign) text.insert(0, padding, ' ');
		else text.append(padding, ' ');
	}
	return text;
}

static std::string CenterCell(const std::string& value, size_t width)
{
	if(width == 0) return "";
	std::string text = value;
	if(text.length() > width) {
		text = text.substr(0, width);
	}
	if(text.length() < width) {
		size_t padding = width - text.length();
		size_t left = padding / 2;
		size_t right = padding - left;
		text.insert(0, left, ' ');
		text.append(right, ' ');
	}
	return text;
}

static std::string BuildCliSeparator(char fill)
{
	static const size_t widths[] = {57, 10, 4, 4, 4, 4, 4, 4, 4};
	std::ostringstream row;
	row << '|';
	for(size_t i = 0; i < sizeof(widths) / sizeof(widths[0]); ++i) {
		row << std::string(widths[i] + 2, fill) << '|';
	}
	row << "\r\n";
	return row.str();
}

static std::string BuildCliRow(
	const std::string& host,
	const std::string& asn,
	int loss,
	int sent,
	int recv,
	int best,
	int avrg,
	int wrst,
	int last)
{
	std::ostringstream row;
	row << "| " << PadCell(host, 57, false)
		<< " | " << PadCell(asn, 10, false)
		<< " | " << PadCell(std::to_string(loss), 4, true)
		<< " | " << PadCell(std::to_string(sent), 4, true)
		<< " | " << PadCell(std::to_string(recv), 4, true)
		<< " | " << PadCell(std::to_string(best), 4, true)
		<< " | " << PadCell(std::to_string(avrg), 4, true)
		<< " | " << PadCell(std::to_string(wrst), 4, true)
		<< " | " << PadCell(std::to_string(last), 4, true)
		<< " |\r\n";
	return row.str();
}

struct cli_trace_thread {
	WinMTRDialog* dialog;
	sockaddr_storage address;
	int addressLength;
};

static volatile LONG g_cliStopRequested = 0;
static bool g_cliUsingAltScreen = false;
static bool g_cliUsingVirtualTerminal = false;
static bool g_cliSavedInputMode = false;
static DWORD g_cliOriginalInputMode = 0;

static BOOL WINAPI CliConsoleHandler(DWORD signal)
{
	switch(signal) {
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	case CTRL_CLOSE_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:
		InterlockedExchange(&g_cliStopRequested, 1);
		return TRUE;
	default:
		return FALSE;
	}
}

static void WriteCliOutput(const char* text)
{
	if(!text || !*text) return;
	HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
	if(output == NULL || output == INVALID_HANDLE_VALUE) return;
	DWORD written = 0;
	WriteFile(output, text, (DWORD)strlen(text), &written, NULL);
}

static bool EnableCliVirtualTerminal()
{
	HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
	if(output == NULL || output == INVALID_HANDLE_VALUE) return false;

	DWORD outputMode = 0;
	if(!GetConsoleMode(output, &outputMode)) return false;
	if((outputMode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0) {
		if(!SetConsoleMode(output, outputMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
			return false;
		}
	}

	g_cliUsingVirtualTerminal = true;
	return true;
}

static void BeginCliInputSession()
{
	HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
	if(input == NULL || input == INVALID_HANDLE_VALUE) return;

	DWORD inputMode = 0;
	if(!GetConsoleMode(input, &inputMode)) return;

	g_cliOriginalInputMode = inputMode;
	g_cliSavedInputMode = true;

	DWORD liveMode = inputMode;
	liveMode &= ~ENABLE_PROCESSED_INPUT;
	liveMode |= ENABLE_EXTENDED_FLAGS;
	SetConsoleMode(input, liveMode);
}

static void EndCliInputSession()
{
	if(!g_cliSavedInputMode) return;

	HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
	if(input != NULL && input != INVALID_HANDLE_VALUE) {
		SetConsoleMode(input, g_cliOriginalInputMode);
	}

	g_cliSavedInputMode = false;
	g_cliOriginalInputMode = 0;
}

static void BeginCliScreenSession()
{
	g_cliUsingAltScreen = false;
	BeginCliInputSession();
	if(!EnableCliVirtualTerminal()) return;
	WriteCliOutput("\x1b[?1049h\x1b[?25l");
	g_cliUsingAltScreen = true;
}

static void EndCliScreenSession()
{
	if(g_cliUsingVirtualTerminal) {
		WriteCliOutput("\x1b[?25h");
		if(g_cliUsingAltScreen) {
			WriteCliOutput("\x1b[?1049l");
		}
	}
	g_cliUsingAltScreen = false;
	g_cliUsingVirtualTerminal = false;
	EndCliInputSession();
}

static bool ClearCliScreen()
{
	if(g_cliUsingVirtualTerminal) {
		WriteCliOutput("\x1b[H\x1b[2J");
		return true;
	}

	HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
	if(output == NULL || output == INVALID_HANDLE_VALUE) return false;

	CONSOLE_SCREEN_BUFFER_INFO csbi;
	if(!GetConsoleScreenBufferInfo(output, &csbi)) return false;

	COORD home = {0, 0};
	DWORD cellCount = csbi.dwSize.X * csbi.dwSize.Y;
	DWORD written = 0;
	FillConsoleOutputCharacter(output, ' ', cellCount, home, &written);
	FillConsoleOutputAttribute(output, csbi.wAttributes, cellCount, home, &written);
	SetConsoleCursorPosition(output, home);
	return true;
}

static bool PollCliStopRequest()
{
	if(InterlockedCompareExchange(&g_cliStopRequested, 0, 0) != 0) {
		return true;
	}

	if((GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0 && (GetAsyncKeyState('C') & 0x8000) != 0) {
		InterlockedExchange(&g_cliStopRequested, 1);
		return true;
	}

	HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
	if(input == NULL || input == INVALID_HANDLE_VALUE) {
		return false;
	}

	DWORD eventCount = 0;
	if(!GetNumberOfConsoleInputEvents(input, &eventCount) || eventCount == 0) {
		return false;
	}

	INPUT_RECORD records[16];
	DWORD recordsRead = 0;
	while(eventCount > 0) {
		DWORD batchSize = eventCount;
		if(batchSize > (DWORD)(sizeof(records) / sizeof(records[0]))) {
			batchSize = (DWORD)(sizeof(records) / sizeof(records[0]));
		}
		if(!ReadConsoleInput(input, records, batchSize, &recordsRead) || recordsRead == 0) {
			break;
		}
		for(DWORD i = 0; i < recordsRead; ++i) {
			const INPUT_RECORD& record = records[i];
			if(record.EventType != KEY_EVENT) continue;
			const KEY_EVENT_RECORD& key = record.Event.KeyEvent;
			if(!key.bKeyDown) continue;
			const DWORD ctrlState = key.dwControlKeyState;
			const bool ctrlPressed = (ctrlState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)) != 0;
			if(ctrlPressed && (key.uChar.AsciiChar == 'c' || key.uChar.AsciiChar == 'C' || key.wVirtualKeyCode == 'C')) {
				InterlockedExchange(&g_cliStopRequested, 1);
				return true;
			}
			if(key.wVirtualKeyCode == VK_CANCEL) {
				InterlockedExchange(&g_cliStopRequested, 1);
				return true;
			}
		}
		if(!GetNumberOfConsoleInputEvents(input, &eventCount)) {
			break;
		}
	}

	return InterlockedCompareExchange(&g_cliStopRequested, 0, 0) != 0;
}

static std::string BuildCliScreen(WinMTRDialog* dialog, const char* hostname, int cycles, int durationSeconds, DWORD elapsedMs)
{
	char host[255];
	char asn[64];
	std::ostringstream screen;
	int nh = dialog->wmtrnet->GetMax();
	int currentCycle = dialog->wmtrnet->GetXmit(0);

	screen << "WinMTR live report for " << hostname << "\r\n";
	screen << "Press Ctrl+C to stop.\r\n\r\n";
	screen << BuildCliSeparator('-');
	screen << "| " << CenterCell("WinMTR statistics", 105) << " |\r\n";
	screen << BuildCliSeparator('-');
	screen << "| " << CenterCell("Host", 57)
		   << " | " << CenterCell("ASN", 10)
		   << " | " << CenterCell("%", 4)
		   << " | " << CenterCell("Sent", 4)
		   << " | " << CenterCell("Recv", 4)
		   << " | " << CenterCell("Best", 4)
		   << " | " << CenterCell("Avrg", 4)
		   << " | " << CenterCell("Wrst", 4)
		   << " | " << CenterCell("Last", 4)
		   << " |\r\n";
	screen << BuildCliSeparator('-');

	for(int i = 0; i < nh; ++i) {
		dialog->wmtrnet->GetName(i, host);
		if(strcmp(host, "") == 0) strcpy(host, "No response from host");
		dialog->wmtrnet->GetASN(i, asn);
		if(strcmp(asn, "") == 0) strcpy(asn, "-");

		screen << BuildCliRow(
			host,
			asn,
			dialog->wmtrnet->GetPercent(i),
			dialog->wmtrnet->GetXmit(i),
			dialog->wmtrnet->GetReturned(i),
			dialog->wmtrnet->GetBest(i),
			dialog->wmtrnet->GetAvg(i),
			dialog->wmtrnet->GetWorst(i),
			dialog->wmtrnet->GetLast(i));
	}

	screen << BuildCliSeparator('-');
	screen << "   WinMTR 2.0 GPLv2\r\n\r\n";

	if(durationSeconds > 0) {
		screen << "Elapsed: " << (elapsedMs / 1000) << "s / " << durationSeconds << "s";
	} else if(cycles > 0) {
		screen << "Cycles: " << currentCycle << " / " << cycles;
	} else {
		screen << "Cycles: " << currentCycle;
	}
	screen << "\r\n";
	return screen.str();
}

//*****************************************************************************
// BEGIN_MESSAGE_MAP
//
//
//*****************************************************************************
BEGIN_MESSAGE_MAP(WinMTRDialog, CDialog)
	ON_WM_PAINT()
	ON_WM_SIZE()
	ON_WM_SIZING()
	ON_WM_CTLCOLOR()
	ON_WM_SETTINGCHANGE()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(ID_RESTART, OnRestart)
	ON_BN_CLICKED(ID_OPTIONS, OnOptions)
	ON_BN_CLICKED(ID_CTTC, OnCTTC)
	ON_BN_CLICKED(ID_CHTC, OnCHTC)
	ON_BN_CLICKED(ID_EXPT, OnEXPT)
	ON_BN_CLICKED(ID_EXPH, OnEXPH)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST_MTR, OnDblclkList)
	ON_CBN_SELCHANGE(IDC_COMBO_HOST, &WinMTRDialog::OnCbnSelchangeComboHost)
	ON_CBN_SELENDOK(IDC_COMBO_HOST, &WinMTRDialog::OnCbnSelendokComboHost)
	ON_CBN_CLOSEUP(IDC_COMBO_HOST, &WinMTRDialog::OnCbnCloseupComboHost)
	ON_WM_TIMER()
	ON_WM_CLOSE()
	ON_BN_CLICKED(IDCANCEL, &WinMTRDialog::OnBnClickedCancel)
END_MESSAGE_MAP()


//*****************************************************************************
// WinMTRDialog::WinMTRDialog
//
//
//*****************************************************************************
WinMTRDialog::WinMTRDialog(CWnd* pParent)
	: CDialog(WinMTRDialog::IDD, pParent),
	  state(IDLE),
	  transition(IDLE_TO_IDLE)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_autostart = 0;
	useDNS = DEFAULT_DNS;
	interval = DEFAULT_INTERVAL;
	pingsize = DEFAULT_PING_SIZE;
	maxLRU = DEFAULT_MAX_LRU;
	nrLRU = 0;
	
	hasIntervalFromCmdLine = false;
	hasPingsizeFromCmdLine = false;
	hasMaxLRUFromCmdLine = false;
	hasUseDNSFromCmdLine = false;
	hasUseIPv6FromCmdLine = false;
	
	traceThreadMutex = CreateMutex(NULL, FALSE, NULL);
	wmtrnet = new WinMTRNet(this);
	useIPv6=2;
}

WinMTRDialog::~WinMTRDialog()
{
	delete wmtrnet;
	CloseHandle(traceThreadMutex);
}

//*****************************************************************************
// WinMTRDialog::DoDataExchange
//
//
//*****************************************************************************
void WinMTRDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, ID_OPTIONS, m_buttonOptions);
	DDX_Control(pDX, IDCANCEL, m_buttonExit);
	DDX_Control(pDX, ID_RESTART, m_buttonStart);
	DDX_Control(pDX, IDC_COMBO_HOST, m_comboHost);
	DDX_Control(pDX, IDC_CHECK_IPV6, m_checkIPv6);
	DDX_Control(pDX, IDC_LIST_MTR, m_listMTR);
	DDX_Control(pDX, IDC_STATICS, m_staticS);
	DDX_Control(pDX, IDC_STATICJ, m_staticJ);
	DDX_Control(pDX, ID_EXPH, m_buttonExpH);
	DDX_Control(pDX, ID_EXPT, m_buttonExpT);
	DDX_Control(pDX, ID_CTTC, m_buttonCopyText);
	DDX_Control(pDX, ID_CHTC, m_buttonCopyHtml);
}


//*****************************************************************************
// WinMTRDialog::OnInitDialog
//
//
//*****************************************************************************
BOOL WinMTRDialog::OnInitDialog()
{
	CDialog::OnInitDialog();
	if(!wmtrnet->initialized) {
		EndDialog(-1);
		return TRUE;
	}
	
#ifndef  _WIN64
	char caption[] = {"WinMTR 2.0 32bit"};
#else
	char caption[] = {"WinMTR 2.0 64bit"};
#endif
	
	SetTimer(1, WINMTR_DIALOG_TIMER, NULL);
	SetWindowText(caption);
	WinMTRRefreshTheme();
	WinMTRApplyThemeToWindow(this);
	
	SetIcon(m_hIcon, TRUE);
	SetIcon(m_hIcon, FALSE);
	
	if(!statusBar.Create(this))
		AfxMessageBox("Error creating status bar");
	statusBar.GetStatusBarCtrl().SetMinHeight(23);
	
	UINT sbi[1];
	sbi[0] = IDS_STRING_SB_NAME;
	statusBar.SetIndicators(sbi,1);
	statusBar.SetPaneInfo(0, statusBar.GetItemID(0),SBPS_STRETCH, NULL);
	
	// create project link
	if(m_buttonCredits.Create(_T("Credits"), WS_CHILD|WS_VISIBLE|WS_TABSTOP, CRect(0,0,0,0), &statusBar, 1234)) {
		m_buttonCredits.SetURL("https://github.com/White-Tiger/WinMTR");
		if(statusBar.AddPane(1234,1)) {
			statusBar.SetPaneWidth(statusBar.CommandToIndex(1234),100);
			statusBar.AddPaneControl(m_buttonCredits,1234,true);
		}
	}
	
	for(int i = 0; i< MTR_NR_COLS; i++)
		m_listMTR.InsertColumn(i, MTR_COLS[i], LVCFMT_LEFT, MTR_COL_LENGTH[i] , -1);
	CHeaderCtrl* header = m_listMTR.GetHeaderCtrl();
	if(header && ::IsWindow(header->GetSafeHwnd())) {
		for(int i = 0; i < header->GetItemCount(); ++i) {
			HDITEM item = {0};
			item.mask = HDI_FORMAT;
			header->GetItem(i, &item);
			item.fmt |= HDF_OWNERDRAW;
			header->SetItem(i, &item);
		}
		m_listHeader.SubclassWindow(header->GetSafeHwnd());
	}
	WinMTRApplyThemeToChildren(this);
	WinMTRConfigureListCtrl(m_listMTR);
	if(!wmtrnet->hasIPv6) m_checkIPv6.EnableWindow(FALSE);
		
	m_comboHost.SetFocus();
	
	// We need to resize the dialog to make room for control bars.
	// First, figure out how big the control bars are.
	CRect rcClientStart;
	CRect rcClientNow;
	GetClientRect(rcClientStart);
	RepositionBars(AFX_IDW_CONTROLBAR_FIRST, AFX_IDW_CONTROLBAR_LAST,
				   0, reposQuery, rcClientNow);
				   
	// Now move all the controls so they are in the same relative
	// position within the remaining client area as they would be
	// with no control bars.
	CPoint ptOffset(rcClientNow.left - rcClientStart.left,
					rcClientNow.top - rcClientStart.top);
					
	CRect  rcChild;
	CWnd* pwndChild = GetWindow(GW_CHILD);
	while(pwndChild) {
		pwndChild->GetWindowRect(rcChild);
		ScreenToClient(rcChild);
		rcChild.OffsetRect(ptOffset);
		pwndChild->MoveWindow(rcChild, FALSE);
		pwndChild = pwndChild->GetNextWindow();
	}
	
	// Adjust the dialog window dimensions
	CRect rcWindow;
	GetWindowRect(rcWindow);
	rcWindow.right += rcClientStart.Width() - rcClientNow.Width();
	rcWindow.bottom += rcClientStart.Height() - rcClientNow.Height();
	MoveWindow(rcWindow, FALSE);
	
	// And position the control bars
	RepositionBars(AFX_IDW_CONTROLBAR_FIRST, AFX_IDW_CONTROLBAR_LAST, 0);
	
	InitRegistry();
	
	if(m_autostart) {
		m_comboHost.SetWindowText(msz_defaulthostname);
		OnRestart();
	}
	
	return FALSE;
}

//*****************************************************************************
// WinMTRDialog::InitRegistry
//
//
//*****************************************************************************
BOOL WinMTRDialog::InitRegistry()
{
	HKEY hKey, hKey_v;
	DWORD tmp_dword, value_size;
	LONG r;
	
	r = RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\WinMTR",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey,NULL);
	if(r != ERROR_SUCCESS)
		return FALSE;
		
	RegSetValueEx(hKey,"Version", 0, REG_SZ, (const unsigned char*)WINMTR_VERSION, sizeof(WINMTR_VERSION)+1);
	RegSetValueEx(hKey,"License", 0, REG_SZ, (const unsigned char*)WINMTR_LICENSE, sizeof(WINMTR_LICENSE)+1);
	RegSetValueEx(hKey,"HomePage", 0, REG_SZ, (const unsigned char*)WINMTR_HOMEPAGE, sizeof(WINMTR_HOMEPAGE)+1);
	
	r = RegCreateKeyEx(hKey,"Config",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey_v,NULL);
	if(r != ERROR_SUCCESS)
		return FALSE;
		
	if(RegQueryValueEx(hKey_v, "PingSize", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = pingsize;
		RegSetValueEx(hKey_v,"PingSize", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		if(!hasPingsizeFromCmdLine) pingsize = (WORD)tmp_dword;
	}
	
	if(RegQueryValueEx(hKey_v, "MaxLRU", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = maxLRU;
		RegSetValueEx(hKey_v,"MaxLRU", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		if(!hasMaxLRUFromCmdLine) maxLRU = tmp_dword;
	}
	
	if(RegQueryValueEx(hKey_v, "UseDNS", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = useDNS ? 1 : 0;
		RegSetValueEx(hKey_v,"UseDNS", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		if(!hasUseDNSFromCmdLine) useDNS = (BOOL)tmp_dword;
	}
	if(RegQueryValueEx(hKey_v, "UseIPv6", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = useIPv6;
		RegSetValueEx(hKey_v,"UseIPv6", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		if(!hasUseIPv6FromCmdLine) useIPv6 = (unsigned char)tmp_dword;
		if(useIPv6>2) useIPv6=1;
	}
	m_checkIPv6.SetCheck(useIPv6);
	
	if(RegQueryValueEx(hKey_v, "Interval", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = (DWORD)(interval * 1000);
		RegSetValueEx(hKey_v,"Interval", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		if(!hasIntervalFromCmdLine) interval = (float)tmp_dword / 1000.0;
	}
	
	r = RegCreateKeyEx(hKey,"LRU",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey_v,NULL);
	if(r != ERROR_SUCCESS)
		return FALSE;
	if(RegQueryValueEx(hKey_v, "NrLRU", 0, NULL, (unsigned char*)&tmp_dword, &value_size) != ERROR_SUCCESS) {
		tmp_dword = nrLRU;
		RegSetValueEx(hKey_v,"NrLRU", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	} else {
		char key_name[20];
		unsigned char str_host[255];
		nrLRU = tmp_dword;
		for(int i=0; i<maxLRU; i++) {
			sprintf(key_name,"Host%d", i+1);
			if(RegQueryValueEx(hKey_v, key_name, 0, NULL, NULL, &value_size) == ERROR_SUCCESS) {
				RegQueryValueEx(hKey_v, key_name, 0, NULL, str_host, &value_size);
				str_host[value_size]='\0';
				m_comboHost.AddString((CString)str_host);
			}
		}
	}
	m_comboHost.AddString(CString((LPCSTR)IDS_STRING_CLEAR_HISTORY));
	RegCloseKey(hKey_v);
	RegCloseKey(hKey);
	return TRUE;
}


//*****************************************************************************
// WinMTRDialog::OnSizing
//
//
//*****************************************************************************
void WinMTRDialog::OnSizing(UINT fwSide, LPRECT pRect)
{
	CDialog::OnSizing(fwSide, pRect);
	
	int iWidth = (pRect->right)-(pRect->left);
	int iHeight = (pRect->bottom)-(pRect->top);
	
	if(iWidth<638)
		pRect->right = pRect->left+638;
	if(iHeight<388)
		pRect->bottom = pRect->top+388;
}


//*****************************************************************************
// WinMTRDialog::OnSize
//
//
//*****************************************************************************
/// @todo (White-Tiger#1#): simplify it... use initial positions from "right" to calculate new position (no fix values here)
void WinMTRDialog::OnSize(UINT nType, int cx, int cy)
{
	CDialog::OnSize(nType, cx, cy);
	CRect rct,lb;
	if(!IsWindow(m_staticS.m_hWnd)) return;
	GetClientRect(&rct);
	m_staticS.GetWindowRect(&lb);
	ScreenToClient(&lb);
	m_staticS.SetWindowPos(NULL, lb.TopLeft().x, lb.TopLeft().y, rct.Width()-lb.TopLeft().x-8, lb.Height() , SWP_NOMOVE | SWP_NOZORDER);
	
	m_staticJ.GetWindowRect(&lb);
	ScreenToClient(&lb);
	m_staticJ.SetWindowPos(NULL, lb.TopLeft().x, lb.TopLeft().y, rct.Width() - 16, lb.Height(), SWP_NOMOVE | SWP_NOZORDER);
	
	m_buttonOptions.GetWindowRect(&lb);
	ScreenToClient(&lb);
	m_buttonOptions.SetWindowPos(NULL, rct.Width() - lb.Width()-52-16, lb.TopLeft().y, lb.Width(), lb.Height() , SWP_NOSIZE | SWP_NOZORDER);
	m_buttonExit.GetWindowRect(&lb);
	ScreenToClient(&lb);
	m_buttonExit.SetWindowPos(NULL, rct.Width() - lb.Width()-16, lb.TopLeft().y, lb.Width(), lb.Height() , SWP_NOSIZE | SWP_NOZORDER);
	
	m_buttonExpH.GetWindowRect(&lb);
	ScreenToClient(&lb);
	m_buttonExpH.SetWindowPos(NULL, rct.Width() - lb.Width()-16, lb.TopLeft().y, lb.Width(), lb.Height() , SWP_NOSIZE | SWP_NOZORDER);
	m_buttonExpT.GetWindowRect(&lb);
	ScreenToClient(&lb);
	m_buttonExpT.SetWindowPos(NULL, rct.Width() - lb.Width()- 103, lb.TopLeft().y, lb.Width(), lb.Height() , SWP_NOSIZE | SWP_NOZORDER);
	
	m_listMTR.GetWindowRect(&lb);
	ScreenToClient(&lb);
	m_listMTR.SetWindowPos(NULL, lb.TopLeft().x, lb.TopLeft().y, rct.Width() - 17, rct.Height() - lb.top - 25, SWP_NOMOVE | SWP_NOZORDER);
	
	RepositionBars(AFX_IDW_CONTROLBAR_FIRST, AFX_IDW_CONTROLBAR_LAST,
				   0, reposQuery, rct);
				   
	RepositionBars(AFX_IDW_CONTROLBAR_FIRST, AFX_IDW_CONTROLBAR_LAST, 0);
	
}


//*****************************************************************************
// WinMTRDialog::OnPaint
//
//
//*****************************************************************************
void WinMTRDialog::OnPaint()
{
	if(IsIconic()) {
		CPaintDC dc(this);
		
		SendMessage(WM_ICONERASEBKGND, (WPARAM) dc.GetSafeHdc(), 0);
		
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;
		
		dc.DrawIcon(x, y, m_hIcon);
	} else {
		CDialog::OnPaint();
	}
}


//*****************************************************************************
// WinMTRDialog::OnQueryDragIcon
//
//
//*****************************************************************************
HCURSOR WinMTRDialog::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}

HBRUSH WinMTRDialog::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH brush = WinMTRHandleCtlColor(pDC, pWnd, nCtlColor);
	if(brush) return brush;
	return CDialog::OnCtlColor(pDC, pWnd, nCtlColor);
}

void WinMTRDialog::OnSettingChange(UINT uFlags, LPCTSTR lpszSection)
{
	CDialog::OnSettingChange(uFlags, lpszSection);
	WinMTRRefreshTheme();
	WinMTRApplyThemeToWindow(this);
	WinMTRApplyThemeToChildren(this);
	WinMTRConfigureListCtrl(m_listMTR);
	Invalidate(TRUE);
}


//*****************************************************************************
// WinMTRDialog::OnDblclkList
//
//*****************************************************************************
void WinMTRDialog::OnDblclkList(NMHDR* /*pNMHDR*/, LRESULT* pResult)
{
	*pResult=0;
	if(state==TRACING || state==IDLE || state==STOPPING) {
	
		POSITION pos = m_listMTR.GetFirstSelectedItemPosition();
		if(pos!=NULL) {
			int nItem = m_listMTR.GetNextSelectedItem(pos);
			WinMTRProperties wmtrprop;
			
			union {sockaddr* addr; sockaddr_in* addr4; sockaddr_in6* addr6;};
			addr=wmtrnet->GetAddr(nItem);
			if(!(addr4->sin_family==AF_INET&&addr4->sin_addr.s_addr) && !(addr6->sin6_family==AF_INET6&&(addr6->sin6_addr.u.Word[0]|addr6->sin6_addr.u.Word[1]|addr6->sin6_addr.u.Word[2]|addr6->sin6_addr.u.Word[3]|addr6->sin6_addr.u.Word[4]|addr6->sin6_addr.u.Word[5]|addr6->sin6_addr.u.Word[6]|addr6->sin6_addr.u.Word[7]))) {
				strcpy(wmtrprop.host,"");
				strcpy(wmtrprop.ip,"");
				wmtrnet->GetName(nItem, wmtrprop.comment);
			} else {
				wmtrnet->GetName(nItem, wmtrprop.host);
				if(getnameinfo(addr,sizeof(sockaddr_in6),wmtrprop.ip,40,NULL,0,NI_NUMERICHOST)) {
					*wmtrprop.ip='\0';
				}
				strcpy(wmtrprop.comment, "Host alive.");
			}
			
			wmtrprop.ping_avrg = (float)wmtrnet->GetAvg(nItem);
			wmtrprop.ping_last = (float)wmtrnet->GetLast(nItem);
			wmtrprop.ping_best = (float)wmtrnet->GetBest(nItem);
			wmtrprop.ping_worst = (float)wmtrnet->GetWorst(nItem);
			
			wmtrprop.pck_loss = wmtrnet->GetPercent(nItem);
			wmtrprop.pck_recv = wmtrnet->GetReturned(nItem);
			wmtrprop.pck_sent = wmtrnet->GetXmit(nItem);
			
			wmtrprop.DoModal();
		}
	}
}



//*****************************************************************************
// WinMTRDialog::SetHostName
//
//*****************************************************************************
void WinMTRDialog::SetHostName(const char* host)
{
	m_autostart = 1;
	strncpy(msz_defaulthostname,host,1000);
}


//*****************************************************************************
// WinMTRDialog::SetPingSize
//
//*****************************************************************************
void WinMTRDialog::SetPingSize(WORD ps)
{
	pingsize = ps;
}

//*****************************************************************************
// WinMTRDialog::SetMaxLRU
//
//*****************************************************************************
void WinMTRDialog::SetMaxLRU(int mlru)
{
	maxLRU = mlru;
}


//*****************************************************************************
// WinMTRDialog::SetInterval
//
//*****************************************************************************
void WinMTRDialog::SetInterval(float i)
{
	interval = i;
}

//*****************************************************************************
// WinMTRDialog::SetUseDNS
//
//*****************************************************************************
void WinMTRDialog::SetUseDNS(BOOL udns)
{
	useDNS = udns;
}




//*****************************************************************************
// WinMTRDialog::OnRestart
//
//
//*****************************************************************************
void WinMTRDialog::OnRestart()
{
	// If clear history is selected, just clear the registry and listbox and return
	if(m_comboHost.GetCurSel() == m_comboHost.GetCount() - 1) {
		ClearHistory();
		return;
	}
	
	CString sHost;
	if(state == IDLE) {
		m_comboHost.GetWindowText(sHost);
		sHost.TrimLeft(); sHost.TrimRight();
		if(sHost.IsEmpty()) {
			AfxMessageBox("No host specified!");
			m_comboHost.SetFocus();
			return ;
		}
		m_listMTR.DeleteAllItems();
		
		HKEY hKey; DWORD tmp_dword;
		if(RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\WinMTR\\Config",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey,NULL)==ERROR_SUCCESS) {
			tmp_dword=m_checkIPv6.GetCheck();
			useIPv6=(unsigned char)tmp_dword;
			RegSetValueEx(hKey,"UseIPv6",0,REG_DWORD,(const unsigned char*)&tmp_dword,sizeof(DWORD));
			RegCloseKey(hKey);
		}
		if(InitMTRNet()) {
			if(m_comboHost.FindString(-1, sHost) == CB_ERR) {
				m_comboHost.InsertString(m_comboHost.GetCount() - 1,sHost);
				if(RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\WinMTR\\LRU",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey,NULL)==ERROR_SUCCESS) {
					char key_name[20];
					if(++nrLRU>maxLRU) nrLRU=0;
					sprintf(key_name, "Host%d", nrLRU);
					RegSetValueEx(hKey,key_name, 0, REG_SZ, (const unsigned char*)(LPCTSTR)sHost, (DWORD)strlen((LPCTSTR)sHost)+1);
					tmp_dword = nrLRU;
					RegSetValueEx(hKey,"NrLRU", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
					RegCloseKey(hKey);
				}
			}
			Transit(TRACING);
		}
	} else {
		Transit(STOPPING);
	}
}


//*****************************************************************************
// WinMTRDialog::OnOptions
//
//
//*****************************************************************************
void WinMTRDialog::OnOptions()
{
	WinMTROptions optDlg(interval,pingsize,maxLRU,useDNS);
	if(IDOK == optDlg.DoModal()) {
	
		pingsize = (WORD)optDlg.GetPingSize();
		interval = optDlg.GetInterval();
		maxLRU = optDlg.GetMaxLRU();
		useDNS = optDlg.GetUseDNS();
		
		HKEY hKey;
		DWORD tmp_dword;
		
		if(RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\WinMTR\\Config",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey,NULL)==ERROR_SUCCESS) {
			tmp_dword = pingsize;
			RegSetValueEx(hKey,"PingSize", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
			tmp_dword = maxLRU;
			RegSetValueEx(hKey,"MaxLRU", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
			tmp_dword = useDNS ? 1 : 0;
			RegSetValueEx(hKey,"UseDNS", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
			tmp_dword = (DWORD)(interval * 1000);
			RegSetValueEx(hKey,"Interval", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
			RegCloseKey(hKey);
		}
		if(maxLRU<nrLRU) {
			if(RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\WinMTR\\LRU",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey,NULL)==ERROR_SUCCESS) {
				char key_name[20];
				for(int i = maxLRU; i<=nrLRU; ++i) {
					sprintf(key_name, "Host%d", i);
					RegDeleteValue(hKey,key_name);
				}
				nrLRU = maxLRU;
				tmp_dword = nrLRU;
				RegSetValueEx(hKey,"NrLRU", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
				RegCloseKey(hKey);
			}
		}
	}
}


//*****************************************************************************
// WinMTRDialog::OnCTTC
//
//
//*****************************************************************************
void WinMTRDialog::OnCTTC()
{
	CString source(BuildTextReport().c_str());
	
	HGLOBAL clipbuffer;
	char* buffer;
	
	OpenClipboard();
	EmptyClipboard();
	
	clipbuffer = GlobalAlloc(GMEM_DDESHARE, source.GetLength()+1);
	buffer = (char*)GlobalLock(clipbuffer);
	strcpy(buffer, LPCSTR(source));
	GlobalUnlock(clipbuffer);
	
	SetClipboardData(CF_TEXT,clipbuffer);
	CloseClipboard();
}


//*****************************************************************************
// WinMTRDialog::OnCHTC
//
//
//*****************************************************************************
void WinMTRDialog::OnCHTC()
{
	CString source(BuildHtmlReport().c_str());
	
	HGLOBAL clipbuffer;
	char* buffer;
	
	OpenClipboard();
	EmptyClipboard();
	
	clipbuffer = GlobalAlloc(GMEM_DDESHARE, source.GetLength()+1);
	buffer = (char*)GlobalLock(clipbuffer);
	strcpy(buffer, LPCSTR(source));
	GlobalUnlock(clipbuffer);
	
	SetClipboardData(CF_TEXT,clipbuffer);
	CloseClipboard();
}


//*****************************************************************************
// WinMTRDialog::OnEXPT
//
//
//*****************************************************************************
void WinMTRDialog::OnEXPT()
{
	TCHAR BASED_CODE szFilter[] = _T("Text Files (*.txt)|*.txt|All Files (*.*)|*.*||");
	
	CFileDialog dlg(FALSE,
					_T("TXT"),
					NULL,
					OFN_HIDEREADONLY | OFN_EXPLORER,
					szFilter,
					this);
	if(dlg.DoModal() == IDOK) {
		std::string textReport = BuildTextReport();
		FILE* fp = fopen(dlg.GetPathName(), "wt");
		if(fp != NULL) {
			fprintf(fp, "%s", textReport.c_str());
			fclose(fp);
		}
	}
}


//*****************************************************************************
// WinMTRDialog::OnEXPH
//
//
//*****************************************************************************
void WinMTRDialog::OnEXPH()
{
	TCHAR BASED_CODE szFilter[] = _T("HTML Files (*.htm, *.html)|*.htm;*.html|All Files (*.*)|*.*||");
	
	CFileDialog dlg(FALSE,
					_T("HTML"),
					NULL,
					OFN_HIDEREADONLY | OFN_EXPLORER,
					szFilter,
					this);
					
	if(dlg.DoModal() == IDOK) {
		std::string htmlReport = BuildHtmlReport();
		FILE* fp = fopen(dlg.GetPathName(), "wt");
		if(fp != NULL) {
			fprintf(fp, "%s", htmlReport.c_str());
			fclose(fp);
		}
	}
	
	
}

std::string WinMTRDialog::BuildTextReport() const
{
	char buf[255];
	char asn[64];
	char line[1024];
	std::ostringstream report;
	int nh = wmtrnet->GetMax();

	report << "|--------------------------------------------------------------------------------------------------------------|\r\n";
	report << "|                                               WinMTR statistics                                              |\r\n";
	report << "|                          Host                           - ASN        - %  | Sent | Recv | Best | Avrg | Wrst | Last |\r\n";
	report << "|---------------------------------------------------------|------------|----|------|------|------|------|------|------|\r\n";

	for(int i = 0; i < nh; ++i) {
		wmtrnet->GetName(i, buf);
		if(strcmp(buf, "") == 0) strcpy(buf, "No response from host");
		wmtrnet->GetASN(i, asn);
		if(strcmp(asn, "") == 0) strcpy(asn, "-");

		sprintf(line, "|%57.57s | %-10.10s | %2d | %4d | %4d | %4d | %4d | %4d | %4d |\r\n",
			buf,
			asn,
			wmtrnet->GetPercent(i),
			wmtrnet->GetXmit(i),
			wmtrnet->GetReturned(i),
			wmtrnet->GetBest(i),
			wmtrnet->GetAvg(i),
			wmtrnet->GetWorst(i),
			wmtrnet->GetLast(i));
		report << line;
	}

	report << "|_________________________________________________________|____________|____|______|______|______|______|______|______|\r\n";
	CString cs_tmp((LPCSTR)IDS_STRING_SB_NAME);
	report << "   " << (LPCTSTR)cs_tmp;
	return report.str();
}

std::string WinMTRDialog::BuildHtmlReport() const
{
	char buf[255];
	char asn[64];
	std::ostringstream report;
	int nh = wmtrnet->GetMax();

	report << "<html><head><title>WinMTR Statistics</title></head><body bgcolor=\"white\">\r\n";
	report << "<center><h2>WinMTR statistics</h2></center>\r\n";
	report << "<p align=\"center\"> <table border=\"1\" align=\"center\">\r\n";
	report << "<tr><td>Host</td><td>ASN</td><td>%</td><td>Sent</td><td>Recv</td><td>Best</td><td>Avrg</td><td>Wrst</td><td>Last</td></tr>\r\n";

	for(int i = 0; i < nh; ++i) {
		wmtrnet->GetName(i, buf);
		if(strcmp(buf, "") == 0) strcpy(buf, "No response from host");
		wmtrnet->GetASN(i, asn);
		if(strcmp(asn, "") == 0) strcpy(asn, "-");

		report << "<tr><td>" << HtmlEscape(buf) << "</td><td>" << HtmlEscape(asn) << "</td><td>"
			   << wmtrnet->GetPercent(i) << "</td><td>"
			   << wmtrnet->GetXmit(i) << "</td><td>"
			   << wmtrnet->GetReturned(i) << "</td><td>"
			   << wmtrnet->GetBest(i) << "</td><td>"
			   << wmtrnet->GetAvg(i) << "</td><td>"
			   << wmtrnet->GetWorst(i) << "</td><td>"
			   << wmtrnet->GetLast(i) << "</td></tr>\r\n";
	}

	report << "</table></body></html>\r\n";
	return report.str();
}


//*****************************************************************************
// WinMTRDialog::WinMTRDialog
//
//
//*****************************************************************************
void WinMTRDialog::OnCancel()
{
}


//*****************************************************************************
// WinMTRDialog::DisplayRedraw
//
//
//*****************************************************************************
int WinMTRDialog::DisplayRedraw()
{
	char buf[255], nr_crt[255];
	int nh = wmtrnet->GetMax();
	while(m_listMTR.GetItemCount() > nh) m_listMTR.DeleteItem(m_listMTR.GetItemCount() - 1);
	
	for(int i=0; i <nh ; ++i) {
	
		wmtrnet->GetName(i, buf);
		if(!*buf) strcpy(buf,"No response from host");
		
		sprintf(nr_crt, "%d", i+1);
		if(m_listMTR.GetItemCount() <= i)
			m_listMTR.InsertItem(i, buf);
		else
			m_listMTR.SetItem(i, 0, LVIF_TEXT, buf, 0, 0, 0, 0);
			
		m_listMTR.SetItem(i, 1, LVIF_TEXT, nr_crt, 0, 0, 0, 0);
		
		sprintf(buf, "%d", wmtrnet->GetPercent(i));
		m_listMTR.SetItem(i, 2, LVIF_TEXT, buf, 0, 0, 0, 0);
		
		sprintf(buf, "%d", wmtrnet->GetXmit(i));
		m_listMTR.SetItem(i, 3, LVIF_TEXT, buf, 0, 0, 0, 0);
		
		sprintf(buf, "%d", wmtrnet->GetReturned(i));
		m_listMTR.SetItem(i, 4, LVIF_TEXT, buf, 0, 0, 0, 0);
		
		sprintf(buf, "%d", wmtrnet->GetBest(i));
		m_listMTR.SetItem(i, 5, LVIF_TEXT, buf, 0, 0, 0, 0);
		
		sprintf(buf, "%d", wmtrnet->GetAvg(i));
		m_listMTR.SetItem(i, 6, LVIF_TEXT, buf, 0, 0, 0, 0);
		
		sprintf(buf, "%d", wmtrnet->GetWorst(i));
		m_listMTR.SetItem(i, 7, LVIF_TEXT, buf, 0, 0, 0, 0);
		
		sprintf(buf, "%d", wmtrnet->GetLast(i));
		m_listMTR.SetItem(i, 8, LVIF_TEXT, buf, 0, 0, 0, 0);
		
		
	}
	
	return 0;
}


//*****************************************************************************
// WinMTRDialog::InitMTRNet
//
//
//*****************************************************************************
int WinMTRDialog::InitMTRNet()
{
	char hostname[255];
	char buf[255];
	m_comboHost.GetWindowText(hostname, 255);
	
	sprintf(buf, "Resolving host %s...", hostname);
	statusBar.SetPaneText(0,buf);
	
	addrinfo* anfo = NULL;
	if(!ResolveTarget(hostname, &anfo, false)) {
		statusBar.SetPaneText(0, CString((LPCSTR)IDS_STRING_SB_NAME));
		AfxMessageBox("Unable to resolve hostname.");
		return 0;
	}
	freeaddrinfo(anfo);
	return 1;
}

int WinMTRDialog::ResolveTarget(const char* hostname, addrinfo** result, bool showErrors)
{
	if(result) *result = NULL;
	addrinfo nfofilter = {0};
	if(wmtrnet->hasIPv6) {
		switch(useIPv6) {
		case 0:
			nfofilter.ai_family = AF_INET; break;
		case 1:
			nfofilter.ai_family = AF_INET6; break;
		default:
			nfofilter.ai_family = AF_UNSPEC;
		}
	}
	nfofilter.ai_socktype = SOCK_RAW;
	nfofilter.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;
	if(getaddrinfo(hostname, NULL, &nfofilter, result) || !result || !*result) {
		if(showErrors) {
			AfxMessageBox("Unable to resolve hostname.");
		}
		return 0;
	}
	return 1;
}

int WinMTRDialog::RunCliTrace(const char* hostname, int cycles, int durationSeconds)
{
	addrinfo* anfo = NULL;
	if(!ResolveTarget(hostname, &anfo, false)) {
		std::string message = "Unable to resolve hostname: ";
		message += hostname;
		message += "\n";
		WriteCliOutput(message.c_str());
		return 0;
	}

	cli_trace_thread* trace = new cli_trace_thread;
	trace->dialog = this;
	trace->addressLength = GetSockaddrLength(anfo->ai_addr);
	memset(&trace->address, 0, sizeof(trace->address));
	memcpy(&trace->address, anfo->ai_addr, trace->addressLength);
	freeaddrinfo(anfo);

	DWORD waitTime = 0;
	if(durationSeconds > 0) {
		waitTime = durationSeconds * 1000;
	} else if(cycles > 0) {
		waitTime = (DWORD)(cycles * interval * 1000.0f);
	}
	if(waitTime == 0) waitTime = (DWORD)(10 * interval * 1000.0f);

	HANDLE worker = (HANDLE)_beginthreadex(NULL, 0, CliTraceThread, trace, 0, NULL);
	if(!worker) {
		delete trace;
		WriteCliOutput("Unable to start trace worker.\n");
		return 0;
	}

	LONG previousStopState = InterlockedExchange(&g_cliStopRequested, 0);
	SetConsoleCtrlHandler(CliConsoleHandler, TRUE);
	BeginCliScreenSession();

	DWORD startTick = GetTickCount();
	int lastRenderedCycle = -1;
	bool running = true;
	while(running) {
		for(int waited = 0; waited < 10 && running; ++waited) {
			Sleep(100);
			if(PollCliStopRequest()) {
				running = false;
			}
		}
		int currentCycle = wmtrnet->GetXmit(0);
		DWORD elapsedMs = GetTickCount() - startTick;

		std::string screen = BuildCliScreen(this, hostname, cycles, durationSeconds, elapsedMs);
		ClearCliScreen();
		WriteCliOutput(screen.c_str());

		if(PollCliStopRequest()) {
			running = false;
		} else if(durationSeconds > 0 && elapsedMs >= (DWORD)(durationSeconds * 1000)) {
			running = false;
		} else if(cycles > 0 && currentCycle >= cycles && currentCycle != lastRenderedCycle) {
			running = false;
		}
		lastRenderedCycle = currentCycle;
	}

	wmtrnet->StopTrace();
	WaitForSingleObject(worker, INFINITE);
	CloseHandle(worker);
	EndCliScreenSession();
	SetConsoleCtrlHandler(CliConsoleHandler, FALSE);
	InterlockedExchange(&g_cliStopRequested, previousStopState);

	WriteCliOutput("\r\n");
	return 1;
}


//*****************************************************************************
// PingThread
//
//
//*****************************************************************************
void PingThread(void* p)
{
	WinMTRDialog* wmtrdlg = (WinMTRDialog*)p;
	WaitForSingleObject(wmtrdlg->traceThreadMutex, INFINITE);
	
	char hostname[255];
	wmtrdlg->m_comboHost.GetWindowText(hostname, 255);
	
	addrinfo* anfo = NULL;
	if(!wmtrdlg->ResolveTarget(hostname, &anfo, false)) { //we use first address returned
		AfxMessageBox("Unable to resolve hostname. (again)");
		ReleaseMutex(wmtrdlg->traceThreadMutex);
		return;
	}
	wmtrdlg->wmtrnet->DoTrace(anfo->ai_addr);
	freeaddrinfo(anfo);
	ReleaseMutex(wmtrdlg->traceThreadMutex);
}

unsigned WINAPI CliTraceThread(void* p)
{
	cli_trace_thread* trace = (cli_trace_thread*)p;
	WaitForSingleObject(trace->dialog->traceThreadMutex, INFINITE);
	trace->dialog->wmtrnet->DoTrace((sockaddr*)&trace->address);
	ReleaseMutex(trace->dialog->traceThreadMutex);
	delete trace;
	return 0;
}



void WinMTRDialog::OnCbnSelchangeComboHost()
{
}

void WinMTRDialog::ClearHistory()
{
	HKEY hKey;
	DWORD tmp_dword;
	char key_name[20];
	
	if(RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\WinMTR\\LRU",0,NULL,0,KEY_ALL_ACCESS,NULL,&hKey,NULL)!=ERROR_SUCCESS) {
		return;
	}
	
	for(int i = 0; i<=nrLRU; i++) {
		sprintf(key_name, "Host%d", i);
		RegDeleteValue(hKey,key_name);
	}
	nrLRU = 0;
	tmp_dword = nrLRU;
	RegSetValueEx(hKey,"NrLRU", 0, REG_DWORD, (const unsigned char*)&tmp_dword, sizeof(DWORD));
	RegCloseKey(hKey);
	
	m_comboHost.Clear();
	m_comboHost.ResetContent();
	m_comboHost.AddString(CString((LPCSTR)IDS_STRING_CLEAR_HISTORY));
}

void WinMTRDialog::OnCbnSelendokComboHost()
{
}

void WinMTRDialog::OnCbnCloseupComboHost()
{
	if(m_comboHost.GetCurSel() == m_comboHost.GetCount() - 1) {
		ClearHistory();
	}
}

void WinMTRDialog::Transit(STATES new_state)
{
	switch(new_state) {
	case IDLE:
		switch(state) {
		case STOPPING:
			transition = STOPPING_TO_IDLE;
			break;
		case IDLE:
			transition = IDLE_TO_IDLE;
			break;
		default:
			TRACE_MSG("Received state IDLE after " << state);
			return;
		}
		state = IDLE;
		break;
	case TRACING:
		switch(state) {
		case IDLE:
			transition = IDLE_TO_TRACING;
			break;
		case TRACING:
			transition = TRACING_TO_TRACING;
			break;
		default:
			TRACE_MSG("Received state TRACING after " << state);
			return;
		}
		state = TRACING;
		break;
	case STOPPING:
		switch(state) {
		case STOPPING:
			transition = STOPPING_TO_STOPPING;
			break;
		case TRACING:
			transition = TRACING_TO_STOPPING;
			break;
		default:
			TRACE_MSG("Received state STOPPING after " << state);
			return;
		}
		state = STOPPING;
		break;
	case EXIT:
		switch(state) {
		case IDLE:
			transition = IDLE_TO_EXIT;
			break;
		case STOPPING:
			transition = STOPPING_TO_EXIT;
			break;
		case TRACING:
			transition = TRACING_TO_EXIT;
			break;
		case EXIT:
			break;
		default:
			TRACE_MSG("Received state EXIT after " << state);
			return;
		}
		state = EXIT;
		break;
	default:
		TRACE_MSG("Received state " << state);
	}
	
	// modify controls according to new state
	switch(transition) {
	case IDLE_TO_IDLE:
		// nothing to be done
		break;
	case IDLE_TO_TRACING:
		m_buttonStart.EnableWindow(FALSE);
		m_buttonStart.SetWindowText("Stop");
		m_comboHost.EnableWindow(FALSE);
		m_checkIPv6.EnableWindow(FALSE);
		m_buttonOptions.EnableWindow(FALSE);
		statusBar.SetPaneText(0, "Double click on host name for more information.");
		_beginthread(PingThread, 0 , this);
		m_buttonStart.EnableWindow(TRUE);
		break;
	case IDLE_TO_EXIT:
		m_buttonStart.EnableWindow(FALSE);
		m_comboHost.EnableWindow(FALSE);
		m_buttonOptions.EnableWindow(FALSE);
		break;
	case STOPPING_TO_IDLE:
		DisplayRedraw();
		m_buttonStart.EnableWindow(TRUE);
		statusBar.SetPaneText(0, CString((LPCSTR)IDS_STRING_SB_NAME));
		m_buttonStart.SetWindowText("Start");
		m_comboHost.EnableWindow(TRUE);
		m_checkIPv6.EnableWindow(TRUE);
		m_buttonOptions.EnableWindow(TRUE);
		m_comboHost.SetFocus();
		break;
	case STOPPING_TO_STOPPING:
		DisplayRedraw();
		break;
	case STOPPING_TO_EXIT:
		break;
	case TRACING_TO_TRACING:
		DisplayRedraw();
		break;
	case TRACING_TO_STOPPING:
		m_buttonStart.EnableWindow(FALSE);
		wmtrnet->StopTrace();
		statusBar.SetPaneText(0, "Waiting for last packets in order to stop trace ...");
		DisplayRedraw();
		break;
	case TRACING_TO_EXIT:
		m_buttonStart.EnableWindow(FALSE);
		wmtrnet->StopTrace();
		statusBar.SetPaneText(0, "Waiting for last packets in order to stop trace ...");
		break;
	default:
		TRACE_MSG("Unknown transition " << transition);
	}
}


void WinMTRDialog::OnTimer(UINT_PTR nIDEvent)
{
	static unsigned int call_count=0;
	if(state == EXIT && WaitForSingleObject(traceThreadMutex, 0) == WAIT_OBJECT_0) {
		ReleaseMutex(traceThreadMutex);
		OnOK();
	}
	
	if(WaitForSingleObject(traceThreadMutex, 0) == WAIT_OBJECT_0) {
		ReleaseMutex(traceThreadMutex);
		Transit(IDLE);
	} else if((++call_count&5)==5) {
		if(state==TRACING) Transit(TRACING);
		else if(state==STOPPING) Transit(STOPPING);
	}
	
	CDialog::OnTimer(nIDEvent);
}


void WinMTRDialog::OnClose()
{
	Transit(EXIT);
}


void WinMTRDialog::OnBnClickedCancel()
{
	Transit(EXIT);
}
