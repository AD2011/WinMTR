//*****************************************************************************
// FILE:            WinMTRMain.h
//
//
// DESCRIPTION:
//
//
// NOTES:
//
//
//*****************************************************************************

#ifndef WINMTRMAIN_H_
#define WINMTRMAIN_H_

#include "WinMTRDialog.h"
#include <string>

struct WinMTRCommandLineOptions {
	WinMTRCommandLineOptions()
		: showHelp(false),
		  cliMode(false),
		  forceGui(false),
		  wantsSctp(false),
		  reportCycles(0),
		  reportDurationSeconds(0)
	{
	}

	bool showHelp;
	bool cliMode;
	bool forceGui;
	bool wantsSctp;
	int reportCycles;
	int reportDurationSeconds;
	std::string hostName;
};


//*****************************************************************************
// CLASS:  WinMTRMain
//
//
//*****************************************************************************

class WinMTRMain : public CWinApp
{
public:
	WinMTRMain();
	
	virtual BOOL InitInstance();
	
	DECLARE_MESSAGE_MAP()
	
private:
	bool	ParseCommandLineParams(LPTSTR cmd, WinMTRDialog* wmtrdlg, WinMTRCommandLineOptions& options);
	bool	RunCliMode(const WinMTRCommandLineOptions& options, WinMTRDialog* wmtrdlg);
	void	HideOwnedConsoleWindow() const;
	bool	SetupConsole() const;
	bool	IsProcessElevated() const;
	void	WriteConsoleText(const char* text) const;
	void	PrintHelp() const;
	int		GetParamValue(LPTSTR cmd, char* param, char sparam, char* value);
	int		GetHostNameParamValue(LPTSTR cmd, std::string& value);
	
};

#endif // ifndef WINMTRMAIN_H_

