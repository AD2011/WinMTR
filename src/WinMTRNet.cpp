//*****************************************************************************
// FILE:            WinMTRNet.cpp
//
//*****************************************************************************
#include "WinMTRGlobal.h"
#include "WinMTRNet.h"
#include "WinMTRDialog.h"
#include <iostream>
#include <string>
#include <sstream>
#include <windns.h>

#pragma comment(lib, "Dnsapi.lib")

#ifndef DNS_TYPE_TEXT
#define DNS_TYPE_TEXT 0x0010
#endif

#ifdef _DEBUG
#	define TRACE_MSG(msg)										\
	{															\
		std::ostringstream dbg_msg(std::ostringstream::out);	\
		dbg_msg << msg << std::endl;							\
		OutputDebugString(dbg_msg.str().c_str());				\
	}
#else
#	define TRACE_MSG(msg)
#endif

#define IPFLAG_DONT_FRAGMENT	0x02
#define MAX_HOPS				30

struct trace_thread {
	WinMTRNet*	winmtr;
	in_addr		address;
	int			ttl;
};
struct trace_thread6 {
	WinMTRNet*		winmtr;
	sockaddr_in6	address;
	int				ttl;
};

struct dns_resolver_thread {
	WinMTRNet*	winmtr;
	int			index;
};

static int GetSockaddrLength(const sockaddr* addr)
{
	if(!addr) return 0;
	return addr->sa_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
}

static void InterruptibleTraceSleep(WinMTRNet* winmtr, DWORD milliseconds)
{
	const DWORD sliceMs = 25;
	DWORD slept = 0;
	while(winmtr->tracing && slept < milliseconds) {
		DWORD remaining = milliseconds - slept;
		DWORD currentSlice = remaining < sliceMs ? remaining : sliceMs;
		Sleep(currentSlice);
		slept += currentSlice;
	}
}

static std::string TrimCopy(const std::string& value)
{
	size_t start = value.find_first_not_of(" \t\r\n");
	if(start == std::string::npos) return "";
	size_t end = value.find_last_not_of(" \t\r\n");
	return value.substr(start, end - start + 1);
}

static bool BuildAsnLookupQuery(const sockaddr* addr, std::string& query)
{
	if(!addr) return false;
	query.clear();
	if(addr->sa_family == AF_INET) {
		const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&reinterpret_cast<const sockaddr_in*>(addr)->sin_addr);
		char buffer[64];
		sprintf(buffer, "%u.%u.%u.%u.origin.asn.cymru.com", bytes[3], bytes[2], bytes[1], bytes[0]);
		query = buffer;
		return true;
	}
	if(addr->sa_family == AF_INET6) {
		const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&reinterpret_cast<const sockaddr_in6*>(addr)->sin6_addr);
		query.reserve(32 * 2 + strlen("origin6.asn.cymru.com"));
		static const char* hex = "0123456789abcdef";
		for(int i = 15; i >= 0; --i) {
			query.push_back(hex[bytes[i] & 0x0F]);
			query.push_back('.');
			query.push_back(hex[(bytes[i] >> 4) & 0x0F]);
			query.push_back('.');
		}
		query += "origin6.asn.cymru.com";
		return true;
	}
	return false;
}

static bool LookupAsn(const sockaddr* addr, std::string& asn)
{
	std::string query;
	if(!BuildAsnLookupQuery(addr, query)) return false;
	PDNS_RECORD records = NULL;
	DNS_STATUS status = DnsQuery_A(query.c_str(), DNS_TYPE_TEXT, DNS_QUERY_STANDARD, NULL, &records, NULL);
	if(status != ERROR_SUCCESS || !records) {
		if(records) DnsRecordListFree(records, DnsFreeRecordList);
		return false;
	}

	bool found = false;
	for(PDNS_RECORD record = records; record; record = record->pNext) {
		if(record->wType != DNS_TYPE_TEXT || record->Data.TXT.dwStringCount == 0) continue;
		std::string text;
		for(DWORD i = 0; i < record->Data.TXT.dwStringCount; ++i) {
			if(record->Data.TXT.pStringArray[i]) text += record->Data.TXT.pStringArray[i];
		}
		size_t pipePos = text.find('|');
		std::string field = TrimCopy(pipePos == std::string::npos ? text : text.substr(0, pipePos));
		if(field.empty() || field == "NA") continue;
		asn = "AS";
		asn += field;
		found = true;
		break;
	}

	DnsRecordListFree(records, DnsFreeRecordList);
	return found;
}

unsigned WINAPI TraceThread(void* p);
unsigned WINAPI TraceThread6(void* p);
void DnsResolverThread(void* p);
static unsigned WINAPI IcmpListenerThread(void* p);
static unsigned WINAPI TcpProbeThread(void* p);
static unsigned WINAPI UdpProbeThread(void* p);

// ---------------------------------------------------------------------------
// TCP/UDP probe engine (PARITY_PLAN.md P1). IPv4 only for now.
//
// Windows cannot send raw TCP (blocked since XP SP2), so TCP SYN probes are
// real non-blocking connect() calls on sockets with IP_TTL set - the OS emits
// the SYN with our TTL. UDP probes are plain sendto on TTL-limited sockets.
// Intermediate hops answer with ICMP TTL-exceeded, captured on one shared raw
// ICMP socket (requires Administrator - non-elevated raw sockets bind but are
// silently starved of traffic) and matched back to the probe by the source
// port embedded in the ICMP error payload. Final hop: TCP - connect completes
// (SYN-ACK) or is refused (RST); UDP - ICMP port-unreachable from the target.
//
// File-scope state: the app has exactly one WinMTRNet instance and one trace
// at a time (traceThreadMutex serializes GUI restarts).
// ---------------------------------------------------------------------------

struct pending_probe {
	USHORT			srcPort;	// host order; 0 = slot free
	LARGE_INTEGER	sendTime;
	HANDLE			event;		// manual-reset, signaled by the listener
	u_long			gateway;	// responder address (network order)
	int				rttMs;
	int				icmpType;
	int				icmpCode;
};

static pending_probe		g_probeTable[MAX_HOPS];
static CRITICAL_SECTION		g_probeLock;
static bool					g_probeLockInit = false;
static SOCKET				g_rawIcmpSocket = INVALID_SOCKET;
static in_addr				g_probeSrcAddr;
static in_addr				g_probeDstAddr;

static int ElapsedMs(const LARGE_INTEGER& since)
{
	LARGE_INTEGER now, freq;
	QueryPerformanceCounter(&now);
	QueryPerformanceFrequency(&freq);
	return (int)((now.QuadPart - since.QuadPart) * 1000 / freq.QuadPart);
}

static unsigned WINAPI IcmpListenerThread(void* p)
{
	WinMTRNet* wmtrnet = (WinMTRNet*)p;
	unsigned char buf[2048];

	while(wmtrnet->tracing) {
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(g_rawIcmpSocket, &readfds);
		timeval tv = {0, 200000};	// 200ms slices so StopTrace is honored
		int sel = select(0, &readfds, NULL, NULL, &tv);
		if(sel == SOCKET_ERROR) break;		// socket closed under us
		if(sel == 0) continue;

		int n = recv(g_rawIcmpSocket, (char*)buf, sizeof(buf), 0);
		if(n == SOCKET_ERROR || n <= 0) break;

		// buf: outer IPv4 header | ICMP header | inner IPv4 header | first 8
		// bytes of the original transport header (enough for the ports).
		if(n < 20) continue;
		int outerIhl = (buf[0] & 0x0F) * 4;
		if(n < outerIhl + 8 + 20 + 4) continue;
		unsigned char type = buf[outerIhl];
		unsigned char code = buf[outerIhl + 1];
		if(type != 11 && type != 3) continue;	// TTL exceeded / unreachable

		int inner = outerIhl + 8;
		int innerIhl = (buf[inner] & 0x0F) * 4;
		if(n < inner + innerIhl + 4) continue;
		unsigned char innerProto = buf[inner + 9];
		if(innerProto != IPPROTO_TCP && innerProto != IPPROTO_UDP) continue;

		// Only errors about probes aimed at our current target.
		u_long innerDst;
		memcpy(&innerDst, buf + inner + 16, 4);
		if(innerDst != g_probeDstAddr.s_addr) continue;

		USHORT sport = (USHORT)((buf[inner + innerIhl] << 8) | buf[inner + innerIhl + 1]);
		u_long gateway;
		memcpy(&gateway, buf + 12, 4);	// outer source = the responding hop

		EnterCriticalSection(&g_probeLock);
		for(int i = 0; i < MAX_HOPS; ++i) {
			if(g_probeTable[i].srcPort == sport) {
				g_probeTable[i].gateway = gateway;
				g_probeTable[i].icmpType = type;
				g_probeTable[i].icmpCode = code;
				g_probeTable[i].rttMs = ElapsedMs(g_probeTable[i].sendTime);
				g_probeTable[i].srcPort = 0;	// claimed
				SetEvent(g_probeTable[i].event);
				break;
			}
		}
		LeaveCriticalSection(&g_probeLock);
	}
	return 0;
}

// Registers the probe in the table (before the packet leaves, so a fast
// reply cannot race the registration).
static void RegisterProbe(int hop, USHORT srcPortHostOrder)
{
	EnterCriticalSection(&g_probeLock);
	ResetEvent(g_probeTable[hop].event);
	QueryPerformanceCounter(&g_probeTable[hop].sendTime);
	g_probeTable[hop].gateway = 0;
	g_probeTable[hop].rttMs = 0;
	g_probeTable[hop].icmpType = 0;
	g_probeTable[hop].icmpCode = 0;
	g_probeTable[hop].srcPort = srcPortHostOrder;
	LeaveCriticalSection(&g_probeLock);
}

static void UnregisterProbe(int hop)
{
	EnterCriticalSection(&g_probeLock);
	g_probeTable[hop].srcPort = 0;
	LeaveCriticalSection(&g_probeLock);
}

// Map an ICMP destination-unreachable code to the IP_* status naming used by
// SetErrorName.
static DWORD UnreachableCodeToIpStatus(int code)
{
	switch(code) {
	case 0:  return IP_DEST_NET_UNREACHABLE;
	case 1:  return IP_DEST_HOST_UNREACHABLE;
	case 2:  return IP_DEST_PROT_UNREACHABLE;
	case 3:  return IP_DEST_PORT_UNREACHABLE;
	default: return IP_DEST_HOST_UNREACHABLE;
	}
}

static void PaceProbe(WinMTRNet* wmtrnet, DWORD probeStartTick)
{
	DWORD intervalMs = (DWORD)(wmtrnet->wmtrdlg->interval * 1000);
	DWORD spent = GetTickCount() - probeStartTick;
	if(spent < intervalMs) {
		InterruptibleTraceSleep(wmtrnet, intervalMs - spent);
	}
}

static unsigned WINAPI TcpProbeThread(void* p)
{
	trace_thread* current = (trace_thread*)p;
	WinMTRNet* wmtrnet = current->winmtr;
	const int hop = current->ttl - 1;
	const USHORT port = (USHORT)(wmtrnet->wmtrdlg->targetPort > 0 ? wmtrnet->wmtrdlg->targetPort : 80);

	while(wmtrnet->tracing) {
		if(current->ttl > wmtrnet->GetMax()) break;
		DWORD probeStartTick = GetTickCount();

		SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if(s == INVALID_SOCKET) break;
		int ttl = current->ttl;
		setsockopt(s, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl));

		sockaddr_in local;
		memset(&local, 0, sizeof(local));
		local.sin_family = AF_INET;
		local.sin_addr = g_probeSrcAddr;
		bind(s, (sockaddr*)&local, sizeof(local));
		sockaddr_in bound;
		int boundLen = sizeof(bound);
		getsockname(s, (sockaddr*)&bound, &boundLen);

		u_long nonBlocking = 1;
		ioctlsocket(s, FIONBIO, &nonBlocking);

		RegisterProbe(hop, ntohs(bound.sin_port));

		sockaddr_in dst;
		memset(&dst, 0, sizeof(dst));
		dst.sin_family = AF_INET;
		dst.sin_addr = current->address;
		dst.sin_port = htons(port);
		connect(s, (sockaddr*)&dst, sizeof(dst));	// WSAEWOULDBLOCK expected
		wmtrnet->AddXmit(hop);

		bool resolved = false;
		DWORD waited = 0;
		const DWORD sliceMs = 25;
		while(waited < ECHO_REPLY_TIMEOUT && wmtrnet->tracing && !resolved) {
			// Intermediate hop / unreachable reported by the ICMP listener?
			if(WaitForSingleObject(g_probeTable[hop].event, 0) == WAIT_OBJECT_0) {
				wmtrnet->UpdateRTT(hop, g_probeTable[hop].rttMs);
				wmtrnet->AddReturned(hop);
				wmtrnet->SetAddr(hop, g_probeTable[hop].gateway);
				if(g_probeTable[hop].icmpType == 3) {
					wmtrnet->SetErrorName(hop, UnreachableCodeToIpStatus(g_probeTable[hop].icmpCode));
				}
				resolved = true;
				break;
			}
			// Destination answered the SYN itself? (SYN-ACK = connect
			// completes; RST = WSAECONNREFUSED). Either way: target reached.
			fd_set writefds, exceptfds;
			FD_ZERO(&writefds);
			FD_ZERO(&exceptfds);
			FD_SET(s, &writefds);
			FD_SET(s, &exceptfds);
			timeval tv = {0, 0};
			if(select(0, NULL, &writefds, &exceptfds, &tv) > 0) {
				int rtt = ElapsedMs(g_probeTable[hop].sendTime);
				if(FD_ISSET(s, &writefds)) {
					wmtrnet->UpdateRTT(hop, rtt);
					wmtrnet->AddReturned(hop);
					wmtrnet->SetAddr(hop, current->address.s_addr);
				} else {
					int soErr = 0;
					int soLen = sizeof(soErr);
					getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&soErr, &soLen);
					if(soErr == WSAECONNREFUSED) {
						wmtrnet->UpdateRTT(hop, rtt);
						wmtrnet->AddReturned(hop);
						wmtrnet->SetAddr(hop, current->address.s_addr);
					} else {
						wmtrnet->SetErrorName(hop, IP_DEST_HOST_UNREACHABLE);
					}
				}
				resolved = true;
				break;
			}
			Sleep(sliceMs);
			waited += sliceMs;
		}

		UnregisterProbe(hop);
		closesocket(s);	// aborts the half-open connect
		if(!resolved && wmtrnet->tracing) {
			wmtrnet->SetErrorName(hop, IP_REQ_TIMED_OUT);
		}
		PaceProbe(wmtrnet, probeStartTick);
	}
	delete current;
	return 0;
}

static unsigned WINAPI UdpProbeThread(void* p)
{
	trace_thread* current = (trace_thread*)p;
	WinMTRNet* wmtrnet = current->winmtr;
	const int hop = current->ttl - 1;
	// Classic traceroute port unless -P was given: high and almost certainly
	// closed on the target, so the final hop answers port-unreachable.
	const USHORT port = (USHORT)(wmtrnet->wmtrdlg->targetPort > 0 ? wmtrnet->wmtrdlg->targetPort : 33434);

	char payload[8192];
	WORD payloadLen = wmtrnet->wmtrdlg->pingsize;
	if(payloadLen > sizeof(payload)) payloadLen = sizeof(payload);
	memset(payload, 32, payloadLen);

	while(wmtrnet->tracing) {
		if(current->ttl > wmtrnet->GetMax()) break;
		DWORD probeStartTick = GetTickCount();

		SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if(s == INVALID_SOCKET) break;
		int ttl = current->ttl;
		setsockopt(s, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl));

		sockaddr_in local;
		memset(&local, 0, sizeof(local));
		local.sin_family = AF_INET;
		local.sin_addr = g_probeSrcAddr;
		bind(s, (sockaddr*)&local, sizeof(local));
		sockaddr_in bound;
		int boundLen = sizeof(bound);
		getsockname(s, (sockaddr*)&bound, &boundLen);

		RegisterProbe(hop, ntohs(bound.sin_port));

		sockaddr_in dst;
		memset(&dst, 0, sizeof(dst));
		dst.sin_family = AF_INET;
		dst.sin_addr = current->address;
		dst.sin_port = htons(port);
		sendto(s, payload, payloadLen, 0, (sockaddr*)&dst, sizeof(dst));
		wmtrnet->AddXmit(hop);

		bool resolved = false;
		DWORD waited = 0;
		const DWORD sliceMs = 25;
		while(waited < ECHO_REPLY_TIMEOUT && wmtrnet->tracing && !resolved) {
			if(WaitForSingleObject(g_probeTable[hop].event, sliceMs) == WAIT_OBJECT_0) {
				wmtrnet->UpdateRTT(hop, g_probeTable[hop].rttMs);
				wmtrnet->AddReturned(hop);
				wmtrnet->SetAddr(hop, g_probeTable[hop].gateway);
				if(g_probeTable[hop].icmpType == 3 && g_probeTable[hop].icmpCode != 3) {
					// Port-unreachable from the target is the expected
					// "destination reached" signal; other codes are errors.
					wmtrnet->SetErrorName(hop, UnreachableCodeToIpStatus(g_probeTable[hop].icmpCode));
				}
				resolved = true;
				break;
			}
			waited += sliceMs;
		}

		UnregisterProbe(hop);
		closesocket(s);
		if(!resolved && wmtrnet->tracing) {
			wmtrnet->SetErrorName(hop, IP_REQ_TIMED_OUT);
		}
		PaceProbe(wmtrnet, probeStartTick);
	}
	delete current;
	return 0;
}

void WinMTRNet::DoTraceSocket(sockaddr* sockaddrTarget)
{
	// IPv4 TCP/UDP trace. Caller (RunCliMode) guarantees elevation and IPv4.
	tracing = true;
	ResetHops();
	host[0].addr.sin_family = AF_INET;
	last_remote_addr = ((sockaddr_in*)sockaddrTarget)->sin_addr;
	g_probeDstAddr = last_remote_addr;

	// Find the outbound interface address so the raw listener and every
	// probe socket bind to the same source.
	g_probeSrcAddr.s_addr = INADDR_ANY;
	SOCKET probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(probe != INVALID_SOCKET) {
		sockaddr_in dst = *(sockaddr_in*)sockaddrTarget;
		dst.sin_port = htons(53);
		if(connect(probe, (sockaddr*)&dst, sizeof(dst)) == 0) {
			sockaddr_in bound;
			int boundLen = sizeof(bound);
			if(getsockname(probe, (sockaddr*)&bound, &boundLen) == 0) {
				g_probeSrcAddr = bound.sin_addr;
			}
		}
		closesocket(probe);
	}

	g_rawIcmpSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(g_rawIcmpSocket == INVALID_SOCKET) {
		SetName(0, (char*)"Raw ICMP socket failed - run as Administrator");
		tracing = false;
		return;
	}
	sockaddr_in bindAddr;
	memset(&bindAddr, 0, sizeof(bindAddr));
	bindAddr.sin_family = AF_INET;
	bindAddr.sin_addr = g_probeSrcAddr;
	if(bind(g_rawIcmpSocket, (sockaddr*)&bindAddr, sizeof(bindAddr)) == SOCKET_ERROR) {
		closesocket(g_rawIcmpSocket);
		g_rawIcmpSocket = INVALID_SOCKET;
		SetName(0, (char*)"Raw ICMP bind failed - run as Administrator");
		tracing = false;
		return;
	}

	if(!g_probeLockInit) {
		InitializeCriticalSection(&g_probeLock);
		g_probeLockInit = true;
	}
	for(int i = 0; i < MAX_HOPS; ++i) {
		g_probeTable[i].srcPort = 0;
		if(!g_probeTable[i].event) {
			g_probeTable[i].event = CreateEvent(NULL, TRUE, FALSE, NULL);
		}
	}

	HANDLE listener = (HANDLE)_beginthreadex(NULL, 0, IcmpListenerThread, this, 0, NULL);

	HANDLE hThreads[MAX_HOPS];
	unsigned char hops = 0;
	unsigned (WINAPI* proberFunc)(void*) = wmtrdlg->probeMode == PROBE_TCP ? TcpProbeThread : UdpProbeThread;
	for(; hops < MAX_HOPS;) {
		trace_thread* current = new trace_thread;
		current->address = ((sockaddr_in*)sockaddrTarget)->sin_addr;
		current->winmtr = this;
		current->ttl = hops + 1;
		hThreads[hops] = (HANDLE)_beginthreadex(NULL, 0, proberFunc, current, 0, NULL);
		InterruptibleTraceSleep(this, 30);
		if(++hops > this->GetMax()) break;
	}
	WaitForMultipleObjects(hops, hThreads, TRUE, INFINITE);
	for(; hops;) CloseHandle(hThreads[--hops]);

	closesocket(g_rawIcmpSocket);	// unblocks the listener's select/recv
	g_rawIcmpSocket = INVALID_SOCKET;
	if(listener) {
		WaitForSingleObject(listener, 2000);
		CloseHandle(listener);
	}
}

WinMTRNet::WinMTRNet(WinMTRDialog* wp)
{

	ghMutex = CreateMutex(NULL, FALSE, NULL);
	hasIPv6=true;
	tracing=false;
	initialized = false;
	wmtrdlg = wp;
	WSADATA wsaData;
	
	if(WSAStartup(MAKEWORD(2, 2), &wsaData)) {
		AfxMessageBox("Failed initializing windows sockets library!");
		return;
	}

	hICMP_DLL=LoadLibrary(_T("Iphlpapi.dll"));
	if(!hICMP_DLL) {
		AfxMessageBox("Failed: Unable to locate Iphlpapi.dll!");
		return;
	}
	
	/*
	 * Get pointers to ICMP.DLL functions
	 */
	//IPv4
	lpfnIcmpCreateFile  = (LPFNICMPCREATEFILE)GetProcAddress(hICMP_DLL,"IcmpCreateFile");
	lpfnIcmpCloseHandle = (LPFNICMPCLOSEHANDLE)GetProcAddress(hICMP_DLL,"IcmpCloseHandle");
	lpfnIcmpSendEcho2   = (LPFNICMPSENDECHO2)GetProcAddress(hICMP_DLL,"IcmpSendEcho2");
	if(!lpfnIcmpCreateFile || !lpfnIcmpCloseHandle || !lpfnIcmpSendEcho2) {
		AfxMessageBox("Wrong ICMP system library !");
		return;
	}
	//IPv6
	lpfnIcmp6CreateFile=(LPFNICMP6CREATEFILE)GetProcAddress(hICMP_DLL,"Icmp6CreateFile");
	lpfnIcmp6SendEcho2=(LPFNICMP6SENDECHO2)GetProcAddress(hICMP_DLL,"Icmp6SendEcho2");
	if(!lpfnIcmp6CreateFile || !lpfnIcmp6SendEcho2) {
		hasIPv6=false;
		AfxMessageBox("IPv6 support not found!");
		return;//@todo : soft fail
	}
	
	/*
	 * IcmpCreateFile() - Open the ping service
	 */
	hICMP = (HANDLE) lpfnIcmpCreateFile();
	if(hICMP == INVALID_HANDLE_VALUE) {
		AfxMessageBox("Error in ICMP module!");
		return;
	}
	if(hasIPv6) {
		hICMP6=(HANDLE)lpfnIcmp6CreateFile();
		if(hICMP6==INVALID_HANDLE_VALUE) {
			AfxMessageBox("Error in ICMPv6 module!");
			return;//@todo : soft fail
		}
	}
	
	ResetHops();
	
	initialized = true;
	return;
}

WinMTRNet::~WinMTRNet()
{
	if(initialized) {
		/*
		 * IcmpCloseHandle - Close the ICMP handle
		 */
		if(hasIPv6) lpfnIcmpCloseHandle(hICMP6);
		lpfnIcmpCloseHandle(hICMP);
		
		// Shut down...
		FreeLibrary(hICMP_DLL);
		
		WSACleanup();
		
		CloseHandle(ghMutex);
	}
}

void WinMTRNet::ResetHops()
{
	memset(host,0,sizeof(host));
}

void WinMTRNet::ResetStatistics()
{
	// Interactive 'r' (restart statistics): zero the counters but keep the
	// resolved addresses/names/ASNs so the display does not blank out while
	// the trace threads keep running.
	WaitForSingleObject(ghMutex, INFINITE);
	for(int i = 0; i < MaxHost; ++i) {
		host[i].xmit = 0;
		host[i].returned = 0;
		host[i].total = 0;
		host[i].m2 = 0;
		host[i].last = 0;
		host[i].best = 0;
		host[i].worst = 0;
		memset(host[i].hist, 0, sizeof(host[i].hist));
		host[i].histCount = 0;
	}
	ReleaseMutex(ghMutex);
}

void WinMTRNet::DoTrace(sockaddr* sockaddr)
{
	// TCP/UDP probe modes use the socket engine (IPv4 only; the CLI blocks
	// -T/-u with IPv6 before we get here, and falls back to ICMP otherwise).
	if(wmtrdlg->probeMode != PROBE_ICMP && sockaddr->sa_family == AF_INET) {
		DoTraceSocket(sockaddr);
		return;
	}

	HANDLE hThreads[MAX_HOPS];
	unsigned char hops=0;
	tracing = true;
	ResetHops();
	if(sockaddr->sa_family==AF_INET6) {
		host[0].addr6.sin6_family=AF_INET6;
		last_remote_addr6=((sockaddr_in6*)sockaddr)->sin6_addr;
		for(; hops<MAX_HOPS;) {// one thread per TTL value
			trace_thread6* current=new trace_thread6;
			current->address=*(sockaddr_in6*)sockaddr;
			current->winmtr=this;
			current->ttl=hops+1;
			hThreads[hops]=(HANDLE)_beginthreadex(NULL,0,TraceThread6,current,0,NULL);
			InterruptibleTraceSleep(this, 30);
			if(++hops>this->GetMax()) break;
		}
	} else {
		host[0].addr.sin_family=AF_INET;
		last_remote_addr=((sockaddr_in*)sockaddr)->sin_addr;
		for(; hops<MAX_HOPS;) {// one thread per TTL value
			trace_thread* current=new trace_thread;
			current->address=((sockaddr_in*)sockaddr)->sin_addr;
			current->winmtr=this;
			current->ttl=hops+1;
			hThreads[hops]=(HANDLE)_beginthreadex(NULL,0,TraceThread,current,0,NULL);
			InterruptibleTraceSleep(this, 30);
			if(++hops>this->GetMax()) break;
		}
	}
	WaitForMultipleObjects(hops, hThreads, TRUE, INFINITE);
	for(; hops;) CloseHandle(hThreads[--hops]);
}

void WinMTRNet::StopTrace()
{
	tracing = false;
}

unsigned WINAPI TraceThread(void* p)
{
	trace_thread* current = (trace_thread*)p;
	WinMTRNet* wmtrnet = current->winmtr;
	TRACE_MSG("Thread with TTL=" << (int)current->ttl << " started.");
	
	IPINFO			stIPInfo, *lpstIPInfo;
	char			achReqData[8192];
	WORD			nDataLen = wmtrnet->wmtrdlg->pingsize;
	union {
		ICMP_ECHO_REPLY icmp_echo_reply;
		char achRepData[sizeof(ICMPECHO)+8192];
	};
	
	lpstIPInfo				= &stIPInfo;
	stIPInfo.Ttl			= (UCHAR)current->ttl;
	stIPInfo.Tos			= 0;
	stIPInfo.Flags			= IPFLAG_DONT_FRAGMENT;
	stIPInfo.OptionsSize	= 0;
	stIPInfo.OptionsData	= NULL;
	for(int i=0; i<nDataLen; ++i) achReqData[i]=32;//whitespaces
	while(wmtrnet->tracing) {
		// For some strange reason, ICMP API is not filling the TTL for icmp echo reply
		// Check if the current thread should be closed
		if(current->ttl > wmtrnet->GetMax()) break;
		// NOTE: some servers does not respond back everytime, if TTL expires in transit; e.g. :
		// ping -n 20 -w 5000 -l 64 -i 7 www.chinapost.com.tw  -> less that half of the replies are coming back from 219.80.240.93
		// but if we are pinging ping -n 20 -w 5000 -l 64 219.80.240.93  we have 0% loss
		// A resolution would be:
		// - as soon as we get a hop, we start pinging directly that hop, with a greater TTL
		// - a drawback would be that, some servers are configured to reply for TTL transit expire, but not to ping requests, so,
		// for these servers we'll have 100% loss
		DWORD dwReplyCount = wmtrnet->lpfnIcmpSendEcho2(wmtrnet->hICMP, 0,NULL,NULL, current->address, achReqData, nDataLen, lpstIPInfo, achRepData, sizeof(achRepData), ECHO_REPLY_TIMEOUT);
		wmtrnet->AddXmit(current->ttl - 1);
		if(dwReplyCount) {
			TRACE_MSG("TTL " << (int)current->ttl << " reply TTL " << (int)icmp_echo_reply.Options.Ttl << " Status " << icmp_echo_reply.Status << " Reply count " << dwReplyCount);
			switch(icmp_echo_reply.Status) {
			case IP_SUCCESS:
			case IP_TTL_EXPIRED_TRANSIT:
				wmtrnet->UpdateRTT(current->ttl - 1, icmp_echo_reply.RoundTripTime);
				wmtrnet->AddReturned(current->ttl - 1);
				wmtrnet->SetAddr(current->ttl - 1, icmp_echo_reply.Address);
				break;
			default:
				wmtrnet->SetErrorName(current->ttl - 1, icmp_echo_reply.Status);
			}
			if((DWORD)(wmtrnet->wmtrdlg->interval * 1000) > icmp_echo_reply.RoundTripTime)
				InterruptibleTraceSleep(wmtrnet, (DWORD)(wmtrnet->wmtrdlg->interval * 1000) - icmp_echo_reply.RoundTripTime);
		} else {
			DWORD err=GetLastError();
			wmtrnet->SetErrorName(current->ttl - 1, err);
			switch(err) {
			case IP_REQ_TIMED_OUT: break;
			default:
				InterruptibleTraceSleep(wmtrnet, (DWORD)(wmtrnet->wmtrdlg->interval * 1000));
			}
		}
	}//end loop
	TRACE_MSG("Thread with TTL=" << (int)current->ttl << " stopped.");
	delete p;
	return 0;
}

unsigned WINAPI TraceThread6(void* p)
{
	static sockaddr_in6 sockaddrfrom= {AF_INET6,0,0,in6addr_any,0};
	trace_thread6* current = (trace_thread6*)p;
	WinMTRNet* wmtrnet = current->winmtr;
	TRACE_MSG("Thread with TTL=" << (int)current->ttl << " started.");
	
	IPINFO			stIPInfo, *lpstIPInfo;
	char			achReqData[8192];
	WORD			nDataLen = wmtrnet->wmtrdlg->pingsize;
	union {
		ICMPV6_ECHO_REPLY icmpv6_echo_reply;
		char achRepData[sizeof(PICMPV6_ECHO_REPLY) + 8192];
	};
	
	lpstIPInfo				= &stIPInfo;
	stIPInfo.Ttl			= (UCHAR)current->ttl;
	stIPInfo.Tos			= 0;
	stIPInfo.Flags			= IPFLAG_DONT_FRAGMENT;
	stIPInfo.OptionsSize	= 0;
	stIPInfo.OptionsData	= NULL;
	for(int i=0; i<nDataLen; ++i) achReqData[i]=32;//whitespaces
	while(wmtrnet->tracing) {
		if(current->ttl > wmtrnet->GetMax()) break;
		DWORD dwReplyCount = wmtrnet->lpfnIcmp6SendEcho2(wmtrnet->hICMP6, 0,NULL,NULL, &sockaddrfrom, &current->address, achReqData, nDataLen, lpstIPInfo, achRepData, sizeof(achRepData), ECHO_REPLY_TIMEOUT);
		wmtrnet->AddXmit(current->ttl - 1);
		if(dwReplyCount) {
			TRACE_MSG("TTL " << (int)current->ttl << " Status " << icmpv6_echo_reply.Status << " Reply count " << dwReplyCount);
			switch(icmpv6_echo_reply.Status) {
			case IP_SUCCESS:
			case IP_TTL_EXPIRED_TRANSIT:
				wmtrnet->UpdateRTT(current->ttl - 1, icmpv6_echo_reply.RoundTripTime);
				wmtrnet->AddReturned(current->ttl - 1);
				wmtrnet->SetAddr6(current->ttl - 1, icmpv6_echo_reply.Address);
				break;
			default:
				wmtrnet->SetErrorName(current->ttl - 1, icmpv6_echo_reply.Status);
			}
			if((DWORD)(wmtrnet->wmtrdlg->interval * 1000) > icmpv6_echo_reply.RoundTripTime)
				InterruptibleTraceSleep(wmtrnet, (DWORD)(wmtrnet->wmtrdlg->interval * 1000) - icmpv6_echo_reply.RoundTripTime);
		} else {
			DWORD err=GetLastError();
			wmtrnet->SetErrorName(current->ttl - 1, err);
			switch(err) {
			case IP_REQ_TIMED_OUT: break;
			default:
				InterruptibleTraceSleep(wmtrnet, (DWORD)(wmtrnet->wmtrdlg->interval * 1000));
			}
		}
	}//end loop
	TRACE_MSG("Thread with TTL=" << (int)current->ttl << " stopped.");
	delete p;
	return 0;
}

sockaddr* WinMTRNet::GetAddr(int at)
{
	return (sockaddr*)&host[at].addr;
}

int WinMTRNet::GetName(int at, char* n)
{
	WaitForSingleObject(ghMutex, INFINITE);
	strcpy(n, host[at].name);
	ReleaseMutex(ghMutex);
	return 0;
}

int WinMTRNet::GetASN(int at, char* n)
{
	WaitForSingleObject(ghMutex, INFINITE);
	strcpy(n, host[at].asn);
	ReleaseMutex(ghMutex);
	return 0;
}

int WinMTRNet::GetBest(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].best;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetWorst(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].worst;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetAvg(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].returned == 0 ? 0 : host[at].total / host[at].returned;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetPercent(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = (host[at].xmit == 0) ? 0 : (100 - (100 * host[at].returned / host[at].xmit));
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetLast(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].last;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetReturned(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].returned;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetXmit(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].xmit;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetMax()
{
	// @todo : improve this (last hop guess)
	WaitForSingleObject(ghMutex, INFINITE);
	int max=0;//first try to find target, if not found, find best guess (doesn't work actually :P)
	if(host[0].addr6.sin6_family==AF_INET6) {
		for(; max<MAX_HOPS && memcmp(&host[max++].addr6.sin6_addr,&last_remote_addr6,sizeof(in6_addr)););
		if(max==MAX_HOPS) {
			while(max>1 && !memcmp(&host[max-1].addr6.sin6_addr,&host[max-2].addr6.sin6_addr,sizeof(in6_addr)) && (host[max-1].addr6.sin6_addr.u.Word[0]|host[max-1].addr6.sin6_addr.u.Word[1]|host[max-1].addr6.sin6_addr.u.Word[2]|host[max-1].addr6.sin6_addr.u.Word[3]|host[max-1].addr6.sin6_addr.u.Word[4]|host[max-1].addr6.sin6_addr.u.Word[5]|host[max-1].addr6.sin6_addr.u.Word[6]|host[max-1].addr6.sin6_addr.u.Word[7])) --max;
		}
	} else {
		for(; max<MAX_HOPS && host[max++].addr.sin_addr.s_addr!=last_remote_addr.s_addr;);
		if(max==MAX_HOPS) {
			while(max>1 && host[max-1].addr.sin_addr.s_addr==host[max-2].addr.sin_addr.s_addr && host[max-1].addr.sin_addr.s_addr) --max;
		}
	}
	ReleaseMutex(ghMutex);
	return max;
}

void WinMTRNet::SetAddr(int at, u_long addr)
{
	bool shouldResolve = false;
	dns_resolver_thread* dnt = NULL;
	WaitForSingleObject(ghMutex, INFINITE);
	if(host[at].addr.sin_addr.s_addr==0) {
		TRACE_MSG("Start DnsResolverThread for new address " << addr << ". Old addr value was " << host[at].addr.sin_addr.s_addr);
		host[at].addr.sin_family=AF_INET;
		host[at].addr.sin_addr.s_addr=addr;
		dnt=new dns_resolver_thread;
		dnt->index=at;
		dnt->winmtr=this;
		shouldResolve = true;
	}
	ReleaseMutex(ghMutex);
	if(shouldResolve) {
		if(wmtrdlg->useDNS) _beginthread(DnsResolverThread, 0, dnt);
		else DnsResolverThread(dnt);
	}
}

void WinMTRNet::SetAddr6(int at, IPV6_ADDRESS_EX addrex)
{
	bool shouldResolve = false;
	dns_resolver_thread* dnt = NULL;
	WaitForSingleObject(ghMutex, INFINITE);
	if(!(host[at].addr6.sin6_addr.u.Word[0]|host[at].addr6.sin6_addr.u.Word[1]|host[at].addr6.sin6_addr.u.Word[2]|host[at].addr6.sin6_addr.u.Word[3]|host[at].addr6.sin6_addr.u.Word[4]|host[at].addr6.sin6_addr.u.Word[5]|host[at].addr6.sin6_addr.u.Word[6]|host[at].addr6.sin6_addr.u.Word[7])) {
		TRACE_MSG("Start DnsResolverThread for new address " << addrex.sin6_addr[0] << ". Old addr value was " << host[at].addr6.sin6_addr.u.Word[0]);
		host[at].addr6.sin6_family=AF_INET6;
		host[at].addr6.sin6_addr=*(in6_addr*)&addrex.sin6_addr;
		dnt=new dns_resolver_thread;
		dnt->index=at;
		dnt->winmtr=this;
		shouldResolve = true;
	}
	ReleaseMutex(ghMutex);
	if(shouldResolve) {
		if(wmtrdlg->useDNS) _beginthread(DnsResolverThread,0,dnt);
		else DnsResolverThread(dnt);
	}
}

void WinMTRNet::SetName(int at, char* n)
{
	WaitForSingleObject(ghMutex, INFINITE);
	strcpy(host[at].name, n);
	ReleaseMutex(ghMutex);
}

void WinMTRNet::SetASN(int at, const char* n)
{
	WaitForSingleObject(ghMutex, INFINITE);
	if(n && *n) strcpy(host[at].asn, n);
	else host[at].asn[0] = '\0';
	ReleaseMutex(ghMutex);
}

void WinMTRNet::SetErrorName(int at, DWORD errnum)
{
	const char* name;
	switch(errnum) {
	case IP_BUF_TOO_SMALL:
		name="Reply buffer too small."; break;
	case IP_DEST_NET_UNREACHABLE:
		name="Destination network unreachable."; break;
	case IP_DEST_HOST_UNREACHABLE:
		name="Destination host unreachable."; break;
	case IP_DEST_PROT_UNREACHABLE:
		name="Destination protocol unreachable."; break;
	case IP_DEST_PORT_UNREACHABLE:
		name="Destination port unreachable."; break;
	case IP_NO_RESOURCES:
		name="Insufficient IP resources were available."; break;
	case IP_BAD_OPTION:
		name="Bad IP option was specified."; break;
	case IP_HW_ERROR:
		name="Hardware error occurred."; break;
	case IP_PACKET_TOO_BIG:
		name="Packet was too big."; break;
	case IP_REQ_TIMED_OUT:
		name="Request timed out."; break;
	case IP_BAD_REQ:
		name="Bad request."; break;
	case IP_BAD_ROUTE:
		name="Bad route."; break;
	case IP_TTL_EXPIRED_REASSEM:
		name="The time to live expired during fragment reassembly."; break;
	case IP_PARAM_PROBLEM:
		name="Parameter problem."; break;
	case IP_SOURCE_QUENCH:
		name="Datagrams are arriving too fast to be processed and datagrams may have been discarded."; break;
	case IP_OPTION_TOO_BIG:
		name="An IP option was too big."; break;
	case IP_BAD_DESTINATION:
		name="Bad destination."; break;
	case IP_GENERAL_FAILURE:
		name="General failure."; break;
	default:
		TRACE_MSG("==UNKNOWN ERROR== " << errnum);
		name="Unknown error! (please report)"; break;
	}
	WaitForSingleObject(ghMutex, INFINITE);
	if(!*host[at].name)
		strcpy(host[at].name,name);
	ReleaseMutex(ghMutex);
}

void WinMTRNet::UpdateRTT(int at, int rtt)
{
	WaitForSingleObject(ghMutex, INFINITE);
	// Welford's online algorithm for running variance.
	// UpdateRTT is called BEFORE AddReturned, so host[at].returned is the
	// count of *previous* replies. total has already been incremented below.
	int prevCount = host[at].returned;
	host[at].total += rtt;
	host[at].last = rtt;
	if(host[at].best > rtt || prevCount == 0)
		host[at].best = rtt;
	if(host[at].worst < rtt)
		host[at].worst = rtt;
	if(prevCount > 0) {
		double oldMean = (double)(host[at].total - rtt) / prevCount;
		double newMean = (double)host[at].total / (prevCount + 1);
		double delta = rtt - oldMean;
		host[at].m2 += delta * (rtt - newMean);
	}
	// Fill the in-flight history slot AddXmit appended for this probe.
	if(host[at].histCount > 0) {
		host[at].hist[(host[at].histCount - 1) % HIST_SLOTS] = rtt;
	}
	ReleaseMutex(ghMutex);
}

int WinMTRNet::GetStDev(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int n = host[at].returned;
	int ret = 0;
	if(n > 1) {
		ret = (int)(sqrt(host[at].m2 / (n - 1)) + 0.5);
	}
	ReleaseMutex(ghMutex);
	return ret;
}
void WinMTRNet::AddReturned(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	++host[at].returned;
	ReleaseMutex(ghMutex);
}

void WinMTRNet::AddXmit(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	++host[at].xmit;
	// Append an in-flight history slot; UpdateRTT overwrites it with the RTT
	// when a reply arrives, otherwise it stays HIST_LOST.
	host[at].hist[host[at].histCount % HIST_SLOTS] = HIST_LOST;
	++host[at].histCount;
	ReleaseMutex(ghMutex);
}

int WinMTRNet::GetHistory(int at, int* buffer, int slots)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int available = host[at].histCount < HIST_SLOTS ? host[at].histCount : HIST_SLOTS;
	int count = available < slots ? available : slots;
	// oldest-first into buffer, newest last
	for(int i = 0; i < count; ++i) {
		int idx = (host[at].histCount - count + i) % HIST_SLOTS;
		buffer[i] = host[at].hist[idx];
	}
	ReleaseMutex(ghMutex);
	return count;
}

void DnsResolverThread(void* p)
{
	dns_resolver_thread* dnt=(dns_resolver_thread*)p;
	WinMTRNet* wn=dnt->winmtr;
	char hostname[NI_MAXHOST];
	sockaddr* address = wn->GetAddr(dnt->index);
	int addressLength = GetSockaddrLength(address);
	if(!getnameinfo(address,addressLength,hostname,NI_MAXHOST,NULL,0,NI_NUMERICHOST)) {
		wn->SetName(dnt->index,hostname);
	}
	std::string asn;
	if(LookupAsn(address, asn)) {
		wn->SetASN(dnt->index, asn.c_str());
	}
	if(wn->wmtrdlg->useDNS) {
		TRACE_MSG("DNS resolver thread started.");
		if(!getnameinfo(address,addressLength,hostname,NI_MAXHOST,NULL,0,0)) {
			wn->SetName(dnt->index,hostname);
		}
		TRACE_MSG("DNS resolver thread stopped.");
	}
	delete p;
}













