/*
*****************************************************************
*    Drakan: Order of the Flame All in One Patch (DLL part)     *
*                                                               *
*           Copyright © 2015 - 2018 UCyborg                     *
*                                                               *
*   This software uses 3rd-party code, which is subject         *
*   to their respective licenses.                               *
*                                                               *
*   This software is provided 'as-is', without any express      *
*   or implied warranty. In no event will the authors be held   *
*   liable for any damages arising from the use of this         *
*   software.                                                   *
*                                                               *
*   1. The origin of this software must not be misrepresented;  *
*      you must not claim that you wrote the original software. *
*      If you use this software in a product, an acknowledgment *
*      (see the following) in the product documentation is      *
*      required.                                                *
*                                                               *
*   2. Altered versions in source or binary form must be        *
*      plainly marked as such, and must not be misrepresented   *
*      as being the original software.                          *
*                                                               *
*   3. This notice may not be removed or altered from any       *
*      source or binary distribution.                           *
*****************************************************************
*/
#define _CRT_SECURE_NO_WARNINGS
#define DIRECTDRAW_VERSION  0x0600
#define DIRECTINPUT_VERSION 0x0600
#define DIRECTSOUND_VERSION 0x0600

#if _MSC_VER >= 1400
#include <intrin.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <WinSock2.h>
#include <Windows.h>
#include <ImageHlp.h>
#include <ShlObj.h>
#include <ddraw.h>
#include <dinput.h>
#include <dsound.h>
#include "detours.h"

#pragma comment(lib, "ddraw")
#pragma comment(lib, "ImageHlp")
#pragma comment(lib, "WinMM")
#pragma comment(lib, "WS2_32")

#ifndef _countof
#define _countof(array) (sizeof(array)/sizeof(array[0]))
#endif

#define NAKED __declspec(naked)

#define INI_NAME "Arokh.ini"

// not sure what exactly causes this to be needed
// uncomment if it crashes on Windows 9x
//#define WIN9X_HACK

void DebugPrintf(char *fmt, ...)
{
	// supposedly max length that can be delivered via OutputDebugString
	char string[4092];
	va_list ap;

	va_start(ap, fmt);
	_vsnprintf(string, sizeof(string), fmt, ap);
	va_end(ap);

	OutputDebugString(string);
}

LONG (WINAPI *O_RegSetValueEx)(HKEY, LPCTSTR, DWORD, DWORD, /*const*/ BYTE *, DWORD);
LONG WINAPI H_RegSetValueEx(HKEY hKey, LPCTSTR lpValueName, DWORD Reserved, DWORD dwType, /*const*/ BYTE *lpData, DWORD cbData)
{
	if (!strcmp(lpValueName, "Settings101"))
	{
		if (*(PDWORD_PTR)0x487A2C)
		{
			// this updates fullscreen/windowed flag on exit as the game doesn't do it
			lpData[32] ^= (-!(*(PBYTE)((*(PDWORD_PTR)0x487A2C) + 0x30) & 2) ^ lpData[32]) & 1;
		}
	}
	return O_RegSetValueEx(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

BOOL __stdcall DDCheckWindowedCap(GUID FAR *lpGUID)
{
	LPDIRECTDRAW lpDD;
	DDCAPS DDDriverCaps;

	if (!DirectDrawCreate(lpGUID, &lpDD, NULL))
	{
		DDDriverCaps.dwSize = sizeof(DDCAPS);
		IDirectDraw_GetCaps(lpDD, &DDDriverCaps, NULL);
		IDirectDraw_Release(lpDD);
		return DDDriverCaps.dwCaps2 & DDCAPS2_CANRENDERWINDOWED;
	}

	return FALSE;
}

typedef struct displaydevice_s
{
	GUID *device;
	BOOL windowedAllowed;
	struct displaydevice_s *next;
} displaydevice_t;

// engine's representation of enumerated display devices
typedef struct riotdisplaydevice_s
{
	BOOL primary;
	GUID guid;
} riotdisplaydevice_t;

displaydevice_t displayDeviceHead;
displaydevice_t *displayDevicePrev = &displayDeviceHead;

// the original function in Drakan.exe has been extended a little
// the engine assumes windowed mode shouldn't be available for non-primary display devices,
// which is a valid assumption for 3D accelerators of the time (Voodoo cards), but not for modern multi-monitor setups
int (__fastcall *O_InitDisplay)(void *, void *, BOOL, BOOL);
int __fastcall H_InitDisplay(void *This, void *unused, BOOL windowedAllowed, BOOL dedicated)
{
	riotdisplaydevice_t *riotDevice;

	if (dedicated) SetErrorMode(SEM_NOGPFAULTERRORBOX);

	riotDevice = (riotdisplaydevice_t *)0x4835B4;

	if (displayDeviceHead.next)
	{
		displaydevice_t *next;
		displaydevice_t *cur = displayDeviceHead.next;

		do
		{
			// loop through enumerated devices and set windowedAllowed if applicable for the device user selected
			if (!windowedAllowed && !riotDevice->primary && !memcmp(cur->device, &riotDevice->guid, sizeof(GUID)))
			{
				windowedAllowed = cur->windowedAllowed;
			}

			// and free the memory while at it, it won't be needed again
			next = cur->next;

			free(cur->device);
			free(cur);

			cur = next;

		} while (cur);

		displayDeviceHead.next = NULL;
	}
	else if (!riotDevice->primary)
	{
		windowedAllowed = DDCheckWindowedCap(&riotDevice->guid);
	}

	// the result of windowedAllowed variable determines whether fullscreen toggle key (F4) actually budges
	// the check to determine whether Windowed mode checkbox in Riot Engine Options should work is somewhere else in Drakan.exe
	return O_InitDisplay(This, unused, windowedAllowed, dedicated);
}

BOOL (WINAPI *O_DDEnumCallback)(GUID FAR *, LPSTR, LPSTR, LPVOID);
BOOL WINAPI DDEnumCallback(GUID FAR *lpGUID, LPSTR lpDriverDescription, LPSTR lpDriverName, LPVOID lpContext)
{
	// we haven't enumerated primary device yet, where windowed mode is always allowed
	if (!displayDeviceHead.windowedAllowed)
	{
		displayDeviceHead.windowedAllowed = TRUE;
	}
	else
	{
		if (displayDevicePrev->next = malloc(sizeof(displaydevice_t)))
		{
			if (displayDevicePrev->next->device = malloc(sizeof(GUID)))
			{
				memcpy(displayDevicePrev->next->device, lpGUID, sizeof(GUID));
				displayDevicePrev->next->windowedAllowed = DDCheckWindowedCap(lpGUID);
				displayDevicePrev->next->next = NULL;
				displayDevicePrev = displayDevicePrev->next;
			}
			else
			{
				free(displayDevicePrev->next);
				displayDevicePrev->next = NULL;
			}
		}
	}
	return O_DDEnumCallback(lpGUID, lpDriverDescription, lpDriverName, lpContext);
}

BOOL WINAPI DDEnumCallbackEx(GUID FAR *lpGUID, LPSTR lpDriverDescription, LPSTR lpDriverName, LPVOID lpContext, HMONITOR hm)
{
	return DDEnumCallback(lpGUID, lpDriverDescription, lpDriverName, lpContext);
}

HRESULT (WINAPI *PTR_DirectDrawEnumerateEx)(LPDDENUMCALLBACKEX, LPVOID, DWORD);
HRESULT (WINAPI *O_DirectDrawEnumerate)(LPDDENUMCALLBACK, LPVOID);
HRESULT WINAPI H_DirectDrawEnumerate(LPDDENUMCALLBACK lpCallback, LPVOID lpContext)
{
	// save the address of engine's callback function so we can call it after saving needed information about each display device
	O_DDEnumCallback = lpCallback;

	// DirectDrawEnumerateEx doesn't exist on Windows NT 4.0
	if (PTR_DirectDrawEnumerateEx) return PTR_DirectDrawEnumerateEx(DDEnumCallbackEx, lpContext, DDENUM_ATTACHEDSECONDARYDEVICES | DDENUM_DETACHEDSECONDARYDEVICES | DDENUM_NONDISPLAYDEVICES);

	return O_DirectDrawEnumerate(DDEnumCallback, lpContext);
}

typedef struct displaymode_s
{
	DWORD width;
	DWORD height;
	DWORD bpp;
} displaymode_t;

// this array is used for display modes in windowed mode
displaymode_t *displayModes = (displaymode_t *)0x48C000;
size_t index;
HRESULT WINAPI EnumModesCallback(LPDDSURFACEDESC lpDDSurfaceDesc, LPVOID lpContext)
{
	if (index >= 128) return DDENUMRET_CANCEL;
	// we're only interested in modes matching our desktop bit depth
	if (lpDDSurfaceDesc->ddpfPixelFormat.dwRGBBitCount == ((LPDDSURFACEDESC)lpContext)->ddpfPixelFormat.dwRGBBitCount)
	{
		displayModes[index].width = lpDDSurfaceDesc->dwWidth;
		displayModes[index].height = lpDDSurfaceDesc->dwHeight;
		displayModes[index].bpp = lpDDSurfaceDesc->ddpfPixelFormat.dwRGBBitCount;
		index++;
	}
	return DDENUMRET_OK;
}

int CompareDisplayModes(const void *p, const void *q)
{
	int pp = ((displaymode_t *)p)->width * ((displaymode_t *)p)->height;
	int qq = ((displaymode_t *)q)->width * ((displaymode_t *)q)->height;

	return (pp - qq);
}

// because Win95 doesn't have this :P
HMONITOR (WINAPI *PTR_MonitorFromWindow)(HWND, DWORD);
BOOL (WINAPI *PTR_GetMonitorInfo)(HMONITOR, LPMONITORINFO);

/*
*****************************************************************
* Borderless windowed mode magic                                *
*                                                               *
* This mostly relies on tracking window state using vars below  *
* and the sequence of calls to those APIs made by the game      *
* and adjusting the window properties accordingly. Forgot       *
* exact meaning of those flags, (windowFlags & 4) means just    *
* started the game.                                             *
*                                                               *
* It's a little more complicated than it would need to be       *
* because if we show the window without borders for the first   *
* time, putting the borders back at later point results in the  *
* missing icon.                                                 *
*****************************************************************
*/
DWORD windowFlags = 4;
LONG currentWidth;
LONG currentHeight;
LONG width;
LONG height;
// to be saved to Arokh.ini, first needed here
char BorderlessWindowHooks[] = "0";
char BorderlessTopmost[] = "0";
BOOL (WINAPI *O_AdjustWindowRectEx)(LPRECT, DWORD, BOOL, DWORD);
BOOL WINAPI H_AdjustWindowRectEx(LPRECT lpRect, DWORD dwStyle, BOOL bMenu, DWORD dwExStyle)
{
	HWND hWnd;

	// dedicated server is running
	if (*(PDWORD)0x487E18)
	{
		return O_AdjustWindowRectEx(lpRect, dwStyle, bMenu, dwExStyle);
	}

	// we need the window handle to work with
	__asm
	{
		mov eax, dword ptr ss:[ebp + 4h]
		mov dword ptr ss:[hWnd], eax
	}

	// if we're in fullscreeen mode
	if (*(PBYTE)((*(PDWORD_PTR)0x487A2C) + 0x30) & 2)
	{
		if (dwStyle & WS_POPUP)
		{
			dwStyle = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE;
			SetWindowLongPtr(hWnd, GWL_STYLE, dwStyle);
			windowFlags = 1;
		}
		return O_AdjustWindowRectEx(lpRect, dwStyle, bMenu, dwExStyle);
	}

	// figure out dimensions of the monitor on which our window resides
	if (PTR_MonitorFromWindow)
	{
		HMONITOR hMonitor;
		MONITORINFO hInfo;

		hMonitor = PTR_MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
		hInfo.cbSize = sizeof(MONITORINFO);
		PTR_GetMonitorInfo(hMonitor, &hInfo);

		currentWidth = hInfo.rcMonitor.right - hInfo.rcMonitor.left;
		currentHeight = hInfo.rcMonitor.bottom - hInfo.rcMonitor.top;
	}
	else
	{
		currentWidth = GetSystemMetrics(SM_CXSCREEN);
		currentHeight = GetSystemMetrics(SM_CYSCREEN);
	}

	// get dimensions of window client area (game resolution)
	width = lpRect->right;
	height = lpRect->bottom;

	// decide whether we need to change the borders
	if (width >= currentWidth && height >= currentHeight)
	{
		if (!(windowFlags & 4))
		{
			if (dwStyle & WS_CAPTION)
			{
				dwStyle = WS_POPUP | WS_VISIBLE;
				SetWindowLongPtr(hWnd, GWL_STYLE, dwStyle);
				windowFlags = 3;
			}
		}
		else
		{
			dwStyle = WS_POPUP | WS_VISIBLE;
			windowFlags |= 2;
		}
	}
	else
	{
		if (dwStyle & WS_POPUP)
		{
			dwStyle = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE;
			SetWindowLongPtr(hWnd, GWL_STYLE, dwStyle);
			windowFlags = 1;
		}
	}
	return O_AdjustWindowRectEx(lpRect, dwStyle, bMenu, dwExStyle);
}

BOOL (WINAPI *O_SetWindowPos)(HWND, HWND, int, int, int, int, UINT);
BOOL WINAPI H_SetWindowPos(HWND hWnd, HWND hWndInsertAfter, int X, int Y, int cx, int cy, UINT uFlags)
{
	// dedicated server is running
	if (*(PDWORD)0x487E18)
	{
		return O_SetWindowPos(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags);
	}

	if (uFlags == (SWP_NOMOVE | SWP_NOZORDER) && *(PBYTE)((*(PDWORD_PTR)0x487A2C) + 0x30) & 2)
	{
		// ignore this call in fullscreen or it may mess up other windows' sizes and positions
		return FALSE;
	}
	else if (*BorderlessWindowHooks != '0')
	{
		if (uFlags & SWP_NOMOVE)
		{
			if (windowFlags & 1)
			{
				uFlags |= SWP_FRAMECHANGED;
				if (windowFlags & 2)
				{
					uFlags &= ~SWP_NOMOVE;
					if (PTR_MonitorFromWindow)
					{
						HMONITOR hMonitor;
						MONITORINFO hInfo;

						hMonitor = PTR_MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
						hInfo.cbSize = sizeof(MONITORINFO);
						PTR_GetMonitorInfo(hMonitor, &hInfo);

						X = hInfo.rcMonitor.left;
						Y = hInfo.rcMonitor.top;
					}
					else
					{
						X = Y = 0;
					}
					if (*BorderlessTopmost != '0')
					{
						hWndInsertAfter = HWND_TOPMOST;
						uFlags &= ~SWP_NOZORDER;
					}
				}
				else if (*BorderlessTopmost != '0')
				{
					hWndInsertAfter = HWND_NOTOPMOST;
					uFlags &= ~SWP_NOZORDER;
				}
				windowFlags &= ~1;
			}
		}
		else if (windowFlags & 2)
		{
			if (PTR_MonitorFromWindow)
			{
				HMONITOR hMonitor;
				MONITORINFO hInfo;

				hMonitor = PTR_MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
				hInfo.cbSize = sizeof(MONITORINFO);
				PTR_GetMonitorInfo(hMonitor, &hInfo);

				X = hInfo.rcMonitor.left;
				Y = hInfo.rcMonitor.top;
			}
			else
			{
				X = Y = 0;
			}
			if (*BorderlessTopmost != '0')
			{
				hWndInsertAfter = HWND_TOPMOST;
			}
		}
	}
	return O_SetWindowPos(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags);
}

BOOL (WINAPI *O_ShowWindow)(HWND, int);
BOOL WINAPI H_ShowWindow(HWND hWnd, int nCmdShow)
{
	BOOL ret = O_ShowWindow(hWnd, nCmdShow);
	// no dedicated server, please
	if (!(*(PDWORD)0x487E18) && (windowFlags & 4))
	{
		if (currentWidth && width >= currentWidth && height >= currentHeight)
		{
			HWND hWndInsertAfter = *BorderlessTopmost != '0' ? HWND_TOPMOST : hWnd;
			SetWindowLongPtr(hWnd, GWL_STYLE, WS_POPUP | WS_VISIBLE);
			O_SetWindowPos(hWnd, hWndInsertAfter, 0, 0, 0, 0, SWP_FRAMECHANGED | SWP_NOSIZE);
		}
		windowFlags &= ~4;
	}
	return ret;
}

// just minimizes the borderless window at user discretion
LRESULT (CALLBACK *O_WindowProc)(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK H_WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (uMsg == WM_ACTIVATE && !LOWORD(wParam))
	{
		if (!(*(PDWORD_PTR)0x487A2C && *(PBYTE)((*(PDWORD_PTR)0x487A2C) + 0x30) & 2))
		{
			if (windowFlags & 2)
			{
				O_ShowWindow(hWnd, SW_MINIMIZE);
			}
		}
	}
	return O_WindowProc(hWnd, uMsg, wParam, lParam);
}

// allow resizing of dedicated server window if desired, not that nice without adjusting the actual output resolution
HWND (WINAPI *O_CreateWindowEx)(DWORD, LPCTSTR, LPCTSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID);
HWND WINAPI H_CreateWindowEx(DWORD dwExStyle, LPCTSTR lpClassName, LPCTSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
	if (*(PDWORD)0x487E18 && lpWindowName && !strcmp(lpWindowName, "Riot Engine"))
	{
		dwStyle |= WS_THICKFRAME | WS_MAXIMIZEBOX;
	}
	return O_CreateWindowEx(dwExStyle, lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}

/*
*****************************************************
* Simple solution to give us working server browser *
*                                                   *
* Original server browser code uses HTTP protocol   *
*****************************************************
*/
char serverListURL[128];
char *pathToServersTXT;
// master server address and location of server list are separate arguments,
// splitting code is in DllMain
void (__fastcall *O_SetMasterAddr)(void *, void *, char *, char *);
void __fastcall H_SetMasterAddr(void *This, void *unused, char *oMasterServerAddr, char *oPathToServersTXT)
{
	O_SetMasterAddr(This, unused, serverListURL, pathToServersTXT);
}

char gameServerAddr[32];
void (*O_FixServerAddr)(void);
void H_FixServerAddr(void)
{
	char *recvServerAddr;
	char *recvServerPort;
	// get the game server address from master
	__asm mov recvServerAddr, edx
	// separate IP from port
	recvServerPort = strchr(recvServerAddr, ':');
	*recvServerPort++ = '\0';
	// feed the address in format the game likes
	// I don't know the purpose of middle integer
	// it's not used by the game
	sprintf(gameServerAddr, "%s 0 %s", recvServerAddr, recvServerPort);
	__asm mov edx, offset gameServerAddr
	O_FixServerAddr();
}

/*
**********************************************************
* NEW server browser backend code using GameSpy protocol *
**********************************************************
*/
// Some good stuff borrowed from Luigi Auriemma's gslist utility

#include "gsmsalg.h"

#define BUFFERSIZE 8192

#define GSQUERY "\\gamename\\drakan" \
                "\\enctype\\0" \
                "\\validate\\%s" \
                "\\final\\" \
                "\\list\\cmp" \
                "\\gamename\\drakan"

/*
finds the value of key in the data buffer and return a new
string containing the value or NULL if nothing has been found
no modifications are made on the input data
*/
char * __stdcall keyval(char *data, char *key)
{
	size_t	nt = 0,
			skip = 1;

	for (;;)
	{
		char *p = strchr(data, '\\');

		if (nt & 1)
		{
			if (p && !_strnicmp(data, key, p - data))
			{
				skip = 0;
			}
		}
		else
		{
			if (!skip)
			{
				char *val;
				size_t len;

				if (!p) p = data + strlen(data);

				len = p - data;
				val = malloc(len + 1);

				if (val)
				{
					memcpy(val, data, len);
					val[len] = '\0';
				}
				// unlikely
				else val = (char *)-1;

				return val;
			}
		}

		if (!p) break;
		nt++;
		data = p + 1;
	}
	return NULL;
}

// pre-defined 2nd argument values for PrintBrowserStatus function
const BYTE browserStatusNormal[] = { 0xE0, 0xFF, 0xFF, 0xFF, 0xE0, 0xFF, 0xFF, 0xFF, 0x20, 0xB0, 0xFF, 0xFF, 0x20, 0xB0, 0xFF, 0xFF };
const BYTE browserStatusOrange[] = { 0x20, 0xFF, 0xFF, 0xFF, 0x20, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF };
const BYTE browserStatusGreen[] = { 0x00, 0xFF, 0xD0, 0xFF, 0x00, 0xFF, 0xD0, 0xFF, 0x00, 0x80, 0x40, 0xFF, 0x00, 0x80, 0x40, 0xFF };

HMODULE hDragon;
void (__fastcall *RFL_PrintBrowserStatus)(void *, void *, char *, const BYTE *);

// displays specified text in a little black rectangle in the Join Game menu
void __stdcall PrintBrowserStatus(char *text, const BYTE *color)
{
	void *This = (void *)(*(PDWORD_PTR)((DWORD_PTR)hDragon + 0x1855D8));

	if (This)
	{
		RFL_PrintBrowserStatus(This, NULL, text, color);
	}
}

int (__fastcall *O_InitConnect)(void *, void *, char *, u_long, DWORD);
int __fastcall H_InitConnect(void *This, void *unused, char *addr, u_long port, DWORD timeout)
{
	int ret;

	if (!(ret = O_InitConnect(This, unused, addr, port, timeout)))
	{
		PrintBrowserStatus("Unable To Resolve Hostname", browserStatusOrange);
	}

	return ret;
}

u_long tcpport;
void (__fastcall *O_Connect)(void *, void *, u_long, char *, int, int);
void __fastcall H_Connect(void *This, void *unused, u_long port, char *addr, DWORD timeout, int unkwn)
{
	O_Connect(This, unused, tcpport, addr, timeout, unkwn);
}

#define SB_BASIC_SECURE_DONE (1 << 0)
#define SB_RECV_SHOWN        (1 << 1)

char *recvBuf;
size_t recvLen;
size_t dynLen;
DWORD sbFlags;
int (__fastcall *O_ConnectCallback)(void *, void *, DWORD);
int __fastcall H_ConnectCallback(void *This, void *unused, DWORD err)
{
	if (!err)
	{
		sbFlags = 0;
		recvLen = 0;
		dynLen = BUFFERSIZE;
		recvBuf = malloc(dynLen + 1);
		PrintBrowserStatus("Connection Established", browserStatusGreen);
	}
	else
	{
		char *errorStr;

		switch (err)
		{
			case WSAECONNREFUSED:
				errorStr = "Connection Refused";
				break;
			case WSAETIMEDOUT:
				errorStr = "Connection Timed Out";
				break;
			case WSAENETUNREACH:
				errorStr = "Unreachable Network";
				break;
			default:
				errorStr = "Connection Attempt Failed With Error";
		}
		PrintBrowserStatus(errorStr, browserStatusOrange);
	}
	return 1;
}

#pragma pack(push, 1)
typedef struct ipport_s
{
	u_long		ip;
	u_short		port;
} ipport_t;
#pragma pack(pop)

int (__stdcall *O_ReceiveCallback)(DWORD, u_long, void *);
int __stdcall H_ReceiveCallback(DWORD err, u_long size, void *ptr)
{
	SOCKET sock;

	if (err)
	{
		return O_ReceiveCallback(err, size, ptr);
	}

	sock = *(SOCKET *)(&ptr + 4);

	if (recvBuf)
	{
		if (recvLen + size > dynLen)
		{
			char *buf;

			do dynLen += BUFFERSIZE; while (recvLen + size > dynLen);
			buf = realloc(recvBuf, dynLen + 1);

			if (buf) recvBuf = buf;
			else
			{
				shutdown(sock, SD_BOTH);
				DebugPrintf("ReceiveCallback() (2)::Out of memory, unable to reallocate %u bytes, shutting down socket %d\n", dynLen, sock);
				return 1;
			}
		}

		if (recv(sock, recvBuf + recvLen, size, 0) == SOCKET_ERROR)
		{
			return O_ReceiveCallback(err = WSAGetLastError(), size, ptr);
		}

		recvLen += size;
		recvBuf[recvLen] = '\0';

		if (!(sbFlags & SB_BASIC_SECURE_DONE))
		{
			char *validate;
			char *secure;
			int sendlen;

			validate = &recvBuf[dynLen / 2];
			secure = keyval(recvBuf, "secure");

			if (secure)
			{
				if (secure != (char *)-1)
				{
					gsseckey(validate, secure, "zCt4De", 0);
					free(secure);
					PrintBrowserStatus("Authenticating...", browserStatusOrange);
				}
				else
				{
					shutdown(sock, SD_BOTH);
					DebugPrintf("ReceiveCallback() (2)::Out of memory, NULL secure, shutting down socket %d\n", sock);
					return 1;
				}
			}
			else
			{
				*validate = '\0';
				DebugPrintf("ReceiveCallback() (2)::Received reply from master server: %s\nSending query with empty validate field...\n", recvBuf);
			}

			sendlen = sprintf(recvBuf, GSQUERY, validate);
			send(sock, recvBuf, sendlen, 0);
			recvLen = 0;
			sbFlags |= SB_BASIC_SECURE_DONE;
		}
		else if (!(sbFlags & SB_RECV_SHOWN))
		{
			sbFlags |= SB_RECV_SHOWN;
			PrintBrowserStatus("Receiving...", browserStatusGreen);
		}
	}
	else
	{
		shutdown(sock, SD_BOTH);
		DebugPrintf("ReceiveCallback() (2)::Out of memory, NULL recvBuf, shutting down socket %d\n", sock);
	}
	return 1;
}

void (__fastcall *O_Close)(void *, void *);
void __fastcall H_Close(void *This, void *unused)
{
	if (recvBuf)
	{
		free(recvBuf);
		recvBuf = NULL;
	}
	O_Close(This, unused);
}

int (__fastcall *O_CloseCallback)(void *, void *, DWORD);
int __fastcall H_CloseCallback(void *This, void *unused, DWORD err)
{
	if (!err)
	{
		if (recvLen >= 7 && !strcmp(recvBuf + recvLen - 7, "\\final\\"))
		{
			recvLen -= 7;
			if (recvLen)
			{
				ipport_t *ipport;
				for (ipport = (ipport_t *)recvBuf; recvLen >= 6; ipport++, recvLen -= 6)
				{
					char *ip = inet_ntoa(*(struct in_addr *)&ipport->ip);
					u_long port = ntohs(ipport->port);

					__asm
					{
						mov eax, dword ptr ds:[487bf4h]
						push 2
						mov ecx, dword ptr ds:[eax + 5eh]
						push port
						mov edx, dword ptr ds:[ecx]
						push ip
						call dword ptr ds:[edx + 4h]
					}
				}
				PrintBrowserStatus("Querying Servers...", browserStatusGreen);
			}
			else PrintBrowserStatus("No Servers Listed", browserStatusOrange);
		}
		else PrintBrowserStatus("Unexpected Response", browserStatusOrange);
	}
	else
	{
		char *errorStr;

		switch (err)
		{
			case WSAECONNRESET:
				errorStr = "Connection Reset";
				break;
			case WSAECONNABORTED:
				errorStr = "Connection Aborted";
				break;
			default:
				errorStr = "Connection Closed With Error";
		}
		PrintBrowserStatus(errorStr, browserStatusOrange);
	}
	return O_CloseCallback(This, unused, err);
}

/*
***********************************************************************
* Texel alignment                                                     *
*                                                                     *
* Adjusts coordinates for text rendering a little to fix distorted    *
* text when multisample anti-aliasing is used. Effective when         *
* Fix Texture Coordinates checkbox is checked in Riot Engine Options. *
***********************************************************************
*/
DWORD_PTR retAddr = 0x437BA6;
void (*O_TexelAlignment)(void);
NAKED void H_TexelAlignment(void)
{
	__asm
	{
		// hack to prevent the map misalignment
		fld dword ptr ss:[esp + 158h]
		fcomp dword ptr ds:[4793bch]
		fstsw ax
		test ah, 41h
		jz end

		mov eax, dword ptr ds:[ebx + 18h]
		mov dword ptr ss:[esp + 38h], 0h
		mov dword ptr ss:[esp + 34h], eax
		lea eax, [esp + 50h]
		fild qword ptr ss:[esp + 34h]
		fdivr dword ptr ds:[47951ch]
		fld dword ptr ds:[47951ch]
		mov ecx, 4h
loopy:
		// D3DVERTEX.x -= 0.5f;
		fld dword ptr ds:[eax]
		fsub st,st(1)
		fstp dword ptr ds:[eax]
		// D3DVERTEX.y -= 0.5f;
		fld dword ptr ds:[eax + 4h]
		fsub st,st(1)
		fstp dword ptr ds:[eax + 4h]
		// ???
		// D3DVERTEX.tu -= 0.5f / [esp + 34h];
		fld dword ptr ds:[eax + 18h]
		fsub st,st(2)
		fstp dword ptr ds:[eax + 18h]
		add eax, 38h
		dec ecx
		jnz loopy
		fstp st
		fstp st
end:
		jmp dword ptr ds:[retAddr]
	}
}

/*
**********************************************************************
* Calls DirectDraw SetDisplayMode method with specified refresh rate *
**********************************************************************
*/
DWORD refreshRate;
void (*O_SetDisplayMode)(void);
NAKED void H_SetDisplayMode(void)
{
	__asm
	{
		push ecx
		push esi
		push dword ptr ds:[refreshRate]
		push dword ptr ss:[esp + 18h]
		push dword ptr ss:[esp + 18h]
		push dword ptr ss:[esp + 18h]
		call dword ptr ds:[O_SetDisplayMode]
		pop ecx
		test eax,eax
		jz end
		// failed, let system pick whatever works
		push esi
		push esi
		push dword ptr ss:[esp + 14h]
		push dword ptr ss:[esp + 14h]
		push dword ptr ss:[esp + 14h]
		call dword ptr ds:[O_SetDisplayMode]
end:
		retn 14h
	}
}

/*
**********
* Timing *
**********
*/
BOOL (WINAPI *O_QueryPerformanceFrequency)(LARGE_INTEGER *);
BOOL WINAPI H_QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency)
{
	return FALSE;
}

DWORD (WINAPI *kernel32_GetTickCount)(void);
DWORD WINAPI WinMM_timeGetTime(void)
{
	return timeGetTime();
}

/*
****************************************************************
* Accurate frame limiter                                       *
*                                                              *
* Adapted from http://www.geisswerks.com/ryan/FAQS/timing.html *
* copyright (c)2002+ Ryan M. Geiss                             *
****************************************************************
*/
LARGE_INTEGER frequency;
LARGE_INTEGER ticks_to_wait;
BOOL useQPC;
int (__fastcall *O_GameFrame)(void *, void *);
int __fastcall H_GameFrame(void *This, void *unused)
{
	static LARGE_INTEGER prev_end_of_frame;
	LARGE_INTEGER t;
	int ret = O_GameFrame(This, unused);

	// already limited elsewhere; server running or no window focus
	// ideally, we should also detect if we're called to update loading bar
	if (*(PDWORD)0x487E18 || !*(PDWORD)0x4841F0) goto end;

	for (;;)
	{
		LARGE_INTEGER ticks_passed;
		LARGE_INTEGER ticks_left;

		if (useQPC)
			QueryPerformanceCounter(&t);
		else
			t.LowPart = timeGetTime();

		// time wrap
		if (t.QuadPart - prev_end_of_frame.QuadPart < 0)
			break;

		ticks_passed.QuadPart = t.QuadPart - prev_end_of_frame.QuadPart;

		if (ticks_passed.QuadPart >= ticks_to_wait.QuadPart)
			break;

		ticks_left.QuadPart = ticks_to_wait.QuadPart - ticks_passed.QuadPart;

		// If > 0.002s left, do Sleep(1), which will actually sleep some
		// steady amount, probably 1-2 ms,
		// and do so in a nice way (CPU meter drops; laptop battery spared).
		if (ticks_left.QuadPart > frequency.QuadPart * 2 / 1000)
			Sleep(1);
	}

	prev_end_of_frame.QuadPart = t.QuadPart;
end:
	return ret;
}

/*
****************************************************
* Hook for our custom function that calculates FOV *
****************************************************
*/
float FOVMultiplier;
void (*O_SetFOV)(void);
// this also multiplies FOV used when zooming in...
// maybe add an option to adjust zoom-in FOV separately
// which would have to be detected somehow
NAKED void H_SetFOV(void)
{
	__asm
	{
		fld dword ptr ss:[esp + 4h]
		fmul dword ptr ds:[FOVMultiplier]
		fstp dword ptr ss:[esp + 4h]
		jmp dword ptr ds:[O_SetFOV]
	}
}

/*
*************************************************
*               445 SP1 Patch                   *
*                                               *
*   Binary patches developed by Drakon Rider    *
*************************************************
*/
/*
typedef struct sp1data_s
{
	DWORD_PTR dwPatchBase;
	SIZE_T patchSize;
	const BYTE *patchBytes;
} sp1data_t;
*/

const BYTE LeftForwardCamOrig[] = { 0xC7, 0x44, 0x24, 0x1C, 0xCB, 0xE9, 0xAC, 0xBF, 0x89, 0x44, 0x24, 0x10 };
const BYTE LeftForwardCamPatch[] = { 0x89, 0x44, 0x24, 0x10, 0xE9, 0x03, 0x04, 0x00, 0x00, 0x90, 0x90, 0x90 };

const BYTE ForwardBackCamOrig[] = { 0xC7, 0x44, 0x24, 0x1C, 0xDA, 0x0F, 0x49, 0xC0, 0x89, 0x44, 0x24, 0x10 };
const BYTE ForwardBackCamPatch[] = { 0x89, 0x44, 0x24, 0x10, 0xE9, 0x41, 0x03, 0x00, 0x00, 0x90, 0x90, 0x90 };

const BYTE AttackIntervalOrig[] = { 0x68, 0x33, 0x33, 0x33, 0x3F };
// just a jump, the rest is in Dragon.rfl
const BYTE AttackIntervalPatch[] = { 0xE9, 0xBA, 0x84, 0x10, 0x00 };

BOOL __stdcall Apply445SP1(BOOL patch)
{
/*
	sp1data_t patchData[3];
	size_t i;
*/
	DWORD_PTR dwPatchBase;
	DWORD dwOldProtect;

/*
	patchData[0].dwPatchBase = (DWORD_PTR)hDragon + 0x60E1B;
	patchData[0].patchSize = sizeof(LeftForwardCamPatch);
	patchData[0].patchBytes = patch ? LeftForwardCamPatch : LeftForwardCamOrig;

	patchData[1].dwPatchBase = (DWORD_PTR)hDragon + 0x60EDD;
	patchData[1].patchSize = sizeof(ForwardBackCamPatch);
	patchData[1].patchBytes = patch ? ForwardBackCamPatch : ForwardBackCamOrig;

	patchData[2].dwPatchBase = (DWORD_PTR)hDragon + 0x6C161;
	patchData[2].patchSize = sizeof(AttackIntervalPatch);
	patchData[2].patchBytes = patch ? AttackIntervalPatch : AttackIntervalOrig;
*/

	dwPatchBase = (DWORD_PTR)hDragon + 0x60E1B;
	VirtualProtect((LPVOID)dwPatchBase, (0x6C161 - 0x60E1B) + sizeof(AttackIntervalPatch), PAGE_EXECUTE_READWRITE, &dwOldProtect);

	memcpy((void *)dwPatchBase, patch ? LeftForwardCamPatch : LeftForwardCamOrig, sizeof(LeftForwardCamPatch));
	memcpy((void *)(dwPatchBase + (0x60EDD - 0x60E1B)), patch ? ForwardBackCamPatch : ForwardBackCamOrig, sizeof(ForwardBackCamPatch));
	memcpy((void *)(dwPatchBase + (0x6C161 - 0x60E1B)), patch ? AttackIntervalPatch : AttackIntervalOrig, sizeof(AttackIntervalPatch));

	VirtualProtect((LPVOID)dwPatchBase, (0x6C161 - 0x60E1B) + sizeof(AttackIntervalPatch), dwOldProtect, &dwOldProtect);

	return patch;
}

typedef struct levellist_s
{
	char *szLevelName;
	struct levellist_s *next;
} levellist_t;

levellist_t *levellist_head;

/*
char **levelFileIndex;
size_t SP1LevelCount;
*/
BOOL patched;
void (*O_LevelFileHook)(void);
void H_LevelFileHook(void)
{
	char *szLevelName;
	BOOL match;
	levellist_t *cur;
//	size_t i;

	__asm mov szLevelName, ebx

	szLevelName = strrchr(szLevelName, '\\') + 1;
	match = FALSE;

	for (cur = levellist_head; cur; cur = cur->next)
	{
		if (!_stricmp(szLevelName, cur->szLevelName))
		{
			match = TRUE;
			break;
		}
	}

/*
	for (i = 0; i < SP1LevelCount; i++)
	{
		if (levelFileIndex[i] && !_stricmp(szLevelName, levelFileIndex[i]))
		{
			match = TRUE;
			break;
		}
	}
*/

	if (match)
	{
		if (!patched) patched = Apply445SP1(TRUE);
	}
	else
	{
		if (patched) patched = Apply445SP1(FALSE);
	}

	O_LevelFileHook();
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID);
BOOL WINAPI DllMainError(HINSTANCE hinstDLL, LPVOID lpvReserved)
{
	if (hinstDLL)
	{
		if (lpvReserved)
		{
			return DllMain(hinstDLL, DLL_PROCESS_DETACH, lpvReserved);
		}
	}
	else
	{
		MessageBox(NULL, "H_WinMain: Error during initialization...", NULL, MB_OK | MB_ICONSTOP);
	}
	return FALSE;
}

char DisablePerformanceCounter[] = "0";
char RefreshRate[4] = "0";
char MaxFPS[4] = "0";
char MinimizeOnFocusLost[] = "0";
char ResizableDedicatedServerWindow[] = "0";
char TCPPort[] = "28900";
char UseHTTP[] = "1";
char UseCustomURL[] = "0";
char UseCustomFormat[] = "0";
char defaultServerListURL[] = "www.qtracker.com/server_list_details.php?game=drakan";
char TexelShiftMode[] = "0";
char IgnoreMaxFogDepth[] = "0";
char DSoundBufGlobalFocus[] = "0";
float LODFactor;
const BYTE LODbytes1[] = { 0xC7, 0x81, 0x88, 0x06, 0x00, 0x00 };
const BYTE LODbytes2[] = { 0xD9, 0x99, 0xBC, 0x06, 0x00, 0x00, 0xDF, 0x6C, 0x24, 0x04, 0x5B, 0xD9, 0x99, 0xC4, 0x06, 0x00, 0x00, 0x83, 0xC4, 0x08, 0xC2, 0x10, 0x00 };
const BYTE origLODbytes[] = { 0x89, 0x99, 0x88, 0x06, 0x00, 0x00, 0xD9, 0x99, 0xBC, 0x06, 0x00, 0x00, 0xDF, 0x6C, 0x24, 0x04, 0x5B, 0xD9, 0x99, 0xC4, 0x06, 0x00, 0x00, 0x83, 0xC4, 0x08, 0xC2, 0x10, 0x00, 0x90, 0x90, 0x90, 0x90 };
BOOL __stdcall ReadUserConfig(char *path, HINSTANCE hinstDLL, LPVOID lpvReserved)
{
	DWORD_PTR dwPatchBase;
	DWORD dwOldProtect;
	DWORD maxFPS;
	size_t serverURLlength;
	char szLODFactor[16];
	char szFOVMultiplier[16];

	if (GetPrivateProfileInt("Refresh", "DisablePerformanceCounter", 0, path))
	{
		*DisablePerformanceCounter = '1';

		dwPatchBase = 0x4790A0;
		VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD_PTR), PAGE_READWRITE, &dwOldProtect);
		(DWORD_PTR)O_QueryPerformanceFrequency = *(DWORD_PTR *)dwPatchBase;
		*(DWORD_PTR *)dwPatchBase = (DWORD_PTR)H_QueryPerformanceFrequency;
		VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect);
	}
	else useQPC = QueryPerformanceFrequency(&frequency);

	if (refreshRate = GetPrivateProfileInt("Refresh", "RefreshRate", 60, path))
	{
		_itoa(refreshRate, RefreshRate, 10);

		if (!((PBYTE)O_SetDisplayMode = DetourFunction((PBYTE)0x439330, (PBYTE)H_SetDisplayMode))) goto fail;
	}

	if (maxFPS = GetPrivateProfileInt("Refresh", "MaxFPS", 59, path))
	{
		if (maxFPS < 15) maxFPS = 15;
		else if (maxFPS > 500) maxFPS = 500;
		_itoa(maxFPS, MaxFPS, 10);

		if (!((PBYTE)O_GameFrame = DetourFunction((PBYTE)0x43AF20, (PBYTE)H_GameFrame))) goto fail;

		if (useQPC)
		{
			ticks_to_wait.QuadPart = frequency.QuadPart / maxFPS;
		}
		else
		{
			frequency.LowPart = 1000;
			// feels more accurate that way
			ticks_to_wait.LowPart = frequency.LowPart / (maxFPS - 1);
		}
	}

	if (GetPrivateProfileInt("Window", "BorderlessWindowHooks", 0, path))
	{
		HMODULE hUser32;
		*BorderlessWindowHooks = '1';

		hUser32 = GetModuleHandle("USER32.dll");
		(FARPROC)PTR_MonitorFromWindow = GetProcAddress(hUser32, "MonitorFromWindow");
		(FARPROC)PTR_GetMonitorInfo = GetProcAddress(hUser32, "GetMonitorInfoA");

		dwPatchBase = 0x479220;
		VirtualProtect((LPVOID)dwPatchBase, (0x479250 - 0x479220) + sizeof(DWORD_PTR), PAGE_READWRITE, &dwOldProtect);

		(DWORD_PTR)O_ShowWindow = *(DWORD_PTR *)dwPatchBase;
		*(DWORD_PTR *)dwPatchBase = (DWORD_PTR)H_ShowWindow;

		(DWORD_PTR)O_AdjustWindowRectEx = *(DWORD_PTR *)(dwPatchBase + (0x479250 - 0x479220));
		*(DWORD_PTR *)(dwPatchBase + 0x30) = (DWORD_PTR)H_AdjustWindowRectEx;

		VirtualProtect((LPVOID)dwPatchBase, (0x479250 - 0x479220) + sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect);
	}

	if (GetPrivateProfileInt("Window", "MinimizeOnFocusLost", 0, path))
	{
		*MinimizeOnFocusLost = '1';

		if (*BorderlessWindowHooks != '0')
		{
			if (!((PBYTE)O_WindowProc = DetourFunction((PBYTE)0x412B70, (PBYTE)H_WindowProc))) goto fail;
		}
	}

	if (GetPrivateProfileInt("Window", "BorderlessTopmost", 0, path)) *BorderlessTopmost = '1';

	if (GetPrivateProfileInt("Window", "ResizableDedicatedServerWindow", 0, path))
	{
		*ResizableDedicatedServerWindow = '1';

		dwPatchBase = 0x4792DC;
		VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD_PTR), PAGE_READWRITE, &dwOldProtect);
		(DWORD_PTR)O_CreateWindowEx = *(DWORD_PTR *)dwPatchBase;
		*(DWORD_PTR *)dwPatchBase = (DWORD_PTR)H_CreateWindowEx;
		VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect);
	}

	if (tcpport = (u_short)GetPrivateProfileInt("ServerBrowser", "TCPPort", 28900, path)) _itoa(tcpport, TCPPort, 10);
	else tcpport = 28900;

	if (!GetPrivateProfileInt("ServerBrowser", "UseHTTP", 0, path))
	{
		*UseHTTP = '0';

		if (!((PBYTE)O_InitConnect = DetourFunction((PBYTE)0x463320, (PBYTE)H_InitConnect))) goto fail;
		if (!((PBYTE)O_Connect = DetourFunction((PBYTE)0x45F910, (PBYTE)H_Connect))) goto fail;
		if (!((PBYTE)O_ConnectCallback = DetourFunction((PBYTE)0x45FA10, (PBYTE)H_ConnectCallback))) goto fail;
		if (!((PBYTE)O_ReceiveCallback = DetourFunction((PBYTE)0x45FBF0, (PBYTE)H_ReceiveCallback))) goto fail;
		if (!((PBYTE)O_Close = DetourFunction((PBYTE)0x463BD0, (PBYTE)H_Close))) goto fail;
		if (!((PBYTE)O_CloseCallback = DetourFunction((PBYTE)0x45FAA0, (PBYTE)H_CloseCallback))) goto fail;
	}

	if (GetPrivateProfileInt("ServerBrowser", "UseCustomURL", 1, path))
	{
		*UseCustomURL = '1';

		if (*UseHTTP != '0')
		{
			if (!((PBYTE)O_SetMasterAddr = DetourFunction((PBYTE)0x45F990, (PBYTE)H_SetMasterAddr))) goto fail;
		}
	}

	if (GetPrivateProfileInt("ServerBrowser", "UseCustomFormat", 1, path))
	{
		*UseCustomFormat = '1';

		if (*UseHTTP != '0')
		{
			if (!((PBYTE)O_FixServerAddr = DetourFunction((PBYTE)0x45FB50, (PBYTE)H_FixServerAddr))) goto fail;
		}
	}

	// we need 1 byte of extra space to be able to split string
	serverURLlength = GetPrivateProfileString("ServerBrowser", "ServerListURL", defaultServerListURL, serverListURL, sizeof(serverListURL) - 1, path);
	if (!serverURLlength)
	{
		strcpy(serverListURL, defaultServerListURL);
		serverURLlength = sizeof(defaultServerListURL) - 1;
	}

	if (GetPrivateProfileInt("Misc", "TexelShiftMode", 1, path))
	{
		*TexelShiftMode = '1';

		if (!((PBYTE)O_TexelAlignment = DetourFunction((PBYTE)0x437B75, (PBYTE)H_TexelAlignment))) goto fail;
	}

	GetPrivateProfileString("Misc", "LODFactor", "0.0", szLODFactor, sizeof(szLODFactor), path);
	LODFactor = (float)atof(szLODFactor);

	if (LODFactor < 0.0f)
	{
		LODFactor = 0.0f;
		sprintf(szLODFactor, "%f", LODFactor);
	}
	else if (LODFactor > 8.0f)
	{
		LODFactor = 8.0f;
		sprintf(szLODFactor, "%f", LODFactor);
	}

	if (LODFactor > 0.0f)
	{
		dwPatchBase = 0x43AB52;
		VirtualProtect((LPVOID)dwPatchBase, sizeof(LODbytes1) + sizeof(LODFactor) + sizeof(LODbytes2), PAGE_EXECUTE_READWRITE, &dwOldProtect);
		memcpy((void *)dwPatchBase, LODbytes1, sizeof(LODbytes1));
		memcpy((void *)(dwPatchBase + 6), &LODFactor, sizeof(LODFactor));
		memcpy((void *)(dwPatchBase + 10), LODbytes2, sizeof(LODbytes2));
		VirtualProtect((LPVOID)dwPatchBase, sizeof(LODbytes1) + sizeof(LODFactor) + sizeof(LODbytes2), dwOldProtect, &dwOldProtect);
	}

	if (GetPrivateProfileInt("Misc", "IgnoreMaxFogDepth", 0, path)) *IgnoreMaxFogDepth = '1';

	GetPrivateProfileString("Misc", "FOVMultiplier", "1.0", szFOVMultiplier, sizeof(szFOVMultiplier), path);
	FOVMultiplier = (float)atof(szFOVMultiplier);

	if (FOVMultiplier < 1.0f)
	{
		FOVMultiplier = 1.0f;
		sprintf(szFOVMultiplier, "%f", FOVMultiplier);
	}
	else if (FOVMultiplier > 1.875f)
	{
		FOVMultiplier = 1.875f;
		sprintf(szFOVMultiplier, "%f", FOVMultiplier);
	}

	if (GetPrivateProfileInt("Misc", "DSoundBufGlobalFocus", 0, path))
	{
		*DSoundBufGlobalFocus = '1';

		dwPatchBase = 0x42717B;
		VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProtect);
		*(DWORD *)dwPatchBase |= DSBCAPS_GLOBALFOCUS;
		VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD), dwOldProtect, &dwOldProtect);

		dwPatchBase = 0x43045D;
		VirtualProtect((LPVOID)dwPatchBase, 27, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		*(DWORD *)dwPatchBase |= DSBCAPS_GLOBALFOCUS;
		*(DWORD *)(dwPatchBase + 23) |= DSBCAPS_GLOBALFOCUS;
		VirtualProtect((LPVOID)dwPatchBase, 27, dwOldProtect, &dwOldProtect);
	}

	// ensure all configurable options end up in our config
	WritePrivateProfileString("Refresh", "DisablePerformanceCounter", DisablePerformanceCounter, path);
	WritePrivateProfileString("Refresh", "RefreshRate", RefreshRate, path);
	WritePrivateProfileString("Refresh", "MaxFPS", MaxFPS, path);

	WritePrivateProfileString("Window", "BorderlessWindowHooks", BorderlessWindowHooks, path);
	WritePrivateProfileString("Window", "MinimizeOnFocusLost", MinimizeOnFocusLost, path);
	WritePrivateProfileString("Window", "BorderlessTopmost", BorderlessTopmost, path);
	WritePrivateProfileString("Window", "ResizableDedicatedServerWindow", ResizableDedicatedServerWindow, path);

	WritePrivateProfileString("ServerBrowser", "TCPPort", TCPPort, path);
	WritePrivateProfileString("ServerBrowser", "UseHTTP", UseHTTP, path);
	WritePrivateProfileString("ServerBrowser", "UseCustomURL", UseCustomURL, path);
	WritePrivateProfileString("ServerBrowser", "UseCustomFormat", UseCustomFormat, path);
	WritePrivateProfileString("ServerBrowser", "ServerListURL", serverListURL, path);

	WritePrivateProfileString("Misc", "LODFactor", szLODFactor, path);
	WritePrivateProfileString("Misc", "FOVMultiplier", szFOVMultiplier, path);
	WritePrivateProfileString("Misc", "IgnoreMaxFogDepth", IgnoreMaxFogDepth, path);
	WritePrivateProfileString("Misc", "TexelShiftMode", TexelShiftMode, path);
	WritePrivateProfileString("Misc", "DSoundBufGlobalFocus", DSoundBufGlobalFocus, path);

	if (O_SetMasterAddr)
	{
		char *temp = serverListURL;
		// fix slashes
		while (*temp)
		{
			if (*temp == '\\')
			{
				*temp = '/';
			}
			temp++;
		}

		// separate master server URL from location of server list
		if (temp = strchr(serverListURL, '/'))
		{
			memmove(pathToServersTXT = temp + 1, temp, strlen(temp) + 1);
			*temp = '\0';
		}
		else
		{
			pathToServersTXT = &serverListURL[serverURLlength];
			*++pathToServersTXT = '/';
		}
	}

	return TRUE;

fail:
	return DllMainError(hinstDLL, lpvReserved);
}

char homePath[MAX_PATH];
char *(__fastcall *O_SetConfigPath)(void *, void *, char *);
char *__fastcall H_SetConfigPath(void *This, void *unused, char *path)
{
	char *temp;
	char *ret;

	strcpy(temp = strchr(homePath, 0), path);
	CopyFile(path, homePath, TRUE);
	ret = O_SetConfigPath(This, unused, homePath);
	*temp = '\0';
	DetourRemove((PBYTE)O_SetConfigPath, (PBYTE)H_SetConfigPath);
	O_SetConfigPath = NULL;
	return ret;
}

int (*O_OutputServerScoresTXT)(char *);
int H_OutputServerScoresTXT(char *file)
{
	char *temp;
	int ret;

	strcpy(temp = strchr(homePath, 0), file);
	ret = O_OutputServerScoresTXT(homePath);
	*temp = '\0';
	return ret;
}

#if _MSC_VER >= 1400
#define NAKEDCOND
#else
#define NAKEDCOND NAKED
#endif

void (__stdcall *O_CombineWithBasePath)(char *, char *, size_t);
NAKEDCOND void __stdcall H_CombineWithBasePath(char *in, char *out, size_t len)
{
#if _MSC_VER < 1400
	__asm
	{
		mov eax, dword ptr ss:[esp]
		sub eax, dword ptr ds:[hDragon]
		cmp eax, 13d0b4h
		ja label2
		je label5
		cmp eax, 0e49fh
		ja label1
		je label5
		sub eax, 47f9h
		jz label5
		sub eax, 9b51h
		jz label5
		sub eax, 46h
		jmp label4
label1:
		cmp eax, 38ec2h
		je label5
		cmp eax, 38f59h
		jmp label4
label2:
		cmp eax, 14796ah
		ja label3
		je label5
		cmp eax, 1435e9h
		je label5
		cmp eax, 1478b6h
		jmp label4
label3:
		cmp eax, 159a4fh
		je label5
		cmp eax, 174586h
label4:
		je label5
		jmp dword ptr ds:[O_CombineWithBasePath]
label5:
		mov eax, dword ptr ds:[O_CombineWithBasePath]
		mov ecx, dword ptr ss:[esp + 0ch]
		mov edx, dword ptr ss:[esp + 8h]
		push ecx
		mov dword ptr ds:[eax + 4h], offset homePath
		mov eax, dword ptr ss:[esp + 8h]
		push edx
		push eax
		call dword ptr ds:[O_CombineWithBasePath]
		mov ecx, dword ptr ds:[O_CombineWithBasePath]
		mov dword ptr ds:[ecx + 4], 487f1ch
		retn 0ch
	}
#else
	DWORD_PTR retAddr = (DWORD_PTR)_ReturnAddress();

	switch (retAddr - (DWORD_PTR)hDragon)
	{
		case 0x47F9:
		case 0xE34A:
		case 0xE390:
		case 0xE49F:
		case 0x38EC2:
		case 0x38F59:
		case 0x13D0B4:
		case 0x1435E9:
		case 0x1478B6:
		case 0x14796A:
		case 0x159A4F:
		case 0x174586:
			*(PDWORD_PTR)((DWORD_PTR)O_CombineWithBasePath + 4) = (DWORD_PTR)&homePath[0];
			O_CombineWithBasePath(in, out, len);
			*(PDWORD_PTR)((DWORD_PTR)O_CombineWithBasePath + 4) = (DWORD_PTR)0x487F1C;
			break;
		default:
			O_CombineWithBasePath(in, out, len);
	}
#endif
}

BOOL PerUserConfigAndSaves;
BOOL __stdcall CreateHomeDir(void)
{
	if (strlen(homePath) > 207)
	{
		MessageBox(NULL, "Path to user's Documents folder is too long, using game folder for config and saves.", NULL, MB_OK | MB_ICONSTOP);
		goto end;
	}
	strcat(homePath, "\\My Games");
	if (!CreateDirectory(homePath, NULL))
		if (GetLastError() != ERROR_ALREADY_EXISTS)
			goto fail;
		strcat(homePath, "\\Drakan\\");
		if (!CreateDirectory(homePath, NULL))
		{
			if (GetLastError() != ERROR_ALREADY_EXISTS)
			{

fail:			MessageBox(NULL, "CreateDirectory failed, using game folder for config and saves.", NULL, MB_OK | MB_ICONSTOP);
end:			return FALSE;
			}
		}
		return TRUE;
}

BOOL __stdcall InstallFileRedirectionHooks(void)
{
	if (!((PBYTE)O_CombineWithBasePath = DetourFunction((PBYTE)0x408EF0, (PBYTE)H_CombineWithBasePath)))
	{
		MessageBox(NULL, "DetourFunction failed, using game folder for config and saves.", NULL, MB_OK | MB_ICONSTOP);
		return FALSE;
	}
	return TRUE;
}

void __stdcall SetupHomePath(void)
{
	HMODULE hShell32 = LoadLibrary("SHELL32.dll");
	HRESULT (WINAPI *PTR_SHGetFolderPath)(HWND, int, HANDLE, DWORD, LPTSTR) = (HRESULT (WINAPI *)(HWND, int, HANDLE, DWORD, LPTSTR))GetProcAddress(hShell32, "SHGetFolderPathA");
	if (PTR_SHGetFolderPath)
	{
		if (!PTR_SHGetFolderPath(NULL, CSIDL_PERSONAL | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, &homePath[0]))
		{
			if (!CreateHomeDir() || !InstallFileRedirectionHooks())
				PerUserConfigAndSaves = FALSE;
		}
		else
		{
			PerUserConfigAndSaves = FALSE;
			MessageBox(NULL, "SHGetFolderPath failed, using game folder for config and saves.", NULL, MB_OK | MB_ICONSTOP);
		}
	}
	else
	{
		HRESULT (WINAPI *PTR_SHGetSpecialFolderPath)(HWND, LPTSTR, int, BOOL) = (HRESULT (WINAPI *)(HWND, LPTSTR, int, BOOL))GetProcAddress(hShell32, "SHGetSpecialFolderPathA");
		if (PTR_SHGetSpecialFolderPath)
		{
			if (PTR_SHGetSpecialFolderPath(NULL, &homePath[0], CSIDL_PERSONAL, TRUE))
			{
				if (!CreateHomeDir())
					PerUserConfigAndSaves = FALSE;
			}
			else
			{
				PerUserConfigAndSaves = FALSE;
				MessageBox(NULL, "SHGetSpecialFolderPath failed, using game folder for config and saves.", NULL, MB_OK | MB_ICONSTOP);
			}
		}
		else PerUserConfigAndSaves = FALSE;
	}
	FreeLibrary(hShell32);
}

size_t screenshotCounter;
int (__fastcall *O_MakeScreenShot)(void *, void *, char *);
int __fastcall H_MakeScreenShot(void *This, void *unused, char *file)
{
	char *temp;
	BOOL res;
	char *path;
	char *filename;
	int ret;

	strcpy(temp = strchr(homePath, 0), "Screenshots\\");
	res = CreateDirectory(PerUserConfigAndSaves ? homePath : "Screenshots", NULL);
	if (!res && GetLastError() != ERROR_ALREADY_EXISTS)
	{
		*temp = '\0';
		goto fail;
	}
	path = PerUserConfigAndSaves ? &homePath[0] : temp;

	if (strncmp(file, "PANO", 4))
	{
		if (screenshotCounter < 10000)
		{
			filename = strchr(path, 0);
			do
			{
				sprintf(filename, "ScreenShot%0004u.tga", screenshotCounter++);
			} while (GetFileAttributes(path) != INVALID_FILE_ATTRIBUTES);
		}
		else
		{
			*temp = '\0';
			goto fail;
		}
	}
	else strcat(path, file);

	ret = O_MakeScreenShot(This, unused, path);
	*temp = '\0';
	return ret;

fail:
	return 0;
}

/*
********************************************************************
* Dragon.rfl hooks for FOVMultiplier and IgnoreMaxFogDepth options *
********************************************************************
*/
const BYTE origFogBytes[] = { 0x08, 0x6A, 0xFF, 0x6A, 0x03, 0x8B, 0x11, 0xFF, 0x52, 0x04, 0x8B, 0x08 };
void __stdcall RemoveStaticRFLHooks(void)
{
	DWORD_PTR dwPatchBase;
	DWORD dwOldProtect;

	if (PerUserConfigAndSaves)
	{
		if (O_OutputServerScoresTXT) DetourRemove((PBYTE)O_OutputServerScoresTXT, (PBYTE)H_OutputServerScoresTXT);
		if (O_SetConfigPath) DetourRemove((PBYTE)O_SetConfigPath, (PBYTE)H_SetConfigPath);
	}

	if (*IgnoreMaxFogDepth != '0')
	{
		DWORD_PTR dwPatchBase = (DWORD_PTR)hDragon + 0x16FD9;
		VirtualProtect((LPVOID)dwPatchBase, sizeof(origFogBytes), PAGE_EXECUTE_READWRITE, &dwOldProtect);
		memcpy((void *)dwPatchBase, origFogBytes, sizeof(origFogBytes));
		VirtualProtect((LPVOID)dwPatchBase, sizeof(origFogBytes), dwOldProtect, &dwOldProtect);
	}

	if (O_SetFOV) DetourRemove((PBYTE)O_SetFOV, (PBYTE)H_SetFOV);

	if (*UseHTTP != '1')
	{
		dwPatchBase = (DWORD_PTR)hDragon + 0x14664A;
		VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProtect);
		*(DWORD *)dwPatchBase = (DWORD)0x0824448D;
		VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD), dwOldProtect, &dwOldProtect);
	}
}

void __stdcall OnDragonUnload(void)
{
	if (O_LevelFileHook)
	{
		DetourRemove((PBYTE)O_LevelFileHook, (PBYTE)H_LevelFileHook);

		if (patched) patched = Apply445SP1(FALSE);
	}

	RemoveStaticRFLHooks();
	hDragon = NULL;
}

BOOL (WINAPI *O_FreeLibrary)(HMODULE);
BOOL WINAPI H_FreeLibrary(HMODULE hModule)
{
	if (hModule == hDragon)
	{
		OnDragonUnload();
	}
	return O_FreeLibrary(hModule);
}

const BYTE fogBytes[] = { 0x4C, 0xE4, 0x08, 0xEB, 0x07 };
BOOL __stdcall InstallStaticRFLHooks(void)
{
	DWORD_PTR dwPatchBase;
	DWORD dwOldProtect;

	if (*UseHTTP != '1')
	{
		RFL_PrintBrowserStatus = (void (__fastcall *)(void *, void *, char *, const BYTE *))((DWORD_PTR)hDragon + 0x146EE0);
		dwPatchBase = (DWORD_PTR)hDragon + 0x14664A;
		VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProtect);
		*(DWORD *)dwPatchBase = 0x909018EB;
		VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD), dwOldProtect, &dwOldProtect);
	}

	if (FOVMultiplier > 1.0f)
	{
		if (!((PBYTE)O_SetFOV = DetourFunction((PBYTE)(DWORD_PTR)hDragon + 0x17448C, (PBYTE)H_SetFOV))) goto fail;
	}

	if (*IgnoreMaxFogDepth != '0')
	{
		DWORD_PTR dwPatchBase = (DWORD_PTR)hDragon + 0x16FD9;
		VirtualProtect((LPVOID)dwPatchBase, sizeof(fogBytes) + 7, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		memcpy((void *)dwPatchBase, fogBytes, sizeof(fogBytes));
		memset((void *)(dwPatchBase + sizeof(fogBytes)), 0x90, 7);
		VirtualProtect((LPVOID)dwPatchBase, sizeof(fogBytes) + 7, dwOldProtect, &dwOldProtect);
	}

	if (PerUserConfigAndSaves)
	{
		if (!((PBYTE)O_SetConfigPath = DetourFunction((PBYTE)(DWORD_PTR)hDragon + 0x264A0, (PBYTE)H_SetConfigPath))) goto fail;
		if (!((PBYTE)O_OutputServerScoresTXT = DetourFunction((PBYTE)(DWORD_PTR)hDragon + 0x144E0, (PBYTE)H_OutputServerScoresTXT))) goto fail;
	}

	return TRUE;
fail:
	return FALSE;
}

HMODULE (WINAPI *O_LoadLibrary)(LPCTSTR);
HMODULE WINAPI H_LoadLibrary(LPCTSTR lpFileName)
{
	HMODULE hModule = O_LoadLibrary(lpFileName);
	if (hModule && !hDragon)
	{
		size_t len = strlen(lpFileName);
		if (len >= 10 && !_stricmp(&lpFileName[len - 10], "Dragon.rfl"))
		{
			HANDLE hDll;
			HANDLE hMap;
			DWORD PECheckSum = 0;

			if ((hDll = CreateFile(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
			{
				if (hMap = CreateFileMapping(hDll, NULL, PAGE_READONLY, 0, 0, NULL))
				{
					LPVOID pDll;
					DWORD HeaderSum;

					if (pDll = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0))
					{
						CheckSumMappedFile(pDll, GetFileSize(hDll, NULL), &HeaderSum, &PECheckSum);
						UnmapViewOfFile(pDll);
					}
					CloseHandle(hMap);
				}
				CloseHandle(hDll);
			}

			if (!PECheckSum)
			{
				OutputDebugString("H_LoadLibrary: Failed to checksum Dragon.rfl");
				O_FreeLibrary(hModule);
				return NULL;
			}
			if (PECheckSum != 0x1BA61E)
			{
				OutputDebugString("H_LoadLibrary: Invalid Dragon.rfl");
				O_FreeLibrary(hModule);
				return NULL;
			}

			hDragon = hModule;
			if (!InstallStaticRFLHooks())
			{
				O_FreeLibrary(hModule);
				hModule = hDragon = NULL;
			}
		}
	}
	return hModule;
}

// proxy stuff
HMODULE hDInput;
char sysDirPath[MAX_PATH];
HMODULE __stdcall LoadDinputIfNotLoaded(void)
{
	if (!hDInput)
	{
		hDInput = LoadLibrary(sysDirPath);
	}
	return hDInput;
}

HRESULT (WINAPI *PTR_DirectInputCreateA)(HINSTANCE, DWORD, LPDIRECTINPUTA, LPUNKNOWN);
HRESULT WINAPI DirectInputCreateA(HINSTANCE hinst, DWORD dwVersion, LPDIRECTINPUTA *ppDI, LPUNKNOWN punkOuter)
{
	if (LoadDinputIfNotLoaded())
	{
		if (!PTR_DirectInputCreateA)
		{
			(FARPROC)PTR_DirectInputCreateA = GetProcAddress(hDInput, "DirectInputCreateA");
			if (PTR_DirectInputCreateA)
			{
ret:			return PTR_DirectInputCreateA(hinst, dwVersion, ppDI, punkOuter);
			}
		}
		else goto ret;
	}
	return DIERR_UNSUPPORTED;
}

HRESULT (WINAPI *PTR_DirectInputCreateEx)(HINSTANCE, DWORD, REFIID, LPVOID, LPUNKNOWN);
HRESULT WINAPI DirectInputCreateEx(HINSTANCE hinst, DWORD dwVersion, REFIID riidltf, LPVOID *ppvOut, LPUNKNOWN punkOuter)
{
	if (LoadDinputIfNotLoaded())
	{
		if (!PTR_DirectInputCreateEx)
		{
			(FARPROC)PTR_DirectInputCreateEx = GetProcAddress(hDInput, "DirectInputCreateEx");
			if (PTR_DirectInputCreateEx)
			{
ret:			return PTR_DirectInputCreateEx(hinst, dwVersion, riidltf, ppvOut, punkOuter);
			}
		}
		else goto ret;
	}
	return DIERR_UNSUPPORTED;
}

HRESULT (WINAPI *PTR_DirectInputCreateW)(HINSTANCE, DWORD, LPDIRECTINPUTW, LPUNKNOWN);
HRESULT WINAPI DirectInputCreateW(HINSTANCE hinst, DWORD dwVersion, LPDIRECTINPUTW *ppDI, LPUNKNOWN punkOuter)
{
	if (LoadDinputIfNotLoaded())
	{
		if (!PTR_DirectInputCreateW)
		{
			(FARPROC)PTR_DirectInputCreateW = GetProcAddress(hDInput, "DirectInputCreateW");
			if (PTR_DirectInputCreateW)
			{
ret:			return PTR_DirectInputCreateW(hinst, dwVersion, ppDI, punkOuter);
			}
		}
		else goto ret;
	}
	return DIERR_UNSUPPORTED;
}

//HRESULT (WINAPI *PTR_DllCanUnloadNow)(void);
HRESULT WINAPI DllCanUnloadNow(void)
{
/*
	if (LoadDinputIfNotLoaded())
	{
		if (!PTR_DllCanUnloadNow)
		{
			(FARPROC)PTR_DllCanUnloadNow = GetProcAddress(hDInput, "DllCanUnloadNow");
			if (PTR_DllCanUnloadNow) return PTR_DllCanUnloadNow();
		}
		else return PTR_DllCanUnloadNow();
	}
*/
	return S_FALSE;
}

HRESULT (WINAPI *PTR_DllGetClassObject)(REFCLSID, REFIID, LPVOID);
HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppv)
{
	if (LoadDinputIfNotLoaded())
	{
		if (!PTR_DllGetClassObject)
		{
			(FARPROC)PTR_DllGetClassObject = GetProcAddress(hDInput, "DllGetClassObject");
			if (PTR_DllGetClassObject)
			{
ret:			return PTR_DllGetClassObject(rclsid, riid, ppv);
			}
		}
		else goto ret;
	}
	return CLASS_E_CLASSNOTAVAILABLE;
}

int (CALLBACK *O_WinMain)(HINSTANCE, HINSTANCE, LPSTR, int);
int CALLBACK H_WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	char rootPath[MAX_PATH];
	char *temp;
//	HMODULE hDInput;
	HMODULE hDDraw;
	LPDIRECTDRAW lpDD;
	int (WINAPI *PTR_SetAppCompatData)(int, int);

	GetModuleFileName(hInstance, rootPath, MAX_PATH);

	if (_stricmp(temp = strrchr(rootPath, '\\') + 1, "Drakan.exe"))
	{
		if (MessageBox(NULL,
					  "The executable file is not named Drakan.exe. This causes \"Invalid or " \
					  "corrupted level!\" error in multiplayer because server and clients must " \
					  "have matching executable file, including its name. Click OK to continue " \
					  "or Cancel to quit.",
					  "Warning",
					   MB_OKCANCEL | MB_ICONWARNING
		   ) == IDCANCEL) goto fail;
	}

/*
	if (!(hDInput = LoadLibrary(sysDirPath)))
	{
		MessageBox(NULL, "Unable to load DirectInput library. Exiting...", "DirectX Error", MB_OK | MB_ICONSTOP);
		goto fail;
	}

	if (!(PTR_DirectInputCreate = GetProcAddress(hDInput, "DirectInputCreateA")))
	{
		MessageBox(NULL, "Missing DirectInputCreateA export. Exiting...", "DirectX Error", MB_OK | MB_ICONSTOP);
		goto fail;
	}
*/

	if (PerUserConfigAndSaves)
	{
		SetupHomePath();
	}

	if (PerUserConfigAndSaves)
	{
		strcpy(temp = strchr(homePath, 0), INI_NAME);
		if (!ReadUserConfig(homePath, NULL, NULL)) goto fail;
		*temp = '\0';
	}
	else
	{
		strcpy(temp, INI_NAME);
		if (!ReadUserConfig(rootPath, NULL, NULL)) goto fail;
	}

	hDDraw = GetModuleHandle("DDRAW.dll");
	(FARPROC)PTR_DirectDrawEnumerateEx = GetProcAddress(hDDraw, "DirectDrawEnumerateExA");
	(FARPROC)PTR_SetAppCompatData = GetProcAddress(hDDraw, "SetAppCompatData");

	// we're running on Win7+ through native ddraw.dll
	// disable maximized windowed mode, only applicable to Win8+, it doesn't do anything on 7
	if (PTR_SetAppCompatData) PTR_SetAppCompatData(12, 0);

	// no need to invoke graphics driver just to get resolutions, though it only behaves that way with native DirectDraw
	if (!DirectDrawCreate((GUID *)DDCREATE_EMULATIONONLY, &lpDD, NULL))
	{
		DDSURFACEDESC DDSurfaceDesc;
		DDSurfaceDesc.dwSize = sizeof(DDSURFACEDESC);

		if (!IDirectDraw_GetDisplayMode(lpDD, &DDSurfaceDesc))
		{
			IDirectDraw_EnumDisplayModes(lpDD, 0, NULL, &DDSurfaceDesc, EnumModesCallback);

			if (index)
			{
				DWORD_PTR dwPatchBase;
				DWORD dwOldProtect;

				qsort(displayModes, index, sizeof(displaymode_t), CompareDisplayModes);

				dwPatchBase = 0x43BAFB;
				VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD_PTR), PAGE_EXECUTE_READWRITE, &dwOldProtect);
				*(PDWORD_PTR)dwPatchBase = (DWORD_PTR)&(displayModes[index].width);
				VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect);
			}
		}

		IDirectDraw_Release(lpDD);
	}

	return O_WinMain(hInstance, hPrevInstance, lpCmdLine, nCmdShow);

fail:
	return -1;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	DWORD_PTR dwPatchBase;
	DWORD dwOldProtect;
//	size_t levelFileCount;

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		char path[MAX_PATH];
		HANDLE hExe;
		HANDLE hMap;
		DWORD PECheckSum;
#ifdef WIN9X_HACK
		OSVERSIONINFO osVersionInfo;
#endif
		HMODULE hDInput;
		UINT Location;
		char *levelStr;

		// not interested in those
		DisableThreadLibraryCalls(hinstDLL);

		// setup proxy stuff
		GetSystemDirectory(sysDirPath, MAX_PATH);
		strcat(sysDirPath, "\\DINPUT.dll");

		GetModuleFileName(NULL, path, MAX_PATH);

		PECheckSum = 0;
		if ((hExe = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
		{
			if (hMap = CreateFileMapping(hExe, NULL, PAGE_READONLY, 0, 0, NULL))
			{
				LPVOID pExe;
				DWORD HeaderSum;

				if (pExe = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0))
				{
					CheckSumMappedFile(pExe, GetFileSize(hExe, NULL), &HeaderSum, &PECheckSum);
					UnmapViewOfFile(pExe);
				}
				CloseHandle(hMap);
			}
			CloseHandle(hExe);
		}

		if (!PECheckSum)
		{
			OutputDebugString("DllMain: Failed to checksum Drakan.exe");
			return TRUE;
		}
		if (PECheckSum != 0x89E91)
		{
			OutputDebugString("DllMain: Invalid Drakan.exe");
			return TRUE;
		}

#ifdef WIN9X_HACK
		osVersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
		GetVersionEx(&osVersionInfo);

		// running on Windows 9x
		// we may need to start new instance of ourselves in which VirtualProtect won't crash when unprotecting read-only memory pages
		if (osVersionInfo.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS)
		{
			HANDLE hEvent;

			if (hEvent = CreateEvent(NULL, FALSE, FALSE, "Drakan9xHack"))
			{
				// if we're new instance
				if (GetLastError() == ERROR_ALREADY_EXISTS)
				{
					// signal old instance to terminate
					SetEvent(hEvent);
					CloseHandle(hEvent);

					// we might want to tell the server launcher our process ID since original instance is going down
					if (hEvent = OpenEvent(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, "Drakan9xServerEvent"))
					{
						if (hMap = OpenFileMapping(FILE_MAP_WRITE, FALSE, "Drakan9xServerId"))
						{
							DWORD *pid;

							if (pid = MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, 0))
							{
								DWORD waitRes;

								*pid = GetCurrentProcessId();
								SetEvent(hEvent);
								UnmapViewOfFile(pid);

								while ((waitRes = WaitForSingleObject(hEvent, 0)) != WAIT_TIMEOUT)
								{
									if (waitRes == WAIT_FAILED) break;
									Sleep(0);
								}
							}
							CloseHandle(hMap);
						}
						CloseHandle(hEvent);
					}
				}
				else
				{
					// otherwise it is yet to be created
					STARTUPINFO sInfo;
					PROCESS_INFORMATION pInfo;

					GetModuleFileName(NULL, path, MAX_PATH);
					GetStartupInfo(&sInfo);

					if (CreateProcess(path, GetCommandLine(), NULL, NULL, FALSE, GetPriorityClass(GetCurrentProcess()), NULL, NULL, &sInfo, &pInfo))
					{
						WaitForSingleObject(hEvent, INFINITE);
						CloseHandle(pInfo.hProcess);
						CloseHandle(pInfo.hThread);
						CloseHandle(hEvent);
						SetErrorMode(SEM_FAILCRITICALERRORS);
						return FALSE;
					}
					else CloseHandle(hEvent);
				}
			}
		}
#endif
		// support for being loaded again after forceful unload by external means (more for testing and being cool)
		// probably doesn't work properly anymore due to some variables being cached down in the program stack
		if (hDInput = GetModuleHandle(sysDirPath))
		{
			(FARPROC)PTR_DirectInputCreateA = GetProcAddress(hDInput, "DirectInputCreateA");
			(FARPROC)PTR_DirectInputCreateEx = GetProcAddress(hDInput, "DirectInputCreateEx");
			(FARPROC)PTR_DirectInputCreateW = GetProcAddress(hDInput, "DirectInputCreateW");
//			(FARPROC)PTR_DllCanUnloadNow = GetProcAddress(hDInput, "DllCanUnloadNow");
			(FARPROC)PTR_DllGetClassObject = GetProcAddress(hDInput, "DllGetClassObject");
			hDragon = GetModuleHandle("Dragon.rfl");
		}

		if (!((PBYTE)O_WinMain = DetourFunction((PBYTE)0x4127F0, (PBYTE)H_WinMain))) goto fail;
		if (!((PBYTE)O_InitDisplay = DetourFunction((PBYTE)0x439B50, (PBYTE)H_InitDisplay))) goto fail;
		if (!((PBYTE)O_MakeScreenShot = DetourFunction((PBYTE)0x43B540, (PBYTE)H_MakeScreenShot))) goto fail;

		dwPatchBase = 0x479000;
		VirtualProtect((LPVOID)dwPatchBase, (0x4792A4 - 0x479000) + sizeof(DWORD_PTR), PAGE_READWRITE, &dwOldProtect);

		(DWORD_PTR)O_RegSetValueEx = *(DWORD_PTR *)dwPatchBase;
		*(DWORD_PTR *)dwPatchBase = (DWORD_PTR)H_RegSetValueEx;

		(DWORD_PTR)O_DirectDrawEnumerate = *(DWORD_PTR *)(dwPatchBase + 0x34);
		*(DWORD_PTR *)(dwPatchBase + 0x34) = (DWORD_PTR)H_DirectDrawEnumerate;

		(DWORD_PTR)O_FreeLibrary = *(DWORD_PTR *)(dwPatchBase + 0x94);
		*(DWORD_PTR *)(dwPatchBase + 0x94) = (DWORD_PTR)H_FreeLibrary;

		(DWORD_PTR)O_LoadLibrary = *(DWORD_PTR *)(dwPatchBase + 0x9C);
		*(DWORD_PTR *)(dwPatchBase + 0x9C) = (DWORD_PTR)H_LoadLibrary;

		(DWORD_PTR)kernel32_GetTickCount = *(DWORD_PTR *)(dwPatchBase + 0x1DC);
		*(DWORD_PTR *)(dwPatchBase + 0x1DC) = (DWORD_PTR)WinMM_timeGetTime;

		(DWORD_PTR)O_SetWindowPos = *(DWORD_PTR *)(dwPatchBase + 0x2A4);
		*(DWORD_PTR *)(dwPatchBase + 0x2A4) = (DWORD_PTR)H_SetWindowPos;

		VirtualProtect((LPVOID)dwPatchBase, (0x4792A4 - 0x479000) + sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect);

		// setup path to our config file, act according to config options
		strcpy(strrchr(path, '\\') + 1, INI_NAME);

		PerUserConfigAndSaves = GetPrivateProfileInt("UserData", "PerUserConfigAndSaves", 1, path);
		if (!lpvReserved)
		{
			SetupHomePath();
			if (PerUserConfigAndSaves)
			{
				char *temp;

				strcpy(temp = strchr(homePath, 0), INI_NAME);
				if (!ReadUserConfig(homePath, hinstDLL, lpvReserved)) return FALSE;
				*temp = '\0';
			}
			else if (!ReadUserConfig(path, hinstDLL, lpvReserved)) return FALSE;
		}

		if (GetPrivateProfileInt("Misc", "ReportFakeDepthMask", 0, path))
		{
			dwPatchBase = 0x43A008;
			VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProtect);
			*(DWORD *)dwPatchBase = 0x90FFC883;
			VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD), dwOldProtect, &dwOldProtect);
		}

		Location = GetPrivateProfileInt("Misc", "Location", 0, path);
		if (Location >= 1 && Location <= 13) _itoa(Location, (char *)0x481870, 10);

		// read in list of levels for which we should apply 445SP1 patch
		levelStr = _alloca(1024);
		if (GetPrivateProfileSection("445SP1", levelStr, 1024, path))
		{
			levellist_t *levellist_cur = malloc(sizeof(levellist_t));
			if (!levellist_cur) goto fail;
			levellist_head = levellist_cur;

			do
			{
				BOOL missingExt;
				size_t len = strlen(levelStr);

				if (len > 4 && !_stricmp((levelStr + len) - 4, ".lvl"))
					missingExt = FALSE;
				else
					missingExt = TRUE;

				len++;

				levellist_cur->szLevelName = malloc(missingExt ? len + 4 : len);

				if (levellist_cur->szLevelName)
				{
					if (!missingExt)
						strcpy(levellist_cur->szLevelName, levelStr);
					else
						sprintf(levellist_cur->szLevelName, "%s%s", levelStr, ".lvl");

					levelStr += len;

					levellist_cur->next = *levelStr ? malloc(sizeof(levellist_t)) : NULL;
					if (*levelStr && !levellist_cur->next) goto fail;
					levellist_cur = levellist_cur->next;
				}
				else goto fail;
			} while (levellist_cur);

			if(!((PBYTE)O_LevelFileHook = DetourFunction((PBYTE)0x438117, (PBYTE)H_LevelFileHook))) goto fail;
		}

		// read in list of levels for which we should apply 445SP1 patch
/*
		if (levelFileCount = GetPrivateProfileInt("445SP1", "FileCount", 0, path))
		{
			if (levelFileIndex = malloc(sizeof(*levelFileIndex) * levelFileCount))
			{
				char szLevelName[64];
				size_t allocSize;

				for (; levelFileCount; SP1LevelCount++, levelFileCount--)
				{
					sprintf(szLevelName, "Level%u", SP1LevelCount + 1);
					if (allocSize = GetPrivateProfileString("445SP1", szLevelName, NULL, szLevelName, sizeof(szLevelName), path))
					{
						if (levelFileIndex[SP1LevelCount] = malloc(allocSize + 1))
						{
							strcpy(levelFileIndex[SP1LevelCount], szLevelName);
						}
						// something's really wrong if this happens
						else goto fail;
					}
					else levelFileIndex[SP1LevelCount] = NULL;
				}

				if(!((PBYTE)O_LevelFileHook = DetourFunction((PBYTE)0x438117, (PBYTE)H_LevelFileHook))) goto fail;
			}
			else goto fail;
		}
*/

		if (hDragon)
		{
			if (!InstallStaticRFLHooks()) goto fail;
		}
	}
	// clean-up, ensure we can be unloaded even mid-game without crashing
	// at least when not unloaded during some critical moment
	else if (fdwReason == DLL_PROCESS_DETACH)
	{
		if (hDragon)
		{
			OnDragonUnload();
		}

/*
		if (SP1LevelCount)
		{
			for (levelFileCount = 0; levelFileCount < SP1LevelCount; levelFileCount++)
			{
				free(levelFileIndex[levelFileCount]);
			}

			free(levelFileIndex);
		}
*/

		if (*DSoundBufGlobalFocus != '0')
		{
			dwPatchBase = 0x43045D;
			VirtualProtect((LPVOID)dwPatchBase, 27, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			*(DWORD *)dwPatchBase &= ~DSBCAPS_GLOBALFOCUS;
			*(DWORD *)(dwPatchBase + 23) &= ~DSBCAPS_GLOBALFOCUS;
			VirtualProtect((LPVOID)dwPatchBase, 27, dwOldProtect, &dwOldProtect);

			dwPatchBase = 0x42717B;
			VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProtect);
			*(DWORD *)dwPatchBase &= ~DSBCAPS_GLOBALFOCUS;
			VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD), dwOldProtect, &dwOldProtect);
		}

		if (LODFactor > 0.0f)
		{
			dwPatchBase = 0x43AB52;
			VirtualProtect((LPVOID)dwPatchBase, sizeof(origLODbytes), PAGE_EXECUTE_READWRITE, &dwOldProtect);
			memcpy((void *)dwPatchBase, origLODbytes, sizeof(origLODbytes));
			VirtualProtect((LPVOID)dwPatchBase, sizeof(origLODbytes), dwOldProtect, &dwOldProtect);
		}

		if (O_TexelAlignment) DetourRemove((PBYTE)O_TexelAlignment, (PBYTE)H_TexelAlignment);

		if (*UseHTTP != '0')
		{
			if (O_FixServerAddr) DetourRemove((PBYTE)O_FixServerAddr, (PBYTE)H_FixServerAddr);

			if (O_SetMasterAddr) DetourRemove((PBYTE)O_SetMasterAddr, (PBYTE)H_SetMasterAddr);
		}
		else
		{
			if (O_CloseCallback) DetourRemove((PBYTE)O_CloseCallback, (PBYTE)H_CloseCallback);
			if (O_Close) DetourRemove((PBYTE)O_Close, (PBYTE)H_Close);
			if (O_ReceiveCallback) DetourRemove((PBYTE)O_ReceiveCallback, (PBYTE)H_ReceiveCallback);
			if (O_ConnectCallback) DetourRemove((PBYTE)O_ConnectCallback, (PBYTE)H_ConnectCallback);
			if (O_Connect) DetourRemove((PBYTE)O_Connect, (PBYTE)H_Connect);
			if (O_InitConnect) DetourRemove((PBYTE)O_InitConnect, (PBYTE)H_InitConnect);
		}

		if (*ResizableDedicatedServerWindow != '0')
		{
			dwPatchBase = 0x4792DC;
			VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD_PTR), PAGE_READWRITE, &dwOldProtect);
			*(DWORD_PTR *)dwPatchBase = (DWORD_PTR)O_CreateWindowEx;
			VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect);
		}

		if (*BorderlessWindowHooks != '0')
		{
			if (O_WindowProc) DetourRemove((PBYTE)O_WindowProc, (PBYTE)H_WindowProc);

			dwPatchBase = 0x479220;
			VirtualProtect((LPVOID)dwPatchBase, (0x479250 - 0x479220) + sizeof(DWORD_PTR), PAGE_READWRITE, &dwOldProtect);

			*(DWORD_PTR *)(dwPatchBase + 0x30) = (DWORD_PTR)O_AdjustWindowRectEx;
			*(DWORD_PTR *)dwPatchBase = (DWORD_PTR)O_ShowWindow;

			VirtualProtect((LPVOID)dwPatchBase, (0x479250 - 0x479220) + sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect);
		}

		if (O_GameFrame) DetourRemove((PBYTE)O_GameFrame, (PBYTE)H_GameFrame);
		if (O_SetDisplayMode) DetourRemove((PBYTE)O_SetDisplayMode, (PBYTE)H_SetDisplayMode);

		if (*DisablePerformanceCounter != '0')
		{
			dwPatchBase = 0x4790A0;
			VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD_PTR), PAGE_READWRITE, &dwOldProtect);
			*(DWORD_PTR *)dwPatchBase = (DWORD_PTR)O_QueryPerformanceFrequency;
			VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect);
		}

		if (O_CombineWithBasePath) DetourRemove((PBYTE)O_CombineWithBasePath, (PBYTE)H_CombineWithBasePath);

		if (levellist_head)
		{
			levellist_t *next;
			levellist_t *cur = levellist_head;

			do
			{
				next = cur->next;

				free(cur->szLevelName);
				free(cur);

				cur = next;
			} while (cur);
		}

		dwPatchBase = 0x479000;
		VirtualProtect((LPVOID)dwPatchBase, (0x4792A4 - 0x479000) + sizeof(DWORD_PTR), PAGE_READWRITE, &dwOldProtect);

		*(DWORD_PTR *)(dwPatchBase + 0x2A4) = (DWORD_PTR)O_SetWindowPos;
		*(DWORD_PTR *)(dwPatchBase + 0x1DC) = (DWORD_PTR)kernel32_GetTickCount;
		*(DWORD_PTR *)(dwPatchBase + 0x9C) = (DWORD_PTR)O_LoadLibrary;
		*(DWORD_PTR *)(dwPatchBase + 0x94) = (DWORD_PTR)O_FreeLibrary;
		*(DWORD_PTR *)(dwPatchBase + 0x34) = (DWORD_PTR)O_DirectDrawEnumerate;
		*(DWORD_PTR *)dwPatchBase = (DWORD_PTR)O_RegSetValueEx;

		VirtualProtect((LPVOID)dwPatchBase, (0x4792A4 - 0x479000) + sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect);

		if (O_MakeScreenShot) DetourRemove((PBYTE)O_MakeScreenShot, (PBYTE)H_MakeScreenShot);
		if (O_InitDisplay) DetourRemove((PBYTE)O_InitDisplay, (PBYTE)H_InitDisplay);
		if (O_WinMain) DetourRemove((PBYTE)O_WinMain, (PBYTE)H_WinMain);
	}
	return TRUE;
fail:
	return DllMainError(hinstDLL, lpvReserved);
}
