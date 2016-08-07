#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <Windows.h>
#include <ddraw.h>
#include "detours.h"

#pragma comment(lib, "ddraw.lib")
#pragma comment(lib, "detours.lib")

DETOUR_TRAMPOLINE(LONG WINAPI O_RegSetValueEx(HKEY hKey, LPCTSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData), RegSetValueEx);
LONG WINAPI H_RegSetValueEx(HKEY hKey, LPCTSTR lpValueName, DWORD Reserved, DWORD dwType, /*const*/ BYTE *lpData, DWORD cbData)
{
	if (!strcmp(lpValueName, "Settings101"))
	{
		if ((*(DWORD *)0x487A2C))
		{
			// this updates fullscreen/windowed flag on exit as the game doesn't do it
			lpData[32] ^= (-!(*(BYTE *)((*(DWORD *)0x487A2C) + 0x30) & 2) ^ lpData[32]) & 1;
		}
	}
	return O_RegSetValueEx(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

typedef struct displaymode_s
{
	DWORD width;
	DWORD height;
	DWORD bpp;
} displaymode_t;

// this array is used for display modes in windowed mode
displaymode_t *displaymodes = (displaymode_t *)0x48F000;
int index;
int currentWidth;
int currentHeight;
HRESULT WINAPI EnumModesCallback(LPDDSURFACEDESC lpDDSurfaceDesc, LPVOID lpContext)
{
	// we're only interested in modes matching our desktop bit depth
	if (lpDDSurfaceDesc->ddpfPixelFormat.dwRGBBitCount == ((LPDDSURFACEDESC)lpContext)->ddpfPixelFormat.dwRGBBitCount)
	{
		displaymodes[index].width = lpDDSurfaceDesc->dwWidth;
		displaymodes[index].height = lpDDSurfaceDesc->dwHeight;
		displaymodes[index].bpp = lpDDSurfaceDesc->ddpfPixelFormat.dwRGBBitCount;
		index++;
	}
	return DDENUMRET_OK;
}

int CompareDisplayModes(const void *p, const void *q)
{
	int pp = (int)((displaymode_t *)p)->width * (int)((displaymode_t *)p)->height;
	int qq = (int)((displaymode_t *)q)->width * (int)((displaymode_t *)q)->height;

	return (pp - qq);
}

// because Win95 doesn't have this :P
typedef HMONITOR (WINAPI *MonitorFromWindow_)(HWND, DWORD);
typedef BOOL (WINAPI *GetMonitorInfo_)(HMONITOR, LPMONITORINFO);

MonitorFromWindow_ MonitorFromWindow__;
GetMonitorInfo_ GetMonitorInfo__;

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
*                                                               *
* And of-course, 3rd party DLLs may call those APIs so subtle   *
* bugs can show up on an occassion.                             *
*****************************************************************
*/
DWORD windowFlags = 4;
int width;
int height;
char BorderlessTopmost[] = "0";
DETOUR_TRAMPOLINE(BOOL WINAPI O_AdjustWindowRectEx(LPRECT lpRect, DWORD dwStyle, BOOL bMenu, DWORD dwExStyle), AdjustWindowRectEx);
BOOL WINAPI H_AdjustWindowRectEx(LPRECT lpRect, DWORD dwStyle, BOOL bMenu, DWORD dwExStyle)
{
	HWND hWnd;

	// dedicated server is running
	if ((*(DWORD *)0x487E18))
	{
		return O_AdjustWindowRectEx(lpRect, dwStyle, bMenu, dwExStyle);
	}

	// we need the window handle to work with
	__asm
	{
		mov eax, dword ptr ss:[ebp + 4h];
		mov dword ptr ss:[hWnd], eax;
	}

	// if we're in fullscreeen mode
	if ((*(BYTE *)((*(DWORD *)0x487A2C) + 0x30) & 2))
	{
		if (dwStyle & WS_POPUP)
		{
			dwStyle = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE;
			SetWindowLong(hWnd, GWL_STYLE, dwStyle);
			windowFlags = 1;
		}
		return O_AdjustWindowRectEx(lpRect, dwStyle, bMenu, dwExStyle);
	}

	// figure out dimensions of the monitor on which our window resides
	if (MonitorFromWindow__)
	{
		HMONITOR hMonitor;
		MONITORINFO hInfo;

		hMonitor = MonitorFromWindow__(hWnd, MONITOR_DEFAULTTONEAREST);
		hInfo.cbSize = sizeof(MONITORINFO);
		GetMonitorInfo__(hMonitor, &hInfo);

		currentWidth = (int)hInfo.rcMonitor.right - (int)hInfo.rcMonitor.left;
		currentHeight = (int)hInfo.rcMonitor.bottom - (int)hInfo.rcMonitor.top;
	}
	else
	{
		currentWidth = GetSystemMetrics(SM_CXSCREEN);
		currentHeight = GetSystemMetrics(SM_CYSCREEN);
	}

	// get dimensions of window client area (game resolution)
	width = (int)lpRect->right;
	height = (int)lpRect->bottom;

	// decide whether we need to change the borders
	if (width >= currentWidth && height >= currentHeight)
	{
		if (!(windowFlags & 4))
		{
			if (dwStyle & WS_CAPTION)
			{
				dwStyle = WS_POPUP | WS_VISIBLE;
				SetWindowLong(hWnd, GWL_STYLE, dwStyle);
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
			SetWindowLong(hWnd, GWL_STYLE, dwStyle);
			windowFlags = 1;
		}
	}
	return O_AdjustWindowRectEx(lpRect, dwStyle, bMenu, dwExStyle);
}

DETOUR_TRAMPOLINE(BOOL WINAPI O_SetWindowPos(HWND hWnd, HWND hWndInsertAfter, int X, int Y, int cx, int cy, UINT uFlags), SetWindowPos);
BOOL WINAPI H_SetWindowPos(HWND hWnd, HWND hWndInsertAfter, int X, int Y, int cx, int cy, UINT uFlags)
{
	// dedicated server is running
	if ((*(DWORD *)0x487E18))
	{
		return O_SetWindowPos(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags);
	}

	if (uFlags & SWP_NOMOVE)
	{
		if (windowFlags & 1)
		{
			uFlags |= SWP_FRAMECHANGED;
			if (windowFlags & 2)
			{
				uFlags &= ~SWP_NOMOVE;
				if (MonitorFromWindow__)
				{
					HMONITOR hMonitor;
					MONITORINFO hInfo;

					hMonitor = MonitorFromWindow__(hWnd, MONITOR_DEFAULTTONEAREST);
					hInfo.cbSize = sizeof(MONITORINFO);
					GetMonitorInfo__(hMonitor, &hInfo);

					X = (int)hInfo.rcMonitor.left;
					Y = (int)hInfo.rcMonitor.top;
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
		if (MonitorFromWindow__)
		{
			HMONITOR hMonitor;
			MONITORINFO hInfo;

			hMonitor = MonitorFromWindow__(hWnd, MONITOR_DEFAULTTONEAREST);
			hInfo.cbSize = sizeof(MONITORINFO);
			GetMonitorInfo__(hMonitor, &hInfo);

			X = (int)hInfo.rcMonitor.left;
			Y = (int)hInfo.rcMonitor.top;
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
	return O_SetWindowPos(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags);
}

DETOUR_TRAMPOLINE(BOOL WINAPI O_ShowWindow(HWND hWnd, int nCmdShow), ShowWindow);
BOOL WINAPI H_ShowWindow(HWND hWnd, int nCmdShow)
{
	BOOL ret = O_ShowWindow(hWnd, nCmdShow);
	// no dedicated server, please
	if (!(*(DWORD *)0x487E18) && (windowFlags & 4))
	{
		if (currentWidth && width >= currentWidth && height >= currentHeight)
		{
			HWND hWndInsertAfter = *BorderlessTopmost != '0' ? HWND_TOPMOST : hWnd;
			SetWindowLong(hWnd, GWL_STYLE, WS_POPUP | WS_VISIBLE);
			O_SetWindowPos(hWnd, hWndInsertAfter, 0, 0, 0, 0, SWP_FRAMECHANGED | SWP_NOSIZE);
		}
		windowFlags &= ~4;
	}
	return ret;
}

// just minimizes the borderless window at user discretion
LRESULT (CALLBACK *O_WindowProc)(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK H_WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (uMsg == WM_ACTIVATE && !LOWORD(wParam))
	{
		if (!(*(DWORD *)0x487A2C && *(BYTE *)((*(DWORD *)0x487A2C) + 0x30) & 2))
		{
			if (windowFlags & 2)
			{
				O_ShowWindow(hwnd, SW_MINIMIZE);
			}
		}
	}
	return O_WindowProc(hwnd, uMsg, wParam, lParam);
}

// allow resizing of dedicated serevr window if desired, not that nice without adjusting the actual output resolution
DETOUR_TRAMPOLINE(HWND WINAPI O_CreateWindowEx(DWORD dwExStyle, LPCTSTR lpClassName, LPCTSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam), CreateWindowEx);
HWND WINAPI H_CreateWindowEx(DWORD dwExStyle, LPCTSTR lpClassName, LPCTSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
	if ((*(DWORD *)0x487E18) && lpWindowName && !strcmp(lpWindowName, "Riot Engine"))
	{
		dwStyle |= WS_THICKFRAME | WS_MAXIMIZEBOX;
	}
	return O_CreateWindowEx(dwExStyle, lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}

/*
*****************************************************
* Simple solution to give us working server browser *
*****************************************************
*/
char server[256] = "www.qtracker.com/server_list_details.php?game=drakan";
char path[256];
// master server address and location of server list are separate arguments,
// splitting code is in DllMain
void (*O_SetMasterAddr)(char *, char *);
void H_SetMasterAddr(char *oserver, char *opath)
{
	oserver = server;
	opath = path;
	O_SetMasterAddr(oserver, opath);
}

// game server address retrieved from master
char addr[256];
char *serveraddr;
char *serverport;
void (*O_FixServerAddr)(void);
void H_FixServerAddr(void)
{
	// get the game server address from master
	__asm mov serveraddr, edx;
	// separate IP from port
	serverport = serveraddr;
	while (*serverport != ':')
		serverport++;
	*serverport = '\0';
	serverport++;
	// feed the address in format the game likes
	// I don't know the purpose of middle integer
	sprintf(addr, "%s %d %s", serveraddr, 0, serverport);
	__asm lea edx, addr;
	O_FixServerAddr();
}

/*
****************************************************
* Hook for our custom function that calculates FOV *
****************************************************
*/
float FOVMultiplier;
void (*O_SetFOV)(float);
// this also multiplies FOV used when zooming in...needs to be fixed
__declspec(naked) void H_SetFOV(float fov)
{
	__asm
	{
		fld dword ptr ss:[esp + 4h];
		fmul dword ptr ds:[FOVMultiplier];
		fstp dword ptr ss:[esp + 4h];
		jmp dword ptr ds:[O_SetFOV];
	}
}

/*
************************************************************************
* Dragon.rfl hooks for FOVMultiplier and DisrespectMaxFogDepth options *
************************************************************************
*/
char DisrespectMaxFogDepth[] = "0";
const BYTE fogBytes[] = { 0x4C, 0xE4, 0x08, 0xEB, 0x07 };
DETOUR_TRAMPOLINE(HMODULE WINAPI O_LoadLibrary(LPCTSTR lpFileName), LoadLibrary);
HMODULE WINAPI H_LoadLibrary(LPCTSTR lpFileName)
{
	HMODULE hDragon = O_LoadLibrary(lpFileName);
	if (strstr(lpFileName, "Dragon.rfl"))
	{
		if (FOVMultiplier && FOVMultiplier > 0.0f)
		{
			O_SetFOV = (void (*)(float))DetourFunction((PBYTE)((DWORD)hDragon + 0x174490), (PBYTE)H_SetFOV);
		}

		if (*DisrespectMaxFogDepth != '0')
		{
			DWORD dwOldProtect;
			DWORD dwPatchBase = (DWORD)hDragon + 0x16FD9;
			VirtualProtect((LPVOID)dwPatchBase, 12, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			memcpy((void *)dwPatchBase, fogBytes, sizeof(fogBytes));
			memset((void *)(dwPatchBase + sizeof(fogBytes)), 0x90, 7);
			VirtualProtect((LPVOID)dwPatchBase, 12, dwOldProtect, &dwOldProtect);
		}

		DetourRemove((PBYTE)O_LoadLibrary, (PBYTE)H_LoadLibrary);
	}
	return hDragon;
}

// proxy stuff
FARPROC DirectInputCreate;
__declspec(naked) void _DirectInputCreate() { __asm { jmp [DirectInputCreate] } }

// for certain compatibility issues
typedef int (WINAPI *SetAppCompatData_)(int index, int data);
typedef VOID (WINAPI *DisableProcessWindowsGhosting_)(void);

// if we need to explicitly load native ddraw.dll
typedef HRESULT (WINAPI *DirectDrawCreate_)(GUID FAR *lpGUID, LPDIRECTDRAW FAR *lplpDD, IUnknown FAR *pUnkOuter);

void FPopulateWindowedResolutions(LPDIRECTDRAW lpDD)
{
	DDSURFACEDESC DDSurfaceDesc;
	DWORD dwOldProtect;
	DDSurfaceDesc.dwSize = sizeof(DDSURFACEDESC);

	IDirectDraw_GetDisplayMode(lpDD, &DDSurfaceDesc);
	IDirectDraw_EnumDisplayModes(lpDD, 0, NULL, &DDSurfaceDesc, EnumModesCallback);
	IDirectDraw_Release(lpDD);
	qsort(displaymodes, index, sizeof(displaymode_t), CompareDisplayModes);
	VirtualProtect((LPVOID)0x43BAFB, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProtect);
	*(DWORD *)0x43BAFB = (DWORD)&(displaymodes[index].width);
	VirtualProtect((LPVOID)0x43BAFB, sizeof(DWORD), dwOldProtect, &dwOldProtect);
}

char SaveWindowedFlag[] = "1";
char BorderlessWindowHooks[] = "0";
char MinimizeOnFocusLost[] = "0";
char ResizableDedicatedServerWindow[] = "1";
char UseCustomURL[] = "1";
char UseCustomFormat[] = "1";
char szFOVMultiplier[16] = "1.0";
const BYTE LODbytes1[] = { 0xC7, 0x81, 0x88, 0x06, 0x00, 0x00 };
const BYTE LODbytes2[] = { 0x83, 0xC4, 0x08, 0xC2, 0x10, 0x00 };
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	// DLL_PROCESS_ATTACH
	if (fdwReason)
	{
		char szPath[MAX_PATH];
		HMODULE hDInput;
		char *temp;
		char PopulateWindowedResolutions[] = "1";
		HMODULE hUser32;
		HMODULE hDDraw;
		SetAppCompatData_ SetAppCompatData;
		char szLODFactor[16];
		float LODFactor;

		// not interested in those
		DisableThreadLibraryCalls(hinstDLL);

		// setup proxy stuff
		GetSystemDirectory(szPath, MAX_PATH);
		strcat(szPath, "\\dinput.dll");
		hDInput = LoadLibrary(szPath);
		DirectInputCreate = GetProcAddress(hDInput, "DirectInputCreateA");

		hDDraw = GetModuleHandle("ddraw.dll");
		hUser32 = GetModuleHandle("user32.dll");

		SetAppCompatData = (SetAppCompatData_)GetProcAddress(hDDraw, "SetAppCompatData");

		// we're running on Win7+ through native ddraw.dll
		if (SetAppCompatData)
		{
			DisableProcessWindowsGhosting_ DisableProcessWindowsGhosting;

			// disable maximized windowed mode, only applicable to Win8+, it does nothing on 7
			SetAppCompatData(12, 0);

			// because game window is considered unresponsive for some reason when it loses focus (5s delay)
			DisableProcessWindowsGhosting = (DisableProcessWindowsGhosting_)GetProcAddress(hUser32, "DisableProcessWindowsGhosting");
			DisableProcessWindowsGhosting();
		}

		// setup path to our config file, act according to config options
		GetModuleFileName(NULL, szPath, MAX_PATH);
		temp = strrchr(szPath, '\\');
		temp++;
		*temp = '\0';
		strcat(szPath, "Arokh.ini");

		if (GetPrivateProfileInt("Window", "SaveWindowedFlag", 1, szPath))
		{
			DetourFunctionWithTrampoline((PBYTE)O_RegSetValueEx, (PBYTE)H_RegSetValueEx);
		}
		else
		{
			*SaveWindowedFlag = '0';
		}

		// use DirectDraw interfaces to retrieve display mode list
		if (GetPrivateProfileInt("Window", "PopulateWindowedResolutions", 1, szPath))
		{
			LPDIRECTDRAW lpDD;

			// DDCREATE_EMULATIONONLY because we don't want to invoke graphics driver DLLs from DllMain
			if (!DirectDrawCreate((GUID *)DDCREATE_EMULATIONONLY, &lpDD, NULL))
			{
				FPopulateWindowedResolutions(lpDD);
			}
			// oops, we're probably running through dgVoodoo, so temporarily load native ddraw.dll
			else
			{
				char szPath[MAX_PATH];
				DirectDrawCreate_ DirectDrawCreate__;

				GetSystemDirectory(szPath, MAX_PATH);
				strcat(szPath, "\\ddraw.dll");
				hDDraw = LoadLibrary(szPath);
				DirectDrawCreate__ = (DirectDrawCreate_)GetProcAddress(hDDraw, "DirectDrawCreate");

				if (!DirectDrawCreate__((GUID *)DDCREATE_EMULATIONONLY, &lpDD, NULL))
				{
					FPopulateWindowedResolutions(lpDD);
				}

				FreeLibrary(hDDraw);
			}
		}
		else
		{
			*PopulateWindowedResolutions = '0';
		}

		if (GetPrivateProfileInt("Window", "BorderlessWindowHooks", 0, szPath))
		{
			MonitorFromWindow__ = (MonitorFromWindow_)GetProcAddress(hUser32, "MonitorFromWindow");
			GetMonitorInfo__ = (GetMonitorInfo_)GetProcAddress(hUser32, "GetMonitorInfoA");

			DetourFunctionWithTrampoline((PBYTE)O_AdjustWindowRectEx, (PBYTE)H_AdjustWindowRectEx);
			DetourFunctionWithTrampoline((PBYTE)O_SetWindowPos, (PBYTE)H_SetWindowPos);
			DetourFunctionWithTrampoline((PBYTE)O_ShowWindow, (PBYTE)H_ShowWindow);

			*BorderlessWindowHooks = '1';
		}

		if (GetPrivateProfileInt("Window", "MinimizeOnFocusLost", 0, szPath))
		{
			if (*BorderlessWindowHooks != '0')
			{
				O_WindowProc = (LRESULT (CALLBACK *)(HWND, UINT, WPARAM, LPARAM))DetourFunction((PBYTE)0x412B70, (PBYTE)H_WindowProc);
			}
			*MinimizeOnFocusLost = '1';
		}

		if (GetPrivateProfileInt("Window", "BorderlessTopmost", 0, szPath))
		{
			*BorderlessTopmost = '1';
		}

		if (GetPrivateProfileInt("Window", "ResizableDedicatedServerWindow", 1, szPath))
		{
			DetourFunctionWithTrampoline((PBYTE)O_CreateWindowEx, (PBYTE)H_CreateWindowEx);
		}
		else
		{
			*ResizableDedicatedServerWindow = '0';
		}

		if (GetPrivateProfileInt("ServerBrowser", "UseCustomURL", 1, szPath))
		{
			O_SetMasterAddr = (void (*)(char *, char *))DetourFunction((PBYTE)0x45F990, (PBYTE)H_SetMasterAddr);
			GetPrivateProfileString("ServerBrowser", "ServerListURL", server, server, sizeof(server), szPath);
		}
		else
		{
			*UseCustomURL = '0';
		}

		if (GetPrivateProfileInt("ServerBrowser", "UseCustomFormat", 1, szPath))
		{
			O_FixServerAddr = (void (*)(void))DetourFunction((PBYTE)0x45FB50, (PBYTE)H_FixServerAddr);
		}
		else
		{
			*UseCustomFormat = '0';
		}

		GetPrivateProfileString("Misc", "LODFactor", "0.0", szLODFactor, sizeof(szLODFactor), szPath);
		LODFactor = (float)atof(szLODFactor);

		if (LODFactor && LODFactor > 0.0f)
		{
			DWORD dwOldProtect;

			VirtualProtect((LPVOID)0x43AB63, 16, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			memcpy((void *)0x43AB63, LODbytes1, sizeof(LODbytes1));
			memcpy((void *)0x43AB69, &LODFactor, sizeof(LODFactor));
			memcpy((void *)0x43AB6D, LODbytes2, sizeof(LODbytes2));
			VirtualProtect((LPVOID)0x43AB63, 16, dwOldProtect, &dwOldProtect);
		}

		GetPrivateProfileString("Misc", "FOVMultiplier", "1.0", szFOVMultiplier, sizeof(szFOVMultiplier), szPath);
		FOVMultiplier = (float)atof(szFOVMultiplier);
		if (GetPrivateProfileInt("Misc", "DisrespectMaxFogDepth", 0, szPath))
		{
			*DisrespectMaxFogDepth = '1';
		}

		if ((FOVMultiplier && FOVMultiplier > 0.0f) || *DisrespectMaxFogDepth != '0')
		{
			DetourFunctionWithTrampoline((PBYTE)O_LoadLibrary, (PBYTE)H_LoadLibrary);
		}

		// ensure all configurable options end up in our config
		WritePrivateProfileString("Window", "SaveWindowedFlag", SaveWindowedFlag, szPath);
		WritePrivateProfileString("Window", "PopulateWindowedResolutions", PopulateWindowedResolutions, szPath);
		WritePrivateProfileString("Window", "BorderlessWindowHooks", BorderlessWindowHooks, szPath);
		WritePrivateProfileString("Window", "MinimizeOnFocusLost", MinimizeOnFocusLost, szPath);
		WritePrivateProfileString("Window", "BorderlessTopmost", BorderlessTopmost, szPath);
		WritePrivateProfileString("Window", "ResizableDedicatedServerWindow", ResizableDedicatedServerWindow, szPath);
		WritePrivateProfileString("ServerBrowser", "UseCustomURL", UseCustomURL, szPath);
		WritePrivateProfileString("ServerBrowser", "UseCustomFormat", UseCustomFormat, szPath);
		WritePrivateProfileString("ServerBrowser", "ServerListURL", server, szPath);
		WritePrivateProfileString("Misc", "LODFactor", szLODFactor, szPath);
		WritePrivateProfileString("Misc", "FOVMultiplier", szFOVMultiplier, szPath);
		WritePrivateProfileString("Misc", "DisrespectMaxFogDepth", DisrespectMaxFogDepth, szPath);

		temp = server;
		// fix slashes
		while (*temp)
		{
			if (*temp == '\\')
			{
				*temp = '/';
			}
			temp++;
		}

		// separate master server address from location of server list
		if (temp = strchr(server, '/'))
		{
			*temp = '\0';
			temp++;
			sprintf(path, "/%s", temp);
		}
	}
	// DLL_PROCESS_DETACH
	// clean-up, ensure we can be unloaded even mid-game without crashing
	else
	{
		if (FOVMultiplier && FOVMultiplier > 0.0f)
		{
			if (GetModuleHandle("Dragon.rfl"))
			{
				DetourRemove((PBYTE)O_SetFOV, (PBYTE)H_SetFOV);
			}
		}

		if (*UseCustomFormat != '0')
		{
			DetourRemove((PBYTE)O_FixServerAddr, (PBYTE)H_FixServerAddr);
		}

		if (*UseCustomURL != '0')
		{
			DetourRemove((PBYTE)O_SetMasterAddr, (PBYTE)H_SetMasterAddr);
		}

		if (*ResizableDedicatedServerWindow != '0')
		{
			DetourRemove((PBYTE)O_CreateWindowEx, (PBYTE)H_CreateWindowEx);
		}

		if (*BorderlessWindowHooks != '0')
		{
			DetourRemove((PBYTE)O_AdjustWindowRectEx, (PBYTE)H_AdjustWindowRectEx);
			DetourRemove((PBYTE)O_SetWindowPos, (PBYTE)H_SetWindowPos);
			DetourRemove((PBYTE)O_ShowWindow, (PBYTE)H_ShowWindow);

			if (*MinimizeOnFocusLost != '0')
			{
				DetourRemove((PBYTE)O_WindowProc, (PBYTE)H_WindowProc);
			}
		}

		if (*SaveWindowedFlag != '0')
		{
			DetourRemove((PBYTE)O_RegSetValueEx, (PBYTE)H_RegSetValueEx);
		}
	}
	return TRUE;
}
