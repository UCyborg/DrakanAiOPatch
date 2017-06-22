#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <ddraw.h>
#include "detours.h"

#pragma comment(lib, "ddraw")

#define NAKED __declspec(naked)

DETOUR_TRAMPOLINE(LONG WINAPI O_RegSetValueEx(HKEY hKey, LPCTSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData), RegSetValueEx);
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

typedef struct displaymode_s
{
	DWORD width;
	DWORD height;
	DWORD bpp;
} displaymode_t;

// this array is used for display modes in windowed mode
displaymode_t *displaymodes = (displaymode_t *)0x48C000;
size_t index;
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
	int pp = (int)(((displaymode_t *)p)->width * ((displaymode_t *)p)->height);
	int qq = (int)(((displaymode_t *)q)->width * ((displaymode_t *)q)->height);

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
*                                                               *
* And of-course, 3rd party DLLs may call those APIs so subtle   *
* bugs can show up on an occassion.                             *
*****************************************************************
*/
DWORD windowFlags = 4;
int currentWidth;
int currentHeight;
int width;
int height;
char BorderlessTopmost[] = "0";
DETOUR_TRAMPOLINE(BOOL WINAPI O_AdjustWindowRectEx(LPRECT lpRect, DWORD dwStyle, BOOL bMenu, DWORD dwExStyle), AdjustWindowRectEx);
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

		currentWidth = (int)(hInfo.rcMonitor.right - hInfo.rcMonitor.left);
		currentHeight = (int)(hInfo.rcMonitor.bottom - hInfo.rcMonitor.top);
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

DETOUR_TRAMPOLINE(BOOL WINAPI O_SetWindowPos(HWND hWnd, HWND hWndInsertAfter, int X, int Y, int cx, int cy, UINT uFlags), SetWindowPos);
BOOL WINAPI H_SetWindowPos(HWND hWnd, HWND hWndInsertAfter, int X, int Y, int cx, int cy, UINT uFlags)
{
	// dedicated server is running
	if (*(PDWORD)0x487E18)
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
				if (PTR_MonitorFromWindow)
				{
					HMONITOR hMonitor;
					MONITORINFO hInfo;

					hMonitor = PTR_MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
					hInfo.cbSize = sizeof(MONITORINFO);
					PTR_GetMonitorInfo(hMonitor, &hInfo);

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
		if (PTR_MonitorFromWindow)
		{
			HMONITOR hMonitor;
			MONITORINFO hInfo;

			hMonitor = PTR_MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
			hInfo.cbSize = sizeof(MONITORINFO);
			PTR_GetMonitorInfo(hMonitor, &hInfo);

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
DETOUR_TRAMPOLINE(HWND WINAPI O_CreateWindowEx(DWORD dwExStyle, LPCTSTR lpClassName, LPCTSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam), CreateWindowEx);
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
*****************************************************
*/
char server[128];
char *path;
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
char addr[32];
char *serveraddr;
char *serverport;
void (*O_FixServerAddr)(void);
void H_FixServerAddr(void)
{
	// get the game server address from master
	__asm mov serveraddr, edx
	// separate IP from port
	serverport = serveraddr;
	while (*serverport != ':')
		serverport++;
	*serverport = '\0';
	serverport++;
	// feed the address in format the game likes
	// I don't know the purpose of middle integer
	sprintf(addr, "%s 0 %s", serveraddr, serverport);
	__asm lea edx, addr
	O_FixServerAddr();
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
DWORD_PTR retaddr = 0x437ba6;
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
		jmp dword ptr ds:[retaddr]
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
****************************************************
* Hook for our custom function that calculates FOV *
****************************************************
*/
float FOVMultiplier;
void (*O_SetFOV)(void);
// this also multiplies FOV used when zooming in...
// maybe add an option to adjust zoom-in FOV separately
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
*****************
* 445 SP1 Patch *
*****************
*/
const BYTE LeftForwardCamOrig[] = { 0xC7, 0x44, 0x24, 0x1C, 0xCB, 0xE9, 0xAC, 0xBF, 0x89, 0x44, 0x24, 0x10 };
const BYTE LeftForwardCamPatch[] = { 0x89, 0x44, 0x24, 0x10, 0xE9, 0x03, 0x04, 0x00, 0x00, 0x90, 0x90, 0x90 };

const BYTE ForwardBackCamOrig[] = { 0xC7, 0x44, 0x24, 0x1C, 0xDA, 0x0F, 0x49, 0xC0, 0x89, 0x44, 0x24, 0x10 };
const BYTE ForwardBackCamPatch[] = { 0x89, 0x44, 0x24, 0x10, 0xE9, 0x41, 0x03, 0x00, 0x00, 0x90, 0x90, 0x90 };

const BYTE AttackIntervalOrig[] = { 0x68, 0x33, 0x33, 0x33, 0x3F };
// just a jump, the rest is in Dragon.rfl
const BYTE AttackIntervalPatch[] = { 0xE9, 0x0A, 0x84, 0x10, 0x00 };

HMODULE hDragon;
DWORD dwOldProtect;
BOOL Apply445SP1(BOOL patch)
{
	if (patch)
	{
		VirtualProtect((LPVOID)((DWORD_PTR)hDragon + 0x60E1B), sizeof(LeftForwardCamPatch), PAGE_EXECUTE_READWRITE, &dwOldProtect);
		memcpy((void *)((DWORD_PTR)hDragon + 0x60E1B), LeftForwardCamPatch, sizeof(LeftForwardCamPatch));
		VirtualProtect((LPVOID)((DWORD_PTR)hDragon + 0x60E1B), sizeof(LeftForwardCamPatch), dwOldProtect, &dwOldProtect);

		VirtualProtect((LPVOID)((DWORD_PTR)hDragon + 0x60EDD), sizeof(ForwardBackCamPatch), PAGE_EXECUTE_READWRITE, &dwOldProtect);
		memcpy((void *)((DWORD_PTR)hDragon + 0x60EDD), ForwardBackCamPatch, sizeof(ForwardBackCamPatch));
		VirtualProtect((LPVOID)((DWORD_PTR)hDragon + 0x60EDD), sizeof(ForwardBackCamPatch), dwOldProtect, &dwOldProtect);

		VirtualProtect((LPVOID)((DWORD_PTR)hDragon + 0x6C161), sizeof(AttackIntervalPatch), PAGE_EXECUTE_READWRITE, &dwOldProtect);
		memcpy((void *)((DWORD_PTR)hDragon + 0x6C161), AttackIntervalPatch, sizeof(AttackIntervalPatch));
		VirtualProtect((LPVOID)((DWORD_PTR)hDragon + 0x6C161), sizeof(AttackIntervalPatch), dwOldProtect, &dwOldProtect);
	}
	else
	{
		VirtualProtect((LPVOID)((DWORD_PTR)hDragon + 0x60E1B), sizeof(LeftForwardCamOrig), PAGE_EXECUTE_READWRITE, &dwOldProtect);
		memcpy((void *)((DWORD_PTR)hDragon + 0x60E1B), LeftForwardCamOrig, sizeof(LeftForwardCamOrig));
		VirtualProtect((LPVOID)((DWORD_PTR)hDragon + 0x60E1B), sizeof(LeftForwardCamOrig), dwOldProtect, &dwOldProtect);

		VirtualProtect((LPVOID)((DWORD_PTR)hDragon + 0x60EDD), sizeof(ForwardBackCamOrig), PAGE_EXECUTE_READWRITE, &dwOldProtect);
		memcpy((void *)((DWORD_PTR)hDragon + 0x60EDD), ForwardBackCamOrig, sizeof(ForwardBackCamOrig));
		VirtualProtect((LPVOID)((DWORD_PTR)hDragon + 0x60EDD), sizeof(ForwardBackCamOrig), dwOldProtect, &dwOldProtect);

		VirtualProtect((LPVOID)((DWORD_PTR)hDragon + 0x6C161), sizeof(AttackIntervalOrig), PAGE_EXECUTE_READWRITE, &dwOldProtect);
		memcpy((void *)((DWORD_PTR)hDragon + 0x6C161), AttackIntervalOrig, sizeof(AttackIntervalOrig));
		VirtualProtect((LPVOID)((DWORD_PTR)hDragon + 0x6C161), sizeof(AttackIntervalOrig), dwOldProtect, &dwOldProtect);
	}
	return patch;
}

char **levelFileIndex;
size_t SP1LevelCount;
BOOL patched;
void (*O_LevelFileHook)(void);
void H_LevelFileHook(void)
{
	char *szLevelName;
	BOOL match;
	size_t i;

	__asm mov szLevelName, ebx

	szLevelName = strrchr(szLevelName, '\\') + 1;
	match = FALSE;

	for (i = 0; i < SP1LevelCount; i++)
	{
		if (levelFileIndex[i] && !_stricmp(szLevelName, levelFileIndex[i]))
		{
			match = TRUE;
			break;
		}
	}

	if (match)
	{
		if (!patched)
		{
			patched = Apply445SP1(TRUE);
		}
	}
	else
	{
		if (patched)
		{
			patched = Apply445SP1(FALSE);
		}
	}

	O_LevelFileHook();
}

/*
********************************************************************
* Dragon.rfl hooks for FOVMultiplier and IgnoreMaxFogDepth options *
********************************************************************
*/
char IgnoreMaxFogDepth[] = "0";
const BYTE origBytes[] = { 0x08, 0x6A, 0xFF, 0x6A, 0x03, 0x8B, 0x11, 0xFF, 0x52, 0x04, 0x8B, 0x08 };
void RemoveStaticRFLHooks(void)
{
	if (*IgnoreMaxFogDepth != '0')
	{
		DWORD_PTR dwPatchBase = (DWORD_PTR)hDragon + 0x16FD9;
		VirtualProtect((LPVOID)dwPatchBase, sizeof(origBytes), PAGE_EXECUTE_READWRITE, &dwOldProtect);
		memcpy((void *)dwPatchBase, origBytes, sizeof(origBytes));
		VirtualProtect((LPVOID)dwPatchBase, sizeof(origBytes), dwOldProtect, &dwOldProtect);
	}

	if (O_SetFOV)
	{
		DetourRemove((PBYTE)O_SetFOV, (PBYTE)H_SetFOV);
	}
}

DETOUR_TRAMPOLINE(BOOL WINAPI O_FreeLibrary(HMODULE hModule), FreeLibrary);
BOOL WINAPI H_FreeLibrary(HMODULE hModule)
{
	if (hModule == hDragon)
	{
		if (O_LevelFileHook)
		{
			DetourRemove((PBYTE)O_LevelFileHook, (PBYTE)H_LevelFileHook);
			if (patched)
			{
				Apply445SP1(FALSE);
			}
		}

		RemoveStaticRFLHooks();
		hDragon = NULL;
		DetourRemove((PBYTE)O_FreeLibrary, (PBYTE)H_FreeLibrary);
	}
	return O_FreeLibrary(hModule);
}

const BYTE fogBytes[] = { 0x4C, 0xE4, 0x08, 0xEB, 0x07 };
void InstallStaticRFLHooks(void)
{
	if (FOVMultiplier > 1.0f)
	{
		O_SetFOV = (void (*)(void))DetourFunction((PBYTE)(DWORD_PTR)hDragon + 0x174490, (PBYTE)H_SetFOV);
	}

	if (*IgnoreMaxFogDepth != '0')
	{
		DWORD_PTR dwPatchBase = (DWORD_PTR)hDragon + 0x16FD9;
		VirtualProtect((LPVOID)dwPatchBase, sizeof(fogBytes) + 7, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		memcpy((void *)dwPatchBase, fogBytes, sizeof(fogBytes));
		memset((void *)(dwPatchBase + sizeof(fogBytes)), 0x90, 7);
		VirtualProtect((LPVOID)dwPatchBase, sizeof(fogBytes) + 7, dwOldProtect, &dwOldProtect);
	}
}

DETOUR_TRAMPOLINE(HMODULE WINAPI O_LoadLibrary(LPCTSTR lpFileName), LoadLibrary);
HMODULE WINAPI H_LoadLibrary(LPCTSTR lpFileName)
{
	HMODULE hModule = O_LoadLibrary(lpFileName);
	if (hModule)
	{
		size_t len = strlen(lpFileName);
		if (len >= 10 && !_stricmp(&lpFileName[len - 10], "Dragon.rfl"))
		{
			PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);

			if (pNtHeaders->FileHeader.TimeDateStamp != 0x389F846E || pNtHeaders->FileHeader.NumberOfSections != 6)
			{
				// wrong RFL
				O_FreeLibrary(hModule);
				return NULL;
			}

			hDragon = hModule;
			InstallStaticRFLHooks();
			DetourRemove((PBYTE)O_LoadLibrary, (PBYTE)H_LoadLibrary);
		}
	}
	return hModule;
}

int (CALLBACK *O_WinMain)(HINSTANCE, HINSTANCE, LPSTR, int);
int CALLBACK H_WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	char szPath[MAX_PATH];
	char *temp;
	HMODULE hDDraw;
	LPDIRECTDRAW lpDD;
	int (WINAPI *PTR_SetAppCompatData)(int, int);

	GetModuleFileName(hInstance, szPath, MAX_PATH);
	GetLongPathName(szPath, szPath, MAX_PATH);

	temp = strrchr(szPath, '\\') + 1;

	if (_stricmp(temp, "Drakan.exe"))
	{
		if (MessageBox(NULL, "The executable file is not named Drakan.exe. This causes Invalid or corrupted level! error in multiplayer because server and clients must have matching executable file, including its name. Click OK to continue or Cancel to quit.", "Warning", MB_OKCANCEL | MB_ICONWARNING) == IDCANCEL)
		{
			return 0;
		}
	}

	hDDraw = GetModuleHandle("ddraw.dll");
	PTR_SetAppCompatData = (int (WINAPI *)(int, int))GetProcAddress(hDDraw, "SetAppCompatData");

	// we're running on Win7+ through native ddraw.dll
	if (PTR_SetAppCompatData)
	{
		// disable maximized windowed mode, only applicable to Win8+, it doesn't do anything on 7
		PTR_SetAppCompatData(12, 0);
	}

	// no need to invoke graphics driver just to get resolutions, though it only works with native DirectDraw
	if (!DirectDrawCreate((GUID *)DDCREATE_EMULATIONONLY, &lpDD, NULL))
	{
		DDSURFACEDESC DDSurfaceDesc;
		DDSurfaceDesc.dwSize = sizeof(DDSURFACEDESC);

		if (!IDirectDraw_GetDisplayMode(lpDD, &DDSurfaceDesc))
		{
			IDirectDraw_EnumDisplayModes(lpDD, 0, NULL, &DDSurfaceDesc, EnumModesCallback);

			if (index)
			{
				qsort(displaymodes, index, sizeof(displaymode_t), CompareDisplayModes);
				VirtualProtect((LPVOID)0x43BAFB, sizeof(DWORD_PTR), PAGE_EXECUTE_READWRITE, &dwOldProtect);
				*(PDWORD_PTR)0x43BAFB = (DWORD_PTR)&(displaymodes[index].width);
				VirtualProtect((LPVOID)0x43BAFB, sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect);
			}
		}

		IDirectDraw_Release(lpDD);
	}

	return O_WinMain(hInstance, hPrevInstance, lpCmdLine, nCmdShow);
}

// proxy stuff
FARPROC PTR_DirectInputCreate;
NAKED void FDirectInputCreate(void) { __asm { jmp [PTR_DirectInputCreate] } }

char BorderlessWindowHooks[] = "0";
char MinimizeOnFocusLost[] = "0";
char ResizableDedicatedServerWindow[] = "0";
char UseCustomURL[] = "1";
char UseCustomFormat[] = "1";
char TexelShiftMode[] = "1";
char RefreshRate[4] = "0";
char szFOVMultiplier[16] = "1.0";
float LODFactor;
const BYTE LODbytes1[] = { 0xC7, 0x81, 0x88, 0x06, 0x00, 0x00 };
const BYTE LODbytes2[] = { 0xD9, 0x99, 0xBC, 0x06, 0x00, 0x00, 0xDF, 0x6C, 0x24, 0x04, 0x5B, 0xD9, 0x99, 0xC4, 0x06, 0x00, 0x00, 0x83, 0xC4, 0x08, 0xC2, 0x10, 0x00 };
const BYTE origLODbytes[] = { 0x89, 0x99, 0x88, 0x06, 0x00, 0x00, 0xD9, 0x99, 0xBC, 0x06, 0x00, 0x00, 0xDF, 0x6C, 0x24, 0x04, 0x5B, 0xD9, 0x99, 0xC4, 0x06, 0x00, 0x00, 0x83, 0xC4, 0x08, 0xC2, 0x10, 0x00, 0x90, 0x90, 0x90, 0x90 };
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	size_t levelFileCount;

	// DLL_PROCESS_ATTACH
	if (fdwReason)
	{
		PIMAGE_DOS_HEADER pDosHeader;
		PIMAGE_NT_HEADERS pNtHeaders;
		char szPath[MAX_PATH];
		HMODULE hDInput;
		char *temp;
		size_t serverURLlength;
		char szLODFactor[16];

		pDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
		pNtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)pDosHeader + pDosHeader->e_lfanew);

		if (pNtHeaders->FileHeader.TimeDateStamp != 0x38979d2d || pNtHeaders->FileHeader.NumberOfSections != 5)
		{
			// definitely not the .exe we're designed for
			return FALSE;
		}

		// not interested in those
		DisableThreadLibraryCalls(hinstDLL);

		// setup proxy stuff
		GetSystemDirectory(szPath, MAX_PATH);
		strcat(szPath, "\\dinput.dll");
		// support for being loaded again after forceful unload by external means (more for testing and being cool)
		if (hDInput = GetModuleHandle(szPath))
		{
			hDragon = GetModuleHandle("Dragon.rfl");
		}
		else
		{
			hDInput = LoadLibrary(szPath);
		}
		PTR_DirectInputCreate = GetProcAddress(hDInput, "DirectInputCreateA");

		// setup path to our config file, act according to config options
		GetModuleFileName(NULL, szPath, MAX_PATH);
		temp = strrchr(szPath, '\\') + 1;
		*temp = '\0';
		strcat(szPath, "Arokh.ini");

		O_WinMain = (int (CALLBACK *)(HINSTANCE, HINSTANCE, LPSTR, int))DetourFunction((PBYTE)0x4127F0, (PBYTE)H_WinMain);

		DetourFunctionWithTrampoline((PBYTE)O_RegSetValueEx, (PBYTE)H_RegSetValueEx);

		if (GetPrivateProfileInt("Window", "BorderlessWindowHooks", 0, szPath))
		{
			HMODULE hUser32 = GetModuleHandle("user32.dll");
			PTR_MonitorFromWindow = (HMONITOR (WINAPI *)(HWND, DWORD))GetProcAddress(hUser32, "MonitorFromWindow");
			PTR_GetMonitorInfo = (BOOL (WINAPI *)(HMONITOR, LPMONITORINFO))GetProcAddress(hUser32, "GetMonitorInfoA");

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

		if (GetPrivateProfileInt("Window", "ResizableDedicatedServerWindow", 0, szPath))
		{
			DetourFunctionWithTrampoline((PBYTE)O_CreateWindowEx, (PBYTE)H_CreateWindowEx);

			*ResizableDedicatedServerWindow = '1';
		}

		if (GetPrivateProfileInt("ServerBrowser", "UseCustomURL", 1, szPath))
		{
			// we need 1 byte of extra space to be able to split string
			serverURLlength = GetPrivateProfileString("ServerBrowser", "ServerListURL", "www.qtracker.com/server_list_details.php?game=drakan", server, sizeof(server) - 1, szPath);
			O_SetMasterAddr = (void (*)(char *, char *))DetourFunction((PBYTE)0x45F990, (PBYTE)H_SetMasterAddr);

			*UseCustomURL = '1';
		}

		if (GetPrivateProfileInt("ServerBrowser", "UseCustomFormat", 1, szPath))
		{
			O_FixServerAddr = (void (*)(void))DetourFunction((PBYTE)0x45FB50, (PBYTE)H_FixServerAddr);

			*UseCustomFormat = '1';
		}

		if (GetPrivateProfileInt("Misc", "TexelShiftMode", 1, szPath))
		{
			O_TexelAlignment = (void (*)(void))DetourFunction((PBYTE)0x437B75, (PBYTE)H_TexelAlignment);

			*TexelShiftMode = '1';
		}

		if (refreshRate = GetPrivateProfileInt("Misc", "RefreshRate", 0, szPath))
		{
			O_SetDisplayMode = (void (*)(void))DetourFunction((PBYTE)0x439330, (PBYTE)H_SetDisplayMode);

			_itoa(refreshRate, RefreshRate, 10);
		}

		GetPrivateProfileString("Misc", "LODFactor", "0.0", szLODFactor, sizeof(szLODFactor), szPath);
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
			VirtualProtect((LPVOID)0x43AB52, sizeof(LODbytes1) + sizeof(LODFactor) + sizeof(LODbytes2), PAGE_EXECUTE_READWRITE, &dwOldProtect);
			memcpy((void *)0x43AB52, LODbytes1, sizeof(LODbytes1));
			memcpy((void *)0x43AB58, &LODFactor, sizeof(LODFactor));
			memcpy((void *)0x43AB5C, LODbytes2, sizeof(LODbytes2));
			VirtualProtect((LPVOID)0x43AB52, sizeof(LODbytes1) + sizeof(LODFactor) + sizeof(LODbytes2), dwOldProtect, &dwOldProtect);
		}

		if (GetPrivateProfileInt("Misc", "IgnoreMaxFogDepth", 0, szPath))
		{
			*IgnoreMaxFogDepth = '1';
		}

		GetPrivateProfileString("Misc", "FOVMultiplier", "1.0", szFOVMultiplier, sizeof(szFOVMultiplier), szPath);
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

		if (FOVMultiplier > 1.0f || *IgnoreMaxFogDepth != '0' || SP1LevelCount)
		{
			DetourFunctionWithTrampoline((PBYTE)O_LoadLibrary, (PBYTE)H_LoadLibrary);
			DetourFunctionWithTrampoline((PBYTE)O_FreeLibrary, (PBYTE)H_FreeLibrary);
		}

		// read in list of levels for which we should apply 445SP1 patch
		if (levelFileCount = GetPrivateProfileInt("445SP1", "FileCount", 0, szPath))
		{
			if (levelFileIndex = malloc(sizeof(*levelFileIndex) * levelFileCount))
			{
				char szLevelName[64];
				size_t allocSize;

				for (; levelFileCount; SP1LevelCount++, levelFileCount--)
				{
					sprintf(szLevelName, "Level%u", SP1LevelCount + 1);
					if (allocSize = GetPrivateProfileString("445SP1", szLevelName, NULL, szLevelName, sizeof(szLevelName), szPath))
					{
						if (levelFileIndex[SP1LevelCount] = malloc(allocSize + 1))
						{
							strcpy(levelFileIndex[SP1LevelCount], szLevelName);
						}
						else
						{
							// something's really wrong if this happens
							return FALSE;
						}
					}
					else
					{
						levelFileIndex[SP1LevelCount] = NULL;
					}
				}

				O_LevelFileHook = (void (*)(void))DetourFunction((PBYTE)0x438117, (PBYTE)H_LevelFileHook);
			}
			else
			{
				return FALSE;
			}
		}

		if (hDragon)
		{
			InstallStaticRFLHooks();
		}

		// ensure all configurable options end up in our config
		WritePrivateProfileString("Window", "BorderlessWindowHooks", BorderlessWindowHooks, szPath);
		WritePrivateProfileString("Window", "MinimizeOnFocusLost", MinimizeOnFocusLost, szPath);
		WritePrivateProfileString("Window", "BorderlessTopmost", BorderlessTopmost, szPath);
		WritePrivateProfileString("Window", "ResizableDedicatedServerWindow", ResizableDedicatedServerWindow, szPath);

		WritePrivateProfileString("ServerBrowser", "UseCustomURL", UseCustomURL, szPath);
		WritePrivateProfileString("ServerBrowser", "UseCustomFormat", UseCustomFormat, szPath);
		WritePrivateProfileString("ServerBrowser", "ServerListURL", server, szPath);

		WritePrivateProfileString("Misc", "LODFactor", szLODFactor, szPath);
		WritePrivateProfileString("Misc", "FOVMultiplier", szFOVMultiplier, szPath);
		WritePrivateProfileString("Misc", "IgnoreMaxFogDepth", IgnoreMaxFogDepth, szPath);
		WritePrivateProfileString("Misc", "TexelShiftMode", TexelShiftMode, szPath);
		WritePrivateProfileString("Misc", "RefreshRate", RefreshRate, szPath);

		if (*UseCustomURL == '1')
		{
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
				memmove(path = temp + 1, temp, strlen(temp) + 1);
				*temp = '\0';
			}
			else
			{
				path = &server[serverURLlength];
				*++path = '/';
			}
		}
	}
	// DLL_PROCESS_DETACH
	// clean-up, ensure we can be unloaded even mid-game without crashing
	else
	{
		if (hDragon)
		{
			if (O_LevelFileHook)
			{
				DetourRemove((PBYTE)O_LevelFileHook, (PBYTE)H_LevelFileHook);

				if (patched)
				{
					Apply445SP1(FALSE);
				}
			}

			RemoveStaticRFLHooks();
			DetourRemove((PBYTE)O_FreeLibrary, (PBYTE)H_FreeLibrary);
		}

		if (SP1LevelCount)
		{
			for (levelFileCount = 0; levelFileCount < SP1LevelCount; levelFileCount++)
			{
				free(levelFileIndex[levelFileCount]);
			}

			free(levelFileIndex);
		}

		if (LODFactor > 0.0f)
		{
			VirtualProtect((LPVOID)0x43AB52, sizeof(origLODbytes), PAGE_EXECUTE_READWRITE, &dwOldProtect);
			memcpy((void *)0x43AB52, origLODbytes, sizeof(origLODbytes));
			VirtualProtect((LPVOID)0x43AB52, sizeof(origLODbytes), dwOldProtect, &dwOldProtect);
		}

		if (*RefreshRate != '0')
		{
			DetourRemove((PBYTE)O_SetDisplayMode, (PBYTE)H_SetDisplayMode);
		}

		if (*TexelShiftMode != '0')
		{
			DetourRemove((PBYTE)O_TexelAlignment, (PBYTE)H_TexelAlignment);
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
			if (O_WindowProc)
			{
				DetourRemove((PBYTE)O_WindowProc, (PBYTE)H_WindowProc);
			}

			DetourRemove((PBYTE)O_ShowWindow, (PBYTE)H_ShowWindow);
			DetourRemove((PBYTE)O_SetWindowPos, (PBYTE)H_SetWindowPos);
			DetourRemove((PBYTE)O_AdjustWindowRectEx, (PBYTE)H_AdjustWindowRectEx);
		}

		DetourRemove((PBYTE)O_RegSetValueEx, (PBYTE)H_RegSetValueEx);
		DetourRemove((PBYTE)O_WinMain, (PBYTE)H_WinMain);
	}

	return TRUE;
}
