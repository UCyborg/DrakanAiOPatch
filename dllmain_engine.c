/*
*****************************************************************
*    Drakan: Order of the Flame All in One Patch (DLL part)     *
*                                                               *
*           Copyright © 2016 - 2018 UCyborg                     *
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
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <ImageHlp.h>
#include <ddraw.h>
#include <dinput.h>
#include "detours.h"

#pragma comment(lib, "ddraw")
#pragma comment(lib, "ImageHlp")
#pragma comment(lib, "WinMM")

#ifndef _countof
#define _countof(array) (sizeof(array)/sizeof(array[0]))
#endif

#define NAKED __declspec(naked)

// not sure what exactly causes this to be needed
// uncomment if it crashes on Windows 9x
#define WIN9X_HACK

#define MDL_MODE	(1 << 0)
#define MDL_SWITCH	(1 << 1)
#define MDL_STATE	(1 << 2)
#define MDL_STATE2	(1 << 3)

BOOL space;
DWORD modelFlags = MDL_SWITCH;
DWORD stompTime;

void (*O_getmodelmode)(void);
NAKED void H_getmodelmode(void)
{
	__asm
	{
		or dword ptr ds:[modelFlags], eax
		push eax
	}
	DetourRemove((PBYTE)O_getmodelmode, (PBYTE)H_getmodelmode);
	__asm
	{
		pop eax
		jmp dword ptr ds:[O_getmodelmode]
	}
}

BOOL (WINAPI *O_PeekMessage)(LPMSG, HWND, UINT, UINT, UINT);
BOOL WINAPI H_PeekMessage(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg)
{
	if (stompTime)
	{
		if (!(modelFlags & MDL_MODE))
		{
			if (!space && ((GetTickCount() - stompTime) > 500))
			{
				// sit tight in here until something interesting happens
				return GetMessage(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax);
			}
		}
		else if (modelFlags & MDL_STATE)
		{
			return GetMessage(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax);
		}
	}
	return O_PeekMessage(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
}

LRESULT (CALLBACK *O_WindowProc)(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK H_WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
		case 0x7EE:
		{
			if (wParam == 0x10)
			{
				stompTime = GetTickCount();
			}
			break;
		}
		case 0x7ED:
		{
			if (modelFlags & MDL_MODE)
			{
				if (!stompTime)
				{
					stompTime = GetTickCount();
				}
				if (wParam == 0x08)
				{
					if (!(modelFlags & MDL_STATE2))
					{
						modelFlags ^= MDL_STATE;
					}
					else
					{
						modelFlags &= ~MDL_STATE2;
					}
				}
				else if (wParam == 0x0D)
				{
					if (!(modelFlags & MDL_SWITCH))
					{
						modelFlags |= MDL_STATE2;
						modelFlags &= ~MDL_STATE;
					}
					else
					{
						modelFlags = MDL_MODE;
					}
				}
				else if (wParam == 0x03)
				{
					modelFlags |= MDL_SWITCH;
					modelFlags &= ~MDL_STATE;
				}
			}
			break;
		}
		case 0x7EF:
		{
			if (!stompTime)
			{
				stompTime = GetTickCount();
			}
			break;
		}
		case WM_KEYDOWN:
		{
			if (wParam == VK_SPACE)
			{
				space = !space;
			}
			break;
		}
		case WM_CLOSE:
		{
			stompTime = 0;
			break;
		}
	}
	return O_WindowProc(hwnd, uMsg, wParam, lParam);
}

typedef struct displaymode_s
{
	DWORD width;
	DWORD height;
	DWORD bpp;
} displaymode_t;

// this array is used for display modes in windowed mode
displaymode_t displayModes[64];
size_t index;
HRESULT WINAPI EnumModesCallback(LPDDSURFACEDESC lpDDSurfaceDesc, LPVOID lpContext)
{
	if (index >= _countof(displayModes)) return DDENUMRET_CANCEL;
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

DWORD (WINAPI *kernel32_GetTickCount)(void);
DWORD WINAPI WinMM_timeGetTime(void)
{
	return timeGetTime();
}

// Adapted from http://www.geisswerks.com/ryan/FAQS/timing.html
// copyright (c)2002+ Ryan M. Geiss
LARGE_INTEGER frequency;
LARGE_INTEGER ticks_to_wait;
BOOL useQPC;
int (__fastcall *O_GameFrame)(void *, void *);
int __fastcall H_GameFrame(void *This, void *unused)
{
	static LARGE_INTEGER prev_end_of_frame;
	LARGE_INTEGER t;
	int ret = O_GameFrame(This, unused);

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

	return ret;
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
			if (PTR_DirectInputCreateA) return PTR_DirectInputCreateA(hinst, dwVersion, ppDI, punkOuter);
		}
		else return PTR_DirectInputCreateA(hinst, dwVersion, ppDI, punkOuter);
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
			if (PTR_DirectInputCreateEx) return PTR_DirectInputCreateEx(hinst, dwVersion, riidltf, ppvOut, punkOuter);
		}
		else return PTR_DirectInputCreateEx(hinst, dwVersion, riidltf, ppvOut, punkOuter);
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
			if (PTR_DirectInputCreateW) return PTR_DirectInputCreateW(hinst, dwVersion, ppDI, punkOuter);
		}
		else return PTR_DirectInputCreateW(hinst, dwVersion, ppDI, punkOuter);
	}
	return DIERR_UNSUPPORTED;
}

//HRESULT (WINAPI *PTR_DllCanUnloadNow)(void);
HRESULT WINAPI DllCanUnloadNow(void)
{
/*	if (LoadDinputIfNotLoaded())
	{
		if (!PTR_DllCanUnloadNow)
		{
			(FARPROC)PTR_DllCanUnloadNow = GetProcAddress(hDInput, "DllCanUnloadNow");
			if (PTR_DllCanUnloadNow) return PTR_DllCanUnloadNow();
		}
		else return PTR_DllCanUnloadNow();
	}*/
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
			if (PTR_DllGetClassObject) return PTR_DllGetClassObject(rclsid, riid, ppv);
		}
		else return PTR_DllGetClassObject(rclsid, riid, ppv);
	}
	return CLASS_E_CLASSNOTAVAILABLE;
}

char sysDirPath[MAX_PATH];
int (CALLBACK *O_WinMain)(HINSTANCE, HINSTANCE, LPSTR, int);
int CALLBACK H_WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
//	HMODULE hDInput;
	HMODULE hDDraw;
	LPDIRECTDRAW lpDD;
	int (WINAPI *PTR_SetAppCompatData)(int, int);

/*	if (!(hDInput = LoadLibrary(sysDirPath)))
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

	hDDraw = GetModuleHandle("DDRAW.dll");
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

				dwPatchBase = 0x43D10D;
				VirtualProtect((LPVOID)dwPatchBase, 0xD2, PAGE_EXECUTE_READWRITE, &dwOldProtect);
				*(PDWORD_PTR)dwPatchBase = (DWORD_PTR)&(displayModes[0].width);
				*(PDWORD_PTR)(dwPatchBase + 0xCE) = (DWORD_PTR)&(displayModes[index].width);
				VirtualProtect((LPVOID)dwPatchBase, 0xD2, dwOldProtect, &dwOldProtect);
			}
		}

		IDirectDraw_Release(lpDD);
	}

	return O_WinMain(hInstance, hPrevInstance, lpCmdLine, nCmdShow);
/*fail:
	return -1;*/
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
BOOL WINAPI DllMainError(HINSTANCE hinstDLL, LPVOID lpvReserved)
{
	if (lpvReserved) return DllMain(hinstDLL, DLL_PROCESS_DETACH, lpvReserved);
	return FALSE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	DWORD_PTR dwPatchBase;
	DWORD dwOldProtect;

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		char path[MAX_PATH];
		HANDLE hExe;
		HANDLE hMap;
		DWORD PECheckSum;
#ifdef WIN9X_HACK
		OSVERSIONINFO osVersionInfo;
#endif
		DWORD maxFPS;

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
			OutputDebugString("DllMain: Failed to checksum Engine.exe");
			return TRUE;
		}
		if (PECheckSum != 0xA3DE5)
		{
			OutputDebugString("DllMain: Invalid Engine.exe");
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

			if (hEvent = CreateEvent(NULL, FALSE, FALSE, "Drakan9xEdHack"))
			{
				// if we're new instance
				if (GetLastError() == ERROR_ALREADY_EXISTS)
				{
					// signal old instance to terminate
					SetEvent(hEvent);
					CloseHandle(hEvent);
				}
				else
				{
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

		if (!((PBYTE)O_WinMain = DetourFunction((PBYTE)0x413110, (PBYTE)H_WinMain))) goto fail;

		dwPatchBase = 0x483108;
		VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD_PTR), PAGE_READWRITE, &dwOldProtect);
		(DWORD_PTR)kernel32_GetTickCount = *(DWORD_PTR *)dwPatchBase;
		*(DWORD_PTR *)dwPatchBase = (DWORD_PTR)WinMM_timeGetTime;
		VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect);

		// setup path to our config file, act according to config options
		strcpy(strrchr(path, '\\') + 1, "Arokh.ini");

		if (maxFPS = GetPrivateProfileInt("Refresh", "MaxFPS", 59, path))
		{
			if (maxFPS < 15) maxFPS = 15;
			else if (maxFPS > 500) maxFPS = 500;

			if (!((PBYTE)O_GameFrame = DetourFunction((PBYTE)0x43C600, (PBYTE)H_GameFrame))) goto fail;

			if (useQPC = QueryPerformanceFrequency(&frequency))
			{
				ticks_to_wait.QuadPart = frequency.QuadPart / maxFPS;
			}
			else
			{
				frequency.LowPart = 1000;
				// feels more accurate that way
				ticks_to_wait.LowPart = frequency.LowPart / (maxFPS - 1);
			}

			timeBeginPeriod(1);
		}

		if (!GetPrivateProfileInt("Refresh", "DontBlockOnInactivity", 0, path))
		{
			if (!((PBYTE)O_WindowProc = DetourFunction((PBYTE)0x4134B0, (PBYTE)H_WindowProc))) goto fail;
			if (!((PBYTE)O_getmodelmode = DetourFunction((PBYTE)0x46944B, (PBYTE)H_getmodelmode))) goto fail;

			dwPatchBase = 0x483340;
			VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD_PTR), PAGE_READWRITE, &dwOldProtect);
			(DWORD_PTR)O_PeekMessage = *(DWORD_PTR *)dwPatchBase;
			*(DWORD_PTR *)dwPatchBase = (DWORD_PTR)H_PeekMessage;
			VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect);
		}
	}
	else if (fdwReason == DLL_PROCESS_DETACH)
	{
		if (O_PeekMessage)
		{
			dwPatchBase = 0x483340;
			VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD_PTR), PAGE_READWRITE, &dwOldProtect);
			*(DWORD_PTR *)dwPatchBase = (DWORD_PTR)O_PeekMessage;
			VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect);
		}

		if (O_WindowProc) DetourRemove((PBYTE)O_WindowProc, (PBYTE)H_WindowProc);
		if (O_GameFrame) DetourRemove((PBYTE)O_GameFrame, (PBYTE)H_GameFrame);

		dwPatchBase = 0x483108;
		VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD_PTR), PAGE_READWRITE, &dwOldProtect);
		*(DWORD_PTR *)dwPatchBase = (DWORD_PTR)kernel32_GetTickCount;
		VirtualProtect((LPVOID)dwPatchBase, sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect);

		if (O_WinMain) DetourRemove((PBYTE)O_WinMain, (PBYTE)H_WinMain);
	}
	return TRUE;
fail:
	return DllMainError(hinstDLL, lpvReserved);
}
