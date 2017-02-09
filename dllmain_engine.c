#define WIN32_LEAN_AND_MEAN
#include <stdlib.h>
#include <Windows.h>
#include "detours.h"

#pragma comment(lib, "detours.lib")

#define NAKED __declspec(naked)

BOOL space;
BOOL modelinit;
BOOL modelmode;
BOOL modelstate;
BOOL modelstate2;
DWORD stomptime;
int timeout;

void (*O_getmodelmode)(void);
NAKED void H_getmodelmode(void)
{
	__asm
	{
		mov dword ptr ds:[modelmode], eax
		push eax
	}
	DetourRemove((PBYTE)O_getmodelmode, (PBYTE)H_getmodelmode);
	__asm
	{
		pop eax
		jmp dword ptr ds:[O_getmodelmode]
	}
}

DETOUR_TRAMPOLINE(BOOL WINAPI O_PeekMessage(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg), PeekMessage);
BOOL WINAPI H_PeekMessage(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg)
{
	if (!modelmode)
	{
		if (!space && ((GetTickCount() - stomptime) > (DWORD)timeout))
		{
			// sit tight in here until something interesting happens
			return GetMessage(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax);
		}
	}
	else if (modelstate)
	{
		return GetMessage(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax);
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
				stomptime = GetTickCount();
			}
			break;
		}
		case 0x7ED:
		{
			if (wParam == 0x08)
			{
				if (!modelstate2)
				{
					modelstate = !modelstate;
				}
				else
				{
					modelstate2 = FALSE;
				}
			}
			else if (wParam == 0x0D)
			{
				modelstate = FALSE;
				if (modelinit)
				{
					modelstate2 = TRUE;
				}
				else
				{
					modelinit = TRUE;
				}
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
		case WM_CREATE:
		{
			stomptime = GetTickCount();
			break;
		}
		case WM_CLOSE:
		{
			DetourRemove((PBYTE)O_PeekMessage, (PBYTE)H_PeekMessage);
			DetourRemove((PBYTE)O_WindowProc, (PBYTE)H_WindowProc);
			break;
		}
	}
	return O_WindowProc(hwnd, uMsg, wParam, lParam);
}

// proxy stuff
FARPROC PTR_DirectInputCreate;
NAKED void FDirectInputCreate(void) { __asm { jmp [PTR_DirectInputCreate] } }

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	// DLL_PROCESS_ATTACH
	if (fdwReason)
	{
		PIMAGE_DOS_HEADER pDosHeader;
		PIMAGE_NT_HEADERS pNtHeader;
		char szPath[MAX_PATH];
		char *temp;
		HMODULE hDInput;
		HMODULE hDDraw;
		int (WINAPI *PTR_SetAppCompatData)(int, int);
		char szTimeout[8];

		// not interested in those
		DisableThreadLibraryCalls(hinstDLL);

		pDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
		pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)(PIMAGE_DOS_HEADER)pDosHeader + pDosHeader->e_lfanew);

		if (pNtHeader->FileHeader.TimeDateStamp != 0x37fd5107)
		{
			// definitely not the .exe we're designed for
			return FALSE;
		}

		// setup proxy stuff
		GetSystemDirectory(szPath, MAX_PATH);
		strcat(szPath, "\\dinput.dll");
		hDInput = LoadLibrary(szPath);
		PTR_DirectInputCreate = GetProcAddress(hDInput, "DirectInputCreateA");

		hDDraw = GetModuleHandle("ddraw.dll");
		PTR_SetAppCompatData = (int (WINAPI *)(int, int))GetProcAddress(hDDraw, "SetAppCompatData");

		// we're running on Win7+ through native ddraw.dll
		if (PTR_SetAppCompatData)
		{
			// disable maximized windowed mode, only applicable to Win8+, it doesn't do anything on 7
			PTR_SetAppCompatData(12, 0);
		}

		// setup path to our config file, act according to config options
		GetModuleFileName(NULL, szPath, MAX_PATH);
		temp = strrchr(szPath, '\\');
		temp++;
		*temp = '\0';
		strcat(szPath, "Arokh.ini");

		timeout = GetPrivateProfileInt("Misc", "Timeout", 1500, szPath);
		if (timeout < 1000)
		{
			timeout = 1000;
		}
		else if (timeout > 5000)
		{
			timeout = 5000;
		}

		// ensure all configurable options end up in our config
		WritePrivateProfileString("Misc", "Timeout", itoa(timeout, szTimeout, 10), szPath);

		O_getmodelmode = (void (*)(void))DetourFunction((PBYTE)0x46944B, (PBYTE)H_getmodelmode);
		O_WindowProc = (LRESULT (CALLBACK *)(HWND, UINT, WPARAM, LPARAM))DetourFunction((PBYTE)0x4134B0, (PBYTE)H_WindowProc);
		DetourFunctionWithTrampoline((PBYTE)O_PeekMessage, (PBYTE)H_PeekMessage);
	}
	return TRUE;
}
