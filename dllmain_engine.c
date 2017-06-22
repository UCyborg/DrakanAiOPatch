#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include "detours.h"

#define NAKED __declspec(naked)

BOOL space;
BOOL engineinit;
BOOL modelmode;
BOOL modelswitch;
BOOL modelstate;
BOOL modelstate2;
DWORD stomptime;

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
		if (!space && ((GetTickCount() - stomptime) > 100))
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

void EngineInit(void)
{
	engineinit = DetourFunctionWithTrampoline((PBYTE)O_PeekMessage, (PBYTE)H_PeekMessage);
	stomptime = GetTickCount();
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
				if (!modelswitch)
				{
					modelstate2 = TRUE;
					modelstate = FALSE;
				}
				else
				{
					modelswitch = FALSE;
					modelstate2 = FALSE;
					modelstate = FALSE;
				}
			}
			else if (wParam == 0x03)
			{
				modelswitch = TRUE;
				modelstate = FALSE;
			}
			break;
		}
		case 0x7EF:
		{
			if (!engineinit)
			{
				EngineInit();
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
		HMODULE hDInput;
		HMODULE hDDraw;
		int (WINAPI *PTR_SetAppCompatData)(int, int);

		// not interested in those
		DisableThreadLibraryCalls(hinstDLL);

		pDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
		pNtHeader = (PIMAGE_NT_HEADERS)((PCHAR)pDosHeader + pDosHeader->e_lfanew);

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

		O_getmodelmode = (void (*)(void))DetourFunction((PBYTE)0x46944B, (PBYTE)H_getmodelmode);
		O_WindowProc = (LRESULT (CALLBACK *)(HWND, UINT, WPARAM, LPARAM))DetourFunction((PBYTE)0x4134B0, (PBYTE)H_WindowProc);
	}

	return TRUE;
}
