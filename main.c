/*
*****************************************************************
*    Drakan: Order of the Flame Dedicated Server Launcher       *
*                                                               *
*           Copyright © 2017 - 2018 UCyborg                     *
*                                                               *
*   Program icon is Copyright © 1998 Surreal Software, Inc.     *
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
#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <Windows.h>

// not sure what exactly causes this to be needed
// uncomment if it crashes on Windows 9x
// must also be uncommented in dllmain.c
//#define WIN9X_HACK

int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	char cmdLine[MAX_PATH];
	char *endCurArg;
	OSVERSIONINFO osVersionInfo;
	DWORD dwCreationFlags;
	HANDLE hcurProcess;
#ifdef WIN9X_HACK
	HANDLE hEvent;
	HANDLE hMap;
#endif
	STARTUPINFO sInfo;
	PROCESS_INFORMATION pInfo;
	DWORD exitcode;

	ZeroMemory(&sInfo, sizeof(sInfo));
#ifdef WIN9X_HACK
	hEvent = NULL;
#endif
	dwCreationFlags = 0;

	osVersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&osVersionInfo);

	hcurProcess = GetCurrentProcess();
	sInfo.cb = sizeof(STARTUPINFO);
	sInfo.dwFlags = STARTF_USESHOWWINDOW;
	sInfo.wShowWindow = nCmdShow;

	endCurArg = lpCmdLine;
	while (isspace(*endCurArg)) endCurArg++;

	if (*endCurArg == '-' || *endCurArg == '+' || *endCurArg == '/')
	{
		char *curArg = endCurArg = endCurArg + 1;
		size_t len;

		while (*endCurArg)
		{
			if (isspace(*endCurArg)) break;
			endCurArg++;
		}

		len = endCurArg - curArg;
		if (!_strnicmp(curArg, "abovenormal", len))
		{
			if (osVersionInfo.dwMajorVersion >= 5)
				dwCreationFlags = ABOVE_NORMAL_PRIORITY_CLASS;
			else
				dwCreationFlags = HIGH_PRIORITY_CLASS;
		}
		else if (!_strnicmp(curArg, "high", len))
		{
			dwCreationFlags = HIGH_PRIORITY_CLASS;
		}
		else endCurArg = curArg - 2;

		if (*endCurArg)
			_snprintf(cmdLine, sizeof(cmdLine), "Drakan.exe -dedicated%s", endCurArg);
		else
			strcpy(cmdLine, "Drakan.exe -dedicated");
	}
	else _snprintf(cmdLine, sizeof(cmdLine), "Drakan.exe %s -dedicated", lpCmdLine);

	do
	{
/*
		if (GetAsyncKeyState(VK_CONTROL) & 0x8000)
			break;
*/

#ifdef WIN9X_HACK
		if (osVersionInfo.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS)
		{
			if (hEvent = CreateEvent(NULL, TRUE, FALSE, "Drakan9xServerEvent"))
			{
				if (!(hMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(DWORD), "Drakan9xServerId")))
				{
					CloseHandle(hEvent);
					break;
				}
			}
			else break;
		}
#endif

		if (!CreateProcess(NULL, cmdLine, NULL, NULL, FALSE, dwCreationFlags ? dwCreationFlags : GetPriorityClass(hcurProcess), NULL, NULL, &sInfo, &pInfo))
		{
#ifdef WIN9X_HACK
			if (hMap)
			{
				CloseHandle(hMap);
				CloseHandle(hEvent);
			}
#endif
			break;
		}

#ifdef WIN9X_HACK
		if (hEvent)
		{
			DWORD *pid;

			CloseHandle(pInfo.hProcess);
			if (!(WaitForSingleObject(hEvent, INFINITE)) && (pid = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0)))
			{
				pInfo.hProcess = OpenProcess(SYNCHRONIZE, FALSE, *pid);
				ResetEvent(hEvent);
				UnmapViewOfFile(pid);
				CloseHandle(hMap);
				CloseHandle(hEvent);
			}
			else
			{
				CloseHandle(hMap);
				CloseHandle(hEvent);
				CloseHandle(pInfo.hThread);
				break;
			}
		}
#endif

		WaitForSingleObject(pInfo.hProcess, INFINITE);
		GetExitCodeProcess(pInfo.hProcess, &exitcode);
		CloseHandle(pInfo.hProcess);
		CloseHandle(pInfo.hThread);
	}
	while (exitcode);

	return 0;
}
