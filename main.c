#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <string.h>
#include <Windows.h>

int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	char szCmdLine[MAX_PATH];
	STARTUPINFO sinfo;
	PROCESS_INFORMATION pinfo;
	DWORD exitcode;

	if (*lpCmdLine)
		_snprintf(szCmdLine, sizeof(szCmdLine), " -dedicated %s", lpCmdLine);
	else
		strcpy(szCmdLine, " -dedicated");

	SetErrorMode(SEM_NOGPFAULTERRORBOX);

	ZeroMemory(&sinfo, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);
	sinfo.dwFlags = STARTF_USESHOWWINDOW;
	sinfo.wShowWindow = nCmdShow;

	do
	{
		if (GetAsyncKeyState(VK_CONTROL) & 0x8000 || !CreateProcess("Drakan.exe", szCmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &sinfo, &pinfo))
			break;

		WaitForSingleObject(pinfo.hProcess, INFINITE);
		GetExitCodeProcess(pinfo.hProcess, &exitcode);

		CloseHandle(pinfo.hProcess);
		CloseHandle(pinfo.hThread);
	} while (exitcode);

	return 0;
}
