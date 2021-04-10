#define _CRT_SECURE_NO_WARNINGS
#include<Windows.h>
#include<stdio.h>
#include<TlHelp32.h>



DWORD Getprocess_PID_by_name(LPCSTR pname)
{

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		wprintf(L"CreateToolhelp32Snapshot Error. (%d)\n", GetLastError());
		return 0;
	}
	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);
	BOOL bProcessRet = Process32First(hProcessSnap, &pe32);
	while (bProcessRet)
	{
		//wprintf(L"PID:%d %s\n", pe32.th32ProcessID, pe32.szExeFile);
		DWORD dwpid = pe32.th32ProcessID;
		MODULEENTRY32 me32 = { 0 };

		me32.dwSize = sizeof(MODULEENTRY32);
		HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwpid);

		if (hModuleSnap == INVALID_HANDLE_VALUE)
		{
			//wprintf(L"\t Cannot get modules. (%d) \n", GetLastError());
		}
		else
		{
			BOOL bModuleRet = Module32First(hModuleSnap, &me32);
			while (bModuleRet)
			{
				//wprintf(L"\t%s (%s)\n", me32.szModule, me32.szExePath);
				bModuleRet = Module32Next(hModuleSnap, &me32);
			}
		}
		bProcessRet = Process32Next(hProcessSnap, &pe32);
	}
	CloseHandle(hProcessSnap);
	return pe32.th32ProcessID;
}

int main(int argc, char* argv[])
{
	DWORD dwProcessID = Getprocess_PID_by_name("notepad.exe");
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
	CHAR szDLLFilePath[MAX_PATH];

	//GET dll full path
	strcpy(szDLLFilePath, "C:\\Users\\benso\\source\\repos\\Dll1\\x64\\Debug\\Dll1.dll");
	int length = strlen(szDLLFilePath) + 1;

	//alloc memory for target process
	LPVOID pDllAddr = VirtualAllocEx(hProcess, NULL, length, MEM_COMMIT, PAGE_READWRITE);

	//inject dll to target process
	SIZE_T dwWriteNum = 0;
	WriteProcessMemory(hProcess, pDllAddr, szDLLFilePath, length, &dwWriteNum);

	//get function address
	LPTHREAD_START_ROUTINE pfnThreadRtn = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pDllAddr, 0, NULL);
	WaitForSingleObject(hRemoteThread, INFINITE);

	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);

}

















