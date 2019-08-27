#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <Tlhelp32.h>
#include <Psapi.h>
#include <string>
#include <algorithm>
#pragma comment (lib,"Psapi.lib") 

void getProcCMD(DWORD pid);

std::string fromStdWString(const std::wstring& wstr)
{
	if (wstr.empty()) {
		return std::string("");
	}
	std::string result;
	int nLen = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)wstr.c_str(), -1, NULL, 0, NULL, NULL);
	if (nLen <= 0)
	{
		return std::string("");
	}
	char *presult = new char[nLen];
	if (NULL == presult)
	{
		return std::string("");
	}
	WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)wstr.c_str(), -1, presult, nLen, NULL, NULL);
	presult[nLen - 1] = 0;
	result = presult;
	delete[] presult;
	return result;
}


DWORD GetAllByName(const std::string& strProcessName)
{
	PROCESSENTRY32 mype;
	mype.dwSize = sizeof(PROCESSENTRY32);
	HANDLE SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (SnapshotHandle == INVALID_HANDLE_VALUE)
	{
		return 0;
	}
	DWORD dwRet = 0;
	if (Process32First(SnapshotHandle, &mype))
	{
		std::string upperInputName = strProcessName;
		std::transform(upperInputName.begin(), upperInputName.end(), upperInputName.begin(), toupper);
		do
		{
			std::string exeFile = fromStdWString(mype.szExeFile);
			std::transform(exeFile.begin(), exeFile.end(), exeFile.begin(), toupper);
			if (exeFile == upperInputName) {
				dwRet = mype.th32ProcessID;
				printf("%u\n", mype.th32ProcessID);
				getProcCMD(mype.th32ProcessID);
			}
		} while (Process32Next(SnapshotHandle, &mype));
	}
	return dwRet;
}


typedef NTSTATUS(WINAPI *NtQueryInformationProcessFake)(HANDLE, DWORD, PVOID, ULONG, PULONG);

NtQueryInformationProcessFake ntQ = NULL;

BOOL SetSeDebugPrivilege(BOOL bEnablePrivilege)
{
	BOOL bRet = 0;
	DWORD dwErr = 0;

	HANDLE hToken = NULL;

	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious;
	HANDLE hThread = GetCurrentThread();
	LPCTSTR Privilege = SE_DEBUG_NAME;

	do
	{
		//OpenThreadToken  
		{
			if (OpenThreadToken(hThread, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
			{
			}
			else
			{
				dwErr = GetLastError();
				if (dwErr != ERROR_NO_TOKEN)
				{
					bRet = -1;
					break;
				}

				if (!ImpersonateSelf(SecurityImpersonation))
				{
					dwErr = GetLastError();
					bRet = -2;
					break;
				}

				if (!OpenThreadToken(hThread, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
				{
					dwErr = GetLastError();
					bRet = -3;
					break;
				}
			}
		}

		//LookupPrivilegeValue  
		{
			if (!LookupPrivilegeValue(NULL, Privilege, &luid))
			{
				dwErr = GetLastError();
				bRet = -4;
				break;
			}

			// first pass.  get current privilege setting  
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = luid;
			tp.Privileges[0].Attributes = 0;
			if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
				&tpPrevious, &cbPrevious))
			{
				dwErr = GetLastError();
				bRet = -5;
				break;
			}

			// second pass.  set privilege based on previous setting  
			tpPrevious.PrivilegeCount = 1;
			tpPrevious.Privileges[0].Luid = luid;
			if (bEnablePrivilege)
			{
				tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
			}
			else
			{
				tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
					tpPrevious.Privileges[0].Attributes);
			}

			if (!AdjustTokenPrivileges(hToken, FALSE, &tpPrevious, cbPrevious, NULL, NULL))
			{
				dwErr = GetLastError();
				bRet = -6;
				break;
			}
		}

		bRet = TRUE;
		dwErr = 0;
	} while (0);

	if (hToken)
	{
		CloseHandle(hToken);
		hToken = NULL;
	}
	return bRet;
}

void getProcCMD(DWORD pid) 
{
	HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (INVALID_HANDLE_VALUE != hproc) 
	{
		HANDLE hnewdup = NULL;
		PEB peb;
		RTL_USER_PROCESS_PARAMETERS upps;
		WCHAR buffer[MAX_PATH] = { NULL };
		HMODULE hm = LoadLibrary(L"ntdll.dll");
		ntQ = (NtQueryInformationProcessFake)GetProcAddress(hm, "NtQueryInformationProcess");
		if (DuplicateHandle(GetCurrentProcess(), hproc, GetCurrentProcess(), &hnewdup, 0, FALSE, DUPLICATE_SAME_ACCESS)) 
		{
			PROCESS_BASIC_INFORMATION pbi;
			NTSTATUS isok = ntQ(hnewdup, 0/*ProcessBasicInformation*/, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), 0);
			if (BCRYPT_SUCCESS(isok)) 
			{
				DWORD dwOldProt, dwNewProt = 0;
				VirtualProtectEx(hnewdup, (void*)pbi.PebBaseAddress, sizeof(PEB), PAGE_READWRITE, &dwOldProt);
				if (ReadProcessMemory(hnewdup, pbi.PebBaseAddress, &peb, sizeof(PEB), 0))
				{
					if (ReadProcessMemory(hnewdup, peb.ProcessParameters, &upps, sizeof(RTL_USER_PROCESS_PARAMETERS), 0))
					{
						WCHAR *buffer = new WCHAR[upps.CommandLine.Length + 1];
						ZeroMemory(buffer, (upps.CommandLine.Length + 1) * sizeof(WCHAR));
						ReadProcessMemory(hnewdup, upps.CommandLine.Buffer, buffer, upps.CommandLine.Length, 0);
						wprintf(L"%s\n", buffer);
						delete buffer;
					}
					else
					{
						printf("ReadProcessMemory2 Error:%u\n", GetLastError());
					}
				}
				else 
				{
					printf("ReadProcessMemory1 Error:%u\n", GetLastError());
				}
				VirtualProtectEx(hnewdup, (void*)pbi.PebBaseAddress, sizeof(PEB), dwOldProt, &dwNewProt);
			}
			CloseHandle(hnewdup);
		}
		CloseHandle(hproc);
	}
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");
	if (argc != 2)
	{
		printf("使用方法: shp.exe chrome.exe\n");
	}
	else
	{
		SetSeDebugPrivilege(TRUE);
		GetAllByName(argv[1]);
	}
	system("pause");
	return 0;
}