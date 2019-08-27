#include <windows.h>
#include <stdio.h>
#include <string>
#include <TlHelp32.h>
#include <algorithm>
#include <vector>
#include "util/WinRegs.h"
#include <Shlwapi.h>
#include "util/StringEx.h"
#include "util/File.h"
#include "util/OSVersion.h"
#include "util/CommonWinFuns.h"

#pragma comment(lib,"SHLWAPI.LIB")

std::vector<DWORD> GetProcessIds(const std::string& strProcessName)
{
	std::vector<DWORD> ret;
	PROCESSENTRY32 mype;
	mype.dwSize = sizeof(PROCESSENTRY32);
	HANDLE SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (SnapshotHandle == INVALID_HANDLE_VALUE)
	{
		return ret;
	}
	if (Process32First(SnapshotHandle, &mype))
	{
		std::string upperInputName(strProcessName);
		std::transform(upperInputName.begin(), upperInputName.end(), upperInputName.begin(), (int(*)(int)) toupper);
		do
		{
			std::wstring strTemp(mype.szExeFile);
			std::string strExeFile = String::fromStdWString(strTemp);
			std::transform(strExeFile.begin(), strExeFile.end(), strExeFile.begin(), (int(*)(int)) toupper);
			if (strExeFile == upperInputName)
			{
				ret.push_back(mype.th32ProcessID);
			}
		} while (Process32Next(SnapshotHandle, &mype));
	}
	CloseHandle(SnapshotHandle);
	return ret;
}

void KillProcess(const std::string& strProcessName)
{
	std::vector<DWORD> vecProcessIDsToKill = GetProcessIds(strProcessName);
	int MAXTryCount = 10;
	bool bFirstTime = true;
	while (!vecProcessIDsToKill.empty())
	{
		for (DWORD i : vecProcessIDsToKill)
		{
			HANDLE h_Process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, FALSE, i);
			if (h_Process)
			{
				printf("Try kill process %u\n", i);
				TerminateProcess(h_Process, 1);
				WaitForSingleObject(h_Process, 1000);
				CloseHandle(h_Process);
			}
			else
			{
				printf("OpenProcess failed with error %u\n", GetLastError());
			}
		}
		
		//最多试MAXTryCount次，如果一直不成功就退出。
		if (0 == MAXTryCount--)
		{
			if (bFirstTime)
			{
				bFirstTime = false;
			}
			else
			{
				printf("Kill process %s,max retry count is %d\r", strProcessName.c_str(), MAXTryCount);
			}
			break;
		}
		Sleep(250);

		std::vector<DWORD> CurrentPIDsExists = GetProcessIds(strProcessName);
		if (CurrentPIDsExists.empty())
		{
			//No any target process exist.
			break;
		}
		
		//
		//Maybe killed process restarted? ignore process restarted.
		//
		std::vector<DWORD> vecToEraseIDs;
		for (DWORD i : vecProcessIDsToKill)
		{
			if (find(CurrentPIDsExists.begin(), CurrentPIDsExists.end(),i) == CurrentPIDsExists.end())
			{
				// Process i has been terminated.
				vecToEraseIDs.push_back(i);
			}
		}

		if (!vecToEraseIDs.empty())
		{
			for (DWORD i : vecToEraseIDs)
			{
				std::vector<DWORD>::const_iterator it = find(vecProcessIDsToKill.begin(), vecProcessIDsToKill.end(),i);
				if (it != vecProcessIDsToKill.end())
				{
					vecProcessIDsToKill.erase(it);
				}
			}
		}
	}
	if (vecProcessIDsToKill.empty())
	{
		printf("Kill process %s DONE.\n", strProcessName.c_str());
	}
	else
		printf("Kill process %s FAILED\n", strProcessName.c_str());
	
	return;
}


void Go2345()
{
	if (1)
	{
		if (1)
		{
			printf("------------------------------------\n");
			printf("STEP 1 : Terminate processes.\n");

			char* lpProcessName = "2345Explorer.exe";
			printf("try to kill process %s\n", lpProcessName);
			KillProcess(lpProcessName);

			lpProcessName = "2345ssp.exe";
			printf("Try to terminate process  %s\n", lpProcessName);
			KillProcess(lpProcessName);

			lpProcessName = "Shield_2345Explorer.exe";
			printf("Try to terminate process  %s\n", lpProcessName);
			KillProcess(lpProcessName);

			printf("------------------------------------\n");
			printf("STEP 2 : Erase 2345 Files.\n");
			if (1)
			{
				const wchar_t* pUnistall = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\2345Explorer";
				if (isWow64())
				{
					pUnistall = L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\2345Explorer";
				}
				CWinRegKey Reg(HKEY_LOCAL_MACHINE, pUnistall, FALSE);
				WCHAR szUnistall[MAX_PATH] = { 0 };
				BOOL bDel = FALSE;
				if (Reg.ReadString(L"UninstallString", szUnistall, sizeof(szUnistall)))
				{
					//C:\Program Files (x86)\2345Soft\2345Explorer\Uninstall.exe
					PathRemoveFileSpecW(szUnistall);
					PathRemoveBackslash(szUnistall);
					if (PathIsDirectoryW(szUnistall))
					{
						String str = String::fromStdWString(szUnistall);
						if (str.endsWith("2345Explorer"))
						{
							printf("Find 2345 path %ls,try to delete it\n", szUnistall);
							File fRemove(str);
							fRemove.remove();
							bDel = TRUE;
						}
					}
				}

				if (!bDel)
				{
					const char* pDefaultFolder = "C:\\Program Files (x86)\\2345Soft\\2345Explorer";
					if (PathFileExistsA(pDefaultFolder))
					{
						printf("Find 2345 path %s,try to delete it\n", pDefaultFolder);
						File fRemove(pDefaultFolder);
						fRemove.remove();
						bDel = TRUE;
					}

					if (!bDel)
					{
						pDefaultFolder = "C:\\Program Files\\2345Soft\\2345Explorer";
						if (PathFileExistsA(pDefaultFolder))
						{
							printf("Find 2345 path %s,try to delete it\n", pDefaultFolder);
							File fRemove(pDefaultFolder);
							fRemove.remove();
							bDel = TRUE;
						}
					}
				}

				if (!bDel)
				{
					printf("Remove 2345Explorer work folder FAILED!\n");
				}
			}

			if (1)
			{
				printf("------------------------------------\n");
				printf("STEP 3 : Erase 2345 registry values.\n");
				const wchar_t* pSubKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\2345Explorer";
				if (isWow64())
				{
					pSubKey = L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\2345Explorer";
				}
				CWinRegKey Reg(HKEY_LOCAL_MACHINE, pSubKey, FALSE);
				printf("Try to remove Registry key:%ls.\n", pSubKey);
				Reg.DeleteSubKey();


				pSubKey = L"SOFTWARE\\2345Explorer";
				if (isWow64())
				{
					pSubKey = L"SOFTWARE\\Wow6432Node\\2345Explorer";
				}
				Reg.SetSubKey(pSubKey);
				printf("Try to remove Registry key:%ls.\n", pSubKey);
				Reg.DeleteSubKey();


				pSubKey = L"SYSTEM\\CurrentControlSet\\services\\2345CPort";
				Reg.SetSubKey(pSubKey);
				printf("Try to remove Registry key:%ls.\n", pSubKey);
				Reg.DeleteSubKey();

				pSubKey = L"SYSTEM\\CurrentControlSet\\services\\2345NsProtect";
				Reg.SetSubKey(pSubKey);
				printf("Try to remove Registry key:%ls.\n", pSubKey);
				Reg.DeleteSubKey();

				pSubKey = L"SYSTEM\\CurrentControlSet\\services\\2345WebProtectFrame";
				Reg.SetSubKey(pSubKey);
				printf("Try to remove Registry key:%ls.\n", pSubKey);
				Reg.DeleteSubKey();
			}

			if (1)
			{
				if (isWow64())
				{
					DisableWow64FsRedir();
				}
				printf("------------------------------------\n");
				printf("STEP 4 : Rename 2345 driver files.\n");
				char szWindir[MAX_PATH] = { 0 };
				GetWindowsDirectoryA(szWindir, _countof(szWindir));
				PathAddBackslashA(szWindir);
				strcat(szWindir, "system32\\drivers\\");

				char szFileName[MAX_PATH] = { 0 };
				char szFileNewName[MAX_PATH] = { 0 };
				strcpy(szFileName, szWindir);
				strcpy(szFileNewName, szWindir);
				strcat(szFileName, "2345CPort.sys");
				strcat(szFileNewName, "BAK2345CPort.sys");
				printf("Rename 2345CPort.sys to BAK2345CPort.sys\n");
				if (!MoveFileA(szFileName, szFileNewName))
				{
					printf("Failed! ERROR %d\n",GetLastError());
				}
				

				strcpy(szFileName, szWindir);
				strcpy(szFileNewName, szWindir);
				strcat(szFileName, "2345NsProtect.sys");
				strcat(szFileNewName, "BAK2345NsProtect.sys");
				MoveFileA(szFileName, szFileNewName);
				printf("Rename 2345NsProtect.sys to BAK2345NsProtect.sys\n");
				if (!MoveFileA(szFileName, szFileNewName))
				{
					printf("Failed! ERROR %d\n", GetLastError());
				}

				strcpy(szFileName, szWindir);
				strcpy(szFileNewName, szWindir);
				strcat(szFileName, "2345WebProtectFrame.sys");
				strcat(szFileNewName, "BAK2345WebProtectFrame.sys");
				MoveFileA(szFileName, szFileNewName);
				printf("Rename 2345WebProtectFrame.sys to BAK2345WebProtectFrame.sys\n");
				if (!MoveFileA(szFileName, szFileNewName))
				{
					printf("Failed! ERROR %d\n", GetLastError());
				}
				if (isWow64())
				{
					RestoreWow64FsRedir();
				}
			}
		}
	}
}

//重启
BOOL ReBootComputer()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		//打开令牌失败
		return FALSE;
	}
	// Get the LUID for the shutdown privilege.
	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
	tkp.PrivilegeCount = 1;  // one privilege to set
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	// Get the shutdown privilege for this process.
	AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, NULL);
	if (GetLastError() != ERROR_SUCCESS)
	{
		return FALSE; //关机失败
	}
	// Shut down the system and force all applications to close.
	ExitWindowsEx(EWX_REBOOT | EWX_FORCE, 0);

	return TRUE;
}


int main(int argc, char** argv)
{
	printf("WARNING! This program will FORCE DELETE \"2345 explorer\"!\n");
	printf("Coninue? Y/N ");
	char c = getchar();
	if (c == 'y' || c == 'Y')
	{
		Go2345();
		printf("Clear! Reboot to apply all changes?\n");
		printf("Entry y/Y to Reboot Windows now ,or entry any other key to quit. Y/N  ");
		
		do 
		{
			c = getchar();
		} while (c == '\n' || c == '\r');

		if (c == 'y' || c == 'Y')
		{
			ReBootComputer();
		}
	}
	
	printf("\n");
	system("pause");
	return 0;
}