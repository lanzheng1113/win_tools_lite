// regldr.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>

static BOOL SetPrivilege(HANDLE hToken, LPCWSTR nameOfPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!LookupPrivilegeValueW(
		NULL,               // lookup privilege on local system
		nameOfPrivilege,   // privilege to lookup 
		&luid))           // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}
	return TRUE;
}

BOOL LoadKey(HKEY KeyRoot, LPCWSTR lpSubKey, LPCWSTR lpFilePath)
{
	// 挂载C盘下的注册表
	HANDLE proccessHandle = GetCurrentProcess();     // get the handle to the current proccess
	DWORD typeOfAccess = TOKEN_ADJUST_PRIVILEGES;   //  requiered to enable or disable the privilege
	HANDLE tokenHandle;                             //  handle to the opened access token
	if (OpenProcessToken(proccessHandle, typeOfAccess, &tokenHandle))
	{
		// Enabling RESTORE and BACKUP privileges
		SetPrivilege(tokenHandle, SE_RESTORE_NAME, TRUE);
		SetPrivilege(tokenHandle, SE_BACKUP_NAME, TRUE);
	}
	else
	{
		printf("Error getting the access token with error %d.\n", GetLastError());
		return FALSE;
	}
	// 挂载文件如C:\windows\system32\config\SOFTWARE到指定的位置。
	HKEY hKey = KeyRoot;
	LPCWSTR subKeyName = lpSubKey;
	LPCWSTR pHive = lpFilePath;
	LONG loadKey = RegLoadKeyW(hKey, subKeyName, pHive);
	if (loadKey != ERROR_SUCCESS)
	{
		printf("Error loading the key. Code: %li\n", loadKey);
		return FALSE;
	}
	return TRUE;
}

BOOL UnLoadKey(HKEY KeyRoot, LPCWSTR lpSubKey)
{
	// 挂载C盘下的注册表
	HANDLE proccessHandle = GetCurrentProcess();     // get the handle to the current proccess
	DWORD typeOfAccess = TOKEN_ADJUST_PRIVILEGES;   //  requiered to enable or disable the privilege
	HANDLE tokenHandle;                             //  handle to the opened access token
	if (OpenProcessToken(proccessHandle, typeOfAccess, &tokenHandle))
	{
		// Enabling RESTORE and BACKUP privileges
		SetPrivilege(tokenHandle, SE_RESTORE_NAME, TRUE);
		SetPrivilege(tokenHandle, SE_BACKUP_NAME, TRUE);
	}
	else
	{
		printf("Error getting the access token with error %d.\n", GetLastError());
		return FALSE;
	}
	return ERROR_SUCCESS == RegUnLoadKeyW(KeyRoot, lpSubKey);
}

int wmain(int argc, _TCHAR* argv[])
{
	if (argc < 3){
		printf("regldr -l load_to \"D:\\123\\SOFTWARE\"\n");
		printf("regldr -u unload_from\n");
		return 1;
	}

	LPCWSTR load_unload = (LPCWSTR)argv[1];
	if (0 == _wcsicmp(load_unload, L"-l"))
	{
		if (argc < 4)
		{
			printf("regldr -l load_to \"D:\\123\\SOFTWARE\"\n");
			return 2;
		}
		LPCWSTR load_to = (LPCWSTR)argv[2];
		LPCWSTR file_to_load = (LPCWSTR)argv[3];
		if (LoadKey(HKEY_LOCAL_MACHINE, load_to, file_to_load))
		{
			printf("Load OK!\n");
			return 0;
		}
		else
		{
			printf("Load Failed!\n");
			return 1;
		}
	}
	else if (0 == _wcsicmp(load_unload, L"-u"))
	{
		LPCWSTR unload_from = (LPCWSTR)argv[2];
		if (UnLoadKey(HKEY_LOCAL_MACHINE, unload_from))
		{
			printf("Unload OK!\n");
			return 0;
		}
		else
		{
			printf("Unload Failed!\n");
			return 1;
		}
	}
	else
	{
		printf("regldr -l load_to \"D:\\123\\SOFTWARE\"\n");
		printf("regldr -u unload_from\n");
		return 1;
	}
    return 5;
}

