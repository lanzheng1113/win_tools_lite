#include "windows.h"
#include "crossx64.h"
#include "stdio.h"

inline HMODULE LoadSystemLibray(LPCSTR lpszDllName)
{
    if (NULL == lpszDllName)
    {
        return NULL;
    }
    CHAR szSystemFolder[MAX_PATH] = {0};
    if (!SHGetSpecialFolderPathA(NULL, szSystemFolder, CSIDL_SYSTEM, FALSE))
    {
        return FALSE;
    }
    PathAppendA(szSystemFolder, lpszDllName);
    if (!PathFileExistsA(szSystemFolder))
    {
        return FALSE;
    }
    return LoadLibraryA(szSystemFolder);
}

inline BOOL IATHook(HMODULE hDLL, LPCSTR lpszImportDllName, LPCSTR lpszFunName, LPVOID pHookFun, XDWORD& pOriginalFun, LPVOID* ppIATAddr = NULL)
{
    if (NULL == hDLL)
    {
        return FALSE;
    }
    PBYTE pStart = (PBYTE)hDLL;
    BOOL bRetVal = FALSE;

    PIMAGE_DOS_HEADER pDosHeader = NULL;
    pDosHeader = (PIMAGE_DOS_HEADER)hDLL;
    if (pDosHeader->e_magic != 0x5A4D)
    {
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNtHeader = NULL;
    pNtHeader = (PIMAGE_NT_HEADERS)(pStart + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != 0x4550)
    {
        return FALSE;
    }

    PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
    pOptionHeader = &pNtHeader->OptionalHeader;
    if (NULL == pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
    {
        return FALSE;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDescription = NULL;
    pImportDescription = (PIMAGE_IMPORT_DESCRIPTOR)(pStart + pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    BOOL bFound = FALSE;
    while (pImportDescription->Characteristics != NULL)
    {
        LPCSTR lpName = (PCHAR)(pStart + pImportDescription->Name);
        if (_stricmp(lpName, lpszImportDllName) == 0)
        {
            bFound = TRUE;
            break;
        }
        pImportDescription++;
    }
    if (!bFound)
    {
        return FALSE;
    }

    if (NULL == pImportDescription->OriginalFirstThunk ||
        NULL == pImportDescription->FirstThunk)
    {
        return FALSE;
    }

	PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)(pStart + pImportDescription->OriginalFirstThunk);
	PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pStart + pImportDescription->FirstThunk);
	for (int i = 0; pOriginalThunk[i].u1.Function != NULL; i++)
	{
		if (IMAGE_ORDINAL_FLAG == (pOriginalThunk[i].u1.Ordinal & IMAGE_ORDINAL_FLAG))
		{
			continue;
		}
		if (NULL == pOriginalThunk[i].u1.AddressOfData)
		{
			continue;
		}
		PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(pStart + pOriginalThunk[i].u1.AddressOfData);
		if (NULL == pImportByName->Name)
		{
			continue;
		}
		LPSTR lpszName = (PCHAR)(pImportByName->Name);
		if (strcmp(lpszName, lpszFunName) != 0)
		{
			continue;
		}

        DWORD dwProtect;
        if (VirtualProtect(&pThunk[i], sizeof(pThunk[i]), PAGE_EXECUTE_READWRITE, &dwProtect))
        {
            pOriginalFun = (XDWORD)pThunk[i].u1.Function;
            pThunk[i].u1.Function = (XDWORD)pHookFun;
            VirtualProtect(&pThunk[i], sizeof(pThunk[i]), dwProtect, &dwProtect);
            bRetVal = TRUE;
        }
        if (ppIATAddr != NULL)
        {
            *ppIATAddr = &pThunk[i];
        }
        break;
    }
    return bRetVal;
}

inline BOOL EraseIATFuncName(LPCSTR lpszDllName, LPCSTR lpszImportDllName, LPCSTR lpszFunName)
{
    if (NULL == lpszDllName || NULL == lpszImportDllName || NULL == lpszFunName)
    {
        return FALSE;
    }
    HMODULE hDLL = GetModuleHandleA(lpszDllName);
    if (NULL == hDLL)
    {
        return FALSE;
    }

    PBYTE pStart = (PBYTE)hDLL;
    BOOL bRetVal = FALSE;

    PIMAGE_DOS_HEADER pDosHeader = NULL;
    pDosHeader = (PIMAGE_DOS_HEADER)hDLL;
    if (pDosHeader->e_magic != 0x5A4D)
    {
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNtHeader = NULL;
    pNtHeader = (PIMAGE_NT_HEADERS)(pStart + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != 0x4550)
    {
        return FALSE;
    }

    PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
    pOptionHeader = &pNtHeader->OptionalHeader;
    if (NULL == pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
    {
        return FALSE;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDescription = NULL;
    pImportDescription = (PIMAGE_IMPORT_DESCRIPTOR)(pStart + pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    BOOL bFound = FALSE;
    while (pImportDescription->Characteristics != NULL)
    {
        LPCSTR lpName = (PCHAR)(pStart + pImportDescription->Name);
        if (stricmp(lpName, lpszImportDllName) == 0)
        {
            bFound = TRUE;
            break;
        }
        pImportDescription++;
    }
    if (!bFound)
    {
        return FALSE;
    }

    if (NULL == pImportDescription->OriginalFirstThunk ||
        NULL == pImportDescription->FirstThunk)
    {
        return FALSE;
    }

    PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)(pStart + pImportDescription->OriginalFirstThunk);
    PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pStart + pImportDescription->FirstThunk);
    for (int i = 0; pOriginalThunk[i].u1.Function != NULL; i++)
    {
        if (IMAGE_ORDINAL_FLAG == (pOriginalThunk[i].u1.Ordinal & IMAGE_ORDINAL_FLAG))
        {
            continue;
        }
        if (NULL == pOriginalThunk[i].u1.AddressOfData)
        {
            continue;
        }
        PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(pStart + pOriginalThunk[i].u1.AddressOfData);
        if (NULL == pImportByName->Name)
        {
            continue;
        }
        LPSTR lpszName = (PCHAR)(pImportByName->Name);
        if (strcmp(lpszName, lpszFunName) != 0)
        {
            continue;
        }
        int nLen = strlen(lpszName);
        DWORD dwProtect;
        if (VirtualProtect(lpszName, nLen, PAGE_READWRITE, &dwProtect))
        {
            ZeroMemory(lpszName, nLen);
            VirtualProtect(lpszName, nLen, dwProtect, &dwProtect);
            bRetVal = TRUE;
        }

        break;
    }
    return bRetVal;
}

inline BOOL IATHook(LPCSTR lpszDllName, 
                    LPCSTR lpszImportDllName, 
                    LPCSTR lpszFunName, 
                    LPVOID pHookFun, 
                    XDWORD& pOriginalFun, 
                    LPVOID* ppIATAddr = NULL, 
                    BOOL bClearImportFuncionName = FALSE)
{
    BOOL bResult = FALSE;

    if (NULL == lpszDllName || NULL == lpszImportDllName || NULL == lpszFunName || NULL == pHookFun)
    {goto _abort;}

    HMODULE hDLL = ::GetModuleHandleA(lpszDllName);
    if (NULL == hDLL)
    {
        hDLL = LoadSystemLibray(lpszDllName);
        if (NULL == hDLL)
        {goto _abort;}
    }

    bResult = IATHook(hDLL, lpszImportDllName, lpszFunName, pHookFun, pOriginalFun, ppIATAddr);
    if (bResult && bClearImportFuncionName)
    {
        EraseIATFuncName(lpszDllName, lpszImportDllName, lpszFunName);
    }

_abort:

    return bResult;
}
