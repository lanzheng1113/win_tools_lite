#include "dumpIat.h"
#include "stdlib.h"
#include "windows.h"
#include "fsdef.h"
#include "shlobj.h"
#include "shlwapi.h"
#include "iathook.h"

void dumpMode(HMODULE hMod)
{
	if (hMod)
	{
		printf("hMode = %x\n",hMod);
	}

	PBYTE pStart = (PBYTE)hMod;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pStart;
	//1. e_magic：DOS头的标识，为4Dh和5Ah。分别为字母MZ。
	if (pDosHeader->e_magic != 0x5A4D){
		printf("This is not a illigal PE File.\n");
		goto rabort;
	}

	//2. e_lfanew：一个双字数据，为PE头的离文件头部的偏移量。Windows加载器通过它可以跳过DOS Stub部分直接找到PE头。
	DWORD e_lfanew = pDosHeader->e_lfanew;
	if (e_lfanew)
		printf("e_lfanew = %d\n",e_lfanew);

	//3. DOS头后跟一个DOS Stub数据，是链接器链接执行文件的时候加入的部分数据，一般是“This program must be run under Microsoft Windows”。这个可以通过修改链接器的设置来修改成自己定义的数据。
	
	//三、 PE头结构。
	//PE头的数据结构被定义为IMAGE_NT_HEADERS。包含三部分：
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pStart + e_lfanew);

	//1. Signature：PE头的标识。双字结构。为50h, 45h, 00h, 00h. 即“PE”。
	if(pNtHeader->Signature != 0x4550){
		goto rabort;
	}
	//2. FileHeader：20字节的数据。包含了文件的物理层信息及文件属性。
	printf("/////////////////////////////////\n");
	printf("FileHeader\n");
	printf("Machine = %d\n",pNtHeader->FileHeader.Machine);
	printf("NumberOfSections = %d\n",pNtHeader->FileHeader.NumberOfSections);
	printf("NumberOfSymbols = %d\n",pNtHeader->FileHeader.NumberOfSymbols);
	printf("SizeOfOptionalHeader = %d\n",pNtHeader->FileHeader.SizeOfOptionalHeader);
	printf("TimeDateStamp = 0x%08x\n",pNtHeader->FileHeader.TimeDateStamp);
	//3. OptionalHeader：总共224个字节。最后128个字节为数据目录(Data Directory)
	PIMAGE_OPTIONAL_HEADER pOptionHeader = &pNtHeader->OptionalHeader;
	if (0)
	{
		printf("/////////////////////////////////\n");
		printf("pOptionHeader = 0x%08x\n",pOptionHeader);
		//4.OptionHeader
		printf("    Magic = %x\n",pOptionHeader->Magic);
		printf("    MajorLinkerVersion = %x\n",pOptionHeader->MajorLinkerVersion);
		printf("    MinorLinkerVersion = %x\n",pOptionHeader->MinorLinkerVersion);
		printf("    SizeOfCode = %x\n",pOptionHeader->SizeOfCode);
		printf("    SizeOfInitializedData = %x\n",pOptionHeader->SizeOfInitializedData);
		printf("    SizeOfUninitializedData = %x\n",pOptionHeader->SizeOfUninitializedData);
		printf("    AddressOfEntryPoint = %x\n",pOptionHeader->AddressOfEntryPoint);
		printf("    BaseOfCode = %x\n",pOptionHeader->BaseOfCode);
//		printf("    BaseOfData = %x\n",pOptionHeader->BaseOfData);
		printf("    ImageBase = %x\n",pOptionHeader->ImageBase);
		printf("    SectionAlignment = %x\n",pOptionHeader->SectionAlignment);
		printf("    FileAlignment = %x\n",pOptionHeader->FileAlignment);
		printf("    MajorOperatingSystemVersion = %x\n",pOptionHeader->MajorOperatingSystemVersion);
		printf("    MinorOperatingSystemVersion = %x\n",pOptionHeader->MinorOperatingSystemVersion);
		printf("    MajorImageVersion = %x\n",pOptionHeader->MajorImageVersion);
		printf("    MinorImageVersion = %x\n",pOptionHeader->MinorImageVersion);
		printf("    MajorSubsystemVersion = %x\n",pOptionHeader->MajorSubsystemVersion);
		printf("    MinorSubsystemVersion = %x\n",pOptionHeader->MinorSubsystemVersion);
		printf("    Win32VersionValue = %x\n",pOptionHeader->Win32VersionValue);
		printf("    SizeOfImage = %x\n",pOptionHeader->SizeOfImage);
		printf("    SizeOfHeaders = %x\n",pOptionHeader->SizeOfHeaders);
		printf("    CheckSum = %x\n",pOptionHeader->CheckSum);
		printf("    Subsystem = %x\n",pOptionHeader->Subsystem);
		printf("    DllCharacteristics = %x\n",pOptionHeader->DllCharacteristics);
		printf("    SizeOfStackReserve = %x\n",pOptionHeader->SizeOfStackReserve);
		printf("    SizeOfStackCommit = %x\n",pOptionHeader->SizeOfStackCommit);
		printf("    SizeOfHeapReserve = %x\n",pOptionHeader->SizeOfHeapReserve);
		printf("    SizeOfHeapCommit = %x\n",pOptionHeader->SizeOfHeapCommit);
		printf("    LoaderFlags = %x\n",pOptionHeader->LoaderFlags);
		printf("    NumberOfRvaAndSizes = %x\n",pOptionHeader->NumberOfRvaAndSizes);
	}
	//四、 数据目录结构(Data Directory)。
	//	DataDirectory是OptionalHeader的最后128个字节，也是IMAGE_NT_HEADERS的最后一部分数据。它由16个IMAGE_DATA_DIRECTORY结构组成的数组构成。IMAGE_DATA_DIRECTORY的结构如下：
	/*
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	*/
	if (0)
	{
		DWORD ExportVa = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		DWORD ExportSz = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		printf("导出表基址=0x%08x,大小=0x%08x\n",ExportVa,ExportSz);

		if (ExportSz != 0 && ExportVa != 0){
			//打印导出表
			PIMAGE_EXPORT_DIRECTORY ExportTable = (PIMAGE_EXPORT_DIRECTORY)(pStart + ExportVa);
			printf("    导出模块名=%s\n",(CHAR*)(pStart + ExportTable->Name));
			printf("    导出数量=%d\n",ExportTable->NumberOfFunctions);
			printf("    有名字的函数数量=%d\n",ExportTable->NumberOfNames);
			DWORD ExportNameTable = ExportTable->AddressOfNames;
			for (int i=0; i!=ExportTable->NumberOfFunctions; i++){
				//ExportNameTable存放名字指针[0x6000]
				CHAR* name = (CHAR*)(pStart + *(DWORD*)(pStart+ExportNameTable+i*sizeof(DWORD)));
				DWORD rva = *(DWORD*)(pStart + ExportTable->AddressOfFunctions + i*sizeof(DWORD));
				DWORD va = (DWORD)pStart + rva;
#ifdef _WIN64
				printf("      Func: %s,RVA=0x%016x,VA=%0x016x\n",name,rva,va);
#else
				printf("      Func: %s,RVA=0x%08x,VA=%0x08x\n",name,rva,va);
#endif
			}
		}
	}

	DWORD ImportVa = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD ImportSz = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	printf("导入表基址=0x%x,大小=0x%x\n",ImportVa,ImportSz);
	if (ImportSz != 0 && ImportVa != 0){
		PIMAGE_IMPORT_DESCRIPTOR pImportDescription = NULL;
		pImportDescription = (PIMAGE_IMPORT_DESCRIPTOR)(pStart + ImportVa);
		while (pImportDescription->Characteristics != NULL)
		{
			LPCSTR lpName = (PCHAR)(pStart + pImportDescription->Name);
			printf("    M:%s\n",lpName);

			PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)(pStart + pImportDescription->OriginalFirstThunk);
			PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pStart + pImportDescription->FirstThunk);
			for (int i = 0; pOriginalThunk[i].u1.Function != NULL; i++)
			{
				if (IMAGE_ORDINAL_FLAG == (pOriginalThunk[i].u1.Ordinal & IMAGE_ORDINAL_FLAG)){
					continue;
				}
				if (NULL == pOriginalThunk[i].u1.AddressOfData){
					continue;
				}
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(pStart + pOriginalThunk[i].u1.AddressOfData);
				if (NULL == pImportByName->Name){
					continue;
				}
				LPSTR lpszName = (PCHAR)(pImportByName->Name);
#ifdef _WIN64
				printf("     Name = %s,va=0x%I64x,va_ori=0x%I64x\n",lpszName,(XDWORD)pThunk[i].u1.Function,(XDWORD)pOriginalThunk[i].u1.AddressOfData);
#else
				printf("     Name = %s,va=0x%x,va_ori=0x%x\n",lpszName,(XDWORD)pThunk[i].u1.Function,(XDWORD)pOriginalThunk[i].u1.AddressOfData);
#endif
			}
			pImportDescription++;
		}
	}

rabort:
	return;
}

pf_NtSetInformationFile Fori_NtSetInformationFile;

NTSTATUS NTAPI HookFun_NtSetInformationFile(
	IN HANDLE               FileHandle,
	OUT PIO_STATUS_BLOCK    IoStatusBlock,
	IN PVOID                FileInformation,
	IN ULONG                Length,
	IN FILE_INFORMATION_CLASS FileInformationClass )
{
	if (FileDispositionInformation == FileInformationClass)
	{
		printf("FileHandle = 0x%x,FileInformation = 0x%x,Length = %d,FIC = %d\n",FileHandle,(DWORD)FileInformation,Length,FileInformationClass);
		WCHAR szFilePath[MAX_PATH] = {0};
		BOOL bxx = GetFileNameFromHandleW(FileHandle,szFilePath);
		if (bxx){
			printf("成功获取文件路径=%ls\n",szFilePath);
			if (wcsicmp(szFilePath,L"C:\\lock.zip") == 0){
				printf("是要保护的文件，拒绝删除！\n");
				return ERROR_ACCESS_DENIED;
			}
		}else{
			printf("GetFileHandle Failed!FileHandle = 0x%x,FileInformation = 0x%x,Length = %d,FIC = %d\n",FileHandle,(DWORD)FileInformation,Length,FileInformationClass);
		}
	}
	return Fori_NtSetInformationFile(FileHandle,IoStatusBlock,FileInformation,Length,FileInformationClass);
}

BOOL GetFileNameFromHandleW(HANDLE hFile, LPWSTR lpFilePath)
{
	const int ObjectNameInformation = 1;  // enum OBJECT_INFORMATION_CLASS;
	lpFilePath[0] = 0x00;
	HMODULE hNtDLL = LoadLibraryW(L"ntdll.dll"); 
	if (hNtDLL == 0x00){ 
		return FALSE; 
	}
	pf_ZwQueryObject ZwQueryObject = (pf_ZwQueryObject)GetProcAddress(hNtDLL, "ZwQueryObject");
	if (ZwQueryObject == NULL) { 
		return FALSE; 
	}

	WCHAR  szPathInfo[MAX_PATH + 4];
	WCHAR  szDrive   [MAX_PATH];
	WCHAR *lpDrive = szDrive;
	ULONG  dwResult;
	int    iPathLen;

	if (ZwQueryObject(hFile, ObjectNameInformation, szPathInfo, sizeof(szPathInfo)-1 , &dwResult) != 0) { return 0x00; }

	// if the file on net drive
	const PWCHAR szNetDevice = L"//Device//LanmanRedirector";
	if (!wcsnicmp(szPathInfo + 4, szNetDevice, lstrlenW(szNetDevice))) {
		lstrcpyW(lpFilePath, L"//");
		lstrcatW(lpFilePath, szPathInfo + 4 + lstrlenW(szNetDevice));
		return TRUE;
	}

	if (GetLogicalDriveStringsW(MAX_PATH-1, szDrive) >= MAX_PATH) 
	{ 
		return FALSE;
	}

	while ((iPathLen = lstrlenW(lpDrive)) != 0) {
		WCHAR szDevName[MAX_PATH];
		lpDrive[iPathLen - 1] = 0x00;
		int iDevLen = (int)QueryDosDeviceW(lpDrive, szDevName, MAX_PATH);
		if (iDevLen && iDevLen < MAX_PATH){
			iDevLen = lstrlenW(szDevName);
			if (!wcsnicmp(szPathInfo + 4, szDevName, iDevLen)) {
				lstrcpyW(lpFilePath, lpDrive);
				lstrcatW(lpFilePath, szPathInfo + 4 + iDevLen);
				break;
			}
		}
		lpDrive += iPathLen + 1;
	}
	return TRUE;
}

int main(int argc,TCHAR** argv)
{
//  	HMODULE hModKernel32 = GetModuleHandleA("Kernel32.dll");
//  	if (hModKernel32)
//  	{ 	
//  //		dumpMode(hModKernel32);
//   		XDWORD oldFunAddr = 0;
//   		BOOL bxx = IATHook(hModKernel32,"ntdll.dll","NtSetInformationFile",HookFun_NtSetInformationFile,oldFunAddr);
//   		if (!bxx){
//   			printf("HOOK Kernel32 NtSetInformationFile 失败了！\n");
//   		}else{
//   			Fori_NtSetInformationFile = (pf_NtSetInformationFile)oldFunAddr;
//   			printf("成功HOOK Kernel32 NtSetInformationFile,原地址 = 0x%x\n",oldFunAddr);
//   		}
//  	}
//  
//  	HMODULE hModKernelBase = GetModuleHandleA("KernelBase.dll");
//  	if (hModKernelBase)
//  	{ 	
//  // 		dumpMode(hModKernelBase);
//   		XDWORD oldFunAddr = 0;
//   		BOOL bxx = IATHook(hModKernelBase,"ntdll.dll","NtSetInformationFile",HookFun_NtSetInformationFile,oldFunAddr);
//   		if (!bxx){
//   			printf("HOOK KernelBase NtSetInformationFile 失败了！\n");
//   		}else{
//   			Fori_NtSetInformationFile = (pf_NtSetInformationFile)oldFunAddr;
//   			printf("成功HOOK KernelBase NtSetInformationFile,原地址 = 0x%x\n",oldFunAddr);
//   		}
//  	}
 	printf("输入任意值继续尝试使用deletefilea\n");
 	getchar();
	BOOL bxx1 = DeleteFileA("c:\\lock.zip");
	if (bxx1){
		printf("删除文件成功！\n");
	}else{
		printf("删除文件失败！错误ID = %d\n",GetLastError());
	}
	system("pause");
	return 0;
}