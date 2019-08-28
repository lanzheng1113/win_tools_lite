#include "BaseHeader.h"

//////////////////////////////////////////////////////////////////////////
//常量定义
//////////////////////////////////////////////////////////////////////////
#define		IOCTL_TEST		CTL_CODE(\
								FILE_DEVICE_UNKNOWN,	\
								0X800,	\
								METHOD_BUFFERED,	\
								FILE_ANY_ACCESS)

#define		IOCTL_LISTPROCESS_HANDLE_TABLE_LIST		CTL_CODE(	\
													FILE_DEVICE_UNKNOWN,	\
													0X801,	\
													METHOD_BUFFERED,	\
													FILE_ANY_ACCESS)

#define		IOCTL_LISTPROCESS_PSPCIDTABLE	CTL_CODE(	\
											FILE_DEVICE_UNKNOWN,	\
											0X802,	\
											METHOD_BUFFERED,	\
											FILE_ANY_ACCESS)

#define		IOCTL_LISTPROCESS_CSRSS_TABLE	CTL_CODE(	\
											FILE_DEVICE_UNKNOWN,	\
											0X803,	\
											METHOD_BUFFERED,	\
											FILE_ANY_ACCESS)
#define WIN2003

#ifdef WIN2003
	#define		HandleTableOffset		0x0d4UL
	#define EProcess_ImageFileName_offset 0x164
	#define		PIDOFFSET				0X94      //EPROCESS中UniqueProcessId偏移
	#define		ThreadsCountOffset		0x190UL
	#define		PriorityClassOffset		0x24CUL
	#define		SectionObjectOffset		0x124UL
	#define		OffsetPEP				0x218
	#define		FLINKOFFSET				0x98    //EPROCESS中ActiveProcessLinks偏移
	#define offset_get_pspcid_table 0x1F
#else
	#define		HandleTableOffset		0x0c4UL
	#define EProcess_ImageFileName_offset 0x174
	#define		PIDOFFSET				0X84      //EPROCESS中UniqueProcessId偏移
	#define		ThreadsCountOffset		0x1a0UL
	#define		PriorityClassOffset		0x254UL
	#define		SectionObjectOffset		0x138UL
	#define		OffsetPEP				0x220UL	//ETHREAD中ThreadProcess的偏移
	#define		FLINKOFFSET				0x88    //EPROCESS中ActiveProcessLinks偏移
	#define offset_get_pspcid_table 0x1A
#endif

#define		HandleTableListOffset	0x01cUL
#define		QuotaProcessOffset		0x004UL
#define		PebOffset				0x1b0UL  //ot used

//#define		ProcessParametersOffset 0x010UL
//#define		ImagePathNameOffset		0x038UL


#define		MAX_PATH				260
#define		MAX_PROCESS_COUNT		256			//最长256

#define		TABLE_LEVEL_MASK		0x003UL
#define		XP_TABLE_ENTRY_LOCK_BIT	0x001UL   

//////////////////////////////////////////////////////////////////////////
//类型定义
//////////////////////////////////////////////////////////////////////////
typedef struct _DEVICE_EXTENSION {
			PDEVICE_OBJECT pDevice;
			UNICODE_STRING ustrDeviceName;	//设备名称
			UNICODE_STRING ustrSymLinkName;	//符号链接名
			KSPIN_LOCK	   Driver_Lock;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION; 

typedef	struct _MYPROCESSINFO
{
		DWORD				ProcessID;
		WCHAR				uslpszExeFile[50];
		DWORD				cntThreads;
		DWORD				pcPriClassBase;
		WCHAR				uslpszExePath[MAX_PATH];
		DWORD				isHide;
}MYPROCESSINFO,*PMYPROCESSINFO;

typedef struct _OUTBUF_PARAMETER
{
	ULONG		ulMaxSize;
	PVOID		buffer;
	ULONG		CurCount;
}OUTBUF_PARAMETER, *POUTBUF_PARAMETER;

typedef BOOL (*pFunWalkHandleTableCallBack)(PVOID Context, PVOID Object);

//////////////////////////////////////////////////////////////////////////
//导入函数和变量
//////////////////////////////////////////////////////////////////////////
NTSTATUS
ObQueryNameString(
				  IN PVOID  Object,
				  OUT POBJECT_NAME_INFORMATION  ObjectNameInfo,
				  IN ULONG  Length,
				  OUT PULONG  ReturnLength
				  ); 

NTSTATUS ZwQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,   
								  OUT PVOID SystemInformation,   
								  IN ULONG SystemInformationLength,   
								  OUT PULONG ReturnLength OPTIONAL);

NTSTATUS PsLookupProcessByProcessId(IN	ULONG ulProcId,
									OUT	PEPROCESS *pEProcess);

//////////////////////////////////////////////////////////////////////////
//驱动框架函数
//////////////////////////////////////////////////////////////////////////
NTSTATUS	DriverEntry (IN PDRIVER_OBJECT	pDriverObject,
						IN PUNICODE_STRING	pRegistryPath);

NTSTATUS	UnRootkitDriverCreateDevice (IN PDRIVER_OBJECT pDriverObject);
VOID		UnRootkitDriverUnload (IN PDRIVER_OBJECT pDriverObject);

NTSTATUS	UnRootkitDriverIOControl(IN PDEVICE_OBJECT pDevObj,
								   IN PIRP pIrp);

NTSTATUS	UnRootkitDriverDispatchRoutine(IN PDEVICE_OBJECT pDevObj, 
										 IN PIRP pIrp);

//////////////////////////////////////////////////////////////////////////
//全局变量
//////////////////////////////////////////////////////////////////////////
ULONG		KernalModuleBase;
ULONG		KernalModuleSize;
PLIST_ENTRY	HandleTableListHead;
PHANDLE_TABLE	*PspCidTable;

//////////////////////////////////////////////////////////////////////////
//工作函数
//////////////////////////////////////////////////////////////////////////
NTSTATUS	GetKernalModuleBaseAndSize();
VOID		GetPspCidTable();
BOOL		ScanHandleTablesList(PVOID pOutputBuffer,PULONG pSizeReturn);

VOID		ScanHandleTable(PHANDLE_TABLE HandleTable,
							pFunWalkHandleTableCallBack pFunCallBack,
							PVOID pContext);
//自定义回调 Object是ScanHanleTable句柄对应的对象
BOOL		DumpHanelTableCallBack(IN OUT PVOID pContext,IN PVOID Object);
BOOL		CollectProcessCallBack(IN OUT PVOID pContext,IN PVOID Object);

BOOL		DumpCsrssHanelTableCallBack(IN OUT PVOID pContext,IN PVOID Object);//从CSRSS.EXE里收集进程列表
BOOL		CollectCsrssProcessCallBack(IN OUT PVOID pContext,IN PVOID Object);//DUMP CSRSS.EXE句柄表
PHANDLE_TABLE	GetCsrssHandleTable();
