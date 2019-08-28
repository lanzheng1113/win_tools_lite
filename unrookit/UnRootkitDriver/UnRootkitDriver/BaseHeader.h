#ifndef _BASE_HEADER
#define _BASE_HEADER


#include <ntddk.h>

#define PAGEDCODE code_seg("PAGE")
#define LOCKEDCODE code_seg()
#define INITCODE code_seg("INIT")

#define PAGEDDATA data_seg("PAGE")
#define LOCKEDDATA data_seg()
#define INITDATA data_seg("INIT")

//////////////////////////////////////////////////////////////////////////
//extern symbol -->Object Type
//////////////////////////////////////////////////////////////////////////
extern POBJECT_TYPE *PsProcessType;
extern POBJECT_TYPE *PsThreadType;
extern POBJECT_TYPE *PsJobType;
extern POBJECT_TYPE	*IoDriverObjectType;
extern POBJECT_TYPE	*ExDesktopObjectType;
extern POBJECT_TYPE	*ExEventObjectType;
extern POBJECT_TYPE	*ExSemaphoreObjectType;
extern POBJECT_TYPE	*ExWindowStationObjectType;
extern POBJECT_TYPE	*IoAdapterObjectType;
extern POBJECT_TYPE	*IoDeviceHandlerObjectType;
extern POBJECT_TYPE	*IoDeviceObjectType;
extern POBJECT_TYPE	*IoDriverObjectType;
extern POBJECT_TYPE	*IoFileObjectType;
extern POBJECT_TYPE	*LpcPortObjectType;
extern POBJECT_TYPE	*MmSectionObjectType;
extern POBJECT_TYPE	*SeTokenObjectType;

typedef	ULONG	DWORD	;
typedef	int		BOOL	;
typedef PVOID	POBJECT	;
//---------系统信息结构---------   
typedef enum _SYSTEM_INFORMATION_CLASS {   
	SystemBasicInformation,   
	SystemProcessorInformation,   
	SystemPerformanceInformation,   
	SystemTimeOfDayInformation,   
	SystemNotImplemented1,   
	SystemProcessesAndThreadsInformation,   
	SystemCallCounts,   
	SystemConfigurationInformation,   
	SystemProcessorTimes,   
	SystemGlobalFlag,   
	SystemNotImplemented2, 
	SystemModuleInformation,   
	SystemLockInformation,   
	SystemNotImplemented3,   
	SystemNotImplemented4,   
	SystemNotImplemented5,   
	SystemHandleInformation,   
	SystemObjectInformation,   
	SystemPagefileInformation,   
	SystemInstructionEmulationCounts,   
	SystemInvalidInfoClass1,   
	SystemCacheInformation,   
	SystemPoolTagInformation,   
	SystemProcessorStatistics,   
	SystemDpcInformation,   
	SystemNotImplemented6,   
	SystemLoadImage,   
	SystemUnloadImage,   
	SystemTimeAdjustment,   
	SystemNotImplemented7,   
	SystemNotImplemented8,   
	SystemNotImplemented9,   
	SystemCrashDumpInformation,   
	SystemExceptionInformation,   
	SystemCrashDumpStateInformation,   
	SystemKernelDebuggerInformation,   
	SystemContextSwitchInformation,   
	SystemRegistryQuotaInformation,   
	SystemLoadAndCallImage,   
	SystemPrioritySeparation,   
	SystemNotImplemented10,   
	SystemNotImplemented11,   
	SystemInvalidInfoClass2,   
	SystemInvalidInfoClass3,   
	SystemTimeZoneInformation,   
	SystemLookasideInformation,   
	SystemSetTimeSlipEvent,   
	SystemCreateSession,   
	SystemDeleteSession,   
	SystemInvalidInfoClass4,   
	SystemRangeStartInformation,   
	SystemVerifierInformation,   
	SystemAddVerifier,   
	SystemSessionProcessesInformation   
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;   
//------------------------------   

//---------线程信息结构---------   
typedef struct _SYSTEM_THREAD {   
	LARGE_INTEGER           KernelTime;   
	LARGE_INTEGER           UserTime;   
	LARGE_INTEGER           CreateTime;   
	ULONG                   WaitTime;   
	PVOID                   StartAddress;   
	CLIENT_ID               ClientId;   
	KPRIORITY               Priority;   
	LONG                    BasePriority;   
	ULONG                   ContextSwitchCount;   
	ULONG                   State;   
	KWAIT_REASON            WaitReason;   
} SYSTEM_THREAD, *PSYSTEM_THREAD;   
//------------------------------   

//---------进程信息结构---------   
typedef struct _SYSTEM_PROCESS_INFORMATION {   
	ULONG                   NextEntryOffset; //NextEntryDelta 构成结构序列的偏移量   
	ULONG                   NumberOfThreads; //线程数目   
	LARGE_INTEGER           Reserved[3];   
	LARGE_INTEGER           CreateTime;   //创建时间   
	LARGE_INTEGER           UserTime;     //用户模式(Ring 3)的CPU时间   
	LARGE_INTEGER           KernelTime;   //内核模式(Ring 0)的CPU时间   
	UNICODE_STRING          ImageName;    //进程名称   
	KPRIORITY               BasePriority; //进程优先权   
	HANDLE                  ProcessId;    //ULONG UniqueProcessId 进程标识符   
	HANDLE                  InheritedFromProcessId; //父进程的标识符   
	ULONG                   HandleCount; //句柄数目   
	ULONG                   Reserved2[2];   
	ULONG                   PrivatePageCount;   
	VM_COUNTERS             VirtualMemoryCounters; //虚拟存储器的结构   
	IO_COUNTERS             IoCounters; //IO计数结构   
	SYSTEM_THREAD           Threads[1]; //进程相关线程的结构数组   
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;   

//typedef SYSTEM_PROCESSES SYSTEM_PROCESS_INFORMATION;   
//typedef PSYSTEM_PROCESSES PSYSTEM_PROCESS_INFORMATION;   
//MSDN此结构定义在SDK的winternl.h中，以上部分信息未文档化   
//_SYSTEM_PROCESS_INFORMATION = _SYSTEM_PROCESSES   
//------------------------------   
typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX 
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_INFORMATION Information[1];
}SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;
//Module info struct
typedef struct _SYSTEM_MODULE_INFORMATION { 
	ULONG Reserved[2]; 
	PVOID Base; 
	ULONG Size; 
	ULONG Flags; 
	USHORT Index; 
	USHORT Unknown; 
	USHORT LoadCount; 
	USHORT ModuleNameOffset; 
	CHAR ImageName[256]; 
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _DBGKD_DEBUG_DATA_HEADER32 {
	LIST_ENTRY32 List;
	ULONG        OwnerTag;    
	ULONG           Size;
} DBGKD_DEBUG_DATA_HEADER32, *PDBGKD_DEBUG_DATA_HEADER32;

typedef struct _KDDEBUGGER_DATA32 {   
	ULONG    Unknown1[12];    
	DBGKD_DEBUG_DATA_HEADER32 Header;    
	ULONG   KernBase;    ULONG    Unknown2;    
	ULONG   BreakpointWithStatus;       // address of breakpoint    
	ULONG   SavedContext;    
	USHORT  ThCallbackStack;            // offset in thread data    
	USHORT  NextCallback;               // saved pointer to next callback frame    
	USHORT  FramePointer;               // saved frame pointer    
	USHORT  PaeEnabled:1;    
	ULONG    Unknown[2];    
	ULONG   KiCallUserMode;             // kernel routine    
	ULONG	 Unknown3;   
	ULONG   KeUserCallbackDispatcher;   // address in ntdll    
	ULONG    Unknown4;    
	ULONG   PsLoadedModuleList;    
	ULONG    Unknown5;    
	ULONG   PsActiveProcessHead;    
	ULONG    Unknown6;    
	ULONG   PspCidTable;    
	ULONG    Unknown7;    
	ULONG   ExpSystemResourcesList;    
	ULONG    Unknown8;    
	ULONG   ExpPagedPoolDescriptor;    
	ULONG    Unknown9;   
	ULONG   ExpNumberOfPagedPools;    
	ULONG    Unknown10;    
	ULONG   KeTimeIncrement;    
	ULONG    Unknown11;   
	ULONG   KeBugCheckCallbackListHead;    
	ULONG    Unknown12;   
	ULONG   KiBugcheckData;    
	ULONG    Unknown13;    
	ULONG   IopErrorLogListHead;    
	ULONG    Unknown14;    
	ULONG   ObpRootDirectoryObject;    
	ULONG    Unknown15;    
	ULONG   ObpTypeObjectType;    
	ULONG    Unknown16;    
	ULONG   MmSystemCacheStart;    
	ULONG    Unknown17;    
	ULONG   MmSystemCacheEnd;    
	ULONG    Unknown18;    
	ULONG   MmSystemCacheWs;    
	ULONG    Unknown19;    
	ULONG   MmPfnDatabase;    
	ULONG    Unknown210;    
	ULONG   MmSystemPtesStart;   
	ULONG    Unknown20;    
	ULONG   MmSystemPtesEnd;    
	ULONG    Unknown21;    
	ULONG   MmSubsectionBase;    
	ULONG    Unknown22;    
	ULONG   MmNumberOfPagingFiles;    
	ULONG    Unknown23;    
	ULONG   MmLowestPhysicalPage;   
	ULONG    Unknown24;    
	ULONG   MmHighestPhysicalPage;    
	ULONG    Unknown25;    
	ULONG   MmNumberOfPhysicalPages;    
	ULONG    Unknown26;    
	ULONG   MmMaximumNonPagedPoolInBytes;    
	ULONG    Unknown27;    
	ULONG   MmNonPagedSystemStart;    
	ULONG    Unknown28;    
	ULONG   MmNonPagedPoolStart;    
	ULONG    Unknown29;    
	ULONG   MmNonPagedPoolEnd;    
	ULONG    Unknown30;    
	ULONG   MmPagedPoolStart;    
	ULONG    Unknown31;    
	ULONG   MmPagedPoolEnd;    
	ULONG    Unknown32;    
	ULONG   MmPagedPoolInformation;    
	ULONG    Unknown33;    
	ULONG   MmPageSize;    
	ULONG    Unknown34;    
	ULONG   MmSizeOfPagedPoolInBytes;    
	ULONG    Unknown35;    
	ULONG   MmTotalCommitLimit;    
	ULONG    Unknown36;    
	ULONG   MmTotalCommittedPages;    
	ULONG    Unknown37;    
	ULONG   MmSharedCommit;    
	ULONG    Unknown38;    
	ULONG   MmDriverCommit;    
	ULONG    Unknown39;    
	ULONG   MmProcessCommit;    
	ULONG    Unknown40;    
	ULONG   MmPagedPoolCommit;    
	ULONG    Unknown41[3];    
	ULONG   MmZeroedPageListHead;    
	ULONG    Unknown43;    
	ULONG   MmFreePageListHead;    
	ULONG    Unknown44;    
	ULONG   MmStandbyPageListHead;    
	ULONG    Unknown45;    
	ULONG   MmModifiedPageListHead;    
	ULONG    Unknown46;    
	ULONG   MmModifiedNoWritePageListHead;    
	ULONG    Unknown47;    
	ULONG   MmAvailablePages;    
	ULONG    Unknown48;    
	ULONG   MmResidentAvailablePages;    
	ULONG    Unknown49;    
	ULONG   PoolTrackTable;    
	ULONG    Unknown50;    
	ULONG   NonPagedPoolDescriptor;    
	ULONG    Unknown51;    
	ULONG   MmHighestUserAddress;    
	ULONG    Unknown52;    
	ULONG   MmSystemRangeStart;    
	ULONG    Unknown53;    
	ULONG   MmUserProbeAddress;    
	ULONG    Unknown54;    
	ULONG   KdPrintCircularBuffer;    
	ULONG    Unknown55;    
	ULONG   KdPrintCircularBufferEnd;    
	ULONG    Unknown56;    
	ULONG   KdPrintWritePointer;    
	ULONG    Unknown57;    
	ULONG   KdPrintRolloverCount;    
	ULONG    Unknown58;    
	ULONG   MmLoadedUserImageList;
} KDDEBUGGER_DATA32, *PKDDEBUGGER_DATA32;

typedef PULONG	_EX_PUSH_LOCK;
typedef	PULONG	PHANDLE_TRACE_DEBUG_INFO;


typedef struct _HANDLE_TABLE_ENTRY {
	//
	//  The pointer to the object overloaded with three ob attributes bits in
	//  the lower order and the high bit to denote locked or unlocked entries
	//
	union {
		PVOID Object;
		ULONG ObAttributes;
	};
	//
	//  This field either contains the granted access mask for the handle or an
	//  ob variation that also stores the same information.  Or in the case of
	//  a free entry the field stores the index for the next free entry in the
	//  free list.  This is like a FAT chain, and is used instead of pointers
	//  to make table duplication easier, because the entries can just be
	//  copied without needing to modify pointers.
	//

	union {
		union {
			ACCESS_MASK GrantedAccess;

			struct {
				USHORT GrantedAccessIndex;
				USHORT CreatorBackTraceIndex;
			};
		};
		LONG NextFreeTableEntry;
	};

} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

typedef struct _HANDLE_TABLE {
		/*
		nt!_HANDLE_TABLE
		+0x000 TableCode        : Uint4B
		+0x004 QuotaProcess     : Ptr32 _EPROCESS
		+0x008 UniqueProcessId  : Ptr32 Void
		+0x00c HandleTableLock  : [4] _EX_PUSH_LOCK
		+0x01c HandleTableList  : _LIST_ENTRY
		+0x024 HandleContentionEvent : _EX_PUSH_LOCK
		+0x028 DebugInfo        : Ptr32 _HANDLE_TRACE_DEBUG_INFO
		+0x02c ExtraInfoPages   : Int4B
		+0x030 FirstFree        : Uint4B
		+0x034 LastFree         : Uint4B
		+0x038 NextHandleNeedingPool : Uint4B
		+0x03c HandleCount      : Int4B
		+0x040 Flags            : Uint4B
		+0x040 StrictFIFO       : Pos 0, 1 Bit
		*/
		ULONG			TableCode;
		PEPROCESS		QuotaProcess;
		PVOID			UniqueProcessId;
		_EX_PUSH_LOCK	HandleTableLock[4];
		LIST_ENTRY		HandleTableList;
		_EX_PUSH_LOCK	HandleContentionEvent;
		PHANDLE_TRACE_DEBUG_INFO  DebugInfo;
		DWORD			ExtraInfoPages;
		DWORD			FirstFree;
		DWORD			LastFree;
		DWORD			NextHandleNeedingPool;
		DWORD			HandleCount;
		DWORD			Flags;
}HANDLE_TABLE,*PHANDLE_TABLE;
/*
nt!_CURDIR
+0x000 DosPath          : _UNICODE_STRING
+0x008 Handle           : Ptr32 Void
*/
typedef struct _CURDIR
{
	UNICODE_STRING		DosPath;
	PVOID				Handle;
}CURDIR,*PCURDIR;
/*
nt!_RTL_DRIVE_LETTER_CURDIR
+0x000 Flags            : Uint2B
+0x002 Length           : Uint2B
+0x004 TimeStamp        : Uint4B
+0x008 DosPath          : _STRING
*/

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT		Flags;
	USHORT		Length;
	ULONG		TimeStamp;
	STRING		DosPath;
}RTL_DRIVE_LETTER_CURDIR,*PRTL_DRIVE_LETTER_CURDIR;

/*
+0x000 MaximumLength    : Uint4B
+0x004 Length           : Uint4B
+0x008 Flags            : Uint4B
+0x00c DebugFlags       : Uint4B
+0x010 ConsoleHandle    : Ptr32 Void
+0x014 ConsoleFlags     : Uint4B
+0x018 StandardInput    : Ptr32 Void
+0x01c StandardOutput   : Ptr32 Void
+0x020 StandardError    : Ptr32 Void
+0x024 CurrentDirectory : _CURDIR
+0x030 DllPath          : _UNICODE_STRING
+0x038 ImagePathName    : _UNICODE_STRING
+0x040 CommandLine      : _UNICODE_STRING
+0x048 Environment      : Ptr32 Void
+0x04c StartingX        : Uint4B
+0x050 StartingY        : Uint4B
+0x054 CountX           : Uint4B
+0x058 CountY           : Uint4B
+0x05c CountCharsX      : Uint4B
+0x060 CountCharsY      : Uint4B
+0x064 FillAttribute    : Uint4B
+0x068 WindowFlags      : Uint4B
+0x06c ShowWindowFlags  : Uint4B
+0x070 WindowTitle      : _UNICODE_STRING
+0x078 DesktopInfo      : _UNICODE_STRING
+0x080 ShellInfo        : _UNICODE_STRING
+0x088 RuntimeData      : _UNICODE_STRING
+0x090 CurrentDirectores : [32] _RTL_DRIVE_LETTER_CURDIR
*/
typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG	MaximumLength;
	ULONG	Length;
	ULONG	Flags;
	ULONG	DebugFlags;
	PULONG	ConsoleHandle;
	ULONG	ConsoleFlags;
	PULONG	StandardInput;
	PULONG	StandardOutput;
	PULONG	StandardError;
	CURDIR	CurrentDirectory;
	UNICODE_STRING	DllPath;
	UNICODE_STRING	ImagePathName;
	UNICODE_STRING	CommandLine;
	PVOID	Environment;
	ULONG	StartingX;
	ULONG	StartingY;
	ULONG	CountX;
	ULONG	CountY;
	ULONG	CountCharsX;
	ULONG	CountCharsY;
	ULONG	FillAttribute;
	ULONG	WindowFlags;
	ULONG	ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
}RTL_USER_PROCESS_PARAMETERS,*PRTL_USER_PROCESS_PARAMETERS;
/*
nt!_PEB_LDR_DATA
+0x000 Length           : Uint4B
+0x004 Initialized      : UChar
+0x008 SsHandle         : Ptr32 Void
+0x00c InLoadOrderModuleList : _LIST_ENTRY
+0x014 InMemoryOrderModuleList : _LIST_ENTRY
+0x01c InInitializationOrderModuleList : _LIST_ENTRY
+0x024 EntryInProgress  : Ptr32 Void
*/

typedef struct _PEB_LDR_DATA 
{
	ULONG			Length;
	ULONG			Initialized;
	PVOID			SsHandle;
	LIST_ENTRY		InLoadOrderModuleList;
	LIST_ENTRY		InMemoryOrderModuleList;
	LIST_ENTRY		InInitializationOrderModuleList;
	PVOID			EntryInProgress;
}PEB_LDR_DATA ,PPEB_LDR_DATA;
/*
nt!_PEB_FREE_BLOCK
+0x000 Next             : Ptr32 _PEB_FREE_BLOCK
+0x004 Size             : Uint4B
*/

typedef struct _PEB_FREE_BLOCK
{
	struct _PEB_FREE_BLOCK	*NEXT;
	ULONG					SIZE;
}PEB_FREE_BLOCK,*PPEB_FREE_BLOCK;
/*
nt!_RTL_CRITICAL_SECTION_DEBUG
+0x000 Type             : Uint2B
+0x002 CreatorBackTraceIndex : Uint2B
+0x004 CriticalSection  : Ptr32 _RTL_CRITICAL_SECTION
+0x008 ProcessLocksList : _LIST_ENTRY
+0x010 EntryCount       : Uint4B
+0x014 ContentionCount  : Uint4B
+0x018 Spare            : [2] Uint4B
*/

typedef struct _RTL_CRITICAL_SECTION_DEBUG
{
	USHORT		Type;
	USHORT		CreatorBackTraceIndex;
	struct _RTL_CRITICAL_SECTION*		CriticalSection;
	LIST_ENTRY		ProcessLocksList;
	ULONG		EntryCount;
	ULONG		ContentionCount;
	ULONG		Spare[2];
}RTL_CRITICAL_SECTION_DEBUG,*PRTL_CRITICAL_SECTION_DEBUG;

/*
nt!_RTL_CRITICAL_SECTION
+0x000 DebugInfo        : Ptr32 _RTL_CRITICAL_SECTION_DEBUG
+0x004 LockCount        : Int4B
+0x008 RecursionCount   : Int4B
+0x00c OwningThread     : Ptr32 Void
+0x010 LockSemaphore    : Ptr32 Void
+0x014 SpinCount        : Uint4B
*/
typedef struct _RTL_CRITICAL_SECTION
{
	PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
	ULONG		LockCount;
	ULONG		RecursionCount;
	PVOID		OwningThread;
	PVOID		LockSemaphore;
	ULONG		SpinCount;
}RTL_CRITICAL_SECTION,*PRTL_CRITICAL_SECTION;
/*nt!_PEB
+0x000 InheritedAddressSpace : UChar
+0x001 ReadImageFileExecOptions : UChar
+0x002 BeingDebugged    : UChar
+0x003 SpareBool        : UChar
+0x004 Mutant           : Ptr32 Void
+0x008 ImageBaseAddress : Ptr32 Void
+0x00c Ldr              : Ptr32 _PEB_LDR_DATA
+0x010 ProcessParameters : Ptr32 _RTL_USER_PROCESS_PARAMETERS
+0x014 SubSystemData    : Ptr32 Void
+0x018 ProcessHeap      : Ptr32 Void
+0x01c FastPebLock      : Ptr32 _RTL_CRITICAL_SECTION
+0x020 FastPebLockRoutine : Ptr32 Void
+0x024 FastPebUnlockRoutine : Ptr32 Void
+0x028 EnvironmentUpdateCount : Uint4B
+0x02c KernelCallbackTable : Ptr32 Void
+0x030 SystemReserved   : [1] Uint4B
+0x034 AtlThunkSListPtr32 : Uint4B
+0x038 FreeList         : Ptr32 _PEB_FREE_BLOCK
+0x03c TlsExpansionCounter : Uint4B
+0x040 TlsBitmap        : Ptr32 Void
+0x044 TlsBitmapBits    : [2] Uint4B
+0x04c ReadOnlySharedMemoryBase : Ptr32 Void
+0x050 ReadOnlySharedMemoryHeap : Ptr32 Void
+0x054 ReadOnlyStaticServerData : Ptr32 Ptr32 Void
+0x058 AnsiCodePageData : Ptr32 Void
+0x05c OemCodePageData  : Ptr32 Void
+0x060 UnicodeCaseTableData : Ptr32 Void
+0x064 NumberOfProcessors : Uint4B
+0x068 NtGlobalFlag     : Uint4B
+0x070 CriticalSectionTimeout : _LARGE_INTEGER
+0x078 HeapSegmentReserve : Uint4B
+0x07c HeapSegmentCommit : Uint4B
+0x080 HeapDeCommitTotalFreeThreshold : Uint4B
+0x084 HeapDeCommitFreeBlockThreshold : Uint4B
+0x088 NumberOfHeaps    : Uint4B
+0x08c MaximumNumberOfHeaps : Uint4B
+0x090 ProcessHeaps     : Ptr32 Ptr32 Void
+0x094 GdiSharedHandleTable : Ptr32 Void
+0x098 ProcessStarterHelper : Ptr32 Void
+0x09c GdiDCAttributeList : Uint4B
+0x0a0 LoaderLock       : Ptr32 Void
+0x0a4 OSMajorVersion   : Uint4B
+0x0a8 OSMinorVersion   : Uint4B
+0x0ac OSBuildNumber    : Uint2B
+0x0ae OSCSDVersion     : Uint2B
+0x0b0 OSPlatformId     : Uint4B
+0x0b4 ImageSubsystem   : Uint4B
+0x0b8 ImageSubsystemMajorVersion : Uint4B
+0x0bc ImageSubsystemMinorVersion : Uint4B
+0x0c0 ImageProcessAffinityMask : Uint4B
+0x0c4 GdiHandleBuffer  : [34] Uint4B
+0x14c PostProcessInitRoutine : Ptr32     void 
+0x150 TlsExpansionBitmap : Ptr32 Void
+0x154 TlsExpansionBitmapBits : [32] Uint4B
+0x1d4 SessionId        : Uint4B
+0x1d8 AppCompatFlags   : _ULARGE_INTEGER
+0x1e0 AppCompatFlagsUser : _ULARGE_INTEGER
+0x1e8 pShimData        : Ptr32 Void
+0x1ec AppCompatInfo    : Ptr32 Void
+0x1f0 CSDVersion       : _UNICODE_STRING
+0x1f8 ActivationContextData : Ptr32 Void
+0x1fc ProcessAssemblyStorageMap : Ptr32 Void
+0x200 SystemDefaultActivationContextData : Ptr32 Void
+0x204 SystemAssemblyStorageMap : Ptr32 Void
+0x208 MinimumStackCommit : Uint4B
*/
typedef struct _PEB
{
		UCHAR			InheritedAddressSpace ;
		UCHAR			ReadImageFileExecOptions ;
		UCHAR			BeingDebugged ;
		UCHAR			SpareBool ;
		PVOID			Mutant ;
		PVOID			ImageBaseAddress; 
		PPEB_LDR_DATA	Ldr;					//ptr32 _PEB_LDR_DATA
		PRTL_USER_PROCESS_PARAMETERS	ProcessParameters;// Ptr32 _RTL_USER_PROCESS_PARAMETERS
		PVOID			SubSystemData ;			//Ptr32 Void
		PVOID			ProcessHeap;			//Ptr32 Void
		PRTL_CRITICAL_SECTION FastPebLock;		//Ptr32 _RTL_CRITICAL_SECTION
		PVOID			FastPebLockRoutine;		//Ptr32 Void
		PVOID			FastPebUnlockRoutine;	//Ptr32 Void
		ULONG			EnvironmentUpdateCount;	//Uint4B
		PVOID			KernelCallbackTable;	//Ptr32 Void
		ULONG			SystemReserved ;		//Uint4B
		ULONG			AtlThunkSListPtr32;		//Uint4B
		PPEB_FREE_BLOCK FreeList;				//Ptr32 _PEB_FREE_BLOCK
		ULONG			TlsExpansionCounter;	//Uint4B
		PVOID			TlsBitmap;				//Ptr32 Void
		ULONG			TlsBitmapBits[2];		//[2] Uint4B
		PVOID			ReadOnlySharedMemoryBase;//Ptr32 Void
		PVOID			ReadOnlySharedMemoryHeap;//Ptr32 Void
		PVOID			*ReadOnlyStaticServerData;//Ptr32 Ptr32 Void
		PVOID			AnsiCodePageData;		//Ptr32 Void
		PVOID			OemCodePageData;	//Ptr32 Void
		PVOID			UnicodeCaseTableData;	//Ptr32 Void
		ULONG			NumberOfProcessors;		//Uint4B
		ULONG			NtGlobalFlag;			//Uint4B
		LARGE_INTEGER	CriticalSectionTimeout; // _LARGE_INTEGER
		ULONG			HeapSegmentReserve;		//Uint4B
		ULONG			HeapSegmentCommit;		//Uint4B
		ULONG			HeapDeCommitTotalFreeThreshold;//Uint4B
		ULONG			HeapDeCommitFreeBlockThreshold;//Uint4B
		ULONG			NumberOfHeaps;			//Uint4B
		ULONG			MaximumNumberOfHeaps;	//Uint4B
		PVOID			ProcessHeaps;			//Ptr32 Ptr32 Void
		PVOID			GdiSharedHandleTable;	//Ptr32 Void
		PVOID			ProcessStarterHelper;	//Ptr32 Void
		ULONG			GdiDCAttributeList;		//Uint4B
		PVOID			LoaderLock;				// Ptr32 Void
		ULONG			OSMajorVersion;			//Uint4B
		ULONG			OSMinorVersion;			//Uint4B
		USHORT			OSBuildNumber;			//Uint2B
		USHORT			OSCSDVersion;			//Uint2B
		ULONG			OSPlatformId;			//Uint4B
		ULONG			ImageSubsystem;			//Uint4B
		ULONG			ImageSubsystemMajorVersion;	//Uint4B
		ULONG			ImageSubsystemMinorVersion;	//Uint4B
		ULONG			ImageProcessAffinityMask;	//Uint4B
		ULONG			GdiHandleBuffer[34];		//[34] Uint4B
		PVOID			PostProcessInitRoutine;		//Ptr32     void 
		PVOID			TlsExpansionBitmap;			//Ptr32 Void
		ULONG			TlsExpansionBitmapBits[32];	//[32] Uint4B
		ULONG			SessionId;					//Uint4B
		ULARGE_INTEGER AppCompatFlags;				//_ULARGE_INTEGER
		ULARGE_INTEGER AppCompatFlagsUser;			//_ULARGE_INTEGER
		PVOID			pShimData;					//Ptr32 Void
		PVOID			AppCompatInfo;				//Ptr32 Void
		UNICODE_STRING	CSDVersion;					//_UNICODE_STRING
		PVOID			ActivationContextData;		//Ptr32 Void
		PVOID			ProcessAssemblyStorageMap;	//Ptr32 Void
		PVOID			SystemDefaultActivationContextData;//Ptr32 Void
		PVOID			SystemAssemblyStorageMap;	//Ptr32 Void
		ULONG			MinimumStackCommit;			//Uint4B
}PEB,*PPEB;
/*
nt!_SEGMENT
+0x000 ControlArea      : Ptr32 _CONTROL_AREA
+0x004 TotalNumberOfPtes : Uint4B
+0x008 NonExtendedPtes  : Uint4B
+0x00c WritableUserReferences : Uint4B
+0x010 SizeOfSegment    : Uint8B
+0x018 SegmentPteTemplate : _MMPTE
+0x020 NumberOfCommittedPages : Uint4B
+0x024 ExtendInfo       : Ptr32 _MMEXTEND_INFO
+0x028 SystemImageBase  : Ptr32 Void
+0x02c BasedAddress     : Ptr32 Void
+0x030 u1               : __unnamed
+0x034 u2               : __unnamed
+0x038 PrototypePte     : Ptr32 _MMPTE
+0x040 ThePtes          : [1] _MMPTE
*/
typedef struct _SEGMENT
{
	PVOID		ControlArea;//ontrolArea      : Ptr32 _CONTROL_AREA
	ULONG		TotalNumberOfPtes;
	ULONG		NonExtendedPtes;
	ULONG		WritableUserReferences;
	LONGLONG	SizeOfSegment;
	UCHAR		Unknow1[8];//+0x018 SegmentPteTemplate : _MMPTE
	ULONG		NumberOfCommittedPages;
	PVOID		ExtendInfo; //Ptr32 _MMEXTEND_INFO
	PVOID		SystemImageBase;
	PVOID		BasedAddress;
	ULONG		Unknow2;
	ULONG		Unknow3;
	PVOID		PrototypePte;//Ptr32 _MMPT
	UCHAR		unknow4[4];//ThePtes          : [1] _MMPTE
}SEGMENT,*PSEGMENT;

/*
nt!_CONTROL_AREA
+0x000 Segment          : Ptr32 _SEGMENT
+0x004 DereferenceList  : _LIST_ENTRY
+0x00c NumberOfSectionReferences : Uint4B
+0x010 NumberOfPfnReferences : Uint4B
+0x014 NumberOfMappedViews : Uint4B
+0x018 NumberOfSubsections : Uint2B
+0x01a FlushInProgressCount : Uint2B
+0x01c NumberOfUserReferences : Uint4B
+0x020 u                : __unnamed
+0x024 FilePointer      : Ptr32 _FILE_OBJECT
+0x028 WaitingForDeletion : Ptr32 _EVENT_COUNTER
+0x02c ModifiedWriteCount : Uint2B
+0x02e NumberOfSystemCacheViews : Uint2B
*/
typedef struct  _CONTROL_AREA
{
	PSEGMENT	Segment;
	LIST_ENTRY	DereferenceList;
	ULONG		NumberOfSectionReferences;
	ULONG		NumberOfPfnReferences;
	ULONG		NumberOfMappedViews;
	USHORT		NumberOfSubsections;
	USHORT		FlushInProgressCount;
	ULONG		NumberOfUserReferences;
	UCHAR		Reserve[4];
	PFILE_OBJECT	FilePointer;
	PVOID		WaitingForDeletion;//PEVENT_COUNTER	WaitingForDeletion;
	USHORT		ModifiedWriteCount;
	USHORT		NumberOfSystemCacheViews;
}CONTROL_AREA,*PCONTROL_AREA;
/*
nt!_SEGMENT_OBJECT
+0x000 BaseAddress      : Ptr32 Void
+0x004 TotalNumberOfPtes : Uint4B
+0x008 SizeOfSegment    : _LARGE_INTEGER
+0x010 NonExtendedPtes  : Uint4B
+0x014 ImageCommitment  : Uint4B
+0x018 ControlArea      : Ptr32 _CONTROL_AREA
+0x01c Subsection       : Ptr32 _SUBSECTION
+0x020 LargeControlArea : Ptr32 _LARGE_CONTROL_AREA
+0x024 MmSectionFlags   : Ptr32 _MMSECTION_FLAGS
+0x028 MmSubSectionFlags : Ptr32 _MMSUBSECTION_FLAGS
*/
typedef struct _SEGMENT_OBJECT
{
	PVOID		BaseAddress;
	ULONG		TotalNumberOfPtes;
	LARGE_INTEGER	SizeOfSegment;
	ULONG		NonExtendedPtes;
	ULONG		ImageCommitment;
	PCONTROL_AREA	ControlArea;
	PVOID	Subsection;			//PSUBSECTION	Subsection;
	PVOID	LargeControlArea;	//PLARGE_CONTROL_AREA	LargeControlArea;
	PVOID	MmSectionFlags;		//PMMSECTION_FLAGS	MmSectionFlags
	PVOID	MmSubSectionFlags;	//PMMSUBSECTION_FLAGS	MmSubSectionFlags
}SEGMENT_OBJECT,*PSEGMENT_OBJECT;

/*
nt!_SECTION_OBJECT
+0x000 StartingVa       : Ptr32 Void
+0x004 EndingVa         : Ptr32 Void
+0x008 Parent           : Ptr32 Void
+0x00c LeftChild        : Ptr32 Void
+0x010 RightChild       : Ptr32 Void
+0x014 Segment          : Ptr32 _SEGMENT_OBJECT
*/
typedef struct _SECTION_OBJECT
{
	PVOID	StartingVa;
	PVOID	EndingVa;
	PVOID	Parent;
	PVOID	LeftChild;
	PVOID	RightChild;
	PSEGMENT_OBJECT Segment;
}SECTION_OBJECT,*PSECTION_OBJECT;

typedef struct _OBJECT_DIRECTORY_ENTRY
{
	struct _OBJECT_DIRECTORY_ENTRY *NextEntry;
	POBJECT Object;
}OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY,**PPOBJECT_DIRECTORY_ENTRY;


/*
+0x000 HashBuckets      : [37] Ptr32 _OBJECT_DIRECTORY_ENTRY
+0x094 Lock             : _EX_PUSH_LOCK
+0x098 DeviceMap        : Ptr32 _DEVICE_MAP
+0x09c SessionId        : Uint4B
+0x0a0 Reserved         : Uint2B
+0x0a2 SymbolicLinkUsageCount : Uint2B
*/
typedef struct _OBJECT_DIRECTORY
{	
	POBJECT_DIRECTORY_ENTRY HashTable[37];	
	POBJECT_DIRECTORY_ENTRY CurrentEntry;
	BOOLEAN CurrentEntryValid;	
	UCHAR  Reserved1;	
	USHORT Reserved2;	
	ULONG Reserved3;	
}OBJECT_DIRECTORY, *POBJECT_DIRECTORY;

typedef PVOID	POBJECT;

typedef struct _OBJECT_NAME 
{
	POBJECT		   pObject;
	UNICODE_STRING name;
	ULONG		   Reserved;
}OBJECT_NAME, *POBJECT_NAME;

/*
nt!_OBJECT_CREATE_INFORMATION
+0x000 Attributes       : Uint4B
+0x004 RootDirectory    : Ptr32 Void
+0x008 ParseContext     : Ptr32 Void
+0x00c ProbeMode        : Char
+0x010 PagedPoolCharge  : Uint4B
+0x014 NonPagedPoolCharge : Uint4B
+0x018 SecurityDescriptorCharge : Uint4B
+0x01c SecurityDescriptor : Ptr32 Void
+0x020 SecurityQos      : Ptr32 _SECURITY_QUALITY_OF_SERVICE
+0x024 SecurityQualityOfService : _SECURITY_QUALITY_OF_SERVICE
*/
typedef struct _OBJECT_CREATE_INFORMATION
{
	ULONG Attributes;
	HANDLE RootDirectory;
	PVOID ParseContext;
	KPROCESSOR_MODE ProbeMode;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG SecurityDescriptorCharge;
	PSECURITY_DESCRIPTOR SecurityDescriptor;
	PSECURITY_QUALITY_OF_SERVICE SecurityQos;
	SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_CREATE_INFORMATION, * POBJECT_CREATE_INFORMATION;
/*
nt!_OBJECT_HEADER
+0x000 PointerCount     : Int4B
+0x004 HandleCount      : Int4B
+0x004 NextToFree       : Ptr32 Void
+0x008 Type             : Ptr32 _OBJECT_TYPE
+0x00c NameInfoOffset   : UChar
+0x00d HandleInfoOffset : UChar
+0x00e QuotaInfoOffset  : UChar
+0x00f Flags            : UChar
+0x010 ObjectCreateInfo : Ptr32 _OBJECT_CREATE_INFORMATION
+0x010 QuotaBlockCharged : Ptr32 Void
+0x014 SecurityDescriptor : Ptr32 Void
+0x018 Body             : _QUAD
*/

typedef struct _OBJECT_HEADER
{
	LONG PointerCount;
	union
	{
		LONG HandleCount;
		PSINGLE_LIST_ENTRY SEntry;
	};
	POBJECT_TYPE Type;
	UCHAR NameInfoOffset;
	UCHAR HandleInfoOffset;
	UCHAR QuotaInfoOffset;
	UCHAR Flags;
	union
	{
		POBJECT_CREATE_INFORMATION ObjectCreateInfo;
		PVOID QuotaBlockCharged;
	};
	PSECURITY_DESCRIPTOR SecurityDescriptor;
	QUAD Body;
} OBJECT_HEADER, * POBJECT_HEADER;

//#define  OBJECT_TO_OBJECT_HEADER(a) 
//EPROCESS->SectionObject(_SECTION_OBJECT)->Segment(_SEGMENT)->ControlArea (_CONTROL_AREA)->FilePointer( _FILE_OBJECT)
#endif