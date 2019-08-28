#include "winnt.h"

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef enum _FILE_INFORMATION_CLASS { 
	FileDirectoryInformation                 = 1,
	FileFullDirectoryInformation,
	FileBothDirectoryInformation,
	FileBasicInformation,
	FileStandardInformation,
	FileInternalInformation,
	FileEaInformation,
	FileAccessInformation,
	FileNameInformation,
	FileRenameInformation,
	FileLinkInformation,
	FileNamesInformation,
	FileDispositionInformation,
	FilePositionInformation,
	FileFullEaInformation,
	FileModeInformation,
	FileAlignmentInformation,
	FileAllInformation,
	FileAllocationInformation,
	FileEndOfFileInformation,
	FileAlternateNameInformation,
	FileStreamInformation,
	FilePipeInformation,
	FilePipeLocalInformation,
	FilePipeRemoteInformation,
	FileMailslotQueryInformation,
	FileMailslotSetInformation,
	FileCompressionInformation,
	FileObjectIdInformation,
	FileCompletionInformation,
	FileMoveClusterInformation,
	FileQuotaInformation,
	FileReparsePointInformation,
	FileNetworkOpenInformation,
	FileAttributeTagInformation,
	FileTrackingInformation,
	FileIdBothDirectoryInformation,
	FileIdFullDirectoryInformation,
	FileValidDataLengthInformation,
	FileShortNameInformation,
	FileIoCompletionNotificationInformation,
	FileIoStatusBlockRangeInformation,
	FileIoPriorityHintInformation,
	FileSfioReserveInformation,
	FileSfioVolumeInformation,
	FileHardLinkInformation,
	FileProcessIdsUsingFileInformation,
	FileNormalizedNameInformation,
	FileNetworkPhysicalNameInformation,
	FileIdGlobalTxDirectoryInformation,
	FileIsRemoteDeviceInformation,
	FileAttributeCacheInformation,
	FileNumaNodeInformation,
	FileStandardLinkInformation,
	FileRemoteProtocolInformation,
	FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef NTSTATUS (__stdcall *pf_NtSetInformationFile)(HANDLE FileHandle,PIO_STATUS_BLOCK IoStatusBlock,PVOID FileInformation,ULONG Length,FILE_INFORMATION_CLASS FileInformationClass);

typedef struct _FILE_NAME_INFORMATION
{
	ULONG FileNameLength;
	WCHAR FileName[MAX_PATH];
} FILE_NAME_INFORMATION;

//NTSYSAPI NTSTATUS NTAPI NtQueryInformationFile(IN HANDLE FileHandle,OUT PIO_STATUS_BLOCK IoStatusBlock,OUT PVOID FileInformation,IN ULONG Length,IN FILE_INFORMATION_CLASS FileInformationClass );
typedef NTSTATUS (__stdcall * pf_NtQueryInformationFile)(IN HANDLE FileHandle,OUT PIO_STATUS_BLOCK IoStatusBlock,OUT PVOID FileInformation,IN ULONG Length,IN FILE_INFORMATION_CLASS FileInformationClass );

//NTSYSAPI NTSTATUS NTAPI ZwQueryObject( IN HANDLE ObjectHandle,IN ULONG ObjectInformationClass,OUT PVOID ObjectInformation,IN ULONG ObjectInformationLength,OUT PULONG ReturnLength OPTIONAL);
typedef NTSTATUS (__stdcall* pf_ZwQueryObject)(HANDLE ObjectHandle,ULONG  ObjectInformationClass,PVOID  ObjectInformation,ULONG  ObjectInformationLength,PULONG ReturnLength);
// typedef struct _UNICODE_STRING {
// 	USHORT Length;
// 	USHORT MaximumLength;
// 	PWSTR  Buffer;
// } UNICODE_STRING, *PUNICODE_STRING;
// 
// typedef struct _STRING {
// 	USHORT Length;
// 	USHORT MaximumLength;
// 	PCHAR  Buffer;
// } ANSI_STRING, *PANSI_STRING;
BOOL GetFileNameFromHandleW(HANDLE hFile, LPWSTR lpFilePath);


