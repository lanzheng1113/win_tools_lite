
// UnRootkitDlg.h : 头文件
//

#pragma once

#include <tlhelp32.h>
#include <afxtempl.h>
#include "psapi.h"
#include <winioctl.h>
#include "ProcessDlg.h"
#include "HandleDlg.h"
#include "afxcmn.h"
#include "DriverInfoDlg.h"

#define DIM(x) ( sizeof((x)) / sizeof((x)[0]) )
#define MAX_PROCESS_COUNT	256
#define MAX_DRIVER_COUNT	256

#define		IOCTL_TEST		CTL_CODE(	\
								FILE_DEVICE_UNKNOWN,	\
								0X800,	\
								METHOD_BUFFERED,	\
								FILE_ANY_ACCESS)

#define		IOCTL_LISTPROCESS_HANDLE_TABLE_LIST	CTL_CODE(	\
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

typedef struct _SYSTEM_MODULE_INFORMATION { 
	DWORD Reserved[2]; 
	PVOID Base; 
	DWORD Size; 
	DWORD Flags; 
	WORD Index; 
	WORD Unknown; 
	WORD LoadCount; 
	WORD ModuleNameOffset; 
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _PROCESS_INFO
{
	DWORD		ProcessID;
	CString		lpszExeFile;
	DWORD		cntThreads;
	DWORD		pcPriClassBase;
	CString		lpszExePath;
	BOOL		isHide;
}PROCESS_INFO,*PPROCESS_INFO;

typedef struct DRIVER_INFO
{
	CString		lpszDriverName;
	CString		lpszFullPath;
	DWORD		dwBaseAddr;
	DWORD		dwImageSize;
	BOOL		bIsHide;
	CString		lpszReferences;
}DRIVER_INFO,*PDRIVER_INFO;


typedef struct _UNICODE_STRING { 
	USHORT Length; 
	USHORT MaximumLength; 
	PWSTR  Buffer;                 //注意，这里为Unicode类型
} UNICODE_STRING, *PUNICODE_STRING;

typedef	struct _MyProcessInfo
{
	DWORD				ProcessID;
	WCHAR				uslpszExeFile[50];
	DWORD				cntThreads;
	DWORD				pcPriClassBase;
	WCHAR				uslpszExePath[MAX_PATH];
	DWORD				isHide;
}MyProcessInfo,*pMyProcessInfo;

typedef	struct _MYDRIVERINFO
{
	WCHAR		lpszDriverName[50];
	WCHAR		lpszFullPath[MAX_PATH];
	DWORD		dwBaseAddr;
	DWORD		dwImageSize;
	BOOL		bIsHide;
	WCHAR		lpszReferences[100];
}MYDRIVERINFO,*PMYDRIVERINFO;

typedef DWORD (WINAPI *fun_NtQuerySystemInfo)(SYSTEM_INFORMATION_CLASS ,PVOID, DWORD, PDWORD);
// CUnRootkitDlg 对话框
class CUnRootkitDlg : public CDialog
{
// 构造
public:
	CUnRootkitDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_UNROOTKIT_DIALOG };
	
protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持
	

// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
private:
	void ProcessErrorMessage(TCHAR* ErrorText);
	void UnLoadDriver();
	BOOL LoadDriver();
public:
	CTabCtrl		m_TabCtrl;
	CProcessDlg		m_ProcessDlg;
	CHandleDlg		m_HandleDlg;
	CDriverInfoDlg	m_DriverInfoDlg;
	DWORD			m_dwProcCntNormal;
	CArray<PROCESS_INFO,PROCESS_INFO&> m_ProcessInfoArray;
	CArray<DRIVER_INFO,DRIVER_INFO&> m_DriverInfoArray;

	BOOL PSAPIGetProcessList();
	BOOL EnableDebugPrivilege(BOOL fEnable) ;
	void SetProcessesDlgList();
	afx_msg void OnTcnSelchangeTab1(NMHDR *pNMHDR, LRESULT *pResult);//切换窗口页

	fun_NtQuerySystemInfo NtQuerySystemInformation;//pointer of function
	void	ShowModuleList();
	HANDLE m_hDevice;
	HMODULE	hModule;
	BOOL m_isDriverLoaded;
	afx_msg void OnDestroy();
	BOOL GetProcessListByHandleTableList(void);
	BOOL GetProcessListByPspCidTable(void);
	BOOL GetProcessListByCSRSSHandleTable(void);
	BOOL GetDriverListByNtQuerySysInfo(void);
};
