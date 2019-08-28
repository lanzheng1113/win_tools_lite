
// UnRootkitDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "UnRootkit.h"
#include "UnRootkitDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CUnRootkitDlg 对话框




CUnRootkitDlg::CUnRootkitDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CUnRootkitDlg::IDD, pParent)
	, m_isDriverLoaded(FALSE)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CUnRootkitDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TAB1, m_TabCtrl);
}

BEGIN_MESSAGE_MAP(CUnRootkitDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_NOTIFY(TCN_SELCHANGE, IDC_TAB1, &CUnRootkitDlg::OnTcnSelchangeTab1)
	ON_WM_DESTROY()
END_MESSAGE_MAP()


// CUnRootkitDlg 消息处理程序

BOOL CUnRootkitDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	hModule = LoadLibrary(_T("NTDLL.DLL"));
	if (hModule == NULL)
	{
		ProcessErrorMessage(_T("载入动态链接库NTDLL.DLL"));
		exit(0);
	}

	NtQuerySystemInformation = (fun_NtQuerySystemInfo)GetProcAddress(hModule,"NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL)
	{
		ProcessErrorMessage(_T("获取链接库函数地址"));
		exit(0);
	}

	if (!LoadDriver())
	{
		ExitProcess(-1);
	}
	m_TabCtrl.InsertItem(0,L"Processes");
	m_TabCtrl.InsertItem(1,L"Handle");
	m_TabCtrl.InsertItem(2,_T("Driver"));
	
	m_DriverInfoDlg.Create(IDD_DIALOG_DRIVER_INFO,GetDlgItem(IDC_TAB1));
	m_ProcessDlg.Create(IDD_DIALOG_PROCESS, GetDlgItem(IDC_TAB1));
	m_HandleDlg.Create(IDD_DIALOG_HANDLE,	GetDlgItem(IDC_TAB1));
	//获得IDC_TABTEST客户区大小
	CRect rs;
	m_TabCtrl.GetClientRect(&rs);
	//调整子对话框在父窗口中的位置
	rs.top+=20; 
	rs.bottom-=1; 
	rs.left+=1; 
	rs.right-=2; 

	//设置子对话框尺寸并移动到指定位置
	m_ProcessDlg.MoveWindow(&rs);
	m_HandleDlg.MoveWindow(&rs);
	m_DriverInfoDlg.MoveWindow(&rs);

	m_ProcessDlg.OnInitialDialogP();
	m_ProcessDlg.ShowWindow(TRUE);
	EnableDebugPrivilege(TRUE); //RAISE UP PRIVILEGE
	
	PSAPIGetProcessList();
	m_TabCtrl.SetCurSel(0);
	GetProcessListByHandleTableList();
	GetProcessListByPspCidTable();
	GetProcessListByCSRSSHandleTable();
	SetProcessesDlgList();
	GetDriverListByNtQuerySysInfo();//获取内核模块列表
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CUnRootkitDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CUnRootkitDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CUnRootkitDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


BOOL CUnRootkitDlg::PSAPIGetProcessList()
{
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;
	
	WCHAR wszProcessName[MAX_PATH] = _T("Open failed!");
	WCHAR wszProcessImageFullName[MAX_PATH] = _T("unknow");

	if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
		return FALSE;

	// Calculate how many process identifiers were returned.
	cProcesses = cbNeeded / sizeof(DWORD);
	m_dwProcCntNormal = cProcesses;

	if (m_ProcessInfoArray.GetSize()!=0)
	{
		m_ProcessInfoArray.RemoveAll();
	}

	// Print the name and process identifier for each process.

	for ( i = 0; i < cProcesses; i++ )
	{    
		// Get a handle to the process.

		HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
										PROCESS_VM_READ,
										FALSE, 
										aProcesses[i] );

		// Get the process name.
		if ( hProcess )
		{
			PROCESS_INFO pi;
			HMODULE hMod;
			DWORD cbNeeded;

			if ( EnumProcessModules( hProcess, &hMod, sizeof(hMod), &cbNeeded) )
			{
				GetModuleBaseName (hProcess,
									hMod, 
									wszProcessName, 
									DIM(wszProcessName));
				GetModuleFileNameEx(hProcess,hMod,wszProcessImageFullName,MAX_PATH);
				//GetProcessImageFileName(hProcess,wszProcessImageFullName,MAX_PATH);
			}
			
			pi.lpszExeFile.Format(_T("%s"),wszProcessName);
			pi.ProcessID = aProcesses[i];
			pi.lpszExePath.Format(_T("%s"),wszProcessImageFullName);
			pi.cntThreads = 0;
			pi.pcPriClassBase = GetPriorityClass(hProcess);
			pi.isHide	= FALSE;
			m_ProcessInfoArray.Add(pi);

		}
		// Print the process name and identifier.
		CloseHandle( hProcess );
	}
	return TRUE;

}

BOOL CUnRootkitDlg::EnableDebugPrivilege(BOOL fEnable) 
{

	// Enabling the debug privilege allows the application to see
	// information about service applications
	BOOL fOk = FALSE;    // Assume function fails
	HANDLE hToken;

	// Try to open this process's access token
	if (OpenProcessToken(GetCurrentProcess(), 
		TOKEN_ADJUST_PRIVILEGES, 
		&hToken)) 
	{
		// Attempt to modify the "Debug" privilege
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return(fOk);
}

void CUnRootkitDlg::SetProcessesDlgList()
{
	for (int i =0; i<m_ProcessInfoArray.GetSize(); i++)
	{
		//item 0
		m_ProcessDlg.m_ProcessListCtrl.InsertItem(i,m_ProcessInfoArray[i].lpszExeFile,0);
		
		//item 1
		WCHAR str_prority[10];
		memset(str_prority,0,10);
		wsprintf(str_prority,_T("%d"),m_ProcessInfoArray[i].pcPriClassBase);
		m_ProcessDlg.m_ProcessListCtrl.SetItemText(i,1,str_prority);
		
		//item 2
		WCHAR str_cntThread[10];
		memset(str_cntThread,0,10);
		wsprintf(str_cntThread,_T("%d"),m_ProcessInfoArray[i].cntThreads);
		m_ProcessDlg.m_ProcessListCtrl.SetItemText(i,2,str_cntThread);
		
		//item 3
		m_ProcessDlg.m_ProcessListCtrl.SetItemText(i,3,m_ProcessInfoArray[i].lpszExePath);
		
		//item 4
		WCHAR str_ProcessID[10];
		memset(str_ProcessID,0,10);
		wsprintf(str_ProcessID,_T("%d"),m_ProcessInfoArray[i].ProcessID);
		m_ProcessDlg.m_ProcessListCtrl.SetItemText(i,4,str_ProcessID);		
		
		//item 5
		WCHAR str_ProcessIsHide[10];
		memset(str_ProcessID,0,10);
		if (m_ProcessInfoArray[i].isHide == TRUE)
		{
			wsprintf(str_ProcessIsHide,_T("%s"),_T("隐藏"));
		}
		else
		{
			wsprintf(str_ProcessIsHide,_T("%s"),_T("正常"));
		}
		m_ProcessDlg.m_ProcessListCtrl.SetItemText(i,5,str_ProcessIsHide);		
	}
}

void CUnRootkitDlg::OnTcnSelchangeTab1(NMHDR *pNMHDR, LRESULT *pResult)
{
	// TODO: Add your control notification handler code here
	*pResult = 0;
	int iSelect;

	iSelect = m_TabCtrl.GetCurSel();
	switch (iSelect)
	{
	case 0:
		m_ProcessDlg.ShowWindow(TRUE);
		m_HandleDlg.ShowWindow(FALSE);
		m_DriverInfoDlg.ShowWindow(FALSE);
		break;
	case 1:
		m_HandleDlg.ShowWindow(TRUE);
		m_ProcessDlg.ShowWindow(FALSE);
		m_DriverInfoDlg.ShowWindow(FALSE);
		break;
	case 2:
		m_DriverInfoDlg.ShowWindow(TRUE);
		m_ProcessDlg.ShowWindow(FALSE);
		m_HandleDlg.ShowWindow(FALSE);
		break;
	default:
		break;
	}
}

BOOL CUnRootkitDlg::LoadDriver() 
{
	// TODO: Add your control notification handler code here
	// TODO: Add your control notification handler code here
	
	m_hDevice = CreateFile(_T("\\\\.\\UnRootkitDevice"),
							GENERIC_READ|GENERIC_WRITE,
							0,
							NULL,
							OPEN_EXISTING,
							FILE_ATTRIBUTE_NORMAL,
							NULL);

	if (m_hDevice == INVALID_HANDLE_VALUE)
	{
		ProcessErrorMessage(_T("打开设备"));
		return FALSE;
	}
	else
	{
		AfxMessageBox(_T("成功打开设备"));
		m_isDriverLoaded = TRUE;
	}
	return TRUE;
}

void CUnRootkitDlg::UnLoadDriver() 
{
	if (m_isDriverLoaded)
	{
		CloseHandle(m_hDevice);
	}
	m_isDriverLoaded = FALSE;
}

void CUnRootkitDlg::ProcessErrorMessage(TCHAR* ErrorText)
{
	TCHAR *Temp = new TCHAR[200];

	LPVOID lpMsgBuf;

	FormatMessage( 
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPTSTR) &lpMsgBuf,
		0,
		NULL 
		);

	wsprintf(Temp, _T("警告:  %s 由于以下错误失败: \n%s"), (TCHAR*)ErrorText, lpMsgBuf); 
	MessageBox(Temp, _T("应用程序错误"), MB_ICONSTOP);
	LocalFree(lpMsgBuf);
	delete [] Temp;
}

void CUnRootkitDlg::OnDestroy()
{
	CDialog::OnDestroy();
	UnLoadDriver();
	// TODO: Add your message handler code here
}

BOOL CUnRootkitDlg::GetProcessListByHandleTableList(void)
{
	MyProcessInfo TempProcList[MAX_PROCESS_COUNT];
	DWORD		ByteReturns = 0;
	BOOL		iSFindHide = TRUE;
	PROCESS_INFO	TempProcessInfo;

	memset(TempProcList, 0, sizeof(MyProcessInfo)*MAX_PROCESS_COUNT);

	BOOL	bRet = DeviceIoControl(m_hDevice,
									IOCTL_LISTPROCESS_HANDLE_TABLE_LIST,//IOCTL_LISTPROCESS_HANDLE_TABLE_LIST
									NULL,0,
									TempProcList,
									sizeof(MyProcessInfo)*MAX_PROCESS_COUNT,
									&ByteReturns,
									NULL);
	if (bRet&&ByteReturns == 0)
	{
		ProcessErrorMessage(_T("通过句柄表获取进程列表失败"));
		return	FALSE;
	}
	
	for (DWORD i=0; i<ByteReturns/sizeof(MyProcessInfo);i++)
	{
		iSFindHide = TRUE;

		for (int j = 0; j<m_ProcessInfoArray.GetSize(); j++)
		{
			if (TempProcList[i].ProcessID == m_ProcessInfoArray[j].ProcessID)
			{
				iSFindHide = FALSE;
				m_ProcessInfoArray[j].cntThreads = TempProcList[i].cntThreads;
				break;
			}
		}

		if (iSFindHide == TRUE)
		{
			TempProcessInfo.cntThreads = TempProcList[i].cntThreads;
			TempProcessInfo.isHide	   = TRUE;
			TempProcessInfo.lpszExeFile.Format(_T("%s"),TempProcList[i].uslpszExeFile);
			TempProcessInfo.lpszExePath.Format(_T("%s"),TempProcList[i].uslpszExePath);
			TempProcessInfo.pcPriClassBase = TempProcList[i].pcPriClassBase;
			TempProcessInfo.ProcessID = TempProcList[i].ProcessID;
			m_ProcessInfoArray.Add(TempProcessInfo);
		}
	}
	return 0;
}

BOOL CUnRootkitDlg::GetProcessListByPspCidTable(void)
{
	MyProcessInfo TempProcList[MAX_PROCESS_COUNT];
	DWORD		ByteReturns = 0;
	BOOL		iSFindHide = TRUE;
	PROCESS_INFO	TempProcessInfo;

	memset(TempProcList, 0, sizeof(MyProcessInfo)*MAX_PROCESS_COUNT);

	BOOL	bRet = DeviceIoControl(m_hDevice,
								IOCTL_LISTPROCESS_PSPCIDTABLE,
								NULL,0,
								TempProcList,
								sizeof(MyProcessInfo)*MAX_PROCESS_COUNT,
								&ByteReturns,
								NULL);

	if (bRet&&ByteReturns == 0)
	{
		ProcessErrorMessage(_T("通过句柄表获取进程列表失败"));
		return	FALSE;
	}
	/*
	CString		str_Size;
	str_Size.Format(_T("通过句柄表获取进程列表:返回列表大小==>%d"),ByteReturns/sizeof(MyProcessInfo));
	MessageBox(str_Size);
	*/
	for (DWORD i=0; i<ByteReturns/sizeof(MyProcessInfo);i++)
	{
		iSFindHide = TRUE;

		for (int j = 0; j<m_ProcessInfoArray.GetSize(); j++)
		{
			if (TempProcList[i].ProcessID == m_ProcessInfoArray[j].ProcessID)
			{
				iSFindHide = FALSE;
				m_ProcessInfoArray[j].cntThreads = TempProcList[i].cntThreads;
				break;
			}
		}
		if (iSFindHide == TRUE)
		{
			TempProcessInfo.cntThreads = TempProcList[i].cntThreads;
			TempProcessInfo.isHide	   = TRUE;
			TempProcessInfo.lpszExeFile.Format(_T("%s"),TempProcList[i].uslpszExeFile);
			TempProcessInfo.lpszExePath.Format(_T("%s"),TempProcList[i].uslpszExePath);
			TempProcessInfo.pcPriClassBase = TempProcList[i].pcPriClassBase;
			TempProcessInfo.ProcessID = TempProcList[i].ProcessID;
			m_ProcessInfoArray.Add(TempProcessInfo);
		}
	}
	return 0;
}

BOOL CUnRootkitDlg::GetProcessListByCSRSSHandleTable(void)
{
	MyProcessInfo TempProcList[MAX_PROCESS_COUNT];
	DWORD		ByteReturns = 0;
	BOOL		iSFindHide = TRUE;
	PROCESS_INFO	TempProcessInfo;

	memset(TempProcList, 0, sizeof(MyProcessInfo)*MAX_PROCESS_COUNT);

	BOOL	bRet = DeviceIoControl(m_hDevice,
								IOCTL_LISTPROCESS_CSRSS_TABLE,
								NULL,0,
								TempProcList,
								sizeof(MyProcessInfo)*MAX_PROCESS_COUNT,
								&ByteReturns,
								NULL);

	if (bRet&&ByteReturns == 0)
	{
		ProcessErrorMessage(_T("通过CSRSS.EXE句柄表获取进程列表失败"));
		return	FALSE;
	}
	
	CString		str_Size;
	str_Size.Format(_T("通过CSRSS.EXE句柄表获取进程列表:返回列表大小==>%d"),ByteReturns/sizeof(MyProcessInfo));
	MessageBox(str_Size);
	
	for (DWORD i=0; i<ByteReturns/sizeof(MyProcessInfo);i++)
	{
		iSFindHide = TRUE;

		for (int j = 0; j<m_ProcessInfoArray.GetSize(); j++)
		{
			if (TempProcList[i].ProcessID == m_ProcessInfoArray[j].ProcessID)
			{
				iSFindHide = FALSE;
				m_ProcessInfoArray[j].cntThreads = TempProcList[i].cntThreads;
				break;
			}
		}
		if (iSFindHide == TRUE)
		{
			TempProcessInfo.cntThreads = TempProcList[i].cntThreads;
			TempProcessInfo.isHide	   = TRUE;
			TempProcessInfo.lpszExeFile.Format(_T("%s"),TempProcList[i].uslpszExeFile);
			TempProcessInfo.lpszExePath.Format(_T("%s"),TempProcList[i].uslpszExePath);
			TempProcessInfo.pcPriClassBase = TempProcList[i].pcPriClassBase;
			TempProcessInfo.ProcessID = TempProcList[i].ProcessID;
			m_ProcessInfoArray.Add(TempProcessInfo);
		}
	}
	return 0;
}

BOOL CUnRootkitDlg::GetDriverListByNtQuerySysInfo(void)
{
	DWORD status = 0;
	ULONG                       n      = 0;
	ULONG                       i      = 0;
	PSYSTEM_MODULE_INFORMATION  module = NULL;
	PVOID                       pbuftmp    = NULL;
	DRIVER_INFO					TempDriverInfo;

	size_t		size;
	size_t		requiredSize;
	wchar_t*	wstr_driverName = NULL;
	wchar_t*	wstr_FullPath = NULL;
	
	if(!m_ProcessInfoArray.IsEmpty())
	{
		m_ProcessInfoArray.RemoveAll();
	}

	(*NtQuerySystemInformation)(SystemModuleInformation, &n, 0, &n);
	if (n==0)
	{
		ProcessErrorMessage(_T("NtQuerySystemInformation"));
		return FALSE;
	}
	pbuftmp = new CHAR[n];
	if (!pbuftmp)
	{
		ProcessErrorMessage(_T("分配内存"));
		return FALSE;
	}

	status = (*NtQuerySystemInformation)(SystemModuleInformation, pbuftmp, n, NULL);
	if ((status == 0) && (n!=0))
	{
		n      = *((PULONG)pbuftmp);
		module = (PSYSTEM_MODULE_INFORMATION)((PULONG )pbuftmp + 1 );

		for ( i = 0; i < n; i++ )
		{
			TempDriverInfo.bIsHide = FALSE;									//is hide?
			TempDriverInfo.dwBaseAddr =  (DWORD)module[i].Base;				//base address
			TempDriverInfo.dwImageSize = module[i].Size;					//size

			requiredSize = mbstowcs(NULL, module[i].ImageName, 0);
			wstr_FullPath = (wchar_t*)malloc((requiredSize + 1) * sizeof(wchar_t));
			if (!wstr_FullPath)
			{
				ProcessErrorMessage(_T("Memory allocation failure."));
				return FALSE;
			}
			size = mbstowcs(wstr_FullPath, module[i].ImageName, requiredSize+1);

			if (size == (size_t) (-1))
			{
				MessageBox(_T("Couldn't convert string--invalid multibyte character.\n"));
				delete [] wstr_FullPath;
				return FALSE;
			}
			TempDriverInfo.lpszFullPath.Format(_T("%s"),wstr_FullPath);
			//wstr_driverName
			requiredSize = mbstowcs(NULL, module[i].ImageName+module[i].ModuleNameOffset, 0);
			wstr_driverName = (wchar_t*)malloc((requiredSize + 1) * sizeof(wchar_t));
			if (!wstr_driverName)
			{
				ProcessErrorMessage(_T("Memory allocation failure."));
				return FALSE;
			}
			size = mbstowcs(wstr_driverName, module[i].ImageName+module[i].ModuleNameOffset, requiredSize+1);
			if (size == (size_t) (-1))
			{
				MessageBox(_T("Couldn't convert string--invalid multibyte character.\n"));
				delete [] wstr_driverName;
				return FALSE;
			}

			TempDriverInfo.lpszDriverName.Format(_T("%s"),wstr_driverName);
			TempDriverInfo.lpszReferences = _T("");

			m_DriverInfoArray.Add(TempDriverInfo);
			delete [] wstr_FullPath;
			delete [] wstr_driverName;
		}
		ShowModuleList();
	}
	//TRACE("EnumModule:\tLeave EnumModule Routine!");
	delete [] pbuftmp;
	return TRUE;
}

VOID CUnRootkitDlg::ShowModuleList()
{
	m_DriverInfoDlg.m_DriverListCtrl.DeleteAllItems();
	WCHAR wstr_BaseAddr[20];
	WCHAR wstr_ImageSize[20];
	
	for (int i = 0; i != m_DriverInfoArray.GetSize(); i++)
	{
		m_DriverInfoDlg.m_DriverListCtrl.InsertItem(i,m_DriverInfoArray[i].lpszDriverName,0);

		m_DriverInfoDlg.m_DriverListCtrl.SetItemText(i,1,m_DriverInfoArray[i].lpszFullPath);	
	
		memset(wstr_BaseAddr,0,10);
		wsprintf(wstr_BaseAddr,_T("0x%08x"),m_DriverInfoArray[i].dwBaseAddr);
		m_DriverInfoDlg.m_DriverListCtrl.SetItemText(i,2,wstr_BaseAddr);

		memset(wstr_ImageSize,0,10);
		wsprintf(wstr_ImageSize,_T("0x%08x"),m_DriverInfoArray[i].dwImageSize);
		m_DriverInfoDlg.m_DriverListCtrl.SetItemText(i,3,wstr_ImageSize);

		if (m_DriverInfoArray[i].bIsHide)
		{
			m_DriverInfoDlg.m_DriverListCtrl.SetItemText(i,4,_T("隐藏"));
		}
		else
		{
			m_DriverInfoDlg.m_DriverListCtrl.SetItemText(i,4,_T("正常"));
		}
		
		m_DriverInfoDlg.m_DriverListCtrl.SetItemText(i,5,m_DriverInfoArray[i].lpszReferences);	
	}
}