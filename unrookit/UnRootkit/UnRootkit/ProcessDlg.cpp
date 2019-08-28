// ProcessDlg.cpp : implementation file
//

#include "stdafx.h"
#include "UnRootkit.h"
#include "ProcessDlg.h"


// CProcessDlg dialog

IMPLEMENT_DYNAMIC(CProcessDlg, CDialog)

CProcessDlg::CProcessDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CProcessDlg::IDD, pParent)
{

}

CProcessDlg::~CProcessDlg()
{
}

void CProcessDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_PROCESS, m_ProcessListCtrl);
}


BEGIN_MESSAGE_MAP(CProcessDlg, CDialog)

END_MESSAGE_MAP()


// CProcessDlg message handlers

void CProcessDlg::OnInitialDialogP(void)
{

}

BOOL CProcessDlg::OnInitDialog()
{
	CDialog::OnInitDialog();
	// TODO:  Add extra initialization here
	InitialListCtrl();
	return TRUE;  
	// return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}

void CProcessDlg::InitialListCtrl(void)
{
	LONG lStyle = m_ProcessListCtrl.SendMessage(LVM_GETEXTENDEDLISTVIEWSTYLE);

	lStyle |= LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP;

	m_ProcessListCtrl.SendMessage(LVM_SETEXTENDEDLISTVIEWSTYLE, 0,(LPARAM)lStyle);

	LVCOLUMN column0;
	column0.pszText = _T("进程名");
	column0.fmt = LVCFMT_LEFT;
	column0.cx = 80;
	column0.cchTextMax = 256;
	column0.mask = LVCF_TEXT|LVCF_FMT|LVCF_WIDTH;
	m_ProcessListCtrl.InsertColumn(0,&column0);

	LVCOLUMN column1;
	column1.pszText = _T("基本优先级");
	column1.fmt = LVCFMT_LEFT;
	column1.cx = 90;
	column1.cchTextMax = 256;
	column1.mask = LVCF_TEXT|LVCF_FMT|LVCF_WIDTH;
	m_ProcessListCtrl.InsertColumn(1,&column1);

	LVCOLUMN column2;
	column2.pszText = _T("线程数");
	column2.fmt = LVCFMT_LEFT;
	column2.cx = 80;
	column2.cchTextMax = 20;
	column2.mask = LVCF_TEXT|LVCF_FMT|LVCF_WIDTH;
	m_ProcessListCtrl.InsertColumn(2,&column2);

	LVCOLUMN column3;
	column3.pszText = _T("全路径");
	column3.fmt = LVCFMT_LEFT;
	column3.cx = 250;
	column3.cchTextMax = 20;
	column3.mask = LVCF_TEXT|LVCF_FMT|LVCF_WIDTH;
	m_ProcessListCtrl.InsertColumn(3,&column3);

	LVCOLUMN column4;
	column4.pszText = _T("进程ID");
	column4.fmt = LVCFMT_LEFT;
	column4.cx = 80;
	column4.cchTextMax = 20;
	column4.mask = LVCF_TEXT|LVCF_FMT|LVCF_WIDTH;
	m_ProcessListCtrl.InsertColumn(4,&column4);

	LVCOLUMN column5;
	column5.pszText = _T("是否隐藏");
	column5.fmt = LVCFMT_LEFT;
	column5.cx = 80;
	column5.cchTextMax = 20;
	column5.mask = LVCF_TEXT|LVCF_FMT|LVCF_WIDTH;
	m_ProcessListCtrl.InsertColumn(5,&column5);
}
