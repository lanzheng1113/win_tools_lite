// DriverInfoDlg.cpp : implementation file
//

#include "stdafx.h"
#include "UnRootkit.h"
#include "DriverInfoDlg.h"


// CDriverInfoDlg dialog

IMPLEMENT_DYNAMIC(CDriverInfoDlg, CDialog)

CDriverInfoDlg::CDriverInfoDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CDriverInfoDlg::IDD, pParent)
{

}

CDriverInfoDlg::~CDriverInfoDlg()
{
}

void CDriverInfoDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_DRIVER_INFO, m_DriverListCtrl);
}


BEGIN_MESSAGE_MAP(CDriverInfoDlg, CDialog)
END_MESSAGE_MAP()


void CDriverInfoDlg::InitialListCtrl(void)
{
	LONG lStyle = m_DriverListCtrl.SendMessage(LVM_GETEXTENDEDLISTVIEWSTYLE);
	lStyle |= LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP;
	m_DriverListCtrl.SendMessage(LVM_SETEXTENDEDLISTVIEWSTYLE, 0,(LPARAM)lStyle);

	LVCOLUMN column0;
	column0.pszText = _T("驱动名");
	column0.fmt = LVCFMT_LEFT;
	column0.cx = 80;
	column0.cchTextMax = 256;
	column0.mask = LVCF_TEXT|LVCF_FMT|LVCF_WIDTH;
	m_DriverListCtrl.InsertColumn(0,&column0);

	LVCOLUMN column1;
	column1.pszText = _T("加载全路径");
	column1.fmt = LVCFMT_LEFT;
	column1.cx = 250;
	column1.cchTextMax = 256;
	column1.mask = LVCF_TEXT|LVCF_FMT|LVCF_WIDTH;
	m_DriverListCtrl.InsertColumn(1,&column1);

	LVCOLUMN column2;
	column2.pszText = _T("加载基址");
	column2.fmt = LVCFMT_LEFT;
	column2.cx = 80;
	column2.cchTextMax = 20;
	column2.mask = LVCF_TEXT|LVCF_FMT|LVCF_WIDTH;
	m_DriverListCtrl.InsertColumn(2,&column2);

	LVCOLUMN column3;
	column3.pszText = _T("大小");
	column3.fmt = LVCFMT_LEFT;
	column3.cx = 80;
	column3.cchTextMax = 20;
	column3.mask = LVCF_TEXT|LVCF_FMT|LVCF_WIDTH;
	m_DriverListCtrl.InsertColumn(3,&column3);

	LVCOLUMN column4;
	column4.pszText = _T("是否隐藏");
	column4.fmt = LVCFMT_LEFT;
	column4.cx = 80;
	column4.cchTextMax = 20;
	column4.mask = LVCF_TEXT|LVCF_FMT|LVCF_WIDTH;
	m_DriverListCtrl.InsertColumn(4,&column4);

	LVCOLUMN column5;
	column5.pszText = _T("其他信息");
	column5.fmt = LVCFMT_LEFT;
	column5.cx = 80;
	column5.cchTextMax = 20;
	column5.mask = LVCF_TEXT|LVCF_FMT|LVCF_WIDTH;
	m_DriverListCtrl.InsertColumn(5,&column5);
}

// CDriverInfoDlg message handlers

BOOL CDriverInfoDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  Add extra initialization here
	InitialListCtrl();
	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}
