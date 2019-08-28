// HandleDlg.cpp : implementation file
//

#include "stdafx.h"
#include "UnRootkit.h"
#include "HandleDlg.h"


// CHandleDlg dialog

IMPLEMENT_DYNAMIC(CHandleDlg, CDialog)

CHandleDlg::CHandleDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CHandleDlg::IDD, pParent)
{

}

CHandleDlg::~CHandleDlg()
{
}

void CHandleDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CHandleDlg, CDialog)

END_MESSAGE_MAP()

