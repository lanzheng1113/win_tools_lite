#pragma once
#include "afxcmn.h"


// CDriverInfoDlg dialog

class CDriverInfoDlg : public CDialog
{
	DECLARE_DYNAMIC(CDriverInfoDlg)

public:
	CDriverInfoDlg(CWnd* pParent = NULL);   // standard constructor
	virtual ~CDriverInfoDlg();

// Dialog Data
	enum { IDD = IDD_DIALOG_DRIVER_INFO };
	
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

public:
	virtual BOOL OnInitDialog();
	CListCtrl m_DriverListCtrl;
	void InitialListCtrl();
	DECLARE_MESSAGE_MAP()

};
