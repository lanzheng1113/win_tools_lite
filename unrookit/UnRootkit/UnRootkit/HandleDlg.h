#pragma once


// CHandleDlg dialog

class CHandleDlg : public CDialog
{
	DECLARE_DYNAMIC(CHandleDlg)

public:
	CHandleDlg(CWnd* pParent = NULL);   // standard constructor
	virtual ~CHandleDlg();

// Dialog Data
	enum { IDD = IDD_DIALOG_HANDLE };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
};
