
// UnRootkit.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CUnRootkitApp:
// �йش����ʵ�֣������ UnRootkit.cpp
//

class CUnRootkitApp : public CWinAppEx
{
public:
	CUnRootkitApp();

// ��д
	public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CUnRootkitApp theApp;