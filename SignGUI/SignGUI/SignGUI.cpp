#include "stdafx.h"

#include <commctrl.h>
#include <stdlib.h>
#include <tchar.h>

#include "resource.h"

#pragma comment(lib, "comctl32.lib")

INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

int APIENTRY WinMain(HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR     lpCmdLine,
	int       nCmdShow)
{
	INITCOMMONCONTROLSEX icc = { 0 };
	icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icc.dwICC = ICC_TREEVIEW_CLASSES;
	BOOL bRet = InitCommonControlsEx(&icc);
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG), NULL, (DLGPROC)DialogProc);

	return 0;
}

INT_PTR CALLBACK DialogProc(HWND hWndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDOK:
			EndDialog(hWndDlg, IDOK);
			break;
		case IDCANCEL:
			EndDialog(hWndDlg, IDCANCEL);
			break;
		}
		break;
	case WM_INITDIALOG:
	{
						  SetFocus(hWndDlg);
	}
		return FALSE; // FALSE since we set focus to hWndTreeView
	case WM_CLOSE:
		if (MessageBox(hWndDlg,
			TEXT("Close the window?"), TEXT("Close"),
			MB_ICONQUESTION | MB_YESNO) == IDYES)
		{
			DestroyWindow(hWndDlg);
		}
		return TRUE;
	case WM_DESTROY:
	{
					   DestroyWindow(hWndDlg);
	}
		break;
	case WM_NOTIFY:
	{
					  //long lResult = handleNotify(hWndDlg, (int)wParam, (LPNMHDR)lParam);

					  // This is the way a dialog box can send back lresults.. 
					  // See documentation for DialogProc for more information
					 // SetWindowLong(hWndDlg, DWL_MSGRESULT, lResult);
					  return TRUE;
	}
		break;
	}
	return FALSE;
}