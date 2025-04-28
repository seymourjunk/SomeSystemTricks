#include "SingleInstance.h"
#include "Helper.h"
#include <iostream>


// TODO: find another way, not FindWindow()
void NotifyOtherInstance()
{
    auto hWnd = ::FindWindow(nullptr, L"SomeSystemTricks");
    if (!hWnd) {
        printf("Failed to launch another instance application: Single instance application\n");
        return;
    }

}


void SetMutexForSingleInstance(LPTSTR lpMutexName)
{
    HANDLE hMutex = ::CreateMutex(nullptr, FALSE, lpMutexName); // TODO: generate name (a malicious user can create this mutex before you do and prevent your application from starting)
    if (!hMutex) {
        printf("[ERROR] Create mutex error\n");
        ShowError(GetLastError());
        exit(1);
    }

    if (::GetLastError() == ERROR_ALREADY_EXISTS) {
        //NotifyOtherInstance();
        ShowError(GetLastError());
        printf("[ERROR] The single instance of application exists\n");
        exit(1);
    }
}


void SetLockedFileForSingleInstance(LPTSTR lpLockFileName)
{
    //WCHAR lockFileName[MAX_PATH + 1] = { lpLockFileName }; // TODO: path
    HANDLE hLockFile = ::CreateFile(lpLockFileName, GENERIC_READ, 0, nullptr, CREATE_NEW, FILE_FLAG_DELETE_ON_CLOSE, nullptr);


    if (!hLockFile) {
        printf("[ERROR] Create lock file error\n");
        ShowError(GetLastError());
        exit(1);
    }

    if (::GetLastError() == ERROR_FILE_EXISTS)
    {
        //NotifyOtherInstance();
        ShowError(GetLastError());
        printf("[ERROR] The single instance of application exists\n");
        exit(1);
    }

}