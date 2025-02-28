#include "ProcessHelper.h"


BOOL KillProcessByPID(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);

    if (!hProcess) {
        printf("ERROR: handle create error\n");
        return FALSE;
    }

    BOOL success = TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);
    return success != FALSE;

}

BOOL GetProcessList()
{
    HANDLE hSnapProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    PROCESSENTRY32 processEntry;

    if (hSnapProcess == INVALID_HANDLE_VALUE)
    {
        printf("ERROR: handle create error\n");
        ShowError(GetLastError());
        return FALSE;
    }

    processEntry.dwSize = sizeof(PROCESSENTRY32);
    if (!::Process32First(hSnapProcess, &processEntry)) // first process
    {
        printf("ERROR: Process32First()\n");
        ShowError(GetLastError());
        CloseHandle(hSnapProcess);
        return FALSE;
    }

    printf("  Process ID  \t  Process Name  \n");
    printf("====================================\n");
    do
    {
        printf("  %-8d \t  %ws  \n", processEntry.th32ProcessID, processEntry.szExeFile);

    } while (::Process32Next(hSnapProcess, &processEntry));

    CloseHandle(hSnapProcess);
    return TRUE;
}