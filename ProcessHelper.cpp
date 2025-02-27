#include "ProcessHelper.h"


BOOL KillProcessByPID(DWORD pid)
{
    HANDLE hProcess = ::OpenProcess(PROCESS_TERMINATE, FALSE, pid);

    if (!hProcess) {
        printf("ERROR: handle create error\n");
        return FALSE;
    }

    BOOL success = ::TerminateProcess(hProcess, 1);
    ::CloseHandle(hProcess);
    return success != FALSE;

}