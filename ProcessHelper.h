#pragma once
#include <iostream>
#include <Windows.h>


BOOL KillProcessByPID(DWORD pid);
BOOL GetProcessList();
std::wstring GetProcessNameById(DWORD pid);
DWORD GetProcessIdByName(std::wstring processName);
