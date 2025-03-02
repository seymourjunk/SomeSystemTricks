#pragma once
#include "Helper.h"
#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>


BOOL KillProcessByPID(DWORD pid);
BOOL GetProcessList();
std::wstring GetProcessNameByPID(DWORD pid);
