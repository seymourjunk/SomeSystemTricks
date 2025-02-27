#pragma once
#include "Helper.h"

#include <iostream>
#include <Windows.h>
#include <winternl.h>

#define FLG_HEAP_ENABLE_TAIL_CHECK		0x10
#define FLG_HEAP_ENABLE_FREE_CHECK		0x20
#define FLG_HEAP_VALIDATE_PARAMETERS	0x40
#define NT_GLOBAL_FLAG_DBG (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)



PVOID GetPEB();
BOOL CheckIsBeingDebugged();							// PEB!BeingDebugged Flag
BOOL CheckNtGlobalFlag();								// PEB!NtGlobalFlag
BOOL CheckHeapFlags();									// PEB!ProcessHeap
BOOL RunCheckRemoteDebuggerPresent();					// run existing WinApi functions and return result
BOOL RunNtQueryInformationProcess_DebugPort();			// use NtQueryInformationProcess() Win32 API function
BOOL RunNtQueryInformationProcess_DebugFlags();			// use NtQueryInformationProcess() Win32 API function
BOOL RunNtQueryInformationProcess_DebugObjectHandle();			// use NtQueryInformationProcess() Win32 API function
void RunAllDbgChecks();

