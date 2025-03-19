#pragma once
#include "Helper.h"
#include "ProcessHelper.h"

#include <iostream>
#include <Windows.h>
#include <winternl.h>

#define FLG_HEAP_ENABLE_TAIL_CHECK		0x10
#define FLG_HEAP_ENABLE_FREE_CHECK		0x20
#define FLG_HEAP_VALIDATE_PARAMETERS	0x40
#define NT_GLOBAL_FLAG_DBG (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

typedef struct _newPROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} newPROCESS_BASIC_INFORMATION;

PVOID GetPEB();
BOOL CheckIsBeingDebugged();							// PEB!BeingDebugged Flag
BOOL CheckNtGlobalFlag();								// PEB!NtGlobalFlag
BOOL CheckHeapFlags();									// PEB!ProcessHeap
BOOL RunCheckRemoteDebuggerPresent();					// run existing WinApi functions and return result
BOOL RunNtQueryInformationProcess_DebugPort();			// use NtQueryInformationProcess() Win32 API function
BOOL RunNtQueryInformationProcess_DebugFlags();
BOOL RunNtQueryInformationProcess_DebugObjectHandle();
BOOL SetInformationThread();
BOOL CheckHardwareBreakpoints();						// check DR0-DR3 registers
BOOL PrintParentProcessIdAndName();
void RunAllDbgChecks();

