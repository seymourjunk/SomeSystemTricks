#include "AntiDbg.h"

typedef NTSTATUS(WINAPI* PNtQueryInformationProcess)(
	IN	HANDLE			ProcessHandle,
	IN	DWORD			ProcessInformationClass,
	OUT	PVOID			ProcessInformation,
	IN	ULONG			ProcessInformationLength,
	OUT	PULONG			ReturnLength
	);

typedef NTSTATUS(WINAPI* PNtSetInformationThread)(
	IN	HANDLE			ThreadHandle,
	IN	ULONG			ThreaInformationClass,
	IN	PVOID			ThreadInformation,
	IN	ULONG			ThreadInformationLength
	);

PVOID GetPEB()
{
#ifdef _WIN64
	PPEB pPEB = (PPEB)(__readgsqword(0x60));
#else
	PPEB pPEB = (PPEB)(__readfsdword(0x30));
#endif

	return (PVOID)pPEB;
}

BOOL CheckIsBeingDebugged() // like IsDebuggerPresent()
{
	PPEB pPEB = (PPEB)GetPEB();
	DWORD isBeingDebugged = pPEB->BeingDebugged;

	printf("PEB->BeingDebugged: 0x%x\n", isBeingDebugged); // TODO: verbose log level
	return (BOOL)isBeingDebugged;
}

BOOL CheckNtGlobalFlag()
{
	PVOID pPEB = GetPEB();
#ifdef _WIN64
	DWORD globalFlag = *(PDWORD)((PBYTE)pPEB + 0xbc);
#else
	DWORD globalFlag = *(PDWORD)((PBYTE)pPEB + 0x68);
#endif

	printf("PEB->NtGlobalFlag: 0x%x\n", globalFlag); // TODO: verbose log level
	return (globalFlag & NT_GLOBAL_FLAG_DBG);
}

BOOL CheckHeapFlags()
{
	PVOID pPEB = GetPEB();
#ifdef _WIN64
	PVOID pProcessHeap = (PVOID)*(PDWORD_PTR)((PBYTE)pPEB + 0x30); // VOID* ProcessHeap;
	DWORD flags = *(PDWORD)((PBYTE)pProcessHeap + 0x70);
	DWORD forcedFlags = *(PDWORD)((PBYTE)pProcessHeap + 0x74);
#else
	PVOID pProcessHeap = (PVOID)*(PDWORD_PTR)((PBYTE)pPEB + 0x18); // VOID* ProcessHeap;
	DWORD flags = *(PDWORD)((PBYTE)pProcessHeap + 0x40);
	DWORD forcedFlags = *(PDWORD)((PBYTE)pProcessHeap + 0x44);
#endif

	printf("PEB->ProcessHeap->Flags: 0x%x\n", flags); // TODO: verbose log level
	printf("PEB->ProcessHeap->ForcedFlags: 0x%x\n", forcedFlags); // TODO: verbose log level
	return ((flags & ~HEAP_GROWABLE) || (forcedFlags));
}

BOOL RunCheckRemoteDebuggerPresent()
{
	BOOL bDebuggerPresent = FALSE;

	CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent);
	printf("CheckRemoteDebuggerPresent() return: %s\n", bDebuggerPresent ? "TRUE" : "FALSE"); // TODO: verbose log level

	return bDebuggerPresent;
}

BOOL RunNtQueryInformationProcess_DebugPort()
{
	HMODULE hNtDll = ::LoadLibrary(L"ntdll.dll");

	if (hNtDll)
	{
		PNtQueryInformationProcess NtQueryInfoProcess = (PNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess"); // retrieves the address of an exported function

		if (NtQueryInfoProcess)
		{
			DWORD_PTR dwProcessDebugPort;

			NTSTATUS status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDebugPort, &dwProcessDebugPort, sizeof(DWORD_PTR), NULL);

			if (NT_SUCCESS(status))
			{
				printf("NtQueryInformationProcess DebugPort return: %d\n", (DWORD)dwProcessDebugPort);  // TODO: verbose log level
				if (dwProcessDebugPort != 0)
					return TRUE;
				else
					return FALSE;
			}
			else
			{
				printf("NT_STATUS isn't STATUS_SUCCESS (0x00000000), but 0x%x: ", status);
				GetNtStatusCode(status);
			}
		}
	}
	return FALSE;
}

BOOL RunNtQueryInformationProcess_DebugFlags()
{
	HMODULE hNtDll = ::LoadLibrary(L"ntdll.dll");

	if (hNtDll)
	{
		PNtQueryInformationProcess NtQueryInfoProcess = (PNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess"); // retrieves the address of an exported function

		if (NtQueryInfoProcess)
		{
			DWORD dwNoDebugInherit;
			const DWORD ProcessDebugFlags = 0x1f;
			NTSTATUS status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDebugFlags, &dwNoDebugInherit, sizeof(DWORD), NULL);

			if (NT_SUCCESS(status))
			{
				printf("NtQueryInformationProcess DebugFlags return: %d\n", dwNoDebugInherit);  // TODO: verbose log level
				if (dwNoDebugInherit == 0)
					return TRUE;
				else
					return FALSE;
			}
			else
			{
				printf("NT_STATUS isn't STATUS_SUCCESS (0x00000000), but 0x%x: ", status);
				GetNtStatusCode(status);
			}
		}
	}
	return FALSE;
}

BOOL RunNtQueryInformationProcess_DebugObjectHandle()
{
	HMODULE hNtDll = ::LoadLibrary(L"ntdll.dll");

	if (hNtDll)
	{
		PNtQueryInformationProcess NtQueryInfoProcess = (PNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess"); // retrieves the address of an exported function

		if (NtQueryInfoProcess)
		{
			HANDLE hProcessDebugObject = nullptr;
			const DWORD ProcessDebugObjectHandle = 0x1e;
			NTSTATUS status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDebugObjectHandle, &hProcessDebugObject, sizeof(HANDLE), NULL);

			if (NT_SUCCESS(status))
			{
				printf("NtQueryInformationProcess DebugObjectHandle return: 0x%x\n", hProcessDebugObject);  // TODO: verbose log level
				if (hProcessDebugObject != 0)
				{
					CloseHandle(hProcessDebugObject);
					return TRUE;
				}
			}
			else
			{
				printf("NT_STATUS isn't STATUS_SUCCESS (0x00000000), but 0x%x: ", status);
				GetNtStatusCode(status);
			}
		}
	}
	
	return FALSE;
}

BOOL PrintParentProcessIdAndName()
{
	HMODULE hNtDll = ::LoadLibrary(L"ntdll.dll");

	if (hNtDll)
	{
		PNtQueryInformationProcess NtQueryInfoProcess = (PNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
		if (NtQueryInfoProcess)
		{
			newPROCESS_BASIC_INFORMATION processInfo;
			NTSTATUS status = NtQueryInfoProcess(GetCurrentProcess(), ProcessBasicInformation, &processInfo, sizeof(newPROCESS_BASIC_INFORMATION), NULL);

			if (NT_SUCCESS(status))
			{
				printf("Parent Process: %d\t %ls\n", (DWORD)processInfo.InheritedFromUniqueProcessId, GetProcessNameByPID(processInfo.InheritedFromUniqueProcessId).c_str());
				return TRUE;
			}
			else {
				printf("NT_STATUS isn't STATUS_SUCCESS (0x00000000), but 0x%x: ", status);
				GetNtStatusCode(status);
			}
		}
	}

	return FALSE;
}

#ifdef _WIN64
#pragma comment(linker, "/include:_tls_used")	// say the linker to create the TLS directory
#else
#pragma comment(linker, "/include:__tls_used")
#endif
#pragma section(".CRT$XLY", long, read)			// create a new section
void WINAPI TlsCallback(PVOID, DWORD, PVOID)
{
	if (IsDebuggerPresent())
	{
		printf("From TLS callback: process is running in a debugger\n");
		exit(-1);
	}
}

//__declspec(allocate(".CRT$XLY")) PIMAGE_TLS_CALLBACK tlsCallbackFunc = TlsCallback;	// tells the compiler that a particular variable is to be placed 
																					// in a specific section in the final executable

BOOL CheckHardwareBreakpoints()
{
	CONTEXT context = {};
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (GetThreadContext(GetCurrentThread(), &context))
	{
		printf("Debug registers: DR0 = 0x%llx, DR1 = 0x%llx, DR2 = 0x%llx, DR3 = 0x%llx\n", context.Dr0, context.Dr1, context.Dr2, context.Dr3);
		return (context.Dr0 || context.Dr1 || context.Dr2 || context.Dr3);
	}
	else
	{
		printf("ERROR: GetThreadContext()\n");
		ShowError(GetLastError());
	}
	
	return FALSE;
}

BOOL SetInformationThread()	
{
	HMODULE hNtDll = ::LoadLibrary(L"ntdll.dll");

	if (hNtDll)
	{
		PNtSetInformationThread NtSetInfoThread = (PNtSetInformationThread)GetProcAddress(hNtDll, "NtSetInformationThread");

		if (NtSetInfoThread)
		{
			const ULONG ThreadHideFromDebugger = 0x11;
			NTSTATUS status = NtSetInfoThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0); // debugger will not receive any events after that

			if (NT_SUCCESS(status))
			{
				printf("ThreadHideFromDebugger is set\n");
				return TRUE;
			}
			else
			{
				printf("NT_STATUS isn't STATUS_SUCCESS (0x00000000), but 0x%x: ", status);
				GetNtStatusCode(status);
			}
		}		
	}
	return FALSE;
}

void RunAllDbgChecks()
{
	// if (CheckIsBeingDebugged() | CheckNtGlobalFlag() | CheckHeapFlags() | RunCheckRemoteDebuggerPresentWin32API() | RunNtQueryInformationProcessWin32API_DebugPort())
	if (RunNtQueryInformationProcess_DebugObjectHandle())
		printf("[WARNING]: process is running in a debugger\n");
}