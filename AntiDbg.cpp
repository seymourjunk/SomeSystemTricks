#include "AntiDbg.h"
#include "Helper.h"
#include "ProcessHelper.h"


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

typedef NTSTATUS(WINAPI* PNtCreateThreadEx)(
	OUT			PHANDLE				ThreadHandle,
	IN			ACCESS_MASK			DesireAccess,
	IN OPTIONAL	POBJECT_ATTRIBUTES	ObjectAttributes,
	IN			HANDLE				ProcessHandle,
	IN			PVOID				StartRoutine,
	IN OPTIONAL	PVOID				Argument,
	IN			ULONG				CreateFlags,
	IN OPTIONAL	ULONG_PTR			ZeroBits,
	IN OPTIONAL	SIZE_T				StackSize,
	IN OPTIONAL	SIZE_T				MaximumStackSize,
	IN OPTIONAL	PVOID				AttributeList
	);

typedef NTSTATUS(WINAPI* PNtQueryInformationThread)(
	IN				HANDLE	ThreadHandle,
	IN				ULONG	ThreadInformationClass,
	IN OPTIONAL		PVOID	ThreadInformation,
	IN				ULONG	ThreadInformationLength,
	OUT OPTIONAL	PULONG	ReturnLength
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

BOOL GetBeingDebuggedFlag() // like IsDebuggerPresent()
{
	PPEB pPEB = (PPEB)GetPEB();
	DWORD isBeingDebugged = pPEB->BeingDebugged;

	printf("PEB->BeingDebugged: 0x%x\n", isBeingDebugged); // TODO: verbose log level
	return (BOOL)isBeingDebugged;
}

void SetBeingDebuggedFlag(DWORD dwFlag)
{
	PPEB pPEB = (PPEB)GetPEB();
	pPEB->BeingDebugged = dwFlag;
	printf("PEB->BeingDebugged is set 0x%x\n", dwFlag);
}

BOOL GetNtGlobalFlag()
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

void SetNtGlobalFlag(DWORD dwFlag)
{
	PVOID pPEB = GetPEB();
#ifdef _WIN64
	PDWORD pGlobalFlag = (PDWORD)((PBYTE)pPEB + 0xbc);
#else
	PDWORD pGlobalFlag = (PDWORD)((PBYTE)pPEB + 0x68);
#endif

	*pGlobalFlag = dwFlag;
	printf("PEB->NtGlobalFlag is set 0x%x\n", dwFlag);
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
				std::wstring processName = GetProcessNameById(processInfo.InheritedFromUniqueProcessId);
				if (processName == L"")
				{
					printf("[ERROR] Process name by id was not found \n");
					return FALSE;
				}

				printf("Parent Process: %d\t %ls\n", (DWORD)processInfo.InheritedFromUniqueProcessId, processName.c_str());
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

void CreateThreadWithHideFromDebuggerFlag()
{
	HMODULE hNtDll = ::LoadLibrary(L"ntdll.dll");

	if (hNtDll)
	{
		HANDLE hThread = 0;
		PNtCreateThreadEx NtCreateThread = (PNtCreateThreadEx)GetProcAddress(hNtDll, "NtCreateThreadEx");

		if (NtCreateThread)
		{
			NTSTATUS status = NtCreateThread(&hThread, THREAD_ALL_ACCESS, 0, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)CheckThreadDebugFlag, 0, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, 0, 0, 0, 0);
			if (NT_SUCCESS(status))
			{
				printf("A new thread [%d] with THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER flag was created\n", GetThreadId(hThread));
				WaitForSingleObject(hThread, INFINITE); // TODO
			}
			else
			{
				printf("NT_STATUS isn't STATUS_SUCCESS (0x00000000), but 0x%x: ", status);
				GetNtStatusCode(status);
			}
		}
	}
}

BOOL CheckThreadDebugFlag()
{
	HMODULE hNtDll = ::LoadLibrary(L"ntdll.dll");

	if (hNtDll)
	{
		BOOLEAN result = FALSE;
		PNtQueryInformationThread NtQueryInfoThread = (PNtQueryInformationThread)GetProcAddress(hNtDll, "NtQueryInformationThread");

		if (NtQueryInfoThread)
		{
			NTSTATUS status = NtQueryInfoThread(NtCurrentThread(), ThreadHideFromDebugger, &result, sizeof(result), 0);

			if (NT_SUCCESS(status))
			{
				if (result) printf("ThreadHideFromDebugger flag set for current thread [%d]\n", GetCurrentThreadId());
				else printf("ThreadHideFromDebugger flag is not set for current thread [%d]\n", GetCurrentThreadId());
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

BOOL CheckSeDebugPrivilegeOfProcess()
{
	// see if we can open system process
	DWORD pidSystemProcess = GetProcessIdByName(L"csrss.exe");
	if (pidSystemProcess == -1)
	{
		printf("[ERROR] Process id by name was not found \n");
		return FALSE;
	}

	HANDLE hDebug = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pidSystemProcess);
	if (hDebug)
	{
		CloseHandle(hDebug);
		return TRUE;
	}
	else ShowError(GetLastError());
	
	return FALSE;
}

BOOL CheckTrapFlag()	// for x86
{
	__try
	{
		__asm
		{
			pushfd
			or dword ptr [esp], 0x100
			popfd
			nop
		}

		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}
}

void RunAllDbgChecks()
{
	if (CheckTrapFlag())
		printf("[WARNING]: process is running in a debugger\n");
}