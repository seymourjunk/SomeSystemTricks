#include "AntiDbg.h"

typedef NTSTATUS(WINAPI* PNtQueryInformationProcess)(
	IN	HANDLE				ProcessHandle,
	IN	DWORD				ProcessInformationClass,
	OUT	PVOID				ProcessInformation,
	IN	ULONG				ProcessInformationLength,
	OUT	PULONG				ReturnLength
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

			printf("NtQueryInformationProcess DebugPort return: %d\n", dwProcessDebugPort);  // TODO: verbose log level
			if (NT_SUCCESS(status))
			{
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

			printf("NtQueryInformationProcess DebugFlags return: %d\n", dwNoDebugInherit);  // TODO: verbose log level
			if (NT_SUCCESS(status))
			{
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
			HANDLE hProcessDebugObject = NULL;
			const DWORD ProcessDebugObjectHandle = 0x1e;
			NTSTATUS status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDebugObjectHandle, &hProcessDebugObject, sizeof(HANDLE), NULL);

			printf("NtQueryInformationProcess DebugFlags return: 0x%x\n", hProcessDebugObject);  // TODO: verbose log level
			if (NT_SUCCESS(status))
			{
				if (hProcessDebugObject != 0)
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

void RunAllDbgChecks()
{
	// if (CheckIsBeingDebugged() | CheckNtGlobalFlag() | CheckHeapFlags() | RunCheckRemoteDebuggerPresentWin32API() | RunNtQueryInformationProcessWin32API_DebugPort())
	if (RunNtQueryInformationProcess_DebugObjectHandle())
		printf("[WARNING]: process is running in a debugger\n");
}