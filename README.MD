#### ABOUT
Just a stash of some snippets from reverse engineering/system programming journey.

##### AntiDbg
Common anti-debug techniques:
- PEB!BeingDebugged Flag
- NtGlobalFlag (PEB)
- Heap Flags (PEB)
- IsDebuggerPresent() (WinAPI)
- CheckRemoteDebuggerPresent() (WinAPI)
- NtQueryInformationProcess() (WinAPI): ProcessDebugPort, ProcessDebugFlags, ProcessDebugObjectHandle
- Get the name and ID of the parent process (PROCESS_BASIC_INFORMATION!InheritedFromUniqueProcessId)


##### SingleInstance
Check that only one instance of app us running
- via mutex
- via locked file
? TODO: generate name (a malicious user can create this mutex before you do and prevent your application from starting)
? TODO: NotifyOtherInstance()

##### ProcessHelper
- kill process by PID

##### Helper
- get description of error and NTSTATUS code
- 