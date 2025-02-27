#include "Helper.h"

void GetNtStatusCode(DWORD _statusValue)
{
	LPTSTR lpStatusCode;
	HMODULE hModule = LoadLibrary(const_cast<LPTSTR>(TEXT("ntdll.dll")));

	if (hModule == NULL)
	{
		printf("LoadLibrary() return null handle\n");
		return;
	}

	if (::FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_FROM_HMODULE,
		hModule, _statusValue, NULL, (LPTSTR)&lpStatusCode, 0, NULL))
	{
		printf("%ws\n", lpStatusCode);
	}
	else {
		printf("FormatMessage() return error %ws\n", GetLastError());
	}

	LocalFree(lpStatusCode);
	FreeLibrary(hModule);
}

void ShowError(DWORD _message)
{
	int message = _message;

	LPWSTR text;

	if (!::FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr, message, 0,
		(LPWSTR)&text, // because shoud be LPWSTR* — a pointer to a pointer 
		0, NULL))
	{
		printf("Error with 0x%x\n", GetLastError());
		return;
	}

	printf("Message %d: %ws\n", message, text);
	::LocalFree(text); // The caller should use the LocalFree function to free the buffer when it is no longer needed

}