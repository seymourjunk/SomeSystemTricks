#pragma once
#include <Windows.h>

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
void GetNtStatusCode(DWORD _statusValue);
void ShowError(DWORD _message);
