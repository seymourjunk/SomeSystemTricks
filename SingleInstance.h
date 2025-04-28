#pragma once
#include <Windows.h>

void SetMutexForSingleInstance(LPTSTR lpMutexName);
void SetLockedFileForSingleInstance(LPTSTR lpLockFileName);