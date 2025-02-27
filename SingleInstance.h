#pragma once
#include "Helper.h"

#include <iostream>
#include <Windows.h>

void SetMutexForSingleInstance(LPTSTR lpMutexName);
void SetLockedFileForSingleInstance(LPTSTR lpLockFileName);