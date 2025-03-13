#pragma once
#include "ProcessInfo.h"
#include <windows.h>
#include <psapi.h>
#include <pdh.h>

class DLL2_API ProcessMonitor {
public:
    ProcessMonitor();
    ~ProcessMonitor();
    ProcessInfo GetProcessInfo(DWORD processID);
};

extern "C" {
    DLL2_API ProcessInfo __stdcall GetProcessInfo(DWORD processID);
} 