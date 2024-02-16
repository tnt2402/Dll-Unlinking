#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <winternl.h>
#include <cstdio>
#include <tchar.h>

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(*_MyNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

struct PEBInfo {
    DWORD PID;
    DWORD64 PEBAddress;
    DWORD64 CrossProcessFlags;
};

extern BOOL EnumerateProcesses();
extern BOOL GetPEB_2(HANDLE hProcess, PEB* outPEB);

