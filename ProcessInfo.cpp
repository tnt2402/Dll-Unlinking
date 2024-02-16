#include "ProcessInfo.h"

BOOL GetPEB_2(HANDLE hProcess, PEB* ppeb) {
    PROCESS_BASIC_INFORMATION pbi;
    if (!NT_SUCCESS(NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr))) {
        _tprintf(_T("Failed to get process information. Error code: %d\n"), GetLastError());
        return FALSE;
    }

    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, ppeb, sizeof(PEB), nullptr)) {
        _tprintf(_T("Failed to read PEB from process memory. Error code: %d\n"), GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL EnumerateProcesses() {
    DWORD dwPIDArray[4096], dwRet, dwPIDS, intCount;
    TCHAR strErrMsg[1024];

    if (!EnumProcesses(dwPIDArray, 4096 * sizeof(DWORD), &dwRet)) {
        DWORD dwRet = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, strErrMsg, 1023, NULL);
        if (dwRet != 0) {
            _ftprintf(stderr, TEXT("[!] EnumProcesses() failed - %s"), strErrMsg);
        }
        else {
            _ftprintf(stderr, TEXT("[!] EnumProcesses() - Error: %d\n"), GetLastError());
        }
        return FALSE;
    }

    dwPIDS = dwRet / sizeof(DWORD);

    for (intCount = 0; intCount < dwPIDS; intCount++) {
        DWORD dwPID = dwPIDArray[intCount];
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
        if (hProcess != NULL) {
            PEB peb;
            if (GetPEB_2(hProcess, &peb)) {
                _tprintf(_T("Process PID: %d, PEB Address: 0x%llx\n"), dwPID, (DWORD64)&peb);
            }
            else {
                _tprintf(_T("Failed to get PEB for process with PID: %d\n"), dwPID);
            }
            CloseHandle(hProcess);
        }
    }

    return TRUE;
}

