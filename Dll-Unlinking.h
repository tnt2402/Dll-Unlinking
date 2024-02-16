// Dll-Unlinking.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <intrin.h>

// Main PEB loader data structure
// https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
//struct PEB_LDR_DATA {
//    BYTE       Reserved1[8];
//    PVOID      Reserved2[3];
//    LIST_ENTRY InMemoryOrderModuleList;
//};

// Data structure corresponding to each loaded DLL
// https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data#remarks
//struct LDR_DATA_TABLE_ENTRY {
//    PVOID Reserved1[2];
//    LIST_ENTRY InMemoryOrderLinks;
//    PVOID Reserved2[2];
//    PVOID DllBase;
//    PVOID EntryPoint;
//    PVOID Reserved3;
//    UNICODE_STRING FullDllName;
//    BYTE Reserved4[8];
//    PVOID Reserved5[3];
//    union {
//        ULONG CheckSum;
//        PVOID Reserved6;
//    };
//    ULONG TimeDateStamp;
//};

typedef struct _MY_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY      InLoadOrderLinks;
    LIST_ENTRY      InMemoryOrderLinks;
    LIST_ENTRY      InInitializationOrderLinks;
    PVOID           DllBase;
    PVOID           EntryPoint;
    ULONG           SizeOfImage;
    UNICODE_STRING  FullDllName;
    UNICODE_STRING  ignored;
    ULONG           Flags;
    SHORT           LoadCount;
    SHORT           TlsIndex;
    LIST_ENTRY      HashTableEntry;
    ULONG           TimeDateStamp;
} MY_LDR_DATA_TABLE_ENTRY;


void list_dlls(void);
void list_dlls_with_init_order_chaining(void);
void printHello(void);