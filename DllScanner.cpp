#include "DllScanner.h"

BOOL debug = TRUE;
BOOL verbose = FALSE;
BOOL veryVerbose = FALSE;

typedef HMODULE(WINAPI* pNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
//NTSTATUS

// Returns a pointer to the PEB by reading the FS or GS registry
// cf. https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
PEB* get_peb() {
#ifdef _WIN64
    return (PEB*)__readgsqword(0x60);
#else
    return  (PEB*)__readfsdword(0x30);
#endif
}




PUNICODE_STRING unicodeStringFromCharArray(char* charString)
{
	unsigned int lengthWithoutNulls = 0;
	PUNICODE_STRING newString = (PUNICODE_STRING)malloc(sizeof(UNICODE_STRING));
	ZeroMemory(newString, sizeof(UNICODE_STRING));
	//printf("\t\tIncomming char String: %s from %#p\n", charString, charString);

	while (charString[lengthWithoutNulls] != 0 && lengthWithoutNulls < MAX_PATH) {
		lengthWithoutNulls++;
	}

	if (lengthWithoutNulls == MAX_PATH && debug)
	{
		printf("WARNING: String is max size. Probably bad string (or not NULL terminated): '%s'\n", charString);
	}
	else if (lengthWithoutNulls == 0) {
		newString->Length = 0;
		newString->MaximumLength = 1;
		PWSTR  Buffer = (PWSTR)malloc(1);
		Buffer[0] = 0;
		newString->Buffer = Buffer;

		return newString;
	}

	// make new unicode string struct
	newString->Length = (lengthWithoutNulls * 2);
	newString->MaximumLength = lengthWithoutNulls * 2;
	PWSTR  Buffer = (PWSTR)malloc(lengthWithoutNulls * 2);
	ZeroMemory(Buffer, lengthWithoutNulls * 2); // I shouldn't actually need this but just to be safe...
	newString->Buffer = Buffer;

	// actually copy the string - assuming UTF-8
	// I shouldn't actually need all these conditions but just to be safe...
	unsigned int i = 0;
	//printf("\t\tAbout to populate UNICODE_STRING String: '%wZ' at address %#p\n", newString, &(newString->Buffer));
	while (i < lengthWithoutNulls && i < MAX_PATH) {
		newString->Buffer[i] = charString[i];		//Buffer[i] doesn't need to be Buffer[i * 2] because Buffer is a wide string
		i++;
	}
	//printf("\t\tReturning UNICODE_STRING String: '%wZ' at address %#p\n", newString, &(newString->Buffer));
	return newString;
}

// AdjustTokenPrivilege sample code
BOOL SetPrivilege(HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,				// lookup privilege on local system
        lpszPrivilege,		// privilege to lookup 
        &luid))				// receives LUID of privilege
    {
        DWORD err = GetLastError();
        printf("LookupPrivilegeValue error: %u\n", err);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        DWORD err = GetLastError();
        printf("Warning: AdjustTokenPrivileges error: %u\n", err);
        return FALSE;
    }

    return TRUE;
}

BOOL SetDebugPrivilege()
{
    HANDLE hToken;
    BOOL ret;
    try
    {
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
        ret = SetPrivilege(hToken, SE_DEBUG_NAME, 1);
    }
    catch (char* str)
    {
        fprintf(stderr, "doSetDebugPrivilege: failed: %s\n", str);
        exit(EXIT_FAILURE);
    }
    return ret;
}

//// returns a new ascii string with only the file created from the full path
//// reimplement these later to prevent hooking
//char* getFileName(char* fullPath)
//{
//    //printf("\t\tFullpath: %s\n", fullPath);
//    char* filename = (char*)malloc(MAX_PATH);
//    ZeroMemory(filename, MAX_PATH);
//
//    strcpy_s(filename, MAX_PATH, fullPath);
//    //printf("\t\tCopy of Fullpath: %s\n", filename);
//    // FltParseFileName() would be nice for unicode
//    PathStripPath(filename);
//
//    //printf("\t\tFile: %s\n", filename);
//    return filename;
//}

// Prints a list of DLLs loaded in the current process
void list_dlls(_PEB* peb) {
    //PEB* peb = get_peb();

    LIST_ENTRY* current = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* first = current;

    while (current->Flink != first) {
        // current->Flink points to the 'InMemoryOrderLinks' field of the LDR_DATA_TABLE_ENTRY we want to reach
        // We use CONTAINING_RECORD to substract the proper offset from this pointer and reach the beginning of the structure
        LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(current->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        printf("%wZ loaded at %p\n", entry->FullDllName, entry->DllBase);
        current = current->Flink;
    }
}

void list_dlls_with_init_order_chaining(_PEB* peb) {
    //PEB* peb = get_peb();

    // Retrieve the entry in memory order
    LIST_ENTRY* inMemoryOrderList = &peb->Ldr->InMemoryOrderModuleList;
    MY_LDR_DATA_TABLE_ENTRY* firstInMemoryEntry = CONTAINING_RECORD(inMemoryOrderList, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

    // Then use the 'in load order' chaining links to iterate over DLLs
    LIST_ENTRY* current = &firstInMemoryEntry->InLoadOrderLinks;
    LIST_ENTRY* first = current;
    while (current->Flink != first) {
        MY_LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(current->Flink, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        printf("%wZ loaded\n", entry->FullDllName);
        current = current->Flink;
    }
}

void unlink_peb(void) {
    PEB* peb = get_peb();
    LIST_ENTRY* current = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* first = current;
    while (current->Flink != first) {
        MY_LDR_DATA_TABLE_ENTRY* entry = (MY_LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(current, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        char dllName[256];
        snprintf(dllName, sizeof(dllName), "%wZ", entry->FullDllName);
        //if (strstr(dllName, "MYMALICIOUSDLL.DLL") != NULL) {
        //    // Found the DLL! Unlink it from the 3 doubly linked lists
        //    entry->InLoadOrderLinks.Blink->Flink = entry->InLoadOrderLinks.Flink;
        //    entry->InLoadOrderLinks.Flink->Blink = entry->InLoadOrderLinks.Blink;

        //    entry->InMemoryOrderLinks.Blink->Flink = entry->InMemoryOrderLinks.Flink;
        //    entry->InMemoryOrderLinks.Flink->Blink = entry->InMemoryOrderLinks.Blink;

        //    entry->InInitializationOrderLinks.Blink->Flink = entry->InInitializationOrderLinks.Flink;
        //    entry->InInitializationOrderLinks.Flink->Blink = entry->InInitializationOrderLinks.Blink;

        //    return;
        //}
        current = current->Flink;
    }
}


int readRemoteProcessForModules(PROCESSENTRY32 pe32, PROCESS_INFORMATION pi, WORD remote32bitPEBAddress) {
	// normally I wouldn't pass the whole struct in, but I don't really need to pass anything back and I don't feel like re-writing code

	//PROCESS_INFORMATION pi = { 0 };
	//PROCESSENTRY32 pe32

	PROCESS_BASIC_INFORMATION pbi = { 0 };
	NTSTATUS status;

	// Setup for loop
	HMODULE ntdll = LoadLibrary("Ntdll.dll");
	// Dyamic calling to (attempt) prevention of defaul shim style hooking
	pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");

	ULONG pbi_len = 0;
	NTSTATUS result = (NTSTATUS)NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &pbi_len);

	BOOL pebResult = FALSE;
	BOOL DllResult = FALSE;
	BOOL DllResultTemp = FALSE;

	SIZE_T bytes_read = 0;
	SIZE_T bytes_read_for_undocumented_remote_peb = 0;

	char* exePath;
	if (result == 0)
	{
		// this will only show the x64 DLLs
		if (pbi.PebBaseAddress)	// read about how this works because I don't think it's getting the right PEB, it's not the 32 bit or 64 bit... maybe I'll need to get the context struct to get the PEB address from the register. Look to see how process explorer and/or process hacker does it
		{
			moonsols_win7_PEB undocumented_remote_peb = { 0 };						// undocumented
			_PEB remote_peb = { 0 };									// documented
			//P_moonsols_win7_PEB_LDR_DATA pLdr = { 0 };				// undocumented
			PPEB_LDR_DATA pLdr = { 0 };									// documented
			_moonsols_win7_PEB_LDR_DATA LdrData = { 0 };				// undocumented
			//PEB_LDR_DATA LdrData = { 0 };								// documented

			bytes_read = 0;
			if (ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &remote_peb, sizeof(_PEB), &bytes_read))
			{

				if (debug) printf("PEB Address in %s: %#p\n", pe32.szExeFile, pbi.PebBaseAddress);
				// I need the undocumented fields so I'm using a undocument struct re-created from windbg
				// I can do this a few different ways (I did this becuase I found a bug in one of the meathods:

				// 1. make another pointer to the remote memory I just read
				//&undocumented_remote_peb = (P_moonsols_win7_PEB)(&(remote_peb));
				//pebResult = pebHasAppCompatFlags((P_moonsols_win7_PEB)&remote_peb);	// not working for some reason	

				// 2. copy the memory into a new custom struct
				//memcpy(&undocumented_remote_peb, &remote_peb, bytes_read);	// PEB and undocumented PEB are different sizes so can't do this

				// 3. Re-read the remote memory
				ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &undocumented_remote_peb, sizeof(moonsols_win7_PEB), &bytes_read_for_undocumented_remote_peb);

				list_dlls(&remote_peb);


				// check the dll names

				// get address of Ldr from the PEB
				PPEB_LDR_DATA remote_ldr_pointer = remote_peb.Ldr;
				if (debug) printf("Remote Ldr Address: 0x%p\n", remote_ldr_pointer);

				// get the Ldr structure
				PEB_LDR_DATA remote_ldr = { 0 };
				status = ReadProcessMemory(pi.hProcess,
					remote_ldr_pointer,
					&remote_ldr,
					sizeof(PEB_LDR_DATA),
					&bytes_read);
				if (debug) printf("Address of copied over Ldr: 0x%p\n", &remote_ldr);

				// get the List entry struct from the Ldr
				LIST_ENTRY InMemoryOrderModuleList = (remote_ldr.InMemoryOrderModuleList);
				if (debug) printf("Address of copied over InMemoryOrderModuleList: 0x%p\n", &InMemoryOrderModuleList);

				// get the first link - Might be PLIST_ENTRY64
				LIST_ENTRY* address_of_remote_link = InMemoryOrderModuleList.Flink;
				if (debug) printf("Remote List Entry Address: 0x%p\n", address_of_remote_link);

				// calculate the address of the LDR_DATA_TABLE_ENTRY (of which the InMemoryOrderLinks is a member)
				LDR_DATA_TABLE_ENTRY* address_of_remote_ldr_ent = CONTAINING_RECORD(address_of_remote_link, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
				if (debug) printf("Remote LDR_DATA_TABLE_ENTRY Address: 0x%p\n", address_of_remote_ldr_ent);

				//get the actual remote Table Entry
				LDR_DATA_TABLE_ENTRY remote_ldr_ent = { 0 };
				status = ReadProcessMemory(pi.hProcess,
					address_of_remote_ldr_ent,
					&remote_ldr_ent,
					sizeof(LDR_DATA_TABLE_ENTRY),
					&bytes_read);
				if (debug) printf("Address of copied over LDR_DATA_TABLE_ENTRY Address: 0x%p\n", &remote_ldr_ent);

				if (debug) printf("Printing DLL list. Starting with: 0x%p\n", &remote_ldr_ent);
				unsigned int i = 0;
				while (TRUE) {
					// the last entry will have a NULL for the name and for the address. Then it cycles back
					if (remote_ldr_ent.DllBase == NULL) break;

					// make the memory for the unicode string
					if (veryVerbose) printf("Making a Unicode String length of: %d. Max: %d\n", remote_ldr_ent.FullDllName.Length, remote_ldr_ent.FullDllName.MaximumLength);
					PWSTR namebuffer = (PWSTR)malloc(remote_ldr_ent.FullDllName.MaximumLength); // I don't know why the string lengths are sometimes smaller than what they say

					// get the string's buffer
					status = ReadProcessMemory(pi.hProcess,
						remote_ldr_ent.FullDllName.Buffer,
						namebuffer,
						remote_ldr_ent.FullDllName.MaximumLength,
						&bytes_read);

					// reconstruct unicode struct
					remote_ldr_ent.FullDllName.Buffer = namebuffer;

					// Check the DLL name
					if (veryVerbose) printf("\tx64 DLL Name: %wZ\n", remote_ldr_ent.FullDllName);

					
					DllResult = DllResult | DllResultTemp;

					LIST_ENTRY* address_of_next_remote_link = remote_ldr_ent.InMemoryOrderLinks.Flink;
					LDR_DATA_TABLE_ENTRY* address_of_next_remote_ldr_ent = CONTAINING_RECORD(address_of_next_remote_link, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

					// free malloc'd string Because the code below will read in another table entry which will over write the pointer anyway
					free(remote_ldr_ent.FullDllName.Buffer);

					//get the actual remote Table Entry
					status = ReadProcessMemory(pi.hProcess,
						address_of_next_remote_ldr_ent,
						&remote_ldr_ent,
						sizeof(LDR_DATA_TABLE_ENTRY),
						&bytes_read);


				}// end while TRUE for looping over the remote LDR_DATA_TABLE_ENTRY entries

			}
			else {
				printf("Could not read other processes memory. Error: %d\n", GetLastError());
			}
		}
		else {
			printf("Could not get other process's PEB base address. Error: %d\n", GetLastError());
		}


		/////////////// Using the Documented way: https://msdn.microsoft.com/en-us/library/windows/desktop/ms686849%28v=vs.85%29.aspx 
		HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
		MODULEENTRY32 me32;

		//  Take a snapshot of all modules in the specified process. 
		hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, pe32.th32ProcessID);
		if (hModuleSnap == INVALID_HANDLE_VALUE)
		{
			printf("Failed at: CreateToolhelp32Snapshot (of modules)");
			return 0;
		}

		//  Set the size of the structure before using it. 
		me32.dwSize = sizeof(MODULEENTRY32);

		//  Retrieve information about the first module, 
		//  and exit if unsuccessful 
		if (!Module32First(hModuleSnap, &me32))
		{
			printf("Failed at Module32First");  // Show cause of failure 
			CloseHandle(hModuleSnap);     // Must clean up the snapshot object! 
			return 0;
		}

		//  Now walk the module list of the process, 
		//  and display information about each module 
		do
		{
			printf("\n\n     MODULE NAME:     %s", me32.szModule);
			printf("\tExecutable = %s\n", me32.szExePath);
			
			/*exePath = getFileName(me32.szExePath);
			PUNICODE_STRING filename = unicodeStringFromCharArray(exePath);
			printf("\t\tComparing Executable: '%wZ'\n", filename);*/
			/*printf("\n     process ID     = 0x%08X", me32.th32ProcessID);
			printf("\n     ref count (g)  =     0x%04X", me32.GlblcntUsage);
			printf("\n     ref count (p)  =     0x%04X", me32.ProccntUsage);
			printf("\n     base address   = 0x%08X", (DWORD)me32.modBaseAddr);
			printf("\n     base size      = %d", me32.modBaseSize);*/

		} while (Module32Next(hModuleSnap, &me32));

		//  Do not forget to clean up the snapshot object. 
		CloseHandle(hModuleSnap);



	} // end NtQueryInformationProcess check
	else {

		if (result == STATUS_ACCESS_DENIED && (verbose || debug)) {
			printf("STATUS_ACCESS_DENIED\n");
		}
		else if (result == STATUS_INVALID_HANDLE && (verbose || debug)) {	// && !cmp ('system') && !cmp(' that other process name')
			printf("STATUS_INVALID_HANDLE\n");
		}
		else if (verbose || debug) {
			printf("NtQuery Failed. Read out %d bytes. Error: 0x%p\n", pbi_len, result);
		}
	}


	return 0;
}
