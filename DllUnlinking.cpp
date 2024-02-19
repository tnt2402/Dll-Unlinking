// Dll-Unlinking.cpp : Defines the entry point for the application.
//
#include "DllUnlinking.h"
#include "DllScanner.h"
#include <TlHelp32.h>
using namespace std;


int main()
{

	// To open a handle to another local process and obtain full access rights, you must enable the SeDebugPrivilege 
	SetDebugPrivilege();

	// check my own PEB
	PPEB peb = (PPEB)__readgsqword(0x60);											// documented
	P_moonsols_win7_PEB local_peb_undocumented = (P_moonsols_win7_PEB)peb;			// undocumented 
	printf("Address of local x64 PEB: %#p\n", peb);
	printf("Address of local x32 PEB: %#p\n", __readgsdword(0x30));
	


	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;


	//_moonsols_win7_PEB_LDR_DATA Ldr	// undocumented way
	_PEB_LDR_DATA Ldr;					// the documented way


	// start going through the first process
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot (of processes) Failed. Exiting.");
		return 0;
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);


	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		printf("Process32First Failed");	// show cause of failure
		CloseHandle(hProcessSnap);          // cleanup the snapshot object
		return 0;
	}


	BOOL pebResult = FALSE;
	BOOL DllResult = FALSE;

	PROCESS_INFORMATION pi = { 0 };

	do
	{

		//PROCESS_ALL_ACCESS will normally work. With  READ_CONTROL I get a lot of access denied
		pi.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);

		printf("Scanning Process \t%s", pe32.szExeFile);
		printf("\tPID \t%d\n", pe32.th32ProcessID);
		


		if (pi.hProcess == 0) {
			unsigned int lastError = GetLastError();
			if (lastError == 0x5) {
				if (0 != strcmp(pe32.szExeFile, "System") && 0 != strcmp(pe32.szExeFile, "audiodg.exe")) {
					//"System" "Process" +	"audiodg.exe" cannot be read from
					printf("STATUS_ACCESS_DENIED for '%s' Try running with higher Privilages\n", pe32.szExeFile);
				}
			}
			else {
				printf("Could not get handle to process. Error: %d\n", lastError);
			}
		}

		// where all the actual work is done
		WORD remote32bitPEBAddress = 0;
		readRemoteProcessForModules(pe32, pi, remote32bitPEBAddress);

	} while (Process32Next(hProcessSnap, &pe32)); //end do while
	CloseHandle(hProcessSnap);

	return 0;
}
