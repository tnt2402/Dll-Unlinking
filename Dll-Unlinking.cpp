// Dll-Unlinking.cpp : Defines the entry point for the application.
//

#include "Dll-Unlinking.h"

using namespace std;



// TODO: Reference additional headers your program requires here.

// Returns a pointer to the PEB by reading the FS or GS registry
// cf. https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
PEB* get_peb() {
#ifdef _WIN64
    return (PEB*)__readgsqword(0x60);
#else
    return  (PEB*)__readfsdword(0x30);
#endif
}

// Prints a list of DLLs loaded in the current process
void list_dlls(void) {
    PEB* peb = get_peb();

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

void list_dlls_with_init_order_chaining(void) {
    PEB* peb = get_peb();

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

void printHello(void) {
    printf("Hello tnt2402\n");
}


int main()
{
    printHello();
    list_dlls();
    list_dlls_with_init_order_chaining();
	return 0;
}
