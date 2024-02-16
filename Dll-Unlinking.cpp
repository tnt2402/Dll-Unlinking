// Dll-Unlinking.cpp : Defines the entry point for the application.
//
#include "Dll-Unlinking.h"
#include "DllScanner.h"
#include "ProcessInfo.h"

using namespace std;


void printHello(void) {
    printf("Hello tnt2402\n\n");
}


int main()
{
    printHello();
    list_dlls();
    list_dlls_with_init_order_chaining();
    EnumerateProcesses();
	return 0;
}
