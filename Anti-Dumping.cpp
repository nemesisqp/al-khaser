
#include "Anti-Dumping.h"


void ErasePEHeaderFromMemory()
{
	
// This function will erase the current images
// PE header from memory preventing a successful image
// if dumped
    DWORD OldProtect = 0;
    
    // Get base address of module
    char *pBaseAddr = (char*)GetModuleHandle(NULL);

    // Change memory protection
    VirtualProtect(pBaseAddr, 4096, // Assume x86 page size
            PAGE_READWRITE, &OldProtect);

    // Erase the header
    ZeroMemory(pBaseAddr, 4096);
}



void SizeOfImage()
{    
	// Any unreasonably large value will work say for example 0x100000 or 100,000h
	__asm    
	{
        mov eax, fs:[0x30]				// PEB
		mov eax, [eax + 0x0c]			 // PEB_LDR_DATA
        mov eax, [eax + 0x0c]			// InOrderModuleList
		mov dword ptr [eax+20h], 20000h // SizeOfImage    
	}
}

