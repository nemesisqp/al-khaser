#include <Windows.h>
#include <stdio.h>

BOOL SoftwareBreakpoints(void* pMemory,  size_t SizeToCheck);

void Myfunction_Trap_Debugger();

void Myfunction_Adresss_Next();

BOOL MemoryBreakpoints();

BOOL HardwareBreakpoints_GetThreadContext();

BOOL HardwareBreakpointsSEH ();





