#include "TimingAttacks.h"

BOOL RDTSC_TimingAttack(TCHAR* pName)
{
	/* RDTSC is an IA-32 instruction that stands for Read Time-Stamp Counter, which is pretty self-explanatory in itself.
	Processors since the Pentium have had a counter attached to the processor that is incremented every clock cycle,
	and reset to 0 when the processor is reset. As you can see, this is a very powerful timing technique; however,
	Intel doesn't serialize the instruction; therefore, it is not guaranteed to be 100% accurate. This is why Microsoft
	encourages the use of its Win32 timing APIs since they're supposed to be as accurate as Windows can guarantee.
	The great thing about timing attacks, in general, though is that implementing the technique is rather simple; 
	all a developer needs to do is decide which functions he or she would like to protect using a timing attack,
	and then he or she can simply surround the blocks of code in a timing block and can compare that to a programmer
	set limit, and can exit the program if the timed section takes too much time to execute. */

	#define SERIAL_THRESHOLD 0x10000 // 10000h ticks
    
	DWORD LocalSerial = 0;
	DWORD RdtscLow = 0; // TSC Low
	size_t strlen = lstrlen(pName); 
	char IsDbgPresent = 0;

	__asm
    {
        rdtsc
        mov RdtscLow, eax
    } 

    /* Random routine to do some calculation
	   Generate serial, decrypt payload or drop a malware */
    for(unsigned int i = 0; i < strlen; i++)
    { 
        LocalSerial += (DWORD) pName[i];
        LocalSerial ^= 0xDEADBEEF;
    }

    __asm
    {
        rdtsc
        sub eax, RdtscLow
        cmp eax, SERIAL_THRESHOLD
        jbe NotDebugged
		mov IsDbgPresent , 1
		NotDebugged:
    } 

    return IsDbgPresent;
}

DWORD Win32TimingAttack(TCHAR* pName)
{
	/* The concepts are exactly the same in this variation except that we have different means of timing our function.
	In the following example, GetTickCount is used, but as commented, could be replaced with timeGetTime or QueryPerformanceCounter. */

    DWORD LocalSerial = 0;
	size_t strlen = lstrlen(pName);

    DWORD Counter = GetTickCount(); // Could be replaced with timeGetTime() or QueryPerformanceCounter ().

    /* Random routine to do some calculation
	   Generate serial, decrypt payload or drop a malware */
    for(unsigned int i = 0; i < strlen; i++)
    { 
        LocalSerial += (DWORD) pName[i];
        LocalSerial ^= 0xDEADBEEF;
    } 
    
    Counter = GetTickCount() - Counter; // Could be replaced with timeGetTime() 
    if(Counter >= 1)			// I replaced 10000 with 1, anyway it depends of the function 'Generate Serial'
        LocalSerial = 1;
	else
		LocalSerial = 0;
    
    return LocalSerial;
}