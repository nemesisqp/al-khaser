#include "BreakpointDetection.h"

BOOL SoftwareBreakpoints(void* pMemory,  size_t SizeToCheck)
{
	/* Software breakpoints aka INT 3 represented in the IA-32 instruction set with the opcode CC (0xCC). 
	Given a memory addresse and size, it is relatively simple to scan for the byte 0xCC -> if(pTmp[i] == 0xCC)
	An obfuscated method would be to check if our memory byte xored with 0x55 is equal 0x99 for example ... */

    unsigned char *pTmp = (unsigned char*)pMemory;
    unsigned char tmpchar = 0;  

    for (size_t i = 0; i < SizeToCheck; i++)
	{
		tmpchar = pTmp[i];
        if( 0x99 == (tmpchar ^ 0x55) ) // Adding another level of indirection : 0xCC xor 0x55 = 0x99
			return TRUE;
	}    
	
	return FALSE;
}

void Myfunction_Trap_Debugger()
{
	/* Setting INT 3 BP here would be detected */
	int a=1;
	int b=2;
	int c=a+b;
	printf ("I am the function that i'll trap your debugger, %d", c);
}

void Myfunction_Adresss_Next()
{ 
};

BOOL MemoryBreakpoints()
{
	 /* In essence, what occurs is that we allocate a dynamic buffer and write a RET to the buffer.
	 We then mark the page as a guard page and push a potential return address onto the stack. Next, we jump to our page,
	 and if we're under a debugger, specifically OllyDBG, then we will hit the RET instruction and return to the address we pushed onto
	 the stack before we jumped to our page. Otherwise, a STATUS_GUARD_PAGE_VIOLATION exception will occur, and we know we're not being 
	 debugged by OllyDBG */


     unsigned char *pMem = NULL;
     SYSTEM_INFO sysinfo = {0}; 
     DWORD OldProtect = 0;
     void *pAllocation = NULL; // Get the page size for the system 
 
    GetSystemInfo(&sysinfo); // Allocate memory 
 
    pAllocation = VirtualAlloc(NULL, sysinfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); 
        
    if (pAllocation == NULL)
        return false; 
    
    // Write a ret to the buffer (opcode 0xc3)
    pMem = (unsigned char*)pAllocation;
    *pMem = 0xc3; 
    
    // Make the page a guard page         
    if (VirtualProtect(pAllocation, sysinfo.dwPageSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &OldProtect) == 0)
        return false;
    
    __try
    {
        __asm
        {
            mov eax, pAllocation
            // This is the address we'll return to if we're under a debugger
            push MemBpBeingDebugged
            jmp eax // Exception or execution, which shall it be :D?
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        // The exception occured and no debugger was detected
        VirtualFree(pAllocation, NULL, MEM_RELEASE);
        return FALSE;
    }     
    
	__asm{MemBpBeingDebugged:}
	VirtualFree(pAllocation, NULL, MEM_RELEASE);
    return TRUE;
}

BOOL HardwareBreakpoints_GetThreadContext()
{
	/* Hardware breakpoints are a technology implemented by Intel in their processor architecture,
	and are controlled by the use of special registers known as Dr0-Dr7.
	Dr0 through Dr3 are 32 bit registers that hold the address of the breakpoint */

    unsigned int NumBps = 0;

    // This structure is key to the function and is the 
    // medium for detection and removal
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(CONTEXT)); 
    
    // The CONTEXT structure is an in/out parameter therefore we have
    // to set the flags so Get/SetThreadContext knows what to set or get.
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS; 
    
    // Get a handle to our thread
    HANDLE hThread = GetCurrentThread();

    // Get the registers
    if(GetThreadContext(hThread, &ctx) == 0)
        return -1;

    // Now we can check for hardware breakpoints, its not 
    // necessary to check Dr6 and Dr7, however feel free to
    if(ctx.Dr0 != 0)
        ++NumBps; 
    if(ctx.Dr1 != 0)
           ++NumBps; 
    if(ctx.Dr2 != 0)
           ++NumBps; 
    if(ctx.Dr3 != 0)
        ++NumBps;
        
    if(NumBps>0) 
		return TRUE;
	else
		return FALSE;
}

BOOL HardwareBreakpointsSEH ()
{
	BOOL IsDbgPresent = TRUE;

	// Raises an exception in the calling thread
	LPEXCEPTION_POINTERS except_ptr; 
	__try   { 
		RaiseException(1, 0, 0, NULL); 
	} 

	/* Or you can do it in asm, in this case I am forcing a memory access violation exception,
	but you can customize this to generate other type of exceptions :
	 __asm xor eax,eax
	 __asm mov dword ptr[eax], ebx */

	// Handling the exception that have just been generated
	__except (except_ptr = GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER) 
		{ 
			//The thread context modified (it containsthe CPU registers at the time the exception was thrown)
			CONTEXT *ctx = except_ptr->ContextRecord; 

			if (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0 )
				IsDbgPresent = TRUE;

			else
				IsDbgPresent = FALSE;
		}

	 /* If we reach this location, it means that the exception was handled by something else, maybe a debugger or another reversing or analysis
    tool, so we return true for security purposes, but not because a HW BP was detected.  */
	return IsDbgPresent;
}
