#include "DebuggerDetection.h"
#include "Commun.h"

BOOL IsDebuggerPresentAPI ()
{
	/* This function is part of the Win32 Debugging API 
	   It determines whether the calling process is being debugged by a user-mode debugger. 
	   If the current process is running in the context of a debugger, the return value is nonzero. */

	return IsDebuggerPresent ();
}

BOOL IsDebuggerPresentPEB ()
{
	/* The IsDebuggerPresent function is actually a wrapper around this code.
	It directly access the PEB for the process and reads a byte value that signifies if the process is being debugged. */

	char IsDbgPresent = 0;
	__asm {
			mov eax, fs:[30h]
			mov al, [eax + 2h]
			mov IsDbgPresent, al
			}

	return IsDbgPresent;
}

BOOL CheckRemoteDebuggerPresentAPI ()
{
	/* This is another Win32 Debugging API function; it can be used to check if a remote process is being debugged,
	However, we can also use this for checking if our own process is being debugged. it calls the NTDLL export
	NtQueryInformationProcess with the SYSTEM_INFORMATION_CLASS set to 7 (ProcessDebugPort) */

	BOOL IsDbgPresent;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &IsDbgPresent);
	return IsDbgPresent;
}

BOOL NtQueryInformationProcess_ProcessDbgPort ()
{
	/* Instead of calling CheckRemoteDebuggerPresent an individual could also make directly the call to 
	NtQueryInformationProcess process theirself */

	// Function Pointer Typedef for NtQueryInformationProcess
	typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(IN  HANDLE, IN  UINT, OUT PVOID, IN ULONG, OUT PULONG);
 
	// ProcessDebugPort
	const int ProcessDbgPort = 7;
 
	// We have to import the function
	pNtQueryInformationProcess NtQueryInfoProcess = NULL;
 
	// Other Vars
	NTSTATUS Status;
	DWORD IsRemotePresent = 0;
 
	HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
	if(hNtDll == NULL)
	{
		// Handle however.. chances of this failing
		// is essentially 0 however since
		// ntdll.dll is a vital system resource
	}
 
	NtQueryInfoProcess = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");

	if(NtQueryInfoProcess == NULL)
	{
		// Handle however it fits your needs but as before,
		// if this is missing there are some SERIOUS issues with the OS
	}
 
	// Time to finally make the call
	Status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDbgPort, &IsRemotePresent, sizeof(unsigned long), NULL);
	if(Status == 0x00000000 && IsRemotePresent != 0)
		return TRUE;
	else 
		return FALSE;
}

BOOL NtQueryInformationProcess_ProcessDebugFlags()
{
	/* When NtQueryProcessInformation is called with the ProcessDebugFlags class, the function will return the inverse of EPROCESS->NoDebugInherit,
	which means that if a debugger is present, then this function will return FALSE if the process is being debugged. */

   	// Function Pointer Typedef for NtQueryInformationProcess
	typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(IN  HANDLE, IN  UINT, OUT PVOID, IN ULONG, OUT PULONG);
 
	// ProcessDebugFlags
	const int ProcessDebugFlags =  0x1f;

	// We have to import the function
	pNtQueryInformationProcess NtQueryInfoProcess = NULL;

	// Other Vars
	NTSTATUS Status;
	DWORD NoDebugInherit = 0; 

	HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
	if(hNtDll == NULL)
	{
		// Handle however.. chances of this failing
		// is essentially 0 however since
		// ntdll.dll is a vital system resource
	}
 
    NtQueryInfoProcess = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
	
	if(NtQueryInfoProcess == NULL)
	{
		// Handle however it fits your needs but as before,
		// if this is missing there are some SERIOUS issues with the OS
	}
	
	// Time to finally make the call
	Status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDebugFlags, &NoDebugInherit, sizeof(DWORD), NULL);
    if (Status != 0x00000000)
		return false; 
    if(NoDebugInherit == FALSE)
		return true;   
	else        
		return false;
}

BOOL NtQueryInformationProcess_ProcessDebugObject()
{
	/*	This function uses NtQuerySystemInformation to try to retrieve a handle to the current process's debug object handle.
		If the function is successful it'll return true which means we're being debugged or it'll return false if it fails
		the process isn't being debugged */

   	// Function Pointer Typedef for NtQueryInformationProcess
	typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(IN  HANDLE, IN  UINT, OUT PVOID, IN ULONG, OUT PULONG);

	// ProcessDebugFlags
	const int ProcessDebugObjectHandle =  0x1e;

	// We have to import the function
	pNtQueryInformationProcess NtQueryInfoProcess = NULL;

	// Other Vars
	NTSTATUS Status;
	HANDLE hDebugObject = NULL; 

	HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
	if(hNtDll == NULL)
	{
		// Handle however.. chances of this failing
		// is essentially 0 however since
		// ntdll.dll is a vital system resource
	}
 
    NtQueryInfoProcess = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
	
	if(NtQueryInfoProcess == NULL)
	{
		// Handle however it fits your needs but as before,
		// if this is missing there are some SERIOUS issues with the OS
	}

	// Time to finally make the call
	Status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDebugObjectHandle, &hDebugObject, sizeof(DWORD), NULL);
    
    if (Status != 0x00000000)
        return false; 

    if(hDebugObject)
        return true;
    else
        return false;
}

BOOL NtGlobalFlag ()
{
	/* NtGlobalFlag is a DWORD value inside the process PEB. It contains many flags set by the OS
	that affects the way the process runs When a process is being debugged, the flags
	FLG_HEAP_ENABLE_TAIL_CHECK (0x10), FLG_HEAP_ENABLE_FREE_CHECK(0x20), and FLG_HEAP_VALIDATE_PARAMETERS(0x40) 
	are set for the process, and we can use this to our advantage to identify if our process is being debugged. */


	unsigned long NtGlobalFlags = 0;
	__asm 
	{
		mov eax, fs:[30h] 
		mov eax, [eax + 68h]
		mov NtGlobalFlags, eax
	}

	if (NtGlobalFlags & 0x70)
	// 0x70 =  FLG_HEAP_ENABLE_TAIL_CHECK |
	//         FLG_HEAP_ENABLE_FREE_CHECK | 
	//         FLG_HEAP_VALIDATE_PARAMETERS
		return TRUE;

	else
		return FALSE;
}

BOOL NtSetInformationThread_ThreadHideFromDebugger()
{
	 /* Calling NtSetInformationThread will attempt with ThreadInformationClass set to  x11 (ThreadHideFromDebugger)
	 to hide a thread from the debugger, Passing NULL for hThread will cause the function to hide the thread the
	 function is running in. Also, the function returns false on failure and true on success. When  the  function
	 is called, the thread will continue  to run but a debugger will no longer receive any events related  to  that  thread. */

	// Function Pointer Typedef for NtQueryInformationProcess
	typedef NTSTATUS (WINAPI *pNtSetInformationThread)(IN HANDLE, IN UINT, IN PVOID, IN ULONG);

	// ThreadHideFromDebugger
	const int ThreadHideFromDebugger =  0x11;

	// We have to import the function
	pNtSetInformationThread NtSetInformationThread = NULL;

	// Other Vars
	NTSTATUS Status;
	BOOL IsBeingDebug = FALSE;

	HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
	if(hNtDll == NULL)
	{
		// Handle however.. chances of this failing
		// is essentially 0 however since
		// ntdll.dll is a vital system resource
	}
 
    NtSetInformationThread = (pNtSetInformationThread)GetProcAddress(hNtDll, "NtSetInformationThread");
	
	if(NtSetInformationThread == NULL)
	{
		// Handle however it fits your needs but as before,
		// if this is missing there are some SERIOUS issues with the OS
	}

	 // Time to finally make the call
	Status = NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);
    
	if(Status)
		IsBeingDebug = TRUE;

return IsBeingDebug;
}

BOOL OutputDebugString()
{
	 /* . OutputDebugString() is typically used to output a string value to the debugging data stream.
	 This string is then displayed in the debugger. Due to this fact, the function OutputDebugString()
	 acts differently based on the existence of a debugger on the running process. If a debugger is
	 attached to the process, the function will execute normally and no error state will be registered;
	 however if there is no debugger attached, LastError will be set by the process letting us know that
	 we are debugger free. To execute this method we set LastError to an arbitrary value of our choosing
	 and then call OutputDebugString(). We then check GetLastError() and if our error code remains,
	 we know we are debugger free. */

	BOOL IsDbgPresent =  FALSE;

	if (IsWinXP_2K()) 	// Works only on windows 2000 / XP 
		{
			DWORD Val = 1337;
			SetLastError(Val);
			OutputDebugString(L"random");

			if (GetLastError() == Val)       
				IsDbgPresent =  TRUE;
		}

	return IsDbgPresent;
}

BOOL CanOpenCsrss()
{  

	HANDLE Csrss = 0; 
    // If we're being debugged and the process has
    // SeDebugPrivileges privileges then this call
    // will be successful, note that this only works
    // with PROCESS_ALL_ACCESS.

	// This routines need to be run as Admin, or
	// the debugger should be started as Admin.
	
	Csrss = OpenProcess(PROCESS_ALL_ACCESS,  FALSE, GetCsrssProcessId()); 
	if (Csrss != NULL)    
	{
        CloseHandle(Csrss);
		return TRUE;
	} 
	else
        return FALSE;
}

BOOL IsParentExplorerExe()
{
    // Both GetParentProcessId and GetExplorerPIDbyShellWindow
    // can be found in the attached source
    DWORD PPID = GetParentProcessId();
    if(PPID != GetExplorerPIDbyShellWindow())
        return true;
    else
        return false;
}

void DebugSelf()
{
	/* Debug self is a function that uses CreateProcess to create an identical copy of the
	current process and debugs it. This  prevents other debuggers from attaching to the same process */

    HANDLE hProcess = NULL;
    DEBUG_EVENT de;
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&si, sizeof(STARTUPINFO));
    ZeroMemory(&de, sizeof(DEBUG_EVENT)); 

    GetStartupInfo(&si);

    // Create the copy of ourself
    CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE,
            DEBUG_PROCESS, NULL, NULL, &si, &pi); 

    // Continue execution
    ContinueDebugEvent(pi.dwProcessId, pi.dwThreadId, DBG_CONTINUE); 

    // Wait for an event
    WaitForDebugEvent(&de, INFINITE);
}

LONG WINAPI UnhandledExcepFilter(PEXCEPTION_POINTERS pExcepPointers)
{
    // Restore old UnhandledExceptionFilter
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)pExcepPointers->ContextRecord->Eax);

    // Skip the exception code
    pExcepPointers->ContextRecord->Eip += 2;

    return EXCEPTION_CONTINUE_EXECUTION;
}

BOOL UnhandledExcepFilterTest ()
{
	BOOL IsBeingDbg = TRUE;
	SetUnhandledExceptionFilter(UnhandledExcepFilter);
	RaiseException(EXCEPTION_FLT_DIVIDE_BY_ZERO, 0, 0, NULL); 

    // Execution resumes here if there is no debugger
    // or if there is a debugger it will never
    // reach this point of execution
	IsBeingDbg = FALSE;

	return IsBeingDbg;
}

BOOL NtQueryObject_ObjectAllTypesInformation  ()
{
    typedef NTSTATUS(NTAPI *pNtQueryObject)(HANDLE, UINT, PVOID, ULONG, PULONG);

    POBJECT_ALL_INFORMATION pObjectAllInfo = NULL;
    void *pMemory = NULL;
    NTSTATUS Status;
    unsigned long Size = 0;

    // Get NtQueryObject
    pNtQueryObject NtQO = (pNtQueryObject)GetProcAddress( GetModuleHandle( TEXT( "ntdll.dll" ) ),"NtQueryObject" );

    // Get the size of the list
    Status = NtQO(NULL, 3, //ObjectAllTypesInformation
                        &Size, 4, &Size);

    // Allocate room for the list
    pMemory = VirtualAlloc(NULL, Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if(pMemory == NULL)
        return false;

    // Now we can actually retrieve the list
    Status = NtQO((HANDLE)-1, 3, pMemory, Size, NULL);

    // Status != STATUS_SUCCESS
    if (Status != 0x00000000)
    {
        VirtualFree(pMemory, 0, MEM_RELEASE);
        return false;
    }

    // We have the information we need
    pObjectAllInfo = (POBJECT_ALL_INFORMATION)pMemory;

    unsigned char *pObjInfoLocation = (unsigned char*)pObjectAllInfo->ObjectTypeInformation;

    ULONG NumObjects = pObjectAllInfo->NumberOfObjects;

    for(UINT i = 0; i < NumObjects; i++)
    {

        POBJECT_TYPE_INFORMATION pObjectTypeInfo =
            (POBJECT_TYPE_INFORMATION)pObjInfoLocation;

        // The debug object will always be present
        if (wcscmp(L"DebugObject", pObjectTypeInfo->TypeName.Buffer) == 0)
        {
            // Are there any objects?
            if (pObjectTypeInfo->TotalNumberOfObjects > 0)
            {
                VirtualFree(pMemory, 0, MEM_RELEASE);
                return true;
            }
            else
            {
                VirtualFree(pMemory, 0, MEM_RELEASE);
                return false;
            }
        }

        // Get the address of the current entries
        // string so we can find the end
        pObjInfoLocation = (unsigned char*)pObjectTypeInfo->TypeName.Buffer;

        // Add the size
        pObjInfoLocation += pObjectTypeInfo->TypeName.Length;

        // Skip the trailing null and alignment bytes
        ULONG tmp = ((ULONG)pObjInfoLocation) & -4;

        // Not pretty but it works
        pObjInfoLocation = ((unsigned char*)tmp) +  sizeof(unsigned long);
    } 

    VirtualFree(pMemory, 0, MEM_RELEASE);
    return true; 
}

BOOL NtQueryObject_ObjectTypesInformation  () 
{

	typedef NTSTATUS(NTAPI * pNtClose)(
		__in  HANDLE hObject
		);

	typedef NTSTATUS(NTAPI * pNtCreateDebugObject)(
		__out PHANDLE DebugObjectHandle,
		__in ACCESS_MASK DesiredAccess,
		__in POBJECT_ATTRIBUTES ObjectAttributes,
		__in ULONG Flags
		);

	typedef NTSTATUS(NTAPI *pNtQueryObject)(HANDLE, UINT, PVOID, ULONG, PULONG);

	HANDLE debugObject = NULL ;
	OBJECT_ATTRIBUTES oa;
	BYTE memory[0x1000] = {0};
	
	InitializeObjectAttributes(&oa,0,0,0,0);

	  
    pNtCreateDebugObject	NtCDO	= (pNtCreateDebugObject)GetProcAddress( GetModuleHandle(TEXT( "ntdll.dll" )),"NtCreateDebugObject" );
	pNtClose				NtC		= (pNtClose)GetProcAddress( GetModuleHandle(TEXT( "ntdll.dll" )),"NtClose" );
	pNtQueryObject			NtQO	= (pNtQueryObject)GetProcAddress( GetModuleHandle( TEXT( "ntdll.dll" ) ),"NtQueryObject" );

	if (NtCDO(&debugObject, DEBUG_ALL_ACCESS, &oa, 0) >= 0)
	{

		POBJECT_TYPE_INFORMATION objectType = (POBJECT_TYPE_INFORMATION)memory;

		if (NtQO(debugObject, ObjectTypeInformation, objectType, sizeof(memory), 0) >= 0)
		{
			if (objectType->TotalNumberOfObjects == 1) //there must be 1 object...
				return FALSE;

			else if (objectType->TotalNumberOfObjects == 0) //bad
				return TRUE;

			else
				return TRUE;

		}
		else
			return TRUE;

		NtC(debugObject);
	}
	else
		return TRUE;
}

BOOL CloseHandleAPI()
{
	// APIs making user of the ZwClose syscall (such as CloseHandle, indirectly) 
	// can be used to detect a debugger. When a process is debugged, calling ZwClose 
	// with an invalid handle will generate a STATUS_INVALID_HANDLE (0xC0000008) exception.
	// As with all anti-debugs that rely on information made directly available 
	// from the kernel (therefore involving a syscall), the only proper way to bypass 
	// the "CloseHandle" anti-debug is to either modify the syscall data from ring3, 
	// before it is called, or set up a kernel hook.
	// This anti-debug, though extremely powerful, does not seem to be widely used 
	// by malicious programs.

	char IsDbgPresent=0;
	__asm {
	
			push offset not_debugged 
			push dword ptr fs:[0] 
			mov fs:[0], esp 
			push 1234h ;invalid handle 
			call CloseHandle 

			mov IsDbgPresent, 1 
			not_debugged: 
			}
	return IsDbgPresent;
}

BOOL HeapFlags()
{
	char IsBeingDbg = FALSE;

	__asm {
		mov eax, FS:[0x30]
		mov eax, [EAX+0x18]
		mov eax, [EAX+0x44]
		cmp eax, 0
		je DebuggerNotFound
		mov IsBeingDbg, 1
		DebuggerNotFound:
	}

	return IsBeingDbg;
}

BOOL ForceFlags ()
{
	char IsBeingDbg = 0;

	__asm {
		MOV EAX, FS:[0x30]
		MOV EAX, [EAX+0x18]
		MOV EAX, [EAX+0x40]
		DEC EAX
		DEC EAX
		jne DebuggerFound
		jmp ExitMe
		DebuggerFound:
			mov IsBeingDbg, 1
		ExitMe:
	}

	return IsBeingDbg;
}

BOOL Int2DCheck()
{
	// depends on the debugger ! 
    __try
    {
        __asm
        {
            int 0x2d
            xor eax, eax
            add eax, 2
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
    
    return true;
}
