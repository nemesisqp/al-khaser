#include "Commun.h"


/************************** Utils Routines ****************************/
int CDECL MessageBoxPrintf (TCHAR * szCaption, TCHAR * szFormat, ...)
{
	TCHAR szBuffer [1024] ;
	va_list pArgList ;
	va_start (pArgList, szFormat);
	_vsnwprintf_s (szBuffer, sizeof (szBuffer) / sizeof (TCHAR),
	szFormat, pArgList) ;
	va_end (pArgList) ;
	return MessageBox (NULL, szCaption , szBuffer,  MB_OK + MB_ICONERROR) ;
}

BOOL IsWinXP_2K () {
    DWORD version = GetVersion();
    DWORD major = (DWORD) (LOBYTE(LOWORD(version)));
    DWORD minor = (DWORD) (HIBYTE(LOWORD(version)));

    return (major == 5) && (minor <= 1);
}

BOOL IsWinVista () {
    DWORD version = GetVersion();
    DWORD major = (DWORD) (LOBYTE(LOWORD(version)));
    DWORD minor = (DWORD) (HIBYTE(LOWORD(version)));

    return (major == 6) && (minor == 0);
}

DWORD GetProcessIdFromName(LPCTSTR ProcessName)
{
	PROCESSENTRY32 pe32;
	HANDLE hSnapshot = NULL;
	ZeroMemory(&pe32, sizeof(PROCESSENTRY32));

	// We want a snapshot of processes
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	// Check for a valid handle, in this case we need to check for
	// INVALID_HANDLE_VALUE instead of NULL
	if(hSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	// Now we can enumerate the running process, also 
	// we can't forget to set the PROCESSENTRY32.dwSize member
	// otherwise the following functions will fail
	pe32.dwSize =  sizeof(PROCESSENTRY32);
	
	if(Process32First(hSnapshot, &pe32) == FALSE)
	{
		// Cleanup the mess
		CloseHandle(hSnapshot);
		return 0;
	}

	// Do our first comparison
	if(_wcsicmp(pe32.szExeFile, ProcessName) == FALSE)
	{
		// Cleanup the mess
		CloseHandle(hSnapshot);
		return pe32.th32ProcessID;
	}

	// Most likely it won't match on the first try so 
	// we loop through the rest of the entries until
	// we find the matching entry or not one at all
	while (Process32Next(hSnapshot, &pe32))
	{
		if(_wcsicmp(pe32.szExeFile, ProcessName) == 0)
		{
			// Cleanup the mess
			CloseHandle(hSnapshot);
			return pe32.th32ProcessID;
		}
	}

	// If we made it this far there wasn't a match
	// so we'll return 0
	CloseHandle(hSnapshot);
	return 0;
}

DWORD GetCsrssProcessId()
{
	// Don't forget to set dw.Size to the appropriate
	// size (either OSVERSIONINFO or OSVERSIONINFOEX)
	OSVERSIONINFO osinfo;
	ZeroMemory(&osinfo, sizeof(OSVERSIONINFO));
	osinfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	
	// Shouldn't fail
	GetVersionEx(&osinfo);

	// Visit http://msdn.microsoft.com/en-us/library/ms724833(VS.85).aspx
	// for a full table of versions however what I have set will
	// trigger on anything XP and newer including Server 2003
	if (osinfo.dwMajorVersion >= 5 && osinfo.dwMinorVersion >= 1)
	{
		// Gotta love functions pointers
		typedef DWORD (__stdcall *pCsrGetId)();
		
		// Grab the export from NtDll
		pCsrGetId CsrGetProcessId = (pCsrGetId)GetProcAddress(GetModuleHandle( TEXT("ntdll.dll") ), "CsrGetProcessId");

		if(CsrGetProcessId)
			return CsrGetProcessId();
		else
			return 0;
	}
	else
		return GetProcessIdFromName(L"csrss.exe");
}

DWORD GetExplorerPIDbyShellWindow()
{
	DWORD PID = 0;
	
	// Get the PID 
	GetWindowThreadProcessId(GetShellWindow(), &PID);

	return PID;
}

DWORD GetParentProcessId()
{
	// Much easier in ASM but C/C++ looks so much better
	typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)
		(HANDLE ,UINT ,PVOID ,ULONG , PULONG);

	// Some locals
	NTSTATUS Status = 0;
	PROCESS_BASIC_INFORMATION pbi;
	ZeroMemory(&pbi, sizeof(PROCESS_BASIC_INFORMATION));

	// Get NtQueryInformationProcess
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
								GetProcAddress( 
								GetModuleHandle( TEXT("ntdll.dll") ), 
								"NtQueryInformationProcess" );

	// Sanity check although there's no reason for it to have failed
	if(NtQIP == 0)
		return 0;

	// Now we can call NtQueryInformationProcess, the second
	// param 0 == ProcessBasicInformation
	Status = NtQIP(GetCurrentProcess(), 0, (void*)&pbi, 
						sizeof(PROCESS_BASIC_INFORMATION), 0);

	if(Status != 0x00000000)
		return 0;
	else
		return pbi.ParentProcessId;
}

void BlockInputAPI()
{
	/* The BlockInput API prevent reverser from controlling the debugger by blocking the keyboard and mouse input. 
	A packer can use it by blocking keyboard and mouse input while the main unpacking routine is being executed
	The system will appear to be unresponsive, leaving the reverser baffled. */
	
	// Need Admin Priviliege

    BlockInput(true);//block
    MessageBox(NULL,L"You are blocked for 10 seconds.",L"AHAHAHA",MB_OK);
    Sleep(10000);//wait 10 sec
    BlockInput(false);//unblock
}
