#include "WinMain.h"

#Are You AYOUB FAOUZI ?
#ANSWER ASAP TO EMAIL:Xraffous@gmail.com
#THANK YOU



int APIENTRY WinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) 
{
	TCHAR szReversingDetected[]		= L"Reverse Engineering Attempt Detected !";	
	TCHAR szReversingNotDetected[]	= L"No Reverse Engineering Attempt Detected !";
	 
	/*

	if (IsDebuggerPresentAPI())
		MessageBoxPrintf(TEXT("Detected from : IsDebuggerPresent () API"), szReversingDetected );
		
	if (IsDebuggerPresentPEB())
		MessageBoxPrintf(TEXT("Detected from : IsDebuggerPresent Using PEB"), szReversingDetected );

	if (CheckRemoteDebuggerPresentAPI())
		MessageBoxPrintf(TEXT("Detected from : CheckRemoteDebuggerPresent () API"), szReversingDetected );

	if (NtGlobalFlag())
		MessageBoxPrintf(TEXT("Detected from : NtGlobalFlags"), szReversingDetected );

	if (HeapFlags())
		MessageBoxPrintf(TEXT("Detected from : Heap Flags"), szReversingDetected );

	if (ForceFlags())
		MessageBoxPrintf(TEXT("Detected from : Force Flags"), szReversingDetected );
		
	if (NtQueryInformationProcess_ProcessDbgPort ())
		MessageBoxPrintf(TEXT("Detected from : NtQueryInformationProcess_ProcessDbgPort Flag"), szReversingDetected );

	if (NtQueryInformationProcess_ProcessDebugFlags ())
		MessageBoxPrintf(TEXT("Detected from : NtQueryInformationProcess_ProcessDebugFlags Flag"), szReversingDetected );
	
	if (NtQueryInformationProcess_ProcessDebugObject())
		MessageBoxPrintf(TEXT("Detected from : NtQueryInformationProcess_ProcessDebugObject Flag"), szReversingDetected );

	if (NtSetInformationThread_ThreadHideFromDebugger())
		MessageBoxPrintf(TEXT("Detected from : NtSetInformationThread_ThreadHideFromDebugger Flag"), szReversingDetected );
		
	if (SoftwareBreakpoints(Myfunction_Trap_Debugger, (size_t)(Myfunction_Adresss_Next) - (size_t)(Myfunction_Trap_Debugger) ))
		MessageBoxPrintf(TEXT("INT 3 Breakpoint Detected"), szReversingDetected );

	if (MemoryBreakpoints())
		MessageBoxPrintf(TEXT("Detected from : Memory Breakpoints"), szReversingDetected );

	if (HardwareBreakpoints_GetThreadContext ())
		MessageBoxPrintf(TEXT("Hardware Breakpoint detected - GetThreadtcontext"), szReversingDetected);

	if (HardwareBreakpointsSEH ())
		MessageBoxPrintf(TEXT("Hardware Breakpoint detected - SEH"), szReversingDetected);

	if (RDTSC_TimingAttack(L"THE GAME"))
		MessageBoxPrintf(TEXT("Detected from : RDTSC"), szReversingDetected );

	if (Win32TimingAttack(L"YOU LOST THE GAME"))
		MessageBoxPrintf(TEXT("Detected from : GetTickCount ()"), szReversingDetected );

	if (OutputDebugString())
		MessageBoxPrintf(TEXT("Detected from : OutputDebugString () API"), szReversingDetected );

	if (CanOpenCsrss())
		MessageBoxPrintf(TEXT("Detected from : Open Process"), szReversingDetected );

	if (IsParentExplorerExe())
		MessageBoxPrintf(TEXT("Detected from : Parent Process"), szReversingDetected );

		DebugSelf ();
		
	if (UnhandledExcepFilterTest())
		MessageBoxPrintf(TEXT("Detected from : UnhandledExcepFilter"), szReversingDetected );
							
	if (NtQueryObject_ObjectAllTypesInformation())
		MessageBoxPrintf(TEXT("Detected from : NtQueryObject_ObjectAllTypesInformation"), szReversingDetected );	

	if (NtQueryObject_ObjectTypesInformation())
		MessageBoxPrintf(TEXT("Detected from : NtQueryObject_ObjectTypesInformation"), szReversingDetected );	

	if(Int2DCheck())
		MessageBoxPrintf(TEXT("Detected from : Interrupt 2D"), szReversingDetected );

		PushPopSS ()

	if (IsDbgPresentPrefixCheck())
		MessageBoxPrintf(TEXT("Detected from : Instruction Prefixes Check"), szReversingDetected );

	if (CloseHandleAPI ())
		MessageBoxPrintf(TEXT("Detected from : CloseHandle () API"), szReversingDetected ); 

		*/
	Bug_ProcessIoPriority () ;

	//if( NtQueryInformationProcess_SystemKernelDebuggerInformation())
	//	MessageBoxPrintf(TEXT("Detected from : NtQueryInformationProcess_SystemKernelDebuggerInformation"), szReversingDetected );	


	//else
	//	MessageBox(NULL,  L"Did you hack me ? :)",szReversingNotDetected , MB_OK + MB_ICONINFORMATION);

}
