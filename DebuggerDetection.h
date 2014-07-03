#include <windows.h>


BOOL IsDebuggerPresentAPI ();

BOOL IsDebuggerPresentPEB ();

BOOL CheckRemoteDebuggerPresentAPI ();

BOOL NtQueryInformationProcess_ProcessDbgPort();

BOOL NtQueryInformationProcess_ProcessDebugFlags();

BOOL NtQueryInformationProcess_ProcessDebugObject();

BOOL NtQueryInformationProcess_SystemKernelDebuggerInformation();

BOOL NtSetInformationThread_ThreadHideFromDebugger();

BOOL NtGlobalFlag ();

BOOL OutputDebugString();

BOOL CanOpenCsrss();

BOOL IsParentExplorerExe();

void DebugSelf();

BOOL UnhandledExcepFilterTest ();

BOOL NtQueryObject_ObjectAllTypesInformation  ();

BOOL NtQueryObject_ObjectTypesInformation  () ;

BOOL CloseHandleAPI() ;

BOOL ForceFlags () ;

BOOL HeapFlags();

BOOL Int2DCheck() ;

void PushPopSS ();

BOOL IsDbgPresentPrefixCheck();

