al-khaser
=========

al-khaser is a PoC malware with good intentions that aimes to stress your malware analysis / sandbox environement.
It performs a bunch of anti-analysis tricks and rootkitting techniques against your framework and the goal is to see if you catch them.
It is licensed under GNU/GPL version 3 and developed in C using Visual C++ 2012 and Inline Assembly.

# Possible uses :

One would like to test if your debugger is hidden : OllyDbg, WinDbg, obsidian(non intruisive debugger)?, Hopper, Visual DuxDebugger, onlinedisassembler, arkdasm )...
Your debugger plugin : IDASealth, PhantOm, Strong OD, OllyAdvanced, ScyllaHide, TitanHide, Stealth64, IceStealth ...
Your (static/dynamic) binary analysis framework : Metasm, Miasm , radare, PaiMei, ...
Your sandbox : Cuckoo, Anubis, Joe, Norman, GFI, Threatexpert, CWSandboxe, ...
Your desktop virtualisation tool : VMWare, VirtualBox, Parallels Desktop, QEMU, ...

# Features :

Debugger Detection :
- IsDebuggerPresentAPI
- IsDebuggerPresentPEB
- CheckRemoteDebuggerPresentAPI
- NtQueryInformationProcess (ProcessDbgPort)
- NtQueryInformationProcess (ProcessDebugFlags)
- NtQueryInformationProcess (ProcessDebugObject)
- NtGlobalFlag
- NtSetInformationThread (HideThreadFromDebugger)
- Open Process
- Parent Process
- Self-Debug (CreateProcess)
- UnhandledExceptionFilter
- NtQueryObject (ObjectAllTypesInformation)
- NtQueryObject (ObjectTypesInformation)


Debugger-Attacks :
- BlockInputAPI
- OutputDebugString

Timing Attacks
- RDTSC
- Win32Timing (GetTickCount) 

Breakpoint Detection:
- Software breakpoints detection (INT3 aka 0xCC BP)
- Memory Breakpoint detection (Guard Pages)
- Hardware Breakpoint detection (with Get/SetThreadContext)
- Hardware Breakpoint detection (with Structured Exception Handling)

Anti-Dumping:
- SizeOfImage (IMAGE_OPTION_HEADER)
- Erase PE Header

# To do

+ More about self debugging
+ Nanomites
+ Stolen Bytes


# References

- An Anti-Reverse Engineering Guide By Josh_Jackson.
- Anti-Unpacker Tricks By Peter Ferrie.
- The Art Of Unpacking By Mark Vincent Yason.
- http://waleedassar.blogspot.de/ By Walied Assar.



