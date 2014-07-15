al-khaser
=========

al-khaser is a PoC malware with good intentions that aimes to stress your malware analysis / sandbox environement.
It performs a bunch of anti-analysis tricks and rootkitting techniques against your framework and the goal is to see if you catch them.
It is licensed under GNU/GPL version 3 and developed in C using Visual C++ 2012 and Inline Assembly.

# Possible uses :

- One would like to test if your debugger is hidden : OllyDbg, WinDbg, obsidian(non intruisive debugger)?, Hopper, Visual DuxDebugger, onlinedisassembler, arkdasm )...
- Your debugger plugin : IDASealth, PhantOm, Strong OD, OllyAdvanced, ScyllaHide, TitanHide, Stealth64, IceStealth ...
- Your (static/dynamic) binary analysis framework : Metasm, Miasm , radare, PaiMei, ...
- Your sandbox : Cuckoo, Anubis, Joe, Norman, GFI, Threatexpert, CWSandboxe, ...
- Your desktop virtualisation tool : VMWare, VirtualBox, Parallels Desktop, QEMU, ...

# Features :

Debugger Detection :
- IsDebuggerPresent() Win32 API
- PEB.BeingDebuggedFlag
- PEB.NtGlobalFlag
- Heap (HeapFlags)
- Heap (ForceFlags)
- Heap (TailFlags) (todo) 
- CheckRemoteDebuggerPresent() Win32 API
- NtQueryInformationProcess (ProcessDbgPort)
- NtQueryInformationProcess (ProcessDebugFlags)
- NtQueryInformationProcess (ProcessDebugObjectHandle)
- NtQuerySystemInformation (SystemKernelDebuggerInformation)
- NtSetInformationThread (HideThreadFromDebugger)
- NtQueryObject (ObjectAllTypesInformation)
- NtQueryObject (ObjectTypesInformation)
- UnhandledExceptionFilter
- OpenProcess (SeDebugPrivilege)
- Parent Process (Explorer.exe)
- Self-Debug (CreateProcess)
- NtClose/ CloseHandle ()
- Ctrl-C signal (EXCEPTION_CTL_C)
- Rogue Int3 (0xCC & 0xCD )

Debugger-Attacks:
- BlockInputAPI
- OutputDebugString
- Misdirection / Stopping via Exceptions (todo)

Timing Checks:
- RDTSC
- GetTickCount
- RDPMC (todo)
- GetLocalTime (todo)
- GetSystemTime (todo)
- GetTickCount (todo)
- KiGetTickCount (todo)
- QueryPerformanceCounter (todo)
- timeGetTime (todo)
- TickCount / TickCountMultiplier (todo)

Breakpoint Detection:
- Software breakpoints detection (INT3 aka 0xCC)
- Memory Breakpoint detection (Guard Pages)
- Hardware Breakpoint detection (Using Get/SetThreadContext)
- Hardware Breakpoint detection (Using Structured Exception Handling)
- Breakpoint Detection by CRC (todo)

Anti-Dumping:
- SizeOfImage (IMAGE_OPTION_HEADER)
- Erase PE Header
- Stolen Bytes (Introduuced by Asprotect) (todo)
- Nanomites (Introduced by Armadillo)(todo)
- Guard Pages (CopyMem2 Armadillo) (todo)
- IAT Elimination / API Redirection (todo)

Code Virtualization:
- todo

IA-32 Instruction Exploits & x86 oddities:
- Interrupt 2D
- Stack Segment
- Popf and the trap flag
- Instruction Prefixes
- Ice Breakpoint (0xF1)

File-format tricks:
- Non-aligned SizeOfImage
- Overlapping structures
- Non-standard NumberOfRvaAndSizes
- Non-aligned SizeOfRawData
- Non-aligned PointerToRawData
- No section table

Anti-Emulation:
- Invalid API parameters (todo)
- Modern CPU instructions (todo)
- Undocumented instructions (todo)
- Time-locks (todo)

Obfuscation:
- Junk Code Insertion (todo)
- Native Code Permutations (todo)
- VFTables (todo)
- Exceptions (SEH) (todo)
- Forcing inlines  (todo)

Specific:
- FindWindow () Win32 API
- OutputDebugString Exploit (OllyDbg)
- Device Drivers Names (todo)

Uncategorized:
- TLS-callback (todo)
- Fake signatures (todo)
- EntryPoint RVA set to 0

Packing:
- Multi-threaded packers

Kernel-Bugs:
- ProcessIoPriority 


# To do

+ More about self debugging


# References

- An Anti-Reverse Engineering Guide By Josh_Jackson.
- Anti-Unpacker Tricks By Peter Ferrie.
- The Art Of Unpacking By Mark Vincent Yason.
- http://waleedassar.blogspot.de/ By Walied Assar.
