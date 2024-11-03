##### Simple shellcode loader examples based on MalDev Academy techniques

- ***Basic_SelfInjector*** - Simple self injector based on standard win apis invoked trough FFI (VirtualAlloc, WriteProcessMemory, VirtualProtect, CreateThread)

- ***Remote_Injector*** - Simple classic remote process injection based on: VirtualAllocEx, VirtualProtectEx, WriteProcessMemory, CreateRemoteThread. Custom implementation for GetModuleHandleA and GetProcAddress for IAT hiding. The PoC is not using any external crates (even for WIN types and structs).