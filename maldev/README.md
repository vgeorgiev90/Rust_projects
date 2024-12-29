##### Simple shellcode loader examples based on MalDev Academy techniques

- ***Basic_SelfInjector*** - Simple self injector based on standard win apis invoked trough FFI (VirtualAlloc, WriteProcessMemory, VirtualProtect, CreateThread)

- ***Remote_Injector*** - Simple classic remote process injection based on: VirtualAllocEx, VirtualProtectEx, WriteProcessMemory, CreateRemoteThread. Custom implementation for GetModuleHandleA and GetProcAddress for IAT hiding. The PoC is not using any external crates (even for WIN types and structs).

- ***DripLoader*** - Rust implementation of a shellcode loader inspired by [xuanxuan0's C++ DripLoader](https://github.com/xuanxuan0/DripLoader/tree/master). Memory alloc based on drip allocation technique (reserving NO_ACCESS in 64KB chunks, then commiting it in 4KB chunks with small delays and writing the shellcode), the shellcode is executed by patching the prologue of a specified function in ntdll (or another lib) with simple jump and then creating a fiber to execute the patched function. At the moment `ntdll.dll` and `RtlpWow64CtxFromAmd64` are choosen. Kudos to @xuanxuan0 for the C++ PoC.