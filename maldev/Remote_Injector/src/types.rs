use std::os::raw::{c_uint, c_ulong, c_ushort, c_ulonglong};
use std::ptr::null_mut;
use std::ffi::{c_void, CString};
use std::ptr;
use std::mem::ManuallyDrop;



// Function signatures
pub type fn_get_thread_id = extern "stdcall" fn() -> u32;  // Only for testing
// VirtualAllocEx
pub type fn_alloc_ex = extern "stdcall" fn(
    hProcess: HANDLE,
    startAddr: LPVOID,
    allocSize: SIZE_T,
    allocType: DWORD,
    allocProtect: DWORD
) -> LPVOID;

// VirtualProtectEx
pub type fn_protect_ex = extern "stdcall" fn(
    hProcess: HANDLE,
    startAddr: LPVOID,
    allocSize: SIZE_T,
    newProtect: DWORD,
    oldProtect: *mut DWORD,
) -> BOOL;

// OpenProcess
pub type fn_open_proc = extern "stdcall" fn(
    access: DWORD,
    inheritHandle: BOOL, 
    processId: DWORD,
) -> HANDLE;

// WriteProcessMemory
pub type fn_write_ex = extern "stdcall" fn(
    hProcess: HANDLE,
    startAddr: LPVOID,
    wBuffer: LPVOID,
    nSize: SIZE_T,
    written: *mut SIZE_T,
) -> BOOL;

// CreateRemoteThread
pub type fn_remote_th = extern "stdcall" fn(
    hProcess: HANDLE,
    thrAttr: *mut SECURITY_ATTRIBUTES,
    stackSize: SIZE_T,
    startAddr: LPTHREAD_START_ROUTINE,
    thrParams: LPVOID,
    creationFlags: DWORD,
    lpThreadId: *mut DWORD,
) -> HANDLE;

// CloseHandle
pub type fn_closer = extern "stdcall" fn(
    hObject: HANDLE
) -> BOOL;





// Some constants
pub const IMAGE_DOS_SIGNATURE: c_ushort = 0x5A4D;
pub const IMAGE_NT_SIGNATURE: c_ulong = 0x00004550;
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;


// Some basic types
pub type LPVOID = *mut c_void;
pub type PVOID = *mut c_void;
pub type BYTE = u8;
pub type SIZE_T = usize;
pub type DWORD = c_ulong;
pub type WORD = c_ushort;
pub type USHORT = c_ushort;
pub type ULONG = c_ulong;
pub type ULONGLONG = c_ulonglong;
pub type PWSTR = *mut u16;
pub type HANDLE = *mut c_void;
pub type LONG = i32;
pub type UCHAR = u8;
pub type CHAR = i8;
pub type PBYTE = *mut u8;
pub type LANGID = u16;
pub type BOOL = i32;



// More specific types
#[cfg(target_pointer_width = "32")]
pub type IMAGE_OPTIONAL_HEADER = IMAGE_OPTIONAL_HEADER32;
#[cfg(target_pointer_width = "64")]
pub type IMAGE_OPTIONAL_HEADER = IMAGE_OPTIONAL_HEADER64;

#[cfg(unicode)]
pub type LPCTSTR = *const u16;  // Unicode (wide character)
#[cfg(not(unicode))]
pub type LPCTSTR = *const i8;   // ANSI (8-bit character)

type PS_POST_PROCESS_INIT_ROUTINE = extern "system" fn(); // Function that takes no arguments and returns ()
type PPS_POST_PROCESS_INIT_ROUTINE = *mut PS_POST_PROCESS_INIT_ROUTINE; // Pointer to PS_POST_PROCESS_INIT_ROUTINE

pub type LPTHREAD_START_ROUTINE = Option<unsafe extern "system" fn(LPVOID) -> DWORD>;




/* 
Windows specific Struct definitions
*/
#[repr(C)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: DWORD,
    pub lpSecurityDescriptor: LPVOID,
    pub bInheritHandle: BOOL,
}

#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: USHORT,
    pub MaximumLength: USHORT,
    pub Buffer: PWSTR,
}


#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub Reserved1: [BYTE; 16],
    pub Reserved2: [PVOID; 10],
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
}

#[repr(C)]
pub struct LIST_ENTRY {
    pub flink: *mut LIST_ENTRY,  // Pointer to the next entry in the list
    pub blink: *mut LIST_ENTRY,  // Pointer to the previous entry in the list
}

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Reserved1: [BYTE; 8],
    pub Reserved2: [PVOID; 3],
    pub InMemoryOrderModuleList: LIST_ENTRY,
}

#[repr(C)]
pub struct PEB {
    pub Reserved1: [BYTE; 2],
    pub BeingDebugged: BYTE,
    pub Reserved2: [BYTE; 1],
    pub Reserved3: [PVOID; 2],
    pub Ldr: *mut PEB_LDR_DATA,
    pub ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
    pub Reserved4: [PVOID; 3],
    pub AtlThunkSListPtr: PVOID,
    pub Reserved5: PVOID,
    pub Reserved6: ULONG,
    pub Reserved7: PVOID,
    pub Reserved8: ULONG,
    pub AtlThunkSListPtr32: ULONG,
    pub Reserved9: [PVOID; 45],
    pub Reserved10: [BYTE; 96],
    pub PostProcessInitRoutine: PPS_POST_PROCESS_INIT_ROUTINE,
    pub Reserved11: [BYTE; 128],
    pub Reserved12: [PVOID; 1],
    pub SessionId: ULONG,
}

#[repr(C)]
pub struct ACTIVATION_CONTEXT {
    pub cbSize: ULONG,   
    pub dwFlags: DWORD,       
    pub lpSource: LPCTSTR,     
    pub wProcessorArchitecture: USHORT, 
    pub wLangId: LANGID,               
    pub lpAssemblyDirectory: LPCTSTR,   
    pub lpResourceName: LPCTSTR,        
    pub lpApplicationName: LPCTSTR,     
}

// Unions for LDR_DATA_TABLE_ENTRY

// Manual drop will be required 
#[repr(C)]
pub union HashLinksOrSection {
    pub HashLinks: ManuallyDrop<LIST_ENTRY>,
    pub Section: ManuallyDrop<SectionInfo>,
}

#[repr(C)]
pub struct SectionInfo {
    pub SectionPointer: PVOID,
    pub CheckSum: ULONG,
}

#[repr(C)]
pub union TimeDateOrLoadedImports {
    pub TimeDateStamp: ULONG,
    pub LoadedImports: PVOID,
}

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub DllBase: PVOID,
    pub EntryPoint: PVOID,
    pub SizeOfImage: ULONG,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub Flags: ULONG,
    pub LoadCount: WORD,
    pub TlsIndex: WORD,
    pub HashUnion: HashLinksOrSection,
    pub TimeUnion: TimeDateOrLoadedImports,
    pub EntryPointActivationContext: *mut ACTIVATION_CONTEXT,
    pub PatchInformation: PVOID,
    pub ForwarderLinks: LIST_ENTRY,
    pub ServiceTagLinks: LIST_ENTRY,
    pub StaticLinks: LIST_ENTRY,
}

// Handle the manual drop for the unions, it may cause some issues but lets see...
impl Drop for LDR_DATA_TABLE_ENTRY {
    fn drop(&mut self) {
        unsafe {
            // Drop both unions, one of them will be valid
            ManuallyDrop::drop(&mut self.HashUnion.HashLinks); 
            ManuallyDrop::drop(&mut self.HashUnion.Section);   
        }
    }
}


/* 
PE parsing related structs
*/
#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: WORD,
    pub e_cblp: WORD,
    pub e_cp: WORD,
    pub e_crlc: WORD,
    pub e_cparhdr: WORD,
    pub e_minalloc: WORD,
    pub e_maxalloc: WORD,
    pub e_ss: WORD,
    pub e_sp: WORD,
    pub e_csum: WORD,
    pub e_ip: WORD,
    pub e_cs: WORD,
    pub e_lfarlc: WORD,
    pub e_ovno: WORD,
    pub e_res: [WORD; 4],
    pub e_oemid: WORD,
    pub e_oeminfo: WORD,
    pub e_res2: [WORD; 10],
    pub e_lfanew: LONG,    
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: WORD,
    pub NumberOfSections: WORD,
    pub TimeDateStamp: ULONG,
    pub PointerToSymbolTable: ULONG,
    pub NumberOfSymbols: ULONG,
    pub SizeOfOptionalHeader: WORD,
    pub Characteristics: WORD,
}


#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: ULONG,
    pub Size: ULONG,
}

// x86
#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER32 {
    pub Magic: WORD,
    pub MajorLinkerVersion: UCHAR,
    pub MinorLinkerVersion: UCHAR,
    pub SizeOfCode: ULONG,
    pub SizeOfInitializedData: ULONG,
    pub SizeOfUninitializedData: ULONG,
    pub AddressOfEntryPoint: ULONG,
    pub BaseOfCode: ULONG,
    pub BaseOfData: ULONG,
    pub ImageBase: ULONG,
    pub SectionAlignment: ULONG,
    pub FileAlignment: ULONG,
    pub MajorOperatingSystemVersion: WORD,
    pub MinorOperatingSystemVersion: WORD,
    pub MajorImageVersion: WORD,
    pub MinorImageVersion: WORD,
    pub MajorSubsystemVersion: WORD,
    pub MinorSubsystemVersion: WORD,
    pub Win32VersionValue: ULONG,
    pub SizeOfImage: ULONG,
    pub SizeOfHeaders: ULONG,
    pub CheckSum: ULONG,
    pub Subsystem: WORD,
    pub DllCharacteristics: WORD,
    pub SizeOfStackReserve: ULONG,
    pub SizeOfStackCommit: ULONG,
    pub SizeOfHeapReserve: ULONG,
    pub SizeOfHeapCommit: ULONG,
    pub LoaderFlags: ULONG,
    pub NumberOfRvaAndSizes: ULONG,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

// x64
#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: WORD,
    pub MajorLinkerVersion: UCHAR,
    pub MinorLinkerVersion: UCHAR,
    pub SizeOfCode: ULONG,
    pub SizeOfInitializedData: ULONG,
    pub SizeOfUninitializedData: ULONG,
    pub AddressOfEntryPoint: ULONG,
    pub BaseOfCode: ULONG,
    pub ImageBase: ULONGLONG, // 64-bit
    pub SectionAlignment: ULONG,
    pub FileAlignment: ULONG,
    pub MajorOperatingSystemVersion: WORD,
    pub MinorOperatingSystemVersion: WORD,
    pub MajorImageVersion: WORD,
    pub MinorImageVersion: WORD,
    pub MajorSubsystemVersion: WORD,
    pub MinorSubsystemVersion: WORD,
    pub Win32VersionValue: ULONG,
    pub SizeOfImage: ULONG,
    pub SizeOfHeaders: ULONG,
    pub CheckSum: ULONG,
    pub Subsystem: WORD,
    pub DllCharacteristics: WORD,
    pub SizeOfStackReserve: ULONGLONG,
    pub SizeOfStackCommit: ULONGLONG,
    pub SizeOfHeapReserve: ULONGLONG,
    pub SizeOfHeapCommit: ULONGLONG,
    pub LoaderFlags: ULONG,
    pub NumberOfRvaAndSizes: ULONG,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
pub struct IMAGE_NT_HEADERS {
    pub Signature: ULONG,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER,
}

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: ULONG,
    pub TimeDateStamp: ULONG,
    pub MajorVersion: USHORT,
    pub MinorVersion: USHORT,
    pub Name: ULONG,
    pub Base: ULONG,
    pub NumberOfFunctions: ULONG,
    pub NumberOfNames: ULONG,
    pub AddressOfFunctions: ULONG,      // RVA from base of image
    pub AddressOfNames: ULONG,          // RVA from base of image
    pub AddressOfNameOrdinals: ULONG,   // RVA from base of image
}