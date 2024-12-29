use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::os::raw::{c_ulong, c_uint, c_ushort};



//Some custom types for ease of management
pub type LPVOID = *mut c_void;
pub type LPCVOID = *const c_void;
pub type SIZE_T = usize;
pub type PSIZE_T = *mut usize;
pub type DWORD = c_ulong;
pub type WORD = c_ushort;
pub type NTSTATUS = i32;
pub type HANDLE = *mut c_void;
pub type LPFIBER_START_ROUTINE = unsafe extern "system" fn(LPVOID);


//Constants
pub const SELF_HANDLE: HANDLE = -1isize as HANDLE;  // handle to the current process
pub const MEM_COMMIT: DWORD = 0x1000;
pub const MEM_RESERVE: DWORD = 0x2000;
pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_EXECUTE_READ: DWORD = 0x20;
pub const THREAD_CREATE_FLAGS: DWORD = 0x00;
pub const PAGE_NOACCESS: DWORD = 0x01;
pub const MEM_FREE: DWORD = 0x10000;
pub const DONT_RESOLVE_DLL_REFERENCES: DWORD = 0x00000001;


// Base memory addresses to search
pub const VC_PREF_BASES: [usize; 10] = [
    0x00000000DDDD0000,
    0x0000000010000000,
    0x0000000021000000,
    0x0000000032000000,
    0x0000000043000000,
    0x0000000050000000,
    0x0000000041000000,
    0x0000000042000000,
    0x0000000040000000,
    0x0000000022000000
];



// Structs
#[repr(C)]
pub struct MEMORY_BASIC_INFORMATION {
    pub BaseAddress: LPVOID,
    pub AllocationBase: LPVOID,
    pub AllocationProtect: DWORD,
    pub PartitionId: WORD,
    pub RegionSize: SIZE_T,
    pub State: DWORD,
    pub Protect: DWORD,
    pub Type: DWORD,
}


// FFI kernel32
#[link(name = "kernel32")]
extern "system" {
    #[link_name = "VirtualQueryEx"]
    pub fn memQuery(proc_hand: HANDLE, base_addr: LPCVOID, out_buff: *mut MEMORY_BASIC_INFORMATION, length: SIZE_T) -> SIZE_T;

    #[link_name = "ConvertThreadToFiber"]
    pub fn convert_fiber(params: LPVOID) -> LPVOID;

    #[link_name = "SwitchToFiber"]
    pub fn switch_fiber(fiber: LPVOID) -> LPVOID;

    #[link_name = "CreateFiber"]
    pub fn create_fiber(stack_size: SIZE_T, startAdd: LPFIBER_START_ROUTINE, params: LPVOID) -> LPVOID; 

    #[link_name = "GetProcAddress"]
    pub fn get_address(mod_hand: HANDLE, proc_name: *const i8) -> LPVOID;

    #[link_name = "LoadLibraryExA"]
    pub fn load_lib(lib_name: *const i8, file_hand: HANDLE, flags: DWORD) -> HANDLE;

    #[link_name = "EnumProcessModules"]
    pub fn enum_mods(proc_hand: HANDLE, mod_hand: *mut HANDLE, cb: DWORD, cb_needed: *mut DWORD) -> i32;

    #[link_name = "GetModuleFileNameExA"]
    pub fn get_mod_name(proc_hand: HANDLE, mod_hand: HANDLE, name: *mut i8, name_size: DWORD) -> i32;
}

// NTDLL APIs 
#[link(name = "ntdll")]
extern "system" {
    #[link_name = "NtAllocateVirtualMemory"]
    pub fn ntAllocator(
        proc_hand: HANDLE, 
        base_addr: *mut LPVOID, 
        zero_bits: SIZE_T, 
        region_size: PSIZE_T, 
        alloc_type: c_ulong, 
        protect: c_ulong
    ) -> NTSTATUS;

    #[link_name = "NtProtectVirtualMemory"]
    pub fn ntProtect(
        proc_hand: HANDLE,
        base_addr: *mut LPVOID,
        region_size: PSIZE_T,
        new_protect: c_ulong,
        old_protect: *mut c_ulong
    ) -> NTSTATUS;

    #[link_name = "NtWriteVirtualMemory"]
    pub fn ntWrite(
        proc_hand: HANDLE,
        base_addr: LPVOID,
        buffer: *const c_void,
        bytes_to_write: SIZE_T,
        written: PSIZE_T
    ) -> NTSTATUS;
}