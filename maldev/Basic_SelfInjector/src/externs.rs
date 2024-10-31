use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::os::raw::{c_ulong, c_uint};

//Some custom types for ease of management
pub type LPVOID = *mut c_void;
pub type SIZE_T = usize;
pub type DWORD = c_ulong;
pub type HANDLE = *mut c_void;
pub type LPTHREAD_START_ROUTINE = Option<unsafe extern "system" fn(LPVOID) -> DWORD>;



//Constants
pub const SELF_HANDLE: HANDLE = -1isize as HANDLE;  // handle to the current process
pub const MEM_COMMIT: DWORD = 0x1000;
pub const MEM_RESERVE: DWORD = 0x2000;
pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_EXECUTE_READ: DWORD = 0x20;
pub const THREAD_CREATE_FLAGS: DWORD = 0x00;


#[link(name = "kernel32")]
extern "system" {
    #[link_name = "VirtualAlloc"]
    pub fn allocator(addr: LPVOID, size: SIZE_T, allocType: DWORD, memProtect: DWORD) -> LPVOID;

    #[link_name = "VirtualProtect"]
    pub fn memProtect(addr: LPVOID, size: SIZE_T, memProtect: DWORD, oldProtect: *mut DWORD) -> i32;

    #[link_name = "WriteProcessMemory"]
    pub fn writer(hProc: HANDLE, baseAddr: LPVOID, writeBuff: LPVOID, buff_size: SIZE_T, written: *mut DWORD) -> i32;

    #[link_name = "CreateThread"]
    pub fn selfStart(threadAttr: LPVOID, stackSize: SIZE_T, startAddr: LPTHREAD_START_ROUTINE, threadParams: LPVOID, createFlags: DWORD, threadID: *mut c_uint) -> HANDLE;
}