use crate::types;
use crate::utils;
use std::ffi::{c_void, CStr};


// Replacement for GetModuleHandleA trough PEB traversal
pub fn GetModHand(hashedLib: u32) -> types::HANDLE {

    println!("[+] Getting pointer to PEB");
    // Get a pointer to PEB
    let pPeb: *mut types::PEB = unsafe { utils::get_peb() };
    if pPeb.is_null() {
        println!("[!] Cant access PEB, pPeb is null");
        return std::ptr::null_mut();
    }

    // Dereference the pPeb pointer to access the PEB structure and get a reference to it
    let PEB = unsafe { &*pPeb };

    // Get a pointer to the Ldr member 
    let pLdr: *mut types::PEB_LDR_DATA = unsafe { PEB.Ldr };
    let LDR = unsafe { &*pLdr };       // Dereference pLdr to access LDR and get a reference to it


    println!("\t- Getting the loaded modules list from LDR");
    // Getting the module list from the LDR
    let modList: &types::LIST_ENTRY = unsafe { &LDR.InMemoryOrderModuleList };

    // Get the first entry
    let mut pTableEntry: *mut types::LDR_DATA_TABLE_ENTRY = unsafe { 
        modList.flink as *mut types::LDR_DATA_TABLE_ENTRY 
    };

    if pTableEntry.is_null() {
        println!("[!] No entries found in the module list.");
    } else {
        println!("\t- Starting to iterate through loaded modules.");
    }

    // Save the base address to know when we reached the end 
    let base_addr = pTableEntry;

    // Try to get a handle to the provided hashed module name
    while !pTableEntry.is_null() {
        unsafe {
            let current_entry = &*pTableEntry;

            if current_entry.FullDllName.Length != 0 {

                // Get a slice to construct the Dll Name
                let dll_name_slices = std::slice::from_raw_parts(
                    current_entry.FullDllName.Buffer,
                    current_entry.FullDllName.Length as usize / 2
                );
                let dll_name = String::from_utf16_lossy(dll_name_slices);

                // Hash the DLL name and compare with the provided hash, if its a match return a handle to the module
                if utils::HashA(dll_name.as_str()) == hashedLib {
                    println!("\t- Found the specified DLL: {}", dll_name);
                    println!("\t- Got handle: {:?}", 
                        current_entry.InInitializationOrderLinks.flink as types::HANDLE
                    );
                    return current_entry.InInitializationOrderLinks.flink as types::HANDLE;
                }
            } 
        
            // Get the next entry
            pTableEntry = current_entry.InLoadOrderLinks.flink as *mut types::LDR_DATA_TABLE_ENTRY;

            // If pTableEntry is null or it equals the base address (we are back to start) break from the loop
            if pTableEntry.is_null() || pTableEntry == base_addr {
                println!("[+] Reached the end of the module list.");
                break;
            }
        }
    }
    // If the module is not found, just return null
    return std::ptr::null_mut();
}


// Replacement for GetProcAddress
// Takes handle to the module and a hashed function name and returns a generic pointer
// which later will be transmuted to a function pointer
pub fn GetAddr(hModule: types::HANDLE, apiName: u32) -> types::LPVOID {
    println!("[+] Attempting to parse the PE structure from the provided handle");
    let peStart = hModule as types::PBYTE;

    // Get pointer to the DOS header
    let pDosHdr = peStart as *const types::IMAGE_DOS_HEADER;
    unsafe {
        if (*pDosHdr).e_magic != types::IMAGE_DOS_SIGNATURE {
            println!("[!] Not a valid DOS header");
            return std::ptr::null_mut();
        } else {
            println!("\t- Valid DOS header found");
        }
    }

    // Get pointer to the NT header
    unsafe {
        let pNtHdr = (peStart as usize + (*pDosHdr).e_lfanew as usize) as *const types::IMAGE_NT_HEADERS; // Cast to usize for artihmetic
        if (*pNtHdr).Signature != types::IMAGE_NT_SIGNATURE {
            println!("[!] Not a valid NT header");
            return std::ptr::null_mut();
        } else {
            println!("\t- Valid NT header found")
        }
    
        // Get pointer to the Optional headers
        let pOptHdr: &types::IMAGE_OPTIONAL_HEADER = &(*pNtHdr).OptionalHeader;

        // Get pointer to the export table
        let pExpTable: *const types::IMAGE_EXPORT_DIRECTORY = 
            (peStart as usize + pOptHdr.DataDirectory[types::IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress as usize) 
            as *const types::IMAGE_EXPORT_DIRECTORY;

        if pExpTable.is_null() {
            println!("[!] Export table pointer is null");
            return std::ptr::null_mut();
        } else {
            println!("\t- Pointer to the export table: {:?}", pExpTable);
        }


        // Get the addresses of the function names, function addresses and function name ordinals arrays
        let fnNameArray: *const types::DWORD = 
            (peStart as usize + (*pExpTable).AddressOfNames as usize) as *const types::DWORD;

        let fnAddrArray: *const types::DWORD = 
            (peStart as usize + (*pExpTable).AddressOfFunctions as usize) as *const types::DWORD;

        let fnNameOrdinals: *const types::WORD = 
            (peStart as usize + (*pExpTable).AddressOfNameOrdinals as usize) as *const types::WORD;

        // Loop trough all functions to find what we need
        for i in 0..(*pExpTable).NumberOfFunctions as u32 {

            // Get a pointer to the function name
            // Offset to function name start
            let funcNameOffset = *fnNameArray.add(i as usize);
            // Calculate the exact address of function name start
            let pFuncName: *const types::CHAR = (peStart as usize + funcNameOffset as usize) as *const types::CHAR;

            let funcName = CStr::from_ptr(pFuncName as *const i8).to_string_lossy();
            if utils::HashA(funcName.as_ref()) == apiName {
                println!("\t- Found searched function: {}", funcName);

                // Get the function ordinal and address and return the address
                let funcOrdinal: types::WORD = *fnNameOrdinals.add(i as usize);
                let funcAddr: types::LPVOID = 
                    (peStart as usize + *fnAddrArray.add(funcOrdinal as usize) as usize) as types::LPVOID;
                

                println!("\t\t- Ordinal: {:?}, Offset: {:?}, Address: {:?}", 
                            funcOrdinal, 
                            *fnAddrArray.add(funcOrdinal as usize) as types::LPVOID,
                            funcAddr
                );
                return funcAddr;
            }
        }

    }
    // If the function is not found return null
    return std::ptr::null_mut();
}