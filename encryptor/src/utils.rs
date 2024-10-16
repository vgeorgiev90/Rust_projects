use std::fs::File;
use std::io;
use std::io::{Read,Write};
use rpassword::read_password;


//Get the password to generate an encryption key
pub fn get_password() -> Result<String, String> {
    println!("[+] Input your encryption key");
    print!("[+] > ");
    let _ = io::stdout().flush();

    match read_password() {
        Ok(secret_key) => {
            return Ok(secret_key.trim_end().to_string());
        },

        Err(e) => {
            return Err(e.to_string());
        }
    }
}

//Write to file
pub fn write_file(path: &str, data: Vec<u8>) -> Result<bool, std::io::Error> {
    let mut file_handle = match File::create(path) {
        Ok(handle) => handle,
        Err(e) => {
            return Err(e);
        }
    };
    match file_handle.write_all(data.as_ref()) {
        Ok(()) => {
            return Ok(true);
        },
        Err(e) => {
            return Err(e);
        }
    }
}


pub fn read_file(path: &str) -> Result<Vec<u8>, io::Error> {
    let mut file_handle = match File::open(path) {
        Ok(file) => file,
        Err(e) => { 
            println!("[!] Error opening file: {}", e);
            return Err(e);
        }
    };

    let mut data: Vec<u8> = Vec::new();
    match file_handle.read_to_end(&mut data) {
        Ok(_) => { 
            Ok(data)
        },
        Err(e) => { 
            println!("[!] Error reading file: {}", e);
            return Err(e); 
        }
    }
}
