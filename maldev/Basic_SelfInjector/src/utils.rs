use std::fs::File;
use std::io::Read;
use reqwest;

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