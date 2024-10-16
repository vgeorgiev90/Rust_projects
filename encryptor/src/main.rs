//TODO
// 1. Possibly make the salt dynamic
mod utils;
mod crypto;
use std::env::args;


fn main() {

    let args: Vec<String> = args().collect();
    if args.len() < 3 {
        usage();
        return;
    }

    let pass: String = match utils::get_password() {
        Ok(pass) => pass,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };
    let encryption_key: [u8; 32] = crypto::get_encryption_key(pass.as_str());


    match args[1].as_str() {
        "encrypt_file" => {
            //Read the file
            let read_path: &str = args[2].as_str();

            let message: Vec<u8> = match utils::read_file(read_path) {
                Ok(message) => message,
                Err(_e) => {
                    return;
                }
            };

            //pass the data as a byte slice &[u8]
            match crypto::encrypt(encryption_key, message.as_ref()) {
                Some(enc) => {  
                    //write the data to file
                    let write_path: String = format!("{}{}", read_path, ".enc");
                    println!("[+] Writing encrypted data to file: {}", write_path);

                    //Convert the base64 encrypted string to Vec<u8>
                    utils::write_file(write_path.as_str(), enc.as_bytes().to_vec()).expect("[!] Failed writing to file");
                },
                None => {
                    println!("[!] Error in encryption!");
                    return;
                }
            }
        },

        "encrypt" => {
            let message: &[u8] = args[2].as_bytes();

            match crypto::encrypt(encryption_key, message) {
                Some(enc) => {
                    println!("[+] Encrypted data: {}", enc);
                },
                None => {
                    println!("[!] Error in encryption!");
                    return;
                }
            }
        },

        "decrypt_file" => {
            let read_path: String = args[2].clone();

            let b64_bytes: Vec<u8> = match utils::read_file(read_path.as_str()) {
                Ok(message) => message,
                Err(_e) => {
                    return;
                }
            };
            let b64_data: String = String::from_utf8(b64_bytes).expect("[!] Malformed base64 data");
            let plain_text: Vec<u8> = crypto::decrypt(encryption_key, b64_data);

            println!("[+] Writing decrypted data to file: ./decrypted");
            utils::write_file("./decrypted", plain_text).expect("[!] Failed writing to file");
        },

        "decrypt" => {
            let b64_data: String = args[2].clone();
            let plain_text: Vec<u8> = crypto::decrypt(encryption_key, b64_data);
            println!("[+] Decrypted: \n{}", String::from_utf8(plain_text).unwrap());
        },
        _ => { usage(); }
    }

}


fn usage() {
    println!("Simple utility for AESGCM encryption, with a password derived key.");
    println!("It can be used to encrypt/decrypt data as an argument or files.\n");
    println!("Usage:");
    println!("./cryptor encrypt plain_text_data");
    println!("./cryptor decrypt b64_encrypted_data");
    println!("./cryptor encrypt_file /path/to/plaintext/file");
    println!("./cryptor decrypt_file /path/to/encrypted/file");
}