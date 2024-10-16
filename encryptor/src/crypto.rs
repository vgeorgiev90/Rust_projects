use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce
};
use base64::prelude::*;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::process;


//Generate encryption key from the provided password
pub fn get_encryption_key(password: &str) -> [u8; 32] {
    let salt: &[u8] = b"6dHxBoQCuo2ubmw6"; //Salt as a byte slice

    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 1_234, &mut key);
    return key;
}


pub fn encrypt(enc_key: [u8; 32], data: &[u8]) -> Option<String> {
    let key = Key::<Aes256Gcm>::from_slice(&enc_key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let cipher = Aes256Gcm::new(key);

    //Pass the data as a byte slice &[u8]
    match cipher.encrypt(&nonce, data) {
        Ok(enc) => {
            //Create new vector and add the nonce as vector, 
            //then append the encrypted data and return
            let mut encrypted_data: Vec<u8> = nonce.to_vec();
            encrypted_data.extend_from_slice(&enc);
            return Some(BASE64_STANDARD.encode(encrypted_data));
        },
        Err(e) => {
            println!("Error encrypting data: {}", e);
            return None;
        }
    }
}


pub fn decrypt(enc_key: [u8; 32], b64_cipher: String) -> Vec<u8> {
    let key = Key::<Aes256Gcm>::from_slice(&enc_key);
    let cipher_data = match BASE64_STANDARD.decode(b64_cipher) {
        Ok(data) => data,
        Err(e) => { 
            println!("[!] Failed b64 decoding the encrypted data: {}", e); 
            process::exit(1);
        }
    };
    let (nonce_part, enc_data_part) = cipher_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_part);

    let cipher = Aes256Gcm::new(key);

    match cipher.decrypt(&nonce, enc_data_part) {
        Ok(data) => {
            return data;
        },
        Err(e) => {
            println!("Error in decryption: {}", e);
            process::exit(1);
        }
    }
}