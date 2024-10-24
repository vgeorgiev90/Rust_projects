use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce
};
use base64::prelude::*;
use crate::ENCRYPTION_KEY;


pub fn encrypt(data: &[u8]) -> Option<String> {
    let key = Key::<Aes256Gcm>::from_slice(ENCRYPTION_KEY.as_bytes());
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


pub fn decrypt(b64_cipher: String) -> Vec<u8> {
    let key = Key::<Aes256Gcm>::from_slice(ENCRYPTION_KEY.as_bytes());
    let cipher_data = match BASE64_STANDARD.decode(b64_cipher) {
        Ok(data) => data,
        Err(e) => { 
            println!("[!] Failed b64 decoding the encrypted data: {}", e); 
            return Vec::new();
        }
    };

    if cipher_data.is_empty() {
        return Vec::new();
    }
    
    let (nonce_part, enc_data_part) = cipher_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_part);

    let cipher = Aes256Gcm::new(key);

    match cipher.decrypt(&nonce, enc_data_part) {
        Ok(data) => {
            return data;
        },
        Err(e) => {
            println!("Error in decryption: {}", e);
            return Vec::new();
        }
    }
}