use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce
};
use base64::{engine, alphabet, Engine as _};
use crate::ENCRYPTION_KEY;


pub fn encrypt(data: &[u8]) -> Option<String> {
    let key = Key::<Aes256Gcm>::from_slice(ENCRYPTION_KEY.as_bytes());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let cipher = Aes256Gcm::new(key);
    let b64_engine = base64_engine();

    // Pass the data as a byte slice &[u8]
    match cipher.encrypt(&nonce, data) {
        Ok(enc) => {
            // Create new vector and add the nonce as vector, 
            // then append the encrypted data and return
            let mut encrypted_data: Vec<u8> = nonce.to_vec();
            encrypted_data.extend_from_slice(&enc);
            return Some(b64_engine.encode(encrypted_data));
        },
        Err(e) => {
            println!("Error encrypting data: {}", e);
            return None;
        }
    }
}


pub fn decrypt(b64_cipher: String) -> Vec<u8> {
    let b64_engine = base64_engine();
    let key = Key::<Aes256Gcm>::from_slice(ENCRYPTION_KEY.as_bytes());
    let cipher_data = match b64_engine.decode(b64_cipher.trim_matches('\0')) {
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


// Slightly customized base64 engine without paddings and url safe alphabet
fn base64_engine() -> base64::engine::GeneralPurpose {
    let alphabet = 
        alphabet::Alphabet::new("-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
        .unwrap();

    let config = engine::GeneralPurposeConfig::new()
                        .with_decode_allow_trailing_bits(true)
                        .with_encode_padding(false)
                        .with_decode_padding_mode(engine::DecodePaddingMode::RequireNone);

    let b64_engine = engine::GeneralPurpose::new(&alphabet, config);
    return b64_engine;
}