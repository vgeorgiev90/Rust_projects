use crate::utils;
use aes::Aes128;
use block_modes::{
    BlockMode, 
    Cbc,
    block_padding::NoPadding
};
use des::decrypt;
use std::fmt::Write;
use md5::{
    Md5, 
    Digest
};



type Aes128Cbc = Cbc<Aes128, NoPadding>;

// AES128 Decryption function
pub fn aes_128_cbc_decrypt(decryption_key: &[u8], iv: &[u8], encrypted: Vec<u8>) -> Vec<u8> {
    let aes128 = Aes128Cbc::new_from_slices(&decryption_key, &iv).expect("[!] Failed creating AES128 cipher");
    let mut decrypted = encrypted;
    match aes128.decrypt(&mut decrypted) {
        Ok(data) => data.to_vec(),
        Err(e) => {
            println!("[!] Failed AES128 decryption: {}", e);
            return Vec::new();
        }
    }
}

// DES decryption function
pub fn des_decrypt(encrypted: &[u8], key_one: [u8; 8], key_two: [u8; 8]) -> String {

    let ntlm1_bytes = decrypt(encrypted, &key_one);
    let mut ntlm1_string = String::new();
    for byte in &ntlm1_bytes[..8] {
        write!(ntlm1_string, "{:02X}", byte).unwrap();
    };

    let ntlm2_bytes = decrypt(encrypted, &key_two);
    let mut ntlm2_string = String::new();
    for byte in &ntlm2_bytes[8..] {
        write!(ntlm2_string, "{:02X}", byte).unwrap();
    };
    
    return format!("{}{}", ntlm1_string, ntlm2_string);
}


// Decryption function for NTLM hashes based on RC4
pub fn rc4_decrypt(
    f_part: Vec<u8>, 
    encrypted_syskey: &[u8], 
    boot_key: Vec<u8>, 
    encrypted_ntlm: &[u8], 
    des_key: [u8; 8]
) -> Vec<u8> {
    
    // Get the encryption key for the syskey
    let mut aqwerty: Vec<u8> = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%".as_bytes().to_vec();
    aqwerty.push(0);
    let mut anum: Vec<u8> = "0123456789012345678901234567890123456789".as_bytes().to_vec();
    anum.push(0);

    let mut md5_hash = Md5::new();
    let rc4_key = utils::get_rc4_key(
        f_part,
        aqwerty,
        boot_key,
        anum
    );
    md5_hash.update(rc4_key);
    let encrypted_syskey_key = md5_hash.finalize();

    // Convert the encrypted syskey and its decryption key to u128
    let mut enc_syskey_128: Vec<u128> = encrypted_syskey.to_vec().into_iter().map(|x| x as u128).collect();
    let mut syskey_key_128: Vec<u128> = encrypted_syskey_key.to_vec().into_iter().map(|x| x as u128).collect();

    // Decrypt the syskey
    let syskey = rc4(enc_syskey_128, syskey_key_128);

    // Generate the NTLM encryption key
    let mut nt_password_string = "NTPASSWORD".as_bytes().to_vec();
    nt_password_string.push(0);

    let mut syskey_u8: Vec<u8> = syskey.into_iter().map(|x| x as u8).collect();

    let mut md5_hash = Md5::new();
    let rc4_key2 = utils::get_rc4_key(
        syskey_u8,
        des_key.to_vec(),
        nt_password_string,
        vec![]       
    );
    md5_hash.update(rc4_key2);
    let ntlm_key = md5_hash.finalize();

    let mut encrypted_ntlm_128: Vec<u128> = encrypted_ntlm.to_vec().into_iter().map(|x| x as u128).collect();
    let mut ntlm_key_128: Vec<u128> = ntlm_key.to_vec().into_iter().map(|x| x as u128).collect();

    let ntlm = rc4(encrypted_ntlm_128, ntlm_key_128);

    let mut ntlm_u8: Vec<u8> = ntlm.to_vec().into_iter().map(|x| x as u8).collect();
    return ntlm_u8;
}


// RC4 decryption routine
fn rc4(data: Vec<u128>, key: Vec<u128>) -> Vec<u128> {
    let mut r: Vec<u128> = data;
    let mut s: [u128; 256] = [0u128; 256];
    let mut k: [u128; 256] = [0u128; 256];

    for i in 0..256 {
        s[i] = i as u128;
        k[i] = key[i % key.len()];
    }

    let mut j: u128 = 0;
    for i in 0..256 {
        j = (j + s[i] + k[i]) % 256;
        let temp = s[i];
        s[i] = s[j as usize];
        s[j as usize] = temp;
    }
        
    let mut i = 0;
    let mut j = 0;
    for x in 0..r.len() {
        i = (i + 1) % 256;
        j = (j + s[i as usize]) % 256;

        let temp = s[i as usize];
        s[i as usize] = s[j as usize];
        s[j as usize] = temp;

        let t = ((s[i as usize] + s[j as usize]) % 256) as usize;
        r[x] = r[x] ^ s[t];
    }
    r
}