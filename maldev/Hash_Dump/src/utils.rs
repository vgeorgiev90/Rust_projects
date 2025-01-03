use std::fs::File;
use std::io::Read;


// Static global constant that will be used to get the ntlm encryption key
static ODD_PARITY: [u8; 256] = [
    1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
    16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
    32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
    49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
    64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
    81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
    97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
    112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
    128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
    145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
    161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
    176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
    193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
    208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
    224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
    241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254,
];



// Reconstruct the RC4 encryption key
pub fn get_rc4_key(i1: Vec<u8>, i2: Vec<u8>, i3: Vec<u8>, i4: Vec<u8>) -> Vec<u8> {
    let mut rc4_key: Vec<u8> = Vec::new();

    for byte in i1 {
        rc4_key.push(byte);
    }
    for byte in i2 {
        rc4_key.push(byte);
    }
    for byte in i3 {
        rc4_key.push(byte);
    }
    for byte in i4 {
        rc4_key.push(byte);
    }

    return rc4_key;
}

// Extract registry value from string to Vec<u8>
pub fn extract_regval(input: String) -> Vec<u8> {
    let first = format!("{:?}", input).replace("F = RegValue(REG_BINARY: [", "");
    let second = format!("{:?}", first)
        .replace("])", "")
        .replace("RegValue(REG_BINARY: [", "")
        .replace(" ", "")
        .replace('"', "")
        .replace("\\[", "")
        .replace("]\\", "");

    let mut byte_vec: Vec<u8> = Vec::new();
    for element in second.split(",").map(String::from) {
        match element.parse::<u8>() {
            Ok(el) => byte_vec.push(el),
            Err(_) => continue
        }
    }
    return byte_vec;  
} 

// Convert unicode chars to string
pub fn unicode_to_str(input: &[u8]) -> String {
    match std::str::from_utf8(&input) {
        Ok(result) => {
            return result.replace("\u{0}", "").to_string();
        },
        Err(e) => {
            println!("[!] Failed parsing Unicode chars to String");
            return String::new();
        }
    }
}

// Prepare the offsets that are needed to get the username
pub fn prepare_username(offset_to_username_part: &[u8], username_len_part: &[u8]) -> (i32, i32) {
    
    let mut buffer = [0u8; 4];
    let mut counter = 0;
    let mut username_offset: i32 = 0;
    let mut username_len: i32 = 0;

    unsafe {
        for i in offset_to_username_part.iter() {
            buffer[counter] = *i;
            counter += 1;
        }
        username_offset = std::mem::transmute::<[u8; 4], i32>(buffer);

        // Calculate the len
        counter = 0;
        for i in username_len_part.iter() {
            buffer[counter] = *i;
            counter += 1;
        }
        username_len = std::mem::transmute::<[u8; 4], i32>(buffer);
    }
    return (username_offset + 204, username_len);
}


// Reconstruct the DES decryption key
pub fn get_des_key(username: String, transforms: Vec<usize>) -> [u8; 8] {

    // Get the TEMP key
    let mut temp_key: Vec<u8> = Vec::new();
    let chars: Vec<char> = username.chars().collect();
    for num in transforms {
        let first = chars[num * 2];
        let second = chars[num * 2 + 1];

        temp_key.push(u8::from_str_radix(format!("{}{}", first, second).as_str(), 16).unwrap());
    }

    // Get the actual key
    let mut encoded_key = vec![];
    let mut key = [0u8; 8];

    encoded_key.push(bitshift(temp_key[0].into(), -1) as u8);
    encoded_key.push(bitshift((temp_key[0] & 1).into(), 6) as u8 | bitshift(temp_key[1].into(), -2) as u8);
    encoded_key.push(bitshift((temp_key[1] & 3).into(), 5) as u8 | bitshift(temp_key[2].into(), -3) as u8);
    encoded_key.push(bitshift((temp_key[2] & 7).into(), 4) as u8 | bitshift(temp_key[3].into(), -4) as u8);
    encoded_key.push(bitshift((temp_key[3] & 15).into(), 3) as u8 | bitshift(temp_key[4].into(), -5) as u8);
    encoded_key.push(bitshift((temp_key[4] & 31).into(), 2) as u8 | bitshift(temp_key[5].into(), -6) as u8);
    encoded_key.push(bitshift((temp_key[5] & 63).into(), 1) as u8 | bitshift(temp_key[6].into(), -7) as u8);
    encoded_key.push(temp_key[6] & 127);

    key[0] = ODD_PARITY[(bitshift(encoded_key[0].into(), 1)) as usize];
    key[1] = ODD_PARITY[(bitshift(encoded_key[1].into(), 1)) as usize];
    key[2] = ODD_PARITY[(bitshift(encoded_key[2].into(), 1)) as usize];
    key[3] = ODD_PARITY[(bitshift(encoded_key[3].into(), 1)) as usize];
    key[4] = ODD_PARITY[(bitshift(encoded_key[4].into(), 1)) as usize];
    key[5] = ODD_PARITY[(bitshift(encoded_key[5].into(), 1)) as usize];
    key[6] = ODD_PARITY[(bitshift(encoded_key[6].into(), 1)) as usize];
    key[7] = ODD_PARITY[(bitshift(encoded_key[7].into(), 1)) as usize];

    return key;
}


fn bitshift(input: f64, power: i32) -> f64 {
    return (input * 2_f64.powi(power)).floor();
}