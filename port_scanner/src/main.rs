mod scanner;
mod utils;
use std::thread;
use std::sync::mpsc;
extern crate argparse;
use argparse::{ArgumentParser, Store};
use std::time::Instant;

/*
TODO
1. Add option for range scan
2. Add option for UDP scan
3. Possibly try to grab a banner if it exist
*/

fn main() {

    let mut threads_arg: String = "".to_string();
    let mut host: String = "".to_string();
    let mut range_arg: String = "".to_string();

    //Argument parser
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Simple TCP port scanner based in rust");
        ap.refer(&mut host)
            .add_option(&["-r", "--host"], Store, "Host to scan, this should be a valid IPv4");
        ap.refer(&mut range_arg)
            .add_option(&["-p", "--port-range"], Store, "Port range to scan, eg: 10000");
        ap.refer(&mut threads_arg)
            .add_option(&["-t", "--threads"], Store, "Number of threads to run the scan with");
        ap.parse_args_or_exit();
    }

    if range_arg.is_empty() || host.is_empty() || threads_arg.is_empty() {
        println!("[!] No arguments passed\n./program -h to see available options");
        return;
    }

    let range: u32 = range_arg.parse::<u32>().expect("[!] Please provide a valid port range");
    let threads: u32 = threads_arg.parse::<u32>().expect("[!] Please provide a valid integer for number of threads");

    let start = Instant::now();

    //Channel
    let (sender, receiver) = mpsc::channel();
    //Vector to store opened ports
    let mut opened_ports: Vec<Vec<u32>> = Vec::new();
    //Vector to store thread handles
    let mut handles = Vec::new();

    println!("[+] Starting port scan for host: {}", host);
    println!("[+] Scheduling {} ports scan to {} threads", range, threads);

    //Split the port range in equal parts
    let range_parts: Vec<u32> = utils::split_range(range, threads);

    for i in 0..range_parts.len() {
        
        //Clone the variables so they can be accessible in every iteration of the loop
        let current = range_parts[i];
        let previous = if i == 0 { 1 } else { range_parts[i - 1] };
        let sender_clone = sender.clone();
        let host_clone = host.clone();
        //println!("[+] Scheduling thread {} for range: {}-{}", i, previous, current);

        let handle = thread::spawn(move || {
            let ports: Vec<u32> = scanner::scan_tcp_ports(previous, current, host_clone.as_str());
            
            //If there are open ports send them to the main thread
            if !ports.is_empty() {
                sender_clone.send(ports).expect("[!] Cant send open ports to main");
            }
        });

        //push the handle to the handles vector
        handles.push(handle);
    }

    drop(sender);

    //Get all messages in the channel
    while let Ok(data) = receiver.recv() {
        opened_ports.push(data);
    };

    //Wait for thread completion
    for hand in handles {
        hand.join().expect("[!] Thread panicked...");
    }

    //receiver.try_iter().for_each(|msg| opened_ports.push(msg));

    let duration = start.elapsed();
    
    //Get the scan duration in seconds
    println!("[+] Scan duration: {:.2}s", duration.as_secs_f64());
    //Concat all vectors, transform the elements to string and finally join them as a single string
    println!("[+] Opened ports: \n\n{}", opened_ports.concat().iter().map(|port| port.to_string()).collect::<Vec<String>>().join(", "));
}