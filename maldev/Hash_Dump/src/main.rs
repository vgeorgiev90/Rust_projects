#![allow(warnings)]
mod utils;
mod ntlm;
mod crypt;


fn main() {
    ntlm::get_user_hashes();
}