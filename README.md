nukrypt
=======
A simple ransomware PoC written in Rust. `nukrypt` will recursively traverse all directories given to it as CLI arguments and encrypt files using AES128. The 128-bit key is generated at runtime and dropped at the current working directory. The AES IV is written to the beginning of each encrypted file. Encrypted files are suffixed with `.nukrypt`.


Features
--------
- AES128
- Literal encryption using [litcrypt](https://docs.rs/litcrypt/latest/litcrypt/)
- Some safeguards to prevent unintended data loss.


Compilation
-----------
- Simply `git clone` the repository and `cargo build` the project:
```
$ git clone https://github.com/hiatus/nukrypt
$ cd nukrypt
$ cargo build --release
```


Usage
-----
```
nukrypt [encrypt|decrypt] [dir]..
```

### Encrypt
When called with `encrypt`, `nukrypt` will first generate a 128-bit key and write it to a file called `nukrypt.key` at the current working directory; if this file already exists, the program will safely exit. After key generation, all `dir`s will be recursively encrypted.

```
$ nukrypt encrypt ./encrypt-me/
[+] Encryption key saved to nukrypt.key

[#] Encrypting: ./encrypt-me/notes.txt
[#] Encrypting: ./encrypt-me/project/curriculum.pdf
[#] Encrypting: ./encrypt-me/project/accounting.xlsx

[+] 3 files encrypted in 0.002 seconds
```

### Decrypt
When called with `decrypt`, `nukrypt` will attempt to read the key from the `nukrypt.key` file in the current working directory and recursively decrypt all `dir`s.
```
$ nukrypt decrypt ./encrypt-me/
[#] Decrypting: ./encrypt-me/notes.txt.nukrypt
[#] Decrypting: ./encrypt-me/project/curriculum.pdf.nukrypt
[#] Decrypting: ./encrypt-me/project/accounting.xlsx.nukrypt

[+] 3 files decrypted in 0.000 seconds
```