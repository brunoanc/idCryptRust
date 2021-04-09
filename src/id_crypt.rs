/*
* idCryptRust
* Copyright (C) 2021 PowerBall253
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#![allow(non_snake_case)]

extern crate getrandom;
extern crate sha2;
extern crate hmac;
extern crate aes;
extern crate block_modes;

use std::path::Path;
use std::ffi::OsStr;
use std::fs::File;
use std::io::prelude::*;
use getrandom::getrandom;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac, NewMac};
use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

type HmacSha256 = Hmac<Sha256>;
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

fn main() {
    println!("id_crypt v1.0 by PowerBall253\n");

    let key_derive_static = "swapTeam\n".to_string();

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
		println!("Usage:\n\tidCrypt <file-path> <internal-file-path>\n");
		println!("Example:\n\tidCrypt D:\\english.bfile strings/english.lang\n");
		println!("If a .blang or .bfile is supplied it'll be decrypted to <file-path>.dec");
		println!("Otherwise the file will be encrypted to <file-path>.blang\n");
		println!("You _must_ use the correct internal filepath for decryption to succeed!");
        std::process::exit(1);
    }

    let mut decrypt = false;

    let file_path = &args[1];
    let internal_path = &args[2];
    let extension = String::from(Path::new(file_path).extension().and_then(OsStr::to_str).unwrap());

    if extension.to_lowercase() == "blang" || extension.to_lowercase() == "bfile" {
        decrypt = true;
    }

    let dest_path: String;

    if decrypt {
        dest_path = format!("{}.{}", file_path, "dec");
    }
    else {
        dest_path = format!("{}.{}", file_path, "blang");
    }

    let mut file = File::open(file_path).expect("Failed to open file for reading."); 
    let mut file_data: Vec<u8> = Vec::new();
    file.read_to_end(&mut file_data).expect("Failed to read file.");
    let size = file_data.len();

    let mut file_salt: Vec<u8>;

    if decrypt {
        file_salt = file_data[0..0xC].to_vec();
    }
    else {
        file_salt = vec![0u8; 0xC];
        getrandom(&mut file_salt).unwrap();
    }

    let mut hasher = Sha256::new();
    hasher.update(&file_salt);
    let mut empty_byte_array = vec![0; 1];
    let mut key_derive_static_bytes = key_derive_static.as_bytes().to_vec();
    key_derive_static_bytes.append(&mut empty_byte_array);
    hasher.update(&key_derive_static_bytes);
    hasher.update(&internal_path);
    let enc_key = hasher.finalize().to_vec();
    
    let mut file_iv = vec![0u8; 0x10];

    if decrypt {
        file_iv = file_data[0xC..(0xC + 0x10)].to_vec();
    }
    else {
        getrandom(&mut file_iv).unwrap();
    }

    let mut file_text = file_data.clone();
    let hmac: Vec<u8>;

    if decrypt {
        file_text = file_data[0x1C..(size as usize - 0x20)].to_vec();

        let file_hmac = file_data[(size as usize - 0x20)..(size as usize)].to_vec();

        let mut mac_hasher = HmacSha256::new_varkey(&enc_key).unwrap();
        mac_hasher.update(&file_salt);
        mac_hasher.update(&file_iv);
        mac_hasher.update(&file_text);
        hmac = mac_hasher.finalize().into_bytes().to_vec();

        assert_eq!(hmac.to_vec(), file_hmac);
    }

    let cipher = Aes128Cbc::new_var(&enc_key[0..0x10].to_vec(), &file_iv).unwrap();
    let crypted_text: Vec<u8>;

    if decrypt {
        crypted_text = cipher.decrypt_vec(&file_text).unwrap();
    }
    else {
        crypted_text = cipher.encrypt_vec(&file_text);
    }

    let mut file = File::create(&dest_path).expect("Failed to open destination path for writing.");

    if decrypt {
        file.write_all(&crypted_text).expect("Failed to write new contents to destination path");

        println!("Decryption succeeded! Wrote to {}\n", dest_path);
    }
    else {
        file.write(&file_salt).expect("Failed to write new contents to destination path.");
        file.write(&file_iv).expect("Failed to write new contents to destination path.");
        file.write(&crypted_text).expect("Failed to write new contents to destination path.");

        let mut mac_hasher = HmacSha256::new_varkey(&enc_key).unwrap();
        mac_hasher.update(&file_salt);
        mac_hasher.update(&file_iv);
        mac_hasher.update(&crypted_text);
        let hmac = mac_hasher.finalize().into_bytes().to_vec();
        file.write(&hmac).expect("Failed to write new contents to destination path.");

        println!("Encryption succeeded! Wrote to {}\n", dest_path);
    }
}
