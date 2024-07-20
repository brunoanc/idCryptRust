/*
* idCryptRust
* Copyright (C) 2024 Bruno Ancona
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

use std::{
    ffi::OsStr,
    fs::File,
    io::{Read, Write},
    path::Path,
    process
};

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

// Display the help message
fn display_help() {
    println!(concat!(
        "Usage: idCrypt [options] <file-path> <internal-file-path>\n\n",
        "Options:\n",
        "\t--decrypt, -d\t\tDecrypts the file.\n",
        "\t--encrypt, -e\t\tEncrypts the file.\n\n",
        "Example: idCrypt D:\\english.bfile strings/english.lang\n\n",
        "If a .dec file is supplied it'll be encrypted to <file-path>.bfile.\n",
        "Otherwise the file will be decrypted to <file-path>.dec.\n",
        "You _must_ use the correct internal filepath for decryption to succeed!"
    ));
}

fn main() {
    println!("id_crypt v2.0 by Bruno Ancona\n");

    let args: Vec<String> = std::env::args().collect();

    // Display usage instructions
    if args.len() < 3 {
        display_help();
        process::exit(1);
    }

    // Process arguments
    let mut decrypt = None;
    let mut file_path = None;
    let mut internal_path = None;

    for arg in &args[1..] {
        match arg.as_str() {
            "--decrypt" | "-decrypt" | "-d" => decrypt = Some(true),
            "--encrypt" | "-encrypt" | "-e" => decrypt = Some(false),
            "--help" | "-help" | "-h" => {
                display_help();
                process::exit(0);
            },
            _ => {
                if file_path.is_none() {
                    file_path = Some(arg);
                }
                else if internal_path.is_none() {
                    internal_path = Some(arg);
                }
                else {
                    display_help();
                    process::exit(1);
                }
            },
        }
    }

    // If the necessary arguments weren't provided, abort
    if file_path.is_none() || internal_path.is_none() {
        display_help();
        process::exit(1);
    }

    let file_path = file_path.unwrap();
    let internal_path = internal_path.unwrap();

    // If operation wasn't specified by user, decrypt by default, unless file extension is .dec
    if decrypt.is_none() {
        let extension = Path::new(&file_path).extension().and_then(OsStr::to_str).unwrap();
        decrypt = Some(extension.to_lowercase() != "dec");
    }

    let decrypt = decrypt.unwrap();

    // Get destination path
    let dest_path: String;

    if decrypt {
        dest_path = format!("{}.{}", file_path, "dec");
    }
    else {
        dest_path = format!("{}.{}", file_path, "bfile");
    }

    // Read input file into a Vec
    let mut file = File::open(file_path).expect("ERROR: Failed to open file for reading.");
    let mut file_data: Vec<u8> = Vec::new();
    file.read_to_end(&mut file_data)
        .expect("ERROR: Failed to read file.");
    let size = file_data.len();

    // Get file salt from encrypted file, or generate a random one
    let mut file_salt = [0u8; 0xC];

    if decrypt {
        file_salt.copy_from_slice(&file_data[0..0xC]);
    }
    else {
        getrandom::getrandom(&mut file_salt).unwrap();
    }

    // Get encryption key from SHA256 hash
    let mut hasher = Sha256::new();
    hasher.update(&file_salt);
    hasher.update(b"swapTeam\n");
    hasher.update(&[0u8; 1]);
    hasher.update(&internal_path);
    let enc_key = hasher.finalize();

    // Get file salt from encrypted file, or generate a random one
    let mut file_iv = [0u8; 0x10];

    if decrypt {
        file_iv.copy_from_slice(&file_data[0xC..(0xC + 0x10)]);
    }
    else {
        getrandom::getrandom(&mut file_iv).unwrap();
    }

    // Get ciphertext / plaintext according to the operation
    let file_text: Vec<u8>;
    let mut hmac = [0u8; 0x20];

    if decrypt {
        file_text = file_data[0x1C..(size - 0x20)].to_vec();

        // Verify the HMAC in the file is correct, abort otherwise
        let mut mac_hasher = HmacSha256::new_from_slice(&enc_key).unwrap();
        mac_hasher.update(&file_salt);
        mac_hasher.update(&file_iv);
        mac_hasher.update(&file_text);
        hmac.copy_from_slice(&mac_hasher.finalize().into_bytes());

        if hmac != &file_data[(size - 0x20)..size] {
            eprintln!("ERROR: The encrypted file's HMAC doesn't match, might be corrupted.");
            process::exit(1);
        }
    }
    else {
        file_text = file_data.clone();
    }

    // Decrypt or encrypt the data using AES 128 CBC
    let crypted_text: Vec<u8>;

    if decrypt {
        crypted_text = Aes128CbcDec::new(enc_key[0..0x10].into(), &file_iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(&file_text)
            .expect("ERROR: Failed to decrypt the file.");
    }
    else {
        crypted_text = Aes128CbcEnc::new(enc_key[0..0x10].into(), &file_iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(&file_text);
    }

    let mut file = File::create(&dest_path).expect("ERROR: Failed to open destination path for writing.");

    if decrypt {
        file.write_all(&crypted_text)
            .expect("ERROR: Failed to write new contents to destination path");

        println!("Decryption succeeded! Wrote to {}\n", dest_path);
    }
    else {
        file.write(&file_salt)
            .expect("ERROR: Failed to write new contents to destination path.");
        file.write(&file_iv)
            .expect("ERROR: Failed to write new contents to destination path.");
        file.write(&crypted_text)
            .expect("ERROR: Failed to write new contents to destination path.");

        // Get the HMAC hash
        let mut mac_hasher = HmacSha256::new_from_slice(&enc_key).unwrap();
        mac_hasher.update(&file_salt);
        mac_hasher.update(&file_iv);
        mac_hasher.update(&crypted_text);
        file.write(&mac_hasher.finalize().into_bytes())
            .expect("ERROR: Failed to write new contents to destination path.");

        println!("Encryption succeeded! Wrote to {}\n", dest_path);
    }
}
