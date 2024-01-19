extern crate num_bigint;
use num_bigint::{BigUInt, Sign};
use std::process::exit;

fn main() {
    println!("Hello, world!");
    let args: Vec<String> = std::env::args().collect();
    dbg!(&args); // debug print the arguments

    if args.len() != 3 {
        eprintln!("Insufficient number of arguments");
        exit(1);
    }

    let key = &args[1];
    let path = &args[2];

    // First argument : discard

    // Second argument : should be 64-char hex. To convert to two u128 keys
    // Assert that it is very well a hex64 input

    {
        if key.len() != 64 || !key.chars().all(|c| c.is_digit(16)) {
            eprintln!("First argument must be a 64 long hexidecimal representation of the key");
            exit(1);
        }
        
    }

    // Third argument : verify file is accessible

    if !std::fs::metadata(path).is_ok() {
        eprintln!("File '{}' is not accessible.", path);
        exit(1);
    }

    let s: u128; 
    let r: u128;

    match extract_keys(key) {
        Ok((s_m, s_r)) => {
            s = s_m;
            r = s_r;
        },

        Err(e) => {
            eprintln!("Error : {}", e);
            exit(1);
        }
    }

    // Now we do the check calculations
    println!("First keys are : s {:x}, r {:x}", s, r);
    let r = poly_1305_clamp(r); // overshadows the r from above
    println!("Clamped r is {:x}", r);


    let P = BigUInt::from_str_radix("3fffffffffffffffffffffffffffffffb", 16).unwrap();
}

// 

// Clamp r associated with the key.
fn poly_1305_clamp(r: u128) -> u128 {
    let mut r = r;
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff;
    r
}

// Extract the keys from the hex string
fn extract_keys(hexstr: &str) -> Result<(u128, u128), std::num::ParseIntError> {
    let (s_hex, r_hex) = hexstr.split_at(32);
    let s = u128::from_str_radix(s_hex, 16)?;
    let r = u128::from_str_radix(r_hex, 16)?;

    Ok((s, r))
}

#[cfg(test)]
fn check_key_extract(hexstr: &str, s: u128, r: u128) {
    let (s_, r_) = extract_keys(hexstr).unwrap();
    assert_eq!(s, s_);
    assert_eq!(r, r_);
}