extern crate crypto_bigint;
extern crate num_bigint;
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 4 {
        eprintln!("Insufficient number of arguments");
        exit(1);
    }

    let key = &args[1];
    let path = &args[2];
    let tag = &args[3];

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
    let msg: Vec<u8>;
    match std::fs::read(path) {
        Ok(_msg) => {
            msg = _msg;
        },

        Err(e) => {
            eprintln!("Error reading file : {}", e);
            exit(1);
        }
    }
    
    let s: u128; 
    let r: u128;

    match poly1305::extract_keys(key) {
        Ok((s_m, s_r)) => {
            s = s_r;
            r = s_m;
        },

        Err(e) => {
            eprintln!("Error : {}", e);
            exit(1);
        }
    }

    // Fourth argument : extract tag in u128 form
    let t: u128;
    match poly1305::tag_to_u128(tag) {
        Ok(_t) => {
            t = _t;
        },

        Err(e) => {
            eprintln!("Error : {}", e);
            exit(1);
        }
    }

    // Now we do the check calculations
    let key = (s, r);
    let result = poly1305::mac(&msg, key);

    // print check result
    if t == result {
        println!("ACCEPT");
    } else {
        println!("REJECT");
    }

}