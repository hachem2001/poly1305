extern crate crypto_bigint;
extern crate num_bigint;
use num_bigint::BigUint;
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
    let msg: Vec<u8>;
    match std::fs::read(path) {
        Ok(_msg) => {
            println!("Read {} bytes from file", _msg.len());
            msg = _msg;
        },

        Err(e) => {
            eprintln!("Error reading file : {}", e);
            exit(1);
        }
    }
    let s: u128; 
    let r: u128;

    match extract_keys(key) {
        Ok((s_m, s_r)) => {
            s = s_r;
            r = s_m;
        },

        Err(e) => {
            eprintln!("Error : {}", e);
            exit(1);
        }
    }

    // Now we do the check calculations
    println!("First keys are : s {:x}, r {:x}", s, r);
    let key = (s, r);
    let result = poly1305_mac(&msg, key);
    println!("Result is : {:x?}", result);
}

// 

// Clamp r associated with the key.
fn poly_1305_clamp(r: u128) -> u128 {
    let mut r = r;
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff;
    r
}

/*
    poly1305_mac(msg, key):
        r = le_bytes_to_num(key[0..15])
        clamp(r)
        s = le_bytes_to_num(key[16..31])
        a = 0  /* a is the accumulator */
        p = (1<<130)-5
        for i=1 upto ceil(msg length in bytes / 16)
            j = min(i*16-1, msg length in bytes - 1)
            n = le_bytes_to_num(msg[((i-1)*16)..j] | [0x01])
            a += n
            a = (r * a) % p
        end

        a += s
        return num_to_16_le_bytes(a)
    end
*/

fn poly1305_mac(msg: &[u8], key: (u128, u128)) -> Vec<u8>{
    let (s, r) = key;
    //let r = BigUint::from(r.clone());
    //let s = BigUint::from(s.clone());
    let r = poly_1305_clamp(r);
    println!("Clamped r is : {:x}", r);
    let p= &((BigUint::from(1u8)) << 130 - 5);
    let mut a = BigUint::from(0u8);

    for i in 1..=msg.len()/16 {
        let j = std::cmp::min(i*16-1, msg.len()-1);
        let mut msg2:Vec<u8> = msg[((i-1)*16)..j].to_vec();
        msg2.push(0x01);


        let n = BigUint::from_bytes_le(&msg2);
        
        a = a + n;
        a = (r * a) % p;
    }

    a += s;

    let a_bytes = a.to_bytes_le();
    a_bytes
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