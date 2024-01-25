use num_bigint::BigUint;

// Clamp r associated with the key.
#[doc = r"Clamp r associated with the key"]
pub fn poly_1305_clamp(r: u128) -> u128 {
    let mask: u128 = 0x0ffffffc0ffffffc0ffffffc0fffffff;
    r & mask
}

// Calculate the MAC
#[doc = r"Calculate poly1305 MAC of msg by key"]
pub fn mac(msg: &[u8], key: (u128, u128)) -> u128 {
    let (s, r) = key;
    let r = poly_1305_clamp(r);
    let p: &BigUint = &(((BigUint::from(1u8)) << 130) - (BigUint::from(5u8)));

    let mut a = BigUint::from(0u8);

    for i in 1..=(((msg.len() as f64) / 16f64).ceil() as usize) {
        let j = std::cmp::min(i * 16, msg.len());
        let mut msg2: Vec<u8> = msg[((i - 1) * 16)..j].to_vec();
        msg2.push(0x01);

        let n = BigUint::from_bytes_le(&msg2);

        a = a + n;
        a = r * a;
        a = a % p;
    }

    a += s;
    let a_bytes = a.to_bytes_le();
    let mut a_bytes_16:[u8; 16] = [0; 16];
    a_bytes_16.copy_from_slice(&a_bytes[0..16]);
    let a = u128::from_be_bytes(a_bytes_16);
    a
}

// Extract the keys from the hex string
#[doc = r"Extract r and s from 32-bytes hexadecimal key"]
pub fn extract_keys(hexstr: &str) -> Result<(u128, u128), std::num::ParseIntError> {
    let (s_hex, r_hex) = hexstr.split_at(32);
    let r = u128::from_str_radix(s_hex, 16)?;
    let s = u128::from_str_radix(r_hex, 16)?;
    let s = s.to_be();
    let r = r.to_be();
    Ok((r, s))
}

pub fn tag_to_u128(hexstr: &str) -> Result<u128, std::num::ParseIntError> {
    let t = u128::from_str_radix(hexstr, 16)?;
    Ok(t)
}