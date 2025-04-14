pub mod ff1error;

use num_bigint::{BigUint, ToBigUint};
use num_traits::{Zero, Pow, ToPrimitive};
use std::convert::TryInto;
use ff1error::FF1Error;
use num_integer::Integer;
use neuedu_cryptos::block_ciphers::sm4_cbc_encrypt;

fn xor_bytes(a: &mut [u8], b: &[u8]) {
    assert_eq!(a.len(), b.len(), "XOR slices must have equal length");
    for (a_byte, b_byte) in a.iter_mut().zip(b.iter()) {
        *a_byte ^= *b_byte;
    }
}

fn ciph(key: &[u8; 16], input: &[u8; 16]) -> Result<[u8; 16], FF1Error> {
    let iv = [0u8; 16];
    let ciphertext = sm4_cbc_encrypt(*key, None, iv, input).unwrap();

    if ciphertext.len() >= 16 {
        Ok(ciphertext[0..16].try_into().unwrap())
    } else {
        Err(FF1Error::CipherLengthError)
    }
}

fn prf(key: &[u8; 16], input: &[u8]) -> Result<[u8; 16], FF1Error> {
    let block_size = 16;
    let num_blocks = (input.len() + block_size - 1) / block_size;
    let padded_len = num_blocks * block_size;
    let mut padded_input = Vec::with_capacity(padded_len);
    padded_input.extend_from_slice(input);
    padded_input.resize(padded_len, 0u8);

    let mut mac = [0u8; 16];

    for block in padded_input.chunks_exact(block_size) {
        let mut block_array: [u8; 16] = block.try_into().expect("Chunk size is 16");
        xor_bytes(&mut block_array, &mac); // XOR with previous MAC
        mac = ciph(key, &block_array)?;    // Encrypt using adapted CIPH
    }

    Ok(mac)
}

fn num_radix(s: &[u32], radix: u32) -> Result<BigUint, FF1Error> {
    let big_radix = radix.to_biguint().ok_or(FF1Error::BigUintConversion)?;
    let mut num = BigUint::zero();
    for &digit in s {
        if digit >= radix {
            return Err(FF1Error::InvalidDigit(digit, radix));
        }
        num = num * &big_radix + digit.to_biguint().ok_or(FF1Error::BigUintConversion)?;
    }
    Ok(num)
}

fn str_radix(mut c: BigUint, radix: u32, len: usize) -> Result<Vec<u32>, FF1Error> {
    if c.is_zero() {
        return Ok(vec![0u32; len]);
    }

    let big_radix = radix.to_biguint().ok_or(FF1Error::BigUintConversion)?;
    let mut s = Vec::with_capacity(len);

    while !c.is_zero() {
        let (quotient, remainder) = c.div_rem(&big_radix);
        s.push(remainder.to_u32().ok_or(FF1Error::BigUintConversion)?);
        c = quotient;
    }

    if s.len() > len {
        // overflow, c >= radix^len, which shouldn't happen after mod op
        return Err(FF1Error::StrLenMismatch);
    }

    // Pad with leading zeros
    s.resize(len, 0u32);
    s.reverse(); // Digits are generated in reverse order
    Ok(s)
}

fn num_bytes(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

fn bytes_radix(n: &BigUint, len: usize) -> Result<Vec<u8>, FF1Error> {
    let bytes = n.to_bytes_be();
    if bytes.len() > len {
        Err(FF1Error::NumToBytesConversion)
    } else {
        let padding_len = len - bytes.len();
        let mut result = Vec::with_capacity(len);
        result.extend(std::iter::repeat(0u8).take(padding_len));
        result.extend(bytes);
        Ok(result)
    }
}


// --- FF1 Encrypt Function ---

/// Implements FF1 Encryption according to the provided algorithm image.
///
/// # Arguments
/// * `key` - The 128-bit (16 byte) key for SM4.
/// * `radix` - The base of the numeral string X (2 <= radix <= 2^16).
/// * `minlen` - Minimum allowed length for X.
/// * `maxlen` - Maximum allowed length for X.
/// * `max_tlen` - Maximum allowed byte length for the tweak T.
/// * `tweak` - The tweak T (byte string).
/// * `x_digits` - The input numeral string X as a slice of digits (u32 values 0..radix-1).
///
/// # Returns
/// * `Ok(Vec<u32>)` - The encrypted numeral string Y as a vector of digits.
/// * `Err(Ff1Error)` - An error if input parameters are invalid or crypto operations fail.
///
/// # Example
/// ```rust
/// use sm4_ff1::ff1_encrypt;
/// use sm4_ff1::ff1error::FF1Error;
///
/// let pt_str = "3216";
/// let tweak_str = "1329999";
/// let key: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
///     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
/// let expected_ciphertext_str = "8956";
/// let radix: u32 = 10;
///
/// let tweak_bytes = tweak_str.as_bytes();
///
/// let minlen = 2;
/// let maxlen = 100;
/// let max_tlen = 32;
///
/// let x_digits: Vec<u32> = pt_str
///     .chars()
///     .map(|c| c.to_digit(radix).ok_or_else(|| FF1Error::InvalidCharDigit(c, radix)))
///     .collect::<Result<Vec<_>, _>>().unwrap();
///
/// let expected_digits: Vec<u32> = expected_ciphertext_str
///     .chars()
///     .map(|c| c.to_digit(radix).ok_or_else(|| FF1Error::InvalidCharDigit(c, radix)))
///     .collect::<Result<Vec<_>, _>>().unwrap();
///
/// let result_digits = ff1_encrypt(&key, radix, minlen, maxlen, max_tlen, tweak_bytes, &x_digits).unwrap();
///
/// assert_eq!(result_digits, expected_digits, "Encryption result does not match expected ciphertext");
/// ```
pub fn ff1_encrypt(
    key: &[u8; 16],
    radix: u32,
    minlen: usize,
    maxlen: usize,
    max_tlen: usize,
    tweak: &[u8],
    x_digits: &[u32],
) -> Result<Vec<u32>, FF1Error> {
    let n = x_digits.len();
    let t = tweak.len();

    // Validate input parameters
    if !(2..=65536).contains(&radix) { // 2^16 = 65536
        return Err(FF1Error::InvalidRadix { radix });
    }
    if !(minlen..=maxlen).contains(&n) {
        return Err(FF1Error::InvalidLength { n });
    }
    if t > max_tlen {
        return Err(FF1Error::InvalidTweakLength { t });
    }

    // Check radix^minlen >= 100 constraint
    let big_radix = radix.to_biguint().ok_or(FF1Error::BigUintConversion)?;
    let min_radix_pow = big_radix.pow(minlen);
    if min_radix_pow < 100u32.to_biguint().unwrap() {
        return Err(FF1Error::ConstraintViolation { radix, minlen });
    }

    for &digit in x_digits {
        if digit >= radix {
            return Err(FF1Error::InvalidDigit(digit, radix));
        }
    }

    // 1. Let u = floor(n/2); v = n - u.
    let u = n / 2;
    let v = n - u;

    // 2. Let A = X[1..u]; B = X[u+1..n].
    let mut a_digits: Vec<u32> = x_digits[0..u].to_vec();
    let mut b_digits: Vec<u32> = x_digits[u..n].to_vec();

    // 3. Let b = ceil( ceil(v * log2(radix)) / 8 ).
    let v_log_radix = v as f64 * (radix as f64).log2();
    let ceil_v_log_radix = v_log_radix.ceil() as usize;
    let b = (ceil_v_log_radix + 7) / 8; // ceil(x / 8) = (x + 7) / 8 for integers

    // 4. Let d = 4 * ceil(b / 4) + 4.
    let ceil_b_div_4 = (b + 3) / 4; // ceil(b / 4)
    let d = 4 * ceil_b_div_4 + 4;

    // 5. Let P = [1]^1 || [2]^1 || [1]^1 || [radix]^3 || [10]^1 || [u mod 256]^1 || [n]^4 || [t]^4.
    // P is always 16 bytes.
    let mut p = Vec::with_capacity(16);
    p.push(1); // [1]^1
    p.push(2); // [2]^1
    p.push(1); // [1]^1
    let radix_bytes = radix.to_be_bytes(); // u32 -> [u8; 4]
    p.extend_from_slice(&radix_bytes[1..4]); // Take bytes 1, 2, 3 (total 3 bytes)

    p.push(10); // [10]^1
    p.push((u % 256) as u8); // [u mod 256]^1
    p.extend_from_slice(&(n as u32).to_be_bytes()); // [n]^4
    p.extend_from_slice(&(t as u32).to_be_bytes()); // [t]^4
    let p_array: [u8; 16] = p.try_into().expect("P should be 16 bytes");


    // 6. For i from 0 to 9:
    for i in 0..10 {
        // i. Let Q = T || [0]^(-t-b-1) mod 16 || [i]^1 || [NUM_radix(B)]^b.
        let num_b = num_radix(&b_digits, radix)?;
        let num_b_bytes = bytes_radix(&num_b, b)?;

        let q_len_before_padding = t + 1 + b; // T + [i]^1 + [NUM_radix(B)]^b
        let num_zeros = (16 - (q_len_before_padding % 16)) % 16; // (-t-b-1) mod 16

        let mut q = Vec::with_capacity(t + num_zeros + 1 + b);
        q.extend_from_slice(tweak); // T
        q.extend(std::iter::repeat(0u8).take(num_zeros)); // [0] padding
        q.push(i as u8); // [i]^1
        q.extend_from_slice(&num_b_bytes); // [NUM_radix(B)]^b

        // ii. Let R = PRF(P || Q).
        let mut prf_input = Vec::with_capacity(16 + q.len());
        prf_input.extend_from_slice(&p_array);
        prf_input.extend_from_slice(&q);
        let r = prf(key, &prf_input)?; // R is 16 bytes

        // iii. Let S be the first d bytes of R || CIPH_K(R ^ [1]^16) || ... || CIPH_K(R ^ [ceil(d/16)-1]^16).
        let num_s_blocks = (d + 15) / 16; // ceil(d/16)
        let mut s_bytes = Vec::with_capacity(num_s_blocks * 16);

        s_bytes.extend_from_slice(&r);

        if num_s_blocks > 1 {
            let mut r_xor_j = r;
            for j in 1..num_s_blocks { // Loop from 1 up to ceil(d/16) - 1
                // Prepare R ^ [j]^16
                // [j]^16 means j represented as 16 bytes, big-endian.
                // Since j is small (max 9 for i=9, d depends on b), only last bytes matter.
                let j_bytes = (j as u32).to_be_bytes(); // Use u32 for j
                let mut j_block = [0u8; 16];
                j_block[12..16].copy_from_slice(&j_bytes); // Place j in the last 4 bytes

                xor_bytes(&mut r_xor_j, &j_block); // R ^ [j]^16 (modifies r_xor_j)

                let s_block = ciph(key, &r_xor_j)?; // CIPH_K(R ^ [j]^16)
                s_bytes.extend_from_slice(&s_block);

                // Important: Reset r_xor_j for the next iteration's XOR
                // Or, more simply, XOR the *original* R with j_block each time
                r_xor_j = r; // Reset to original R before next XOR
                // Alternative: XOR again with j_block to undo, but starting fresh is cleaner.
            }
        }
        // Truncate S to exactly d bytes
        s_bytes.truncate(d);

        // iv. Let y = NUM(S).
        let y = num_bytes(&s_bytes);

        // v. If i is even, let m = u; else, let m = v.
        let m = if i % 2 == 0 { u } else { v };

        // vi. Let c = (NUM_radix(A) + y) mod radix^m.
        let num_a = num_radix(&a_digits, radix)?;
        let big_radix = radix.to_biguint().ok_or(FF1Error::BigUintConversion)?;
        let modulus = big_radix.pow(m);
        let c = (num_a + y) % modulus;

        // vii. Let C = STR_radix^m(c).
        let c_digits = str_radix(c, radix, m)?;

        // viii. Let A = B.
        a_digits = b_digits; // Move B to A

        // ix. Let B = C.
        b_digits = c_digits; // Move C to B
    }

    // 7. Return A || B.
    let mut result_digits = a_digits;
    result_digits.extend(b_digits);

    Ok(result_digits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csdn_case_test() {
        let pt_str = "3216";
        let tweak_str = "1329999";
        let key: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let expected_ciphertext_str = "8956";
        let radix: u32 = 10;

        let tweak_bytes = tweak_str.as_bytes();

        let minlen = 2;
        let maxlen = 100;
        let max_tlen = 32;

        let x_digits: Vec<u32> = pt_str
            .chars()
            .map(|c| c.to_digit(radix).ok_or_else(|| FF1Error::InvalidCharDigit(c, radix)))
            .collect::<Result<Vec<_>, _>>().unwrap(); // Propagate potential char conversion error

        // Convert expected ciphertext string to Vec<u32> digits for comparison
        let expected_digits: Vec<u32> = expected_ciphertext_str
            .chars()
            .map(|c| c.to_digit(radix).ok_or_else(|| FF1Error::InvalidCharDigit(c, radix)))
            .collect::<Result<Vec<_>, _>>().unwrap();

        let result_digits = ff1_encrypt(&key, radix, minlen, maxlen, max_tlen, tweak_bytes, &x_digits).unwrap();
        assert_eq!(result_digits, expected_digits, "Encryption result does not match expected ciphertext");
    }

    #[test]
    fn another_test() {
        let pt_str = "620805";
        let tweak_str = "4601000000004101LS6A2E0F4NA000030";
        let key = b"6666666600000000";
        let expected_ciphertext_str = "003131";
        let radix: u32 = 10;

        let tweak_bytes = tweak_str.as_bytes();

        let minlen = 2;
        let maxlen = 100;
        let max_tlen = 50;

        let x_digits: Vec<u32> = pt_str
            .chars()
            .map(|c| c.to_digit(radix).ok_or_else(|| FF1Error::InvalidCharDigit(c, radix)))
            .collect::<Result<Vec<_>, _>>().unwrap(); // Propagate potential char conversion error

        // Convert expected ciphertext string to Vec<u32> digits for comparison
        let expected_digits: Vec<u32> = expected_ciphertext_str
            .chars()
            .map(|c| c.to_digit(radix).ok_or_else(|| FF1Error::InvalidCharDigit(c, radix)))
            .collect::<Result<Vec<_>, _>>().unwrap();

        let result_digits = ff1_encrypt(&key, radix, minlen, maxlen, max_tlen, tweak_bytes, &x_digits).unwrap();
        assert_eq!(result_digits, expected_digits, "Encryption result does not match expected ciphertext");
    }
}
