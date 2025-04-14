## 基于SM4国密算法的FF1保形加密实现
整体逻辑参照 https://github.com/0NG/Format-Preserving-Encryption 实现，目前只支持CBC模式，希望能实现其他模式。

玩具代码，不做**密码学意义**上的安全性保证，请谨慎使用。此外，仅在下述用例中测试通过，欢迎多多测试，找出问题。

感谢Google Gemini的大力支持。

### 用法
```rust
use sm4_ff1::ff1_encrypt;
use sm4_ff1::ff1error::FF1Error;

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
    .collect::<Result<Vec<_>, _>>().unwrap();

let expected_digits: Vec<u32> = expected_ciphertext_str
    .chars()
    .map(|c| c.to_digit(radix).ok_or_else(|| FF1Error::InvalidCharDigit(c, radix)))
    .collect::<Result<Vec<_>, _>>().unwrap();

let result_digits = ff1_encrypt(&key, radix, minlen, maxlen, max_tlen, tweak_bytes, &x_digits).unwrap();

assert_eq!(result_digits, expected_digits, "Encryption result does not match expected ciphertext");
```