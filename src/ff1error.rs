use thiserror::Error;

#[derive(Error, Debug)]
pub enum FF1Error {
    #[error("Cryptography error")]
    Crypto(),
    #[error("Invalid input length n={n}: must be minlen <= n <= maxlen")]
    InvalidLength { n: usize },
    #[error("Invalid radix={radix}: must be 2 <= radix <= 2^16")]
    InvalidRadix { radix: u32 },
    #[error("Invalid tweak length t={t}: must be 0 <= t <= maxTlen")]
    InvalidTweakLength { t: usize },
    #[error("Constraint violation: radix^minlen ({radix}^{minlen}) must be >= 100")]
    ConstraintViolation { radix: u32, minlen: usize },
    #[error("Internal error: BigUint conversion failed")]
    BigUintConversion,
    #[error("Internal error: Failed to convert number to bytes")]
    NumToBytesConversion,
    #[error("Internal error: Failed to convert bytes to number")]
    BytesToNumConversion,
    #[error("Internal error: String conversion length mismatch")]
    StrLenMismatch,
    #[error("Internal error: Cipher output length mismatch (expected 16 bytes)")]
    CipherLengthError,
    #[error("Invalid digit in input: {0} >= radix {1}")]
    InvalidDigit(u32, u32),
    #[error("Invalid character in input: '{0}' is not a valid digit in radix {1}")]
    InvalidCharDigit(char, u32),
}
