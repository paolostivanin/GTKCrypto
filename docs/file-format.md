# GTKCrypto encrypted-data formats

## GTC3

GTC3 is the only format written by GTKCrypto 3.x. Integer fields use network
byte order. The complete 80-byte header is supplied to GCM as additional
authenticated data.

| Offset | Size | Field | Value |
|---:|---:|---|---|
| 0 | 4 | Magic | ASCII `GTC3` |
| 4 | 1 | Version | `3` |
| 5 | 2 | Header length | `80` |
| 7 | 1 | Flags | `0` |
| 8 | 1 | Cipher | `1` = AES-256-GCM |
| 9 | 1 | KDF | `1` = Argon2id |
| 10 | 1 | Salt length | `32` |
| 11 | 1 | Nonce length | `12` |
| 12 | 1 | Tag length | `16` |
| 13 | 3 | Reserved | zero |
| 16 | 4 | Argon2 time cost | `2` |
| 20 | 4 | Argon2 memory KiB | `19456` |
| 24 | 4 | Argon2 lanes | `1` |
| 28 | 8 | Plaintext length | unsigned byte length |
| 36 | 32 | Salt | random |
| 68 | 12 | Nonce | random |

The header is followed by exactly `plaintext length` bytes of ciphertext and a
16-byte GCM tag. Parsers reject unknown IDs, non-zero reserved fields, unsafe
KDF parameters, integer overflow, and size mismatches before deriving a key.

Passwords are the exact UTF-8 bytes supplied by the user, without a terminating
NUL. No Unicode normalization is performed.

Encrypted text is `GTC3:` followed by standard base64 encoding of the same
binary container.

## Legacy v2

V2 begins with `GTC`, version byte `2`, and the historical packed 62-byte
metadata layout. GTKCrypto reads both integer byte orders and only accepts
known cipher/mode and IV combinations. GCM files end in a 16-byte tag.
CBC/CTR files end in a 64-byte HMAC-SHA3-512 over metadata and ciphertext.

## Legacy v1

V1 serialized an ABI-dependent C structure. GTKCrypto therefore checks the
historical 32-bit and 64-bit layouts in both byte orders. A candidate is used
only when all fields are valid and its HMAC verifies. V1 uses PBKDF2-SHA512
with 100,000 iterations and reproduces the historical password-length bug only
while reading legacy data.

Legacy formats are read-only and should be migrated by decrypting and
re-encrypting with GTKCrypto 3.x.
