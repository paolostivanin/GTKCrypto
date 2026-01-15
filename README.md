# GTKCrypto

## Features
* Encrypt and decrypt files using AES, Twofish, Serpent or Camellia using either CBC or CTR mode. Key size for all algorithms is 256 bits.
* Encrypt and decrypt text using one of the aforementioned algorithms;
* Sign a given file using one of your GPG keys. Of course you can also verify the signature for a given file;
* Compute hashes for a chosen file (MD5, GOST94, SHA1, SHA2, SHA3, and Whirlpool);

## Security
* Encrypt-then-MAC. The plain text is encrypted and then the MAC of the encrypted text is computed and appended to the cipher text.
* Confidentiality is given by AES/Twofish/Serpent/Camellia operating in either CBC or CTR mode using a key size of 256 bits;
* Integrity is given by the MAC calculation (MAC = HMAC+SHA3-512);
* The input key is derived using PBKDF2 with 100'000 iterations and using SHA3-512 as hash algo;
* The key is temporarily stored inside a portion of secure memory which is erased before the program exits;

### Text Encryption
* Encrypt-then-TAG
* Plaintext is encrypted using AES-256 in GCM mode
* The input key is derived using PBKDF2 with 150'000 iterations and using SHA3-256 as hash algo;
* Data is always stored in a secure memory pool allocated by Gcrypt
* The resulting buffer has the following structure: `base64(IV,SALT,encrypt(plaintext),TAG)`

## Requirements
|Name|Min Version|
|----|-----------|
|GTK+|3.20|
|Glib|2.48.0|
|libgcrypt|1.7.0|
|gpgme|1.8.0|


## Screenshots
![Main window](/data/screenshots/mainwin.png?raw=true "Main window")

## How to compile
* `$ git clone https://github.com/paolostivanin/GTKCrypto.git`
* `$ cd GTKCrypto`
* `$ mkdir build && cd $_`
* `$ cmake -DCMAKE_INSTALL_PREFIX=/usr ..`
* `$ make`
* `$ sudo make install`


## How can I trust your program?
Don't trust me, trust the code. But if you really want to be sure that I'm not doing things in the wrong way, then you can just encrypt a file using GTKCrypto and write your own decryption program.
This is a relatively quick and easy task to achieve, just be sure to first understand the structure of the encrypted file (spoiler: `enc_file = metadata + encrypted_data + HMAC`). More info [HERE](https://github.com/paolostivanin/GTKCrypto/blob/master/src/crypt-common.h).


## Testing
* Before each release, I run PVS Studio in order to catch even more errors and/or corner cases
* With every commit to master, GTKCrypto is compiled in CircleCI against different distros


## Latest version
Stable and pre-release versions can be found [HERE](https://github.com/paolostivanin/GTKCrypto/releases)


## Notes
This software is licensed under the GNU General Public License version 3 and above.
