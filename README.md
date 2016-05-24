GTKCrypto (currently being rewritten)
========

* Encrypt and decrypt files using AES, Twofish, Serpent or Camellia (256bit, CBC or CTR mode);
* Encrypt and decrypt text using AES, Twofish, Serpent or Camellia (256bit, CTR mode)
* Compute hashes of a chosen file (MD5, GOST94, SHA1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512 and Whirlpool);

This software is developed by Paolo "Polslinux" Stivanin (https://paolostivanin.com)


Security
--------
* Confidentiality is given by AES/Twofish/Serpent/Camellia;
* Integrity is given by the MAC calculation (MAC = HMAC+SHA512);
* The input key is derived using PBKDF2 with 150'000 iterations and using SHA512 as hash algo;
* The key is temporarly stored inside a portion of secure memory which will be erased when the program exits;
* The original file will be overwritten prior its removing (secure file deletion);


Requirements
------------
* GCC or Clang: suggested version of Clang **>= 3.6**, of GCC **>= 4.9.0**;
* Gcrypt: required version **>=1.7**;
* GTK+: required version **>=3.14**, suggested version **3.20**;
* Glib: required version **>=2.42**, suggested version **2.48**;


How to compile
--------------
* `git clone https://github.com/paolostivanin/GTKCrypto.git`
* `cd GTKCrypto`
* `make`
* `make install`
After you have successfully compiled the software, you will find the `gtkcrypto` binary inside the project's root directory.


Notes
-----
This software is licensed under the GNU General Public License version 3 and above.
