PolCrypt
========

This software let you to:
* Encrypt and decrypt files using AES256-CBC;
* Calculate (and optionally store) the hash of your files (supported hash are MD5, RMD160, SHA1, SHA256, SHA512 and WHIRLPOOL);

This software is developed by Paolo Stivanin (a.k.a Polslinux)

Security
--------
* Confidentiality is given by AES256-CBC;
* Integrity is given by the MAC calculation (MAC = HMAC+SHA512);
* The input key is derived using PBKDF2 with 150'000 iterations and SHA512 as hash algo;
* High security because your key is temporarly stored into a secure memory that will be destroyed when the program exit;
* The input file will be overwritten prior its removing (secure file deletion);


Mockup
------
![Image Alt](https://raw.github.com/polslinux/PolCrypt/master/docs/polcrypt.png)

Latest release
--------------
The latest (v1.1.0-alpha) release can be found in the 'master' branch, just clone it :)

RoadMap
-------
23/01/2014 - v1.1.0-alpha
- [X] ADDED: RMD160, MD5, SHA-1, SHA256, SHA512, WHIRLPOOL
- [X] ADDED: better error reporting;

Requirements
------------
* GCC or Clang	: required version of Clang **>= 3.1**, of GCC **>= 4.4.0**;
* Gcrypt	: required version **>=1.5.0**;
* GTK+		: required version **>=3.6.0**;

How it works
------------
...


How to use
----------
...



How to install
--------------
...


Extra options
-------------
...


Notes
-----
...
