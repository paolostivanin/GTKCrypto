#!/bin/bash

echo "--> Checking compiler..."
gcc_ver=$(gcc --version | grep ^gcc | sed 's/^.* //g' | cut -f1,2 -d'.')
is_clang=$(which clang &>/dev/null&& echo $?)
[[ $is_clang != 0 ]] && echo "--> Using GCC to compile..." || echo "Using Clang to compile..."
[[ $is_clang == 0 ]] && clang_ver=$(clang --version | grep ^clang | cut -f3 -d' ')
echo "--> Cheking deps..."
is_mud=$(find /usr/lib/ -iname *mudflap* &>/dev/null && echo $?)
is_mud2=$(find /lib/ -iname *mudflap* &>/dev/null && echo $?)
is_gcry=$(find /usr/lib/ -name libgcrypt.so &>/dev/null && echo $?)
is_gcry2=$(find /lib/ -name libgcrypt.so &>/dev/null && echo $?)
is_crypto=$(find /usr/lib/ -name libcrypto.so &>/dev/null && echo $?)
is_crypto2=$(find /lib/ -name libcrypto.so &>/dev/null && echo $?)

[[ $is_mud != 0 && $is_mud2 != 0 ]] && echo "libmudflap is missing (libmudflap0-$gcc_ver-dev under Ubuntu/Mint/Debian; gcc-libs under Archlinux)" || echo "libmudflap OK"
[[ $is_gcry != 0 && $is_gcry2 != 0 ]] && echo "libgcrypt is missing (libgcrypt11-dev under Ubuntu >= 11.10, Linux Mint >= 12 and Debian >= testing; libgcrypt under Archlinux)" || echo "libgcrypt OK"
[[ $is_crypto != 0 && $is_crypto2 != 0 ]] && echo "libcrypto is missing (libssl-dev under Ubuntu/Mint/Debian; openssl under Archlinux)" || echo "libcrypto OK"

[[ $is_clang == 0 ]] && export CC=clang || export CC=gcc
make
