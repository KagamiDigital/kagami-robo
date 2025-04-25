#!/usr/bin/env python3

from recover_mnemonic import recover
import binascii

if __name__ == "__main__":
    seed = recover()
    seed = binascii.hexlify(seed)

    print(seed)