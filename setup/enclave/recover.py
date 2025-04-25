#!/usr/bin/env python3

from recover_seed import recover
from mnemonic import Mnemonic
import binascii

if __name__ == "__main__":
    seed = recover()
    hex_data = binascii.hexlify(binary_data)
    mnemo = Mnemonic("english")
    words = mnemo.to_mnemonic(hex_data) 
    print(words)