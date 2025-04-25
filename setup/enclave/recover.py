#!/usr/bin/env python3

from recover_seed import recover
from mnemonic import Mnemonic
import binascii

if __name__ == "__main__":
    seed = recover()
    print(seed)