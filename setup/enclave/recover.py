#!/usr/bin/env python3

import binascii
from recover_seed import recover

if __name__ == "__main__":
    seed = recover()
    seed = binascii.hexlify(seed)

    print(seed)