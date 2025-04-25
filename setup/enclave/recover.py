#!/usr/bin/env python3

from recover_seed import recover
import base64

if __name__ == "__main__":
    seed = recover()
    seed = base64.b64encode(seed).decode('ascii')
    print(seed)