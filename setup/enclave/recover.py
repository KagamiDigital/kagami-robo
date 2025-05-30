#!/usr/bin/env python3

from recover_seed import recover

if __name__ == "__main__":
    seed_tuple = recover()
    seed = seed_tuple[0]
    encrypted_seed = seed_tuple[1]

    print(seed + ',' + encrypted_seed)