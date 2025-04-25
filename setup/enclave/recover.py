#!/usr/bin/env python3

from recover_seed import recover

if __name__ == "__main__":
    seed = recover()
    
    # Just print the raw seed value - no labels or formatting
    # If it's bytes, decode to string first
    if isinstance(seed, bytes):
        print(seed.decode('utf-8'))
    else:
        print(seed)