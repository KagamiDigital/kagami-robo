from mnemonic import Mnemonic
from ecies import encrypt
import sys

mnemo = Mnemonic("english")
words = mnemo.generate(strength=256)
seed = mnemo.to_seed(words, passphrase="")

with open("seed.txt", "w") as file:
    file.write(seed.hex())

pubKeyHex = sys.argv[1]

encryptedSeed = encrypt(pubKeyHex, seed)

with open("encrypted_seed.txt", "w") as file:
    file.write(encryptedSeed.hex())
