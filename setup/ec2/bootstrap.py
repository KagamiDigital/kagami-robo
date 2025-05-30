from kms import create_cmk
from mnemonic import Mnemonic
from encrypt import kms_encrypt
from ecies import encrypt
import time
import sys

keyId, keyARN = create_cmk("robo-enclave-key")

with open("keyId.txt", "w") as file:
    file.write(keyId)
with open("keyARN.txt", "w") as file:
    file.write(keyARN)

time.sleep(10)

mnemo = Mnemonic("english")
words = mnemo.generate(strength=256)
seed = mnemo.to_seed(words, passphrase="")

cyphertext = kms_encrypt(seed, keyId)

with open("seed.txt", "wb") as file:
    file.write(cyphertext)

pubKeyHex = sys.argv[1]

encryptedSeed = encrypt(pubKeyHex, seed)

with open("encrypted_seed.txt", "w") as file:
    file.write(encryptedSeed)
