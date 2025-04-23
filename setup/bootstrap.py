from kms import create_cmk
from mnemonic import Mnemonic
from encrypt import kms_encrypt

keyId, keyARN = create_cmk("robo-enclave-key")

mnemo = Mnemonic("english")
words = mnemo.generate(strength=256)
seed = mnemo.to_seed(words, passphrase="")

cyphertext = kms_encrypt(seed, keyId)

with open("seed.txt", "wb") as file:
    file.write(cyphertext)
with open("keyId.txt", "w") as file:
    file.write(keyId)
with open("keyARN.txt", "w") as file:
    file.write(keyARN)