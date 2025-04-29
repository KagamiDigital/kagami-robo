from kms import create_cmk
from mnemonic import Mnemonic
from encrypt import kms_encrypt
from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt
import binascii
import time

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

#public_key = sys.argv[1]
#pubKeyHex = public_key.to_hex()
#encrypted_seed = encrypt(pubKeyHex, plaintext)

#with open("recovery_seed.txt", "wb") as file:
#    file.write(encrypted_seed)

