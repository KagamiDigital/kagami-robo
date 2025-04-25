from decrypt import kms_decrypt
from mnemonic import Mnemonic

def recover():
    """Recover seedphrase using CMK

    KeyId is used to identify the CMKs to use for decryption.
    """
    with open("/app/seed.txt", "rb") as file:
        cyphertext = file.read()
    with open("/app/keyId.txt", "r") as file:
        keyId = file.read()
    seed = kms_decrypt(cyphertext, keyId)

    mnemo = Mnemonic("english")
    words = mnemo.to_mnemonic(seed)

    return words