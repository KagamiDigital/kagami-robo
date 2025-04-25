from decrypt import kms_decrypt

def recover():
    """Recover seedphrase using CMK

    KeyId is used to identify the CMKs to use for decryption.
    """
    with open("/app/seed.txt", "rb") as file:
        cyphertext = file.read()
    with open("/app/keyId.txt", "r") as file:
        keyId = file.read()
    with open("/app/keyARN.txt", "r") as file:
        keyARN = file.read()
    seed = kms_decrypt(cyphertext, keyId)
    print("seed =>: ", seed)

    return seed