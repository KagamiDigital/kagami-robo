from decrypt import kms_decrypt

def recover():
    """Recover seedphrase using CMK

    KeyId is used to identify the CMKs to use for decryption.
    """
    with open("/home/ec2-user/kagami-robo/setup/ec2/seed.txt", "rb") as file:
        cyphertext = file.read()
    with open("/home/ec2-user/kagami-robo/setup/ec2/keyId.txt", "r") as file:
        keyId = file.read()

    seed = kms_decrypt(cyphertext, keyId)
    seed = seed.hex()

    with open("/home/ec2-user/kagami-robo/setup/ec2/encrypted_seed.txt", "r") as file:
        encrypted_seed = file.read()
    
    return (seed,encrypted_seed)