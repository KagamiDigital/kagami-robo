import boto3

def kms_encrypt(plaintext, keyId):
    """Encrypt plaintext using CMK
    KeyId is used to identify the CMKs to use for encryption.
    """
    kms_client = boto3.client("kms")
    ciphertext = kms_client.encrypt(
        KeyId=keyId,
        Plaintext=plaintext
    )['CiphertextBlob']
    
    return ciphertext