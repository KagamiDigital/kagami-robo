import boto3

def kms_decrypt(cyphertext, keyId):
    """Decrypt cyphertext using CMK

    KeyId is used to identify the CMKs to use for decryption.
    """
    client = boto3.client("kms")

    plaintext = client.decrypt(
        KeyId=keyId,
        CiphertextBlob=cyphertext
    )['Plaintext']

    return plaintext