import os
import boto3

def kms_decrypt(cyphertext, keyId):
    """Decrypt cyphertext using CMK

    KeyId is used to identify the CMKs to use for decryption.
    """
    kms_endpoint = os.environ.get('AWS_KMS_ENDPOINT')
    if kms_endpoint:
        client = boto3.client("kms", endpoint_url=kms_endpoint)
    else:
        client = boto3.client("kms")

    plaintext = client.decrypt(
        KeyId=keyId,
        CiphertextBlob=cyphertext
    )['Plaintext']

    return plaintext