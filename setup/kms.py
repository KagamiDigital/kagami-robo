import boto3
## create KMS key
def create_cmk(description="Enclaver"):
    """Creates a KMS Customer Master Key

    Description is used to differentiate between CMKs.
    """

    kms_client = boto3.client("kms")
    response = kms_client.create_key(Description=description)

    # Return the key ID and ARN
    return response["KeyMetadata"]["KeyId"], response["KeyMetadata"]["Arn"]