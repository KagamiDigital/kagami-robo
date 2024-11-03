const {
    KMSClient,
    ImportKeyMaterialCommand
} = require('@aws-sdk/client-kms');
const fs = require('fs').promises;
const path = require('path');

// AWS configuration
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const kmsClient = new KMSClient({ region: AWS_REGION });

async function importWrappedKey() {
    try {
        const materialDir = path.join(process.cwd(), 'key-material');

        // Read the necessary files
        const keyId = await fs.readFile(
            path.join(materialDir, 'KeyId.txt'),
            'utf8'
        );

        const encryptedKeyMaterial = await fs.readFile(
            path.join(materialDir, 'EncryptedKeyMaterial.bin')
        );

        const importToken = await fs.readFile(
            path.join(materialDir, 'ImportToken.bin')
        );

        // Import the key material
        const importParams = {
            KeyId: keyId,
            ImportToken: importToken,
            EncryptedKeyMaterial: encryptedKeyMaterial,
            ExpirationModel: 'KEY_MATERIAL_DOES_NOT_EXPIRE',
            WrappingAlgorithm: 'RSAES_OAEP_SHA_256',
            WrappingKeySpec: 'RSA_2048'
        };

        const command = new ImportKeyMaterialCommand(importParams);
        await kmsClient.send(command);

        const address = await fs.readFile(
            path.join(materialDir, 'EthereumAddress.txt'),
            'utf8'
        );

        console.log('Successfully imported key material');
        console.log('Key ID:', keyId);
        console.log('Ethereum Address:', address);

    } catch (error) {
        console.error('Error importing key:', error);
        throw error;
    }
}

importWrappedKey();