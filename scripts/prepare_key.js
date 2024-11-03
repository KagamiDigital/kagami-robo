const { ethers } = require('ethers');
const {
    KMSClient,
    CreateKeyCommand,
    GetParametersForImportCommand
} = require('@aws-sdk/client-kms');
const fs = require('fs').promises;
const path = require('path');
const { execSync } = require('child_process');

// AWS configuration
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const kmsClient = new KMSClient({ region: AWS_REGION });

async function prepareKeyFiles() {
    try {
        // Create output directory
        const outputDir = path.join(process.cwd(), 'key-material');
        await fs.mkdir(outputDir, { recursive: true });

        // Generate Ethereum keypair
        const wallet = ethers.Wallet.createRandom();
        const privateKey = Buffer.from(wallet.privateKey.slice(2), 'hex');

        // Create KMS key
        const createKeyParams = {
            Description: 'Imported Ethereum private key',
            KeyUsage: 'SIGN_VERIFY',
            Origin: 'EXTERNAL',
            KeySpec: 'ECC_SECG_P256K1'
        };

        const createCommand = new CreateKeyCommand(createKeyParams);
        const keyResponse = await kmsClient.send(createCommand);
        const keyId = keyResponse.KeyMetadata.KeyId;

        // Get import parameters
        const importParams = {
            KeyId: keyId,
            WrappingAlgorithm: 'RSAES_OAEP_SHA_1',
            WrappingKeySpec: 'RSA_2048'
        };

        const importCommand = new GetParametersForImportCommand(importParams);
        const importResponse = await kmsClient.send(importCommand);

        // Write files
        await fs.writeFile(
            path.join(outputDir, 'PlaintextPrivateKey'),
            wallet.privateKey
        );

        // Write files
        await fs.writeFile(
            path.join(outputDir, 'PlaintextKeyMaterial.bin'),
            privateKey
        );

        await fs.writeFile(
            path.join(outputDir, 'WrappingPublicKey.bin'),
            importResponse.PublicKey
        );

        await fs.writeFile(
            path.join(outputDir, 'ImportToken.bin'),
            importResponse.ImportToken
        );

        // Save key ID for later use
        await fs.writeFile(
            path.join(outputDir, 'KeyId.txt'),
            keyId
        );

        // Save Ethereum address for reference
        await fs.writeFile(
            path.join(outputDir, 'EthereumAddress.txt'),
            wallet.address
        );

        // Execute OpenSSL command
        execSync(`openssl pkeyutl \
            -encrypt \
            -in ${path.join(outputDir, 'PlaintextKeyMaterial.bin')} \
            -out ${path.join(outputDir, 'EncryptedKeyMaterial.bin')} \
            -inkey ${path.join(outputDir, 'WrappingPublicKey.bin')} \
            -keyform DER \
            -pubin \
            -pkeyopt rsa_padding_mode:oaep \
			-pkeyopt rsa_oaep_md:sha1`);
            // -pkeyopt rsa_oaep_md:sha256 \
            // -pkeyopt rsa_mgf1_md:sha256`);

        console.log(`Files created in ${outputDir}:`);
        console.log('- PlaintextKeyMaterial.bin (private key)');
        console.log('- WrappingPublicKey.bin (KMS public key)');
        console.log('- ImportToken.bin (KMS import token)');
        console.log('- EncryptedKeyMaterial.bin (wrapped key)');
        console.log('- KeyId.txt (KMS key ID)');
        console.log('- EthereumAddress.txt (corresponding Ethereum address)');
        console.log('\nKey ID:', keyId);
        console.log('Ethereum Address:', wallet.address);

    } catch (error) {
        console.error('Error:', error);
        throw error;
    }
}

prepareKeyFiles();