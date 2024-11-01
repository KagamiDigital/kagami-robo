const { ethers } = require('ethers');
const {
    KMSClient,
    CreateKeyCommand,
    GetParametersForImportCommand,
    ImportKeyMaterialCommand
} = require('@aws-sdk/client-kms');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

// AWS configuration
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const kmsClient = new KMSClient({ region: AWS_REGION });

// Logging utility
async function logToFile(data, logType = 'key-generation') {
    const timestamp = new Date().toISOString();
    const logDir = path.join(process.cwd(), 'logs');
    const logFile = path.join(logDir, `${logType}-${new Date().toISOString().split('T')[0]}.log`);

    try {
        // Create logs directory if it doesn't exist
        await fs.mkdir(logDir, { recursive: true });

        // Prepare log entry
        const logEntry = {
            timestamp,
            ...data
        };

        // Append to log file
        await fs.appendFile(
            logFile,
            JSON.stringify(logEntry, null, 2) + '\n',
            'utf8'
        );

        console.log(`Logged ${logType} entry to ${logFile}`);
    } catch (error) {
        console.error('Error writing to log file:', error);
        throw error;
    }
}

async function createKMSKeyWithExternalOrigin() {
    const createKeyParams = {
        Description: 'Imported Ethereum private key',
        KeyUsage: 'SIGN_VERIFY',
        Origin: 'EXTERNAL',
        KeySpec: 'ECC_SECG_P256K1',
        BypassPolicyLockoutSafetyCheck: false,
    };

    try {
        const command = new CreateKeyCommand(createKeyParams);
        const response = await kmsClient.send(command);

        // Log full key metadata
        await logToFile({
            event: 'key_created',
            keyId: response.KeyMetadata.KeyId,
            arn: response.KeyMetadata.Arn,
            keySpec: response.KeyMetadata.KeySpec,  // Add this to verify
            creationDate: response.KeyMetadata.CreationDate
        });

        return response.KeyMetadata.KeyId;
    } catch (error) {
        await logToFile({
            event: 'key_creation_error',
            error: error.message,
            stack: error.stack
        }, 'error');
        throw error;
    }
}

async function getImportParameters(keyId) {
    const params = {
        KeyId: keyId,
        WrappingAlgorithm: 'RSAES_OAEP_SHA_1',  // Changed to simpler algorithm
        WrappingKeySpec: 'RSA_2048'
    };

    try {
        const command = new GetParametersForImportCommand(params);
        const response = await kmsClient.send(command);

        await logToFile({
            event: 'import_parameters_received',
            keyId,
            publicKeyLength: response.PublicKey.length,
            importTokenLength: response.ImportToken.length,
            wrappingAlgorithm: 'RSAES_OAEP_SHA_1'
        });

        return {
            publicKey: response.PublicKey,
            importToken: response.ImportToken
        };
    } catch (error) {
        await logToFile({
            event: 'get_parameters_error',
            keyId,
            error: error.message,
            stack: error.stack
        }, 'error');
        throw error;
    }
}

async function wrapKeyMaterial(keyMaterial, publicKey) {
    try {
        // Convert KMS public key from DER format
        const pubKeyObject = crypto.createPublicKey({
            key: publicKey,
            format: 'der',
            type: 'spki'
        });

        // Remove '0x' prefix and convert to Buffer
        const rawPrivateKey = Buffer.from(keyMaterial.slice(2), 'hex');

        // For ECC_SECG_P256K1, we need to ensure the key is exactly 32 bytes
        if (rawPrivateKey.length !== 32) {
            throw new Error(`Invalid private key length: ${rawPrivateKey.length}`);
        }

        // Wrap the key material using OAEP with SHA-1
        const wrappedKey = crypto.publicEncrypt(
            {
                key: pubKeyObject,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha1'  // Changed to sha1 to match KMS algorithm
            },
            rawPrivateKey
        );

        await logToFile({
            event: 'key_wrapped',
            wrappedKeyLength: wrappedKey.length,
            algorithm: 'RSAES_OAEP_SHA_1'
        });

        return wrappedKey;
    } catch (error) {
        await logToFile({
            event: 'key_wrapping_error',
            error: error.message,
            stack: error.stack
        }, 'error');
        throw error;
    }
}


async function importKeyToKMS(keyId, wrappedKeyMaterial, importToken) {
    try {
        await logToFile({
            event: 'import_attempt',
            keyId,
            wrappedKeyLength: wrappedKeyMaterial.length,
            importTokenLength: importToken.length,
            wrappingAlgorithm: 'RSAES_OAEP_SHA_1'
        });

        const params = {
            KeyId: keyId,
            ImportToken: importToken,
            WrappingAlgorithm: 'RSAES_OAEP_SHA_1',
            WrappingKeySpec: 'RSA_2048',
            ExpirationModel: 'KEY_MATERIAL_DOES_NOT_EXPIRE',
            EncryptedKeyMaterial: wrappedKeyMaterial  // Send the buffer directly
        };

        const command = new ImportKeyMaterialCommand(params);
        await kmsClient.send(command);

        await logToFile({
            event: 'key_imported',
            keyId,
            importDate: new Date().toISOString()
        });

        return keyId;
    } catch (error) {
        await logToFile({
            event: 'key_import_error',
            keyId,
            error: error.message,
            stack: error.stack
        }, 'error');
        throw error;
    }
}


async function generateAndImportKeys(numKeys) {
    const results = [];

    for (let i = 0; i < numKeys; i++) {
        try {
            // Generate new Ethereum wallet
            const wallet = ethers.Wallet.createRandom();
            const privateKey = wallet.privateKey;
            const address = wallet.address;

            // Log key generation (without exposing private key)
            await logToFile({
                event: 'key_generation',
                address,
                privateKeyLength: privateKey.length
            });

            // Create KMS key
            const keyId = await createKMSKeyWithExternalOrigin();

            // Get import parameters
            const { publicKey, importToken } = await getImportParameters(keyId);

            // Log wrapping attempt
            await logToFile({
                event: 'wrapping_key',
                keyId,
                publicKeyLength: publicKey.length
            });

            // Wrap the key material
            const wrappedKeyMaterial = await wrapKeyMaterial(privateKey, publicKey);

            // Log wrapped material details (safely)
            await logToFile({
                event: 'wrapped_key',
                keyId,
                wrappedKeyLength: wrappedKeyMaterial.length
            });

            // Import the wrapped key material
            await importKeyToKMS(keyId, wrappedKeyMaterial, importToken);

            const result = {
                index: i + 1,
                ethereumAddress: address,
                kmsKeyId: keyId
            };

            results.push(result);

            await logToFile({
                event: 'keypair_created',
                ...result
            });

            console.log(`Successfully generated and imported key pair ${i + 1}`);
        } catch (error) {
            console.error(`Error processing key pair ${i + 1}:`, error);
            await logToFile({
                event: 'keypair_generation_error',
                index: i + 1,
                error: error.message,
                stack: error.stack
            }, 'error');
        }
    }

    return results;
}

// Command line argument for number of keys or default to 1
const NUM_KEYS_TO_GENERATE = parseInt(process.env.NUM_KEYS_TO_GENERATE || '1', 10);

// Run the script
generateAndImportKeys(NUM_KEYS_TO_GENERATE)
    .then(results => {
        console.log(`\nGenerating ${NUM_KEYS_TO_GENERATE} Key Pairs:`);
        results.forEach(result => {
            console.log(`\nPair ${result.index}:`);
            console.log(`Ethereum Address: ${result.ethereumAddress}`);
            console.log(`AWS KMS Key ID: ${result.kmsKeyId}`);
        });
    })
    .catch(async error => {
        console.error('Script failed:', error);
        await logToFile({
            event: 'script_error',
            error: error.message,
            stack: error.stack
        }, 'error');
        process.exit(1);
    });