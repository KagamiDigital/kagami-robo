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

        // Log key creation
        await logToFile({
            event: 'key_created',
            keyId: response.KeyMetadata.KeyId,
            arn: response.KeyMetadata.Arn,
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
        WrappingAlgorithm: 'RSAES_OAEP_SHA_256',
        WrappingKeySpec: 'RSA_2048'
    };

    try {
        const command = new GetParametersForImportCommand(params);
        const response = await kmsClient.send(command);
        return {
            publicKey: response.PublicKey,
            importToken: response.ImportToken
        };
    } catch (error) {
        await logToFile({
            event: 'import_parameters_error',
            keyId,
            error: error.message,
            stack: error.stack
        }, 'error');
        throw error;
    }
}

function wrapKeyMaterial(keyMaterial, publicKey) {
    const padding = crypto.constants.RSA_PKCS1_OAEP_PADDING;
    const oaepHash = 'sha256';

    const pubKeyObject = crypto.createPublicKey({
        key: publicKey,
        format: 'der',
        type: 'spki'
    });

    // Ensure key material is proper length (32 bytes for secp256k1)
    const keyBuffer = Buffer.from(keyMaterial.slice(2), 'hex');

    // Wrap the key material
    const wrappedKey = crypto.publicEncrypt(
        {
            key: pubKeyObject,
            padding: padding,
            oaepHash: oaepHash
        },
        keyBuffer
    );

    // Return base64-encoded wrapped key
    return wrappedKey;
}

async function importKeyToKMS(keyId, wrappedKeyMaterial, importToken) {
    const params = {
        KeyId: keyId,
        ImportToken: importToken,
        WrappingAlgorithm: 'RSAES_OAEP_SHA_256',
        WrappingKeySpec: 'RSA_2048',
        ExpirationModel: 'KEY_MATERIAL_DOES_NOT_EXPIRE',
		EncryptedKeyMaterial: wrappedKeyMaterial  // AWS SDK will handle Buffer automatically
    };

    try {
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
            const wrappedKeyMaterial = wrapKeyMaterial(privateKey, publicKey);

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