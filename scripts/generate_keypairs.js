const { ethers } = require('ethers');
const { spawn, execSync } = require('child_process');
const {io} = require('socket.io-client');
const dotenv = require("dotenv");
dotenv.config();

const {
    KMSClient,
    CreateKeyCommand,
    GetParametersForImportCommand,
    ImportKeyMaterialCommand
} = require('@aws-sdk/client-kms');

const path = require('path');
const crypto = require('crypto');
const fs = require('fs').promises;

// Environment configuration
const DEPLOYMENT_TYPE = process.env.DEPLOYMENT_TYPE || "new";
const KEYS_JSON = process.env.KEYS_JSON || null;
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const NUM_KEYS_TO_GENERATE = parseInt(process.env.NUM_KEYS_TO_GENERATE || '1', 10);
const LOG_SENSITIVE = process.env.LOG_SENSITIVE === 'true';

// AWS KMS client
const kmsClient = new KMSClient({ region: AWS_REGION });

// Logging utility
async function logOperation(data, logType = 'operation') {
    if (!LOG_SENSITIVE) {
        delete data.privateKey;
        delete data.publicKey;
        delete data.wrappedKey;
        delete data.importToken;
    }

    const timestamp = new Date().toISOString();
    const logDir = path.join(process.cwd(), 'logs');
    const logFile = path.join(logDir, `${logType}-${new Date().toISOString().split('T')[0]}.log`);

    try {
        await fs.mkdir(logDir, { recursive: true });
        await fs.appendFile(
            logFile,
            JSON.stringify({ timestamp, ...data }, null, 2) + '\n',
            'utf8'
        );
    } catch (error) {
        console.error('Logging error:', error);
    }
}

// OpenSSL Utilities
async function runOpenSSLCommand(args, input = null) {
    console.log('Running OpenSSL command:', args.join(' '));
    return new Promise((resolve, reject) => {
        const process = spawn('openssl', args);
        const stdout = [];
        const stderr = [];

        process.stdout.on('data', chunk => stdout.push(chunk));
        process.stderr.on('data', chunk => stderr.push(chunk));

        process.on('close', code => {
            if (code !== 0) {
                console.error('OpenSSL error:', Buffer.concat(stderr).toString());
                reject(new Error(`OpenSSL failed with code ${code}: ${Buffer.concat(stderr)}`));
                return;
            }
            resolve(Buffer.concat(stdout));
        });

        if (input) {
            process.stdin.write(input);
            process.stdin.end();
        }
    });
}

async function verifyRsaKey(keyFile) {
    console.log('Verifying RSA key properties...');
    try {
        const keyInfo = await runOpenSSLCommand([
            'rsa',
            '-in', keyFile,
            '-text',
            '-noout'
        ]);
        console.log('RSA Key Info:', keyInfo.toString());
        return true;
    } catch (error) {
        console.error('Key verification failed:', error);
        return false;
    }
}

async function generateRsaFromEthKey(ethereumPrivateKey, workDir) {
    console.log('Generating RSA key from Ethereum private key...');
    const cleanKey = ethereumPrivateKey.replace('0x', '');
    const seedFile = path.join(workDir, 'seed.bin');
    const configFile = path.join(workDir, 'openssl.cnf');
    const keyFile = path.join(workDir, 'key.pem');

    try {
        // Write seed file from Ethereum private key
        await fs.writeFile(seedFile, Buffer.from(cleanKey, 'hex'));
        console.log('Created seed file');

        // OpenSSL config for deterministic key generation
        const configContent = `
openssl_conf = openssl_def
[openssl_def]
[default_sect]
[provider_sect]
default = default_sect
[drbg_sect]
digest = SHA256
type = CTR
seed = FILE:${seedFile}
        `.trim();

        await fs.writeFile(configFile, configContent);
        process.env.OPENSSL_CONF = configFile;
        console.log('Created OpenSSL config');

        // Generate RSA key for RSASSA_PKCS1_V1_5 signing
        await runOpenSSLCommand([
            'genpkey',
            '-algorithm', 'RSA',
            '-pkeyopt', 'rsa_keygen_bits:2048',
            '-pkeyopt', 'rsa_keygen_pubexp:65537',
            '-outform', 'PEM',
            '-out', keyFile
        ]);
        console.log('Generated RSA key');

        // Verify the key is suitable for signing
        const isValid = await verifyRsaKey(keyFile);
        if (!isValid) {
            throw new Error('Generated key verification failed');
        }

        // Convert to PKCS8 DER format
        const derKey = await runOpenSSLCommand([
            'pkcs8',
            '-topk8',
            '-nocrypt',
            '-in', keyFile,
            '-outform', 'DER'
        ]);
        console.log('Converted key to PKCS8 DER format, size:', derKey.length);

        return derKey;
    } finally {
        // Cleanup
        const files = [seedFile, configFile, keyFile];
        for (const file of files) {
            try {
                await fs.unlink(file);
            } catch (err) {
                console.error(`Failed to delete ${file}:`, err);
            }
        }
        console.log('Cleaned up temporary files');
    }
}

// KMS Workflows
async function createKmsKey() {
    console.log('Creating KMS key...');
    const command = new CreateKeyCommand({
        Description: 'RSA Key for RSASSA_PKCS1_V1_5 Signing',
        KeyUsage: 'SIGN_VERIFY',
        Origin: 'EXTERNAL',
        KeySpec: 'RSA_2048',
    });

    try {
        const response = await kmsClient.send(command);
        console.log('KMS key created:', {
            KeyId: response.KeyMetadata.KeyId,
            Arn: response.KeyMetadata.Arn,
            Description: response.KeyMetadata.Description,
            KeyUsage: response.KeyMetadata.KeyUsage,
            KeyState: response.KeyMetadata.KeyState
        });

        await logOperation({
            event: 'key_created',
            keyId: response.KeyMetadata.KeyId,
            keyArn: response.KeyMetadata.Arn
        });

        return response.KeyMetadata.KeyId;
    } catch (error) {
        console.error('Failed to create KMS key:', error);
        throw error;
    }
}

async function getImportParameters(keyId) {
    console.log('Getting import parameters for key:', keyId);
    const command = new GetParametersForImportCommand({
        KeyId: keyId,
        WrappingAlgorithm: 'RSAES_OAEP_SHA_256',
        WrappingKeySpec: 'RSA_2048'
    });

    try {
        const response = await kmsClient.send(command);
        console.log('Got import parameters:', {
            keyId,
            wrappingAlgorithm: 'RSAES_OAEP_SHA_256',
            publicKeySize: response.PublicKey?.length || 0,
            importTokenSize: response.ImportToken?.length || 0
        });

        await logOperation({
            event: 'import_parameters_received',
            keyId,
            wrappingAlgorithm: 'RSAES_OAEP_SHA_256'
        });

        return {
            publicKey: response.PublicKey,
            importToken: response.ImportToken
        };
    } catch (error) {
        console.error('Failed to get import parameters:', error);
        throw error;
    }
}

function encryptWithKmsPublicKey(keyMaterial, wrappingPublicKeyBase64) {
    console.log('Encrypting key material...');
    console.log('Key material size:', keyMaterial.length);

    // Decode KMS public key from base64
    const wrappingPublicKey = Buffer.from(wrappingPublicKeyBase64, 'base64');
    console.log('Wrapping key size:', wrappingPublicKey.length);

    try {
        // Create public key object for encryption
        const publicKeyObject = crypto.createPublicKey({
            key: wrappingPublicKey,
            format: 'der',
            type: 'spki'
        });

        // Maximum size for RSA-2048 with OAEP SHA-256 is 190 bytes
        if (keyMaterial.length > 190) {
            console.error('Key material too large:', keyMaterial.length, 'bytes (max 190)');
            throw new Error('Key material too large for RSA-2048 OAEP');
        }

        // Encrypt with RSAES_OAEP_SHA_256
        const encryptedKeyMaterial = crypto.publicEncrypt(
            {
                key: publicKeyObject,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            keyMaterial
        );

        console.log('Encrypted key material size:', encryptedKeyMaterial.length);
        return encryptedKeyMaterial;
    } catch (error) {
        console.error('Encryption failed:', error);
        throw error;
    }
}

async function importKeyMaterial(keyId, encryptedKeyMaterial, importToken) {
    console.log('Importing key material for:', keyId);
    console.log('Encrypted material size:', encryptedKeyMaterial.length);
    console.log('Import token size:', importToken.length);

    const command = new ImportKeyMaterialCommand({
        KeyId: keyId,
        ImportToken: importToken,
        EncryptedKeyMaterial: encryptedKeyMaterial,
        ExpirationModel: 'KEY_MATERIAL_DOES_NOT_EXPIRE'
    });

    try {
        await kmsClient.send(command);
        console.log('Successfully imported key material');

        await logOperation({
            event: 'key_imported',
            keyId
        });
    } catch (error) {
        console.error('Failed to import key material:', error);
        await logOperation({
            event: 'import_failed',
            keyId,
            error: error.message
        });
        throw error;
    }
}

async function processKey(privateKeyHex) {
    console.log('Processing key...');

    try {
        // Create KMS key
        const keyId = await createKmsKey();
        console.log('Created KMS key:', keyId);

        // Get import parameters
        const { publicKey, importToken } = await getImportParameters(keyId);
        console.log('Got import parameters');

        // Generate RSA key using ramdisk
        const rsaKeyDer = await generateRsaFromEthKey(privateKeyHex, '/mnt/ram');
        console.log('Generated RSA key');

        // Encrypt with KMS wrapping key
        const encryptedKeyMaterial = encryptWithKmsPublicKey(rsaKeyDer, publicKey);
        console.log('Encrypted key material');

        // Import to KMS
        await importKeyMaterial(keyId, encryptedKeyMaterial, importToken);
        console.log('Imported key material');

        return keyId;
    } catch (error) {
        console.error('Error processing key:', error);
        throw error;
    }
}


// Main execution
async function main() {
    try {
        console.log('Starting key import process...');
        console.log('Deployment type:', DEPLOYMENT_TYPE);

        const socket = io(process.env.API_URL + "/robo", {
            query: {
                apiKey: process.env.API_KEY,
            },
            transports: ["websocket"]
        });

        socket.on("error", async (err) => {
            console.error('Robonet Error:', err);
            await logOperation({
                event: 'robonet_error',
                error: err,
            });
        });

        socket.on("connect_error", async (err) => {
            console.error('Robonet Connect Error:', err);
            await logOperation({
                event: 'robonet_connect_error',
                error: err,
            });
        });

        socket.on("connect", async () => {
            console.log('Robonet: Connected to API Service');
            await logOperation({
                event: 'robonet_connected_to_api',
            });
        });

        socket.on("confirmed_robos_initialized", async () => {
            console.log('Robonet: Robos already initialized');
            await logOperation({
                event: 'robonet_already_initialized',
            });
            process.exit(0);
        });

        // API did not find any existing roboSigners,
        // so it will request the signers information from the Robo
        socket.on("request_initialize_robos", async () => {
            console.log("Received request from API to initialize robos");

            const results = [];
            const keyIds = [];
            const privateKeys = [];

            try {
                // Should we generate new keys, or are we deploying this robo with existing keys?
                if ("import" === DEPLOYMENT_TYPE) {
                    console.log('Processing import deployment');
                    if (!KEYS_JSON) {
                        throw new Error("KEYS_JSON required for public / private key pairs");
                    }

                    const keysJson = JSON.parse(KEYS_JSON);
                    const publicKeys = [];
                    const privateKeys = [];

                    for (const publicKey in keysJson) {
                        const privateKey = keysJson[publicKey];
                        console.log('Processing key pair:', { publicKey });

                        publicKeys.push(publicKey);
                        privateKeys.push(privateKey);

                        socket.emit('robonet_wallet_created', {
                            publicKey: publicKey,
                            seedPhrase: "",
                            source: "imported",
                        });
                    }

                    await appendToEnvFile(publicKeys, privateKeys, keyIds, "IMPORTED");

                } else if ("new" === DEPLOYMENT_TYPE) {
                    console.log('Processing new key deployment');
                    await logOperation({
                        event: "new_key_deployment",
                        num_of_keys: NUM_KEYS_TO_GENERATE,
                    });

                    for (let i = 0; i < NUM_KEYS_TO_GENERATE; i++) {
                        console.log(`Generating key ${i + 1} of ${NUM_KEYS_TO_GENERATE}`);

                        const wallet = await ethers.Wallet.fromMnemonic(
                            ethers.utils.entropyToMnemonic(ethers.utils.randomBytes(32))
                        );
                        console.log("Wallet created:", wallet.address);

                        socket.emit('robonet_wallet_created', {
                            publicKey: wallet.address,
                            seedPhrase: wallet.mnemonic.phrase,
                            source: "created",
                        });

                        await logOperation({
                            event: 'mnemonic_phrase',
                            seedPhrase: wallet.mnemonic.phrase,
                        });

                        // Import keys to AWS KMS
                        const keyId = await processKey(wallet.privateKey);
                        keyIds.push(keyId);
                        privateKeys.push(wallet.privateKey);

                        results.push({
                            keyId,
                            ethereumAddress: wallet.address
                        });

                        await logOperation({
                            event: 'key_processed',
                            keyId,
                            ethereumAddress: wallet.address
                        });
                    }

                    console.log('Processed Keys:', results);
                    await appendToEnvFile(
                        results.map(r => r.ethereumAddress),
                        privateKeys,
                        keyIds,
                        "GENERATED"
                    );
                }

                console.log('Successfully completed key processing');
                process.exit(0);

            } catch (error) {
                console.error('Error in request_initialize_robos:', error);
                await logOperation({
                    event: 'initialization_error',
                    error: error.message
                });
                process.exit(1);
            }
        });

    } catch (error) {
        console.error('Fatal error in main:', error);
        process.exit(1);
    }
}

async function appendToEnvFile(publicKeys, privateKeys, keyIds, operation) {
    console.log('Updating .env file...');

    const envContent = [
        "\n\n# ===== START ===== #",
        `# Keys ${operation} at ${new Date().toISOString()}`,
        `PUBLIC_KEYS="${publicKeys.join(',')}"`,
        `KEYS="${privateKeys.join(',')}"`,
    ];

    if (operation === "GENERATED") {
        const importKeys = {};
        for (let i = 0; i < publicKeys.length; i++) {
            importKeys[publicKeys[i]] = privateKeys[i];
        }
        envContent.push(`IMPORT_KEYS=\`${JSON.stringify(importKeys)}\``);
    }

    if (keyIds.length > 0) {
        envContent.push(`KMS_KEY_IDS="${keyIds.join(',')}"`);
    }

    envContent.push("# ===== END ===== #\n");

    await fs.appendFile('.env', envContent.join('\n'));
    console.log('Updated .env file');
}

// Start the process
main().catch(error => {
    console.error('Unhandled error:', error);
    process.exit(1);
});
