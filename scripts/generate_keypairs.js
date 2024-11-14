const { ethers } = require('ethers');
const { spawn } = require('child_process');
const {io} = require('socket.io-client')
const dotenv = require("dotenv")
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
// new_keys || existing_keys
const DEPLOYMENT_TYPE = process.env.DEPLOYMENT_TYPE || "new"
const KEYS_JSON = process.env.KEYS_JSON || null
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const NUM_KEYS_TO_GENERATE = parseInt(process.env.NUM_KEYS_TO_GENERATE || '1', 10);
const LOG_SENSITIVE = process.env.LOG_SENSITIVE === 'true';

// AWS KMS client
const kmsClient = new KMSClient({ region: AWS_REGION });

// Logging utility (only writes non-sensitive data unless LOG_SENSITIVE is true)
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

// Part 1: OpenSSL Utilities (all operations in memory using pipes)
async function runOpenSSLCommand(args, input = null) {
    return new Promise((resolve, reject) => {
        const process = spawn('openssl', args);
        const stdout = [];
        const stderr = [];

        process.stdout.on('data', chunk => stdout.push(chunk));
        process.stderr.on('data', chunk => stderr.push(chunk));

        process.on('close', code => {
            if (code !== 0) {
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

async function createEcKeyFromPrivate(privateKeyHex) {
    // Remove '0x' prefix if present
    const cleanHex = privateKeyHex.replace('0x', '');

    // Create ASN.1 structure for EC private key
    const asn1 = Buffer.concat([
        Buffer.from('302e0201010420', 'hex'), // header
        Buffer.from(cleanHex, 'hex'),         // private key
        Buffer.from('a00706052b8104000a', 'hex') // secp256k1 OID
    ]);

    return asn1
}

async function convertToPkcs8Der(ecKey) {
    // First convert to PEM format
    const pemResult = await runOpenSSLCommand([
        'ec',
        '-inform', 'DER',
        '-outform', 'PEM',
    ], ecKey);

    // Then convert PEM to PKCS8 DER
    return runOpenSSLCommand([
        'pkcs8',
        '-topk8',
        '-nocrypt',
        '-inform', 'PEM',
        '-outform', 'DER'
    ], pemResult);
}

// Encrypt using Node's Crypto Package because
// OpenSSL pkeyutl requires using files,
// and we don't want to store our keys on disk.
function encryptWithKmsPublicKey(ecPrivateKeyDer, wrappingPublicKeyBase64) {
    // Decode KMS public key from base64
    const wrappingPublicKey = Buffer.from(wrappingPublicKeyBase64, 'base64');

    // Create public key object for encryption
    const publicKeyObject = crypto.createPublicKey({
        key: wrappingPublicKey,
        format: 'der',
        type: 'spki'
    });

    // Encrypt the DER-formatted private key using RSA-OAEP with SHA-256
    const encryptedPrivateKey = crypto.publicEncrypt(
        {
            key: publicKeyObject,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        ecPrivateKeyDer  // The DER-formatted EC private key
    );

    return encryptedPrivateKey;
}

// Part 2: KMS Workflows
async function createKmsKey() {
    const command = new CreateKeyCommand({
        Description: 'Imported Ethereum Private Key',
        KeyUsage: 'SIGN_VERIFY',
        Origin: 'EXTERNAL',
        KeySpec: 'ECC_SECG_P256K1'
    });

    const response = await kmsClient.send(command);

    await logOperation({
        event: 'key_created',
        keyId: response.KeyMetadata.KeyId,
        keyArn: response.KeyMetadata.Arn
    });

    return response.KeyMetadata.KeyId;
}

async function getImportParameters(keyId) {
    const command = new GetParametersForImportCommand({
        KeyId: keyId,
        WrappingAlgorithm: 'RSAES_OAEP_SHA_256',
        WrappingKeySpec: 'RSA_2048'
    });

    const response = await kmsClient.send(command);
    await logOperation({
        event: 'import_parameters_received',
        keyId,
        wrappingAlgorithm: 'RSAES_OAEP_SHA_256'
    });

    return {
        publicKey: response.PublicKey,
        importToken: response.ImportToken
    };
}

async function importKeyMaterial(keyId, encryptedKeyMaterial, importToken) {
    const command = new ImportKeyMaterialCommand({
        KeyId: keyId,
        ImportToken: importToken,
        EncryptedKeyMaterial: encryptedKeyMaterial,
        ExpirationModel: 'KEY_MATERIAL_DOES_NOT_EXPIRE'
    });

    await kmsClient.send(command);
    await logOperation({
        event: 'key_imported',
        keyId
    });
}

// Main process
async function processKey(privateKeyHex) {
    try {
        // Create KMS key
        const keyId = await createKmsKey();

        // Get import parameters
        const { publicKey, importToken } = await getImportParameters(keyId);

        // Convert private key format (all in memory)
        const ecKey = await createEcKeyFromPrivate(privateKeyHex);
        const derKey = await convertToPkcs8Der(ecKey);

        // Encrypt with KMS wrapping key
        const encryptedKeyMaterial = encryptWithKmsPublicKey(derKey, publicKey);

        // Import to KMS
        await importKeyMaterial(keyId, encryptedKeyMaterial, importToken);

        return keyId;
    } catch (error) {
        await logOperation({
            event: 'process_error',
            error: error.message
        }, 'error');
        throw error;
    }
}

// Main execution
async function main() {
    try {

        const socket = io(process.env.API_URL + "/robo", {
            query: {
                apiKey: process.env.API_KEY,
            },
            transports: ["websocket"]
        });

        socket.on("error", async (err) => {
            console.log(`Robonet Error :: Connected to API Service...`, err)
            await logOperation({
                event: 'robonet_error',
                error: err,
            })
        });

        socket.on("connect_error", async (err) => {
            console.log(`Robonet Connect Error :: Connected to API Service...`, err)
            await logOperation({
                event: 'robonet_connect_error',
                error: err,
            })
        });

        socket.on("connect", async () => {
            console.log(`Robonet :: Connected to API Service...`)
            await logOperation({
                event: 'robonet_connected_to_api',
            })

        })

        socket.on("confirmed_robos_initialized", async () => {

            console.log(`Robonet :: Robos already initialized`)
            await logOperation({
                event: 'robonet_already_initialized',
            })

            process.exit(0);
        })

        // API did not find any existing roboSigners,
        // so it will request the signers information from the Robo
        socket.on("request_initialize_robos", async () => {
            console.log("Received request from API to initialize robos")

            const results = [];
            const keyIds = [];
            const privateKeys = []


            // Should we generate new keys, or are we deploying this robo with existing keys?
            if ("import" === DEPLOYMENT_TYPE) {

                if (!KEYS_JSON) {
                    console.error("KEYS_JSON required for public / private key pairs")
                    process.exit(1)
                }

                const keysJson = JSON.parse(KEYS_JSON)

                const publicKeys = []
                const privateKeys = []

                for (const publicKey in keysJson) {
                    const privateKey = keysJson[publicKey]

                    publicKeys.push(publicKey)
                    privateKeys.push(privateKey)

                    socket.emit('robonet_wallet_created', {
                        publicKey: publicKey,
                        seedPhrase: "",
                        source: "imported",
                    })
                }

                const fs = require('fs');
                const publicKeysString = `\nPUBLIC_KEYS="${publicKeys.join(',')}"`
                const privateKeysString = `\nKEYS="${privateKeys.join(',')}"`

                const timestamp = new Date().toISOString();
                fs.appendFileSync('.env', "\n\n");
                fs.appendFileSync('.env', "# ===== START ===== #\n");
                fs.appendFileSync('.env', `# Keys IMPORTED at ${timestamp}`);
                fs.appendFileSync('.env', publicKeysString);
                fs.appendFileSync('.env', privateKeysString);
                fs.appendFileSync('.env', "\n");
                fs.appendFileSync('.env', "# ===== END ===== #");

            } else if ("new" === DEPLOYMENT_TYPE) {

                await logOperation({
                    event: "new_key_deployment",
                    num_of_keys: NUM_KEYS_TO_GENERATE,
                })

                for (let i = 0; i < NUM_KEYS_TO_GENERATE; i++) {

                    const wallet = await ethers.Wallet.fromMnemonic( ethers.utils.entropyToMnemonic(ethers.utils.randomBytes(32)) )
                    console.log("Wallet created :: ", wallet.address)

                    socket.emit('robonet_wallet_created', {
                        publicKey: wallet.address,
                        seedPhrase: wallet.mnemonic.phrase,
                        source: "created",
                    })

                    await logOperation({
                        event: 'mnemonic_phrase',
                        seedPhrase: wallet.mnemonic.phrase,
                    })

                    // import keys to AWS KMS
                    // const keyId = await processKey(wallet.privateKey);
                    // keyIds.push(keyId);

                    privateKeys.push(wallet.privateKey)

                    results.push({
                        // keyId,
                        ethereumAddress: wallet.address
                    });

                    await logOperation({
                        event: 'key_processed',
                        // keyId,
                        ethereumAddress: wallet.address
                    });
                }

                console.log('Processed Keys:', results);

                // Append keyIds to .env file
                const fs = require('fs');
                const keyIdsString = `\nKMS_KEY_IDS="${keyIds.join(',')}"`
                const publicKeysString = `\nPUBLIC_KEYS="${results.map(r => r.ethereumAddress).join(',')}"`
                const privateKeysString = `\nKEYS="${privateKeys.join(',')}"`

                let importKeys = {}

                for (let i = 0; i < results.length; i++) {
                    const publicKey = results[i]
                    const privateKey = privateKeys[i]

                    importKeys[publicKey] = privateKey
                }

                const importString = JSON.stringify(importKeys)

                fs.appendFileSync('.env', keyIdsString);
                const timestamp = new Date().toISOString();
                fs.appendFileSync('.env', "\n\n");
                fs.appendFileSync('.env', "# ===== START ===== #\n");
                fs.appendFileSync('.env', `# Keys GENERATED at ${timestamp}`);
                fs.appendFileSync('.env', publicKeysString);
                fs.appendFileSync('.env', privateKeysString);
                fs.appendFileSync('.env', `${importString}`);
                fs.appendFileSync('.env', "\n");
                fs.appendFileSync('.env', "# ===== END ===== #");

                console.log('Added key IDs to .env file');

                await logOperation({
                    event: 'env_updated',
                    message: "keys written to .env file"
                });
            }

            process.exit(0);
        })

    } catch (error) {
        console.error('Main process error:', error);
        process.exit(1);
    }
}

main();
