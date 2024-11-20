const { ethers } = require("ethers");
const { spawn } = require("child_process");
const { io } = require("socket.io-client");
const dotenv = require("dotenv");
dotenv.config();
const {
    KMSClient,
    CreateKeyCommand,
    GetParametersForImportCommand,
    ImportKeyMaterialCommand,
} = require("@aws-sdk/client-kms");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs").promises;

// Environment configuration
// new_keys || existing_keys
const DEPLOYMENT_TYPE = process.env.DEPLOYMENT_TYPE || "new";
const IMPORT_KEYS = process.env.IMPORT_KEYS || null;
const AWS_REGION = process.env.AWS_REGION || "us-east-1";
const NUM_KEYS_TO_GENERATE = parseInt(
    process.env.NUM_KEYS_TO_GENERATE || "1",
    10,
);
const LOG_SENSITIVE = process.env.LOG_SENSITIVE === "true";

// AWS KMS client
const kmsClient = new KMSClient({ region: AWS_REGION });

// Logging utility (only writes non-sensitive data unless LOG_SENSITIVE is true)
async function logOperation(data, logType = "operation") {
    if (!LOG_SENSITIVE) {
        delete data.privateKey;
        delete data.publicKey;
        delete data.wrappedKey;
        delete data.importToken;
    }

    const timestamp = new Date().toISOString();
    const logDir = path.join(process.cwd(), "logs");
    const logFile = path.join(
        logDir,
        `${logType}-${new Date().toISOString().split("T")[0]}.log`,
    );

    try {
        await fs.mkdir(logDir, { recursive: true });
        await fs.appendFile(
            logFile,
            JSON.stringify({ timestamp, ...data }, null, 2) + "\n",
            "utf8",
        );
    } catch (error) {
        console.error("Logging error:", error);
    }
}

function encryptWithKmsPublicKey(ecPrivateKeyDer, wrappingPublicKeyBin_AWS) {
    // Step 1: Generate a secure AES key and wrap our private key
    const AES_WrappingKey = crypto.randomBytes(32);
    let wrappedPrivateKey;
    {
        // iv = required initialization vector -
        // https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-encrypt-key-material.html
        const iv = Buffer.from("A65959A6", "hex");
        const cipher = crypto.createCipheriv(
            "id-aes256-wrap-pad",
            AES_WrappingKey,
            iv,
        );
        wrappedPrivateKey = cipher.update(ecPrivateKeyDer);
    }

    // Step 2: Encrypte our AES_WrappingKey with the wrappingPublicKeyBin_AWS
    // the public key returned by AWS in binary format
    let wrappedAESKey;
    {
        const encryptor = crypto.createPublicKey({
            key: wrappingPublicKeyBin_AWS,
            format: "der",
            type: "spki",
        });

        wrappedAESKey = crypto.publicEncrypt(
            {
                key: encryptor,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            AES_WrappingKey,
        );
    }

    return Buffer.concat([wrappedAESKey, wrappedPrivateKey]);
}

// Part 2: KMS Workflows
async function createKmsKey() {
    const command = new CreateKeyCommand({
        Description: "Imported Ethereum Private Key",
        KeyUsage: "SIGN_VERIFY",
        Origin: "EXTERNAL",
        KeySpec: "RSA_2048",
        // KeySpec: 'ECC_SECG_P256K1'
    });

    const response = await kmsClient.send(command);

    await logOperation({
        event: "key_created",
        keyId: response.KeyMetadata.KeyId,
        keyArn: response.KeyMetadata.Arn,
    });

    return response.KeyMetadata.KeyId;
}

async function getImportParameters(keyId) {
    const wrappingAlgorithm = "RSA_AES_KEY_WRAP_SHA_256";
    const command = new GetParametersForImportCommand({
        KeyId: keyId,
        WrappingAlgorithm: wrappingAlgorithm,
        WrappingKeySpec: "RSA_4096",
    });

    // According to the docs, the publicKey and importToken
    // should be Base64, but the SDK appears to convert them
    // automatically to Uint8Arrays for the binary data.
    // The data appears to be DER-encoded
    const response = await kmsClient.send(command);
    await logOperation({
        event: "import_parameters_received",
        keyId,
        wrappingAlgorithm,
    });

    return {
        publicKeyDer: response.PublicKey,
        importTokenDer: response.ImportToken,
    };
}

async function importKeyMaterial( keyId, encryptedKeyMaterialBin, importTokenBin) {
    const command = new ImportKeyMaterialCommand({
        KeyId: keyId,
        ImportToken: importTokenBin,
        EncryptedKeyMaterial: encryptedKeyMaterialBin,
        ExpirationModel: "KEY_MATERIAL_DOES_NOT_EXPIRE",
    });

    await kmsClient.send(command);
    await logOperation({
        event: "key_imported",
        keyId,
    });
}

// returns a DER-formatted Private Key, and a PEM-formatted Public Key
function generateRSAKeyPair(keySize = 2048) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
        modulusLength: keySize, // 2048, 3072, or 4096
        publicKeyEncoding: {
            type: "spki",
            format: "pem",
        },
        privateKeyEncoding: {
            type: "pkcs8", // KMS expects PKCS#8 format
            format: "der",
            cipher: undefined, // No encryption for the private key
            passphrase: undefined,
        },
    });

    return { privateKey, publicKey };
}

// Step 2: Deterministically generate an RSA key pair
async function generateDeterministicRSAKeyPair(privateKeyDer, bits = 2048) {
    await logOperation({
        event: "process_key:generateDeterministicRSAKeyPair:start",
        privateKeyDer,
        size: bits,
        description:
            "Begin to deterministically generate an RSA key pair using our private key as a seed",
    });

    // Test with a non-deterministic keypair
    return crypto.generateKeyPair(
        "rsa",
        {
            modulusLength: bits, // Key size in bits
            publicKeyEncoding: {
                type: "spki", // Recommended for public key
                format: "pem", // Output format (PEM or DER)
            },
            privateKeyEncoding: {
                type: "pkcs8", // Recommended for private key
                format: "der", // Output format (PEM or DER)
                cipher: undefined, // Optional: Encrypt private key
                passphrase: undefined, // Required if cipher is used
            },
        },
        (err, publicKey, privateKey) => {
            if (err) {
                console.error("Error generating key pair:", err);
            } else {
                console.log("Public Key:", publicKey);
                console.log("Private Key:", privateKey);
            }
        },
    );



    // TODO WIP: deterministic generation

    // Step 1: Derive a deterministic seed using PBKDF2 with a derived salt
    const salt = crypto.createHash("sha256").update(ecPrivateKey).digest(); // Deterministic salt
    const seed = crypto.pbkdf2Sync(
        Buffer.from(ecPrivateKey.replace("0x", ""), "hex"), // Remove '0x' prefix
        salt,
        100000, // Iterations
        32, // 256-bit seed
        "sha256",
    );

    const keyPair = crypto.generateKeyPairSync("rsa", {
        modulusLength: bits, // Key size (e.g., 2048 bits)
        publicExponent: 0x10001, // Common exponent (65537)
        publicKeyEncoding: {
            type: "spki",
            format: "pem",
        },
        privateKeyEncoding: {
            type: "pkcs8", // PKCS #8 format required for AWS KMS
            format: "der",
            cipher: undefined,
            passphrase: undefined,
        },
        randomBytes: (size) => {
            // Create a deterministic stream of random bytes using the seed
            const hmac = crypto.createHmac("sha256", seed);
            let randomStream = Buffer.alloc(0);
            while (randomStream.length < size) {
                hmac.update(randomStream);
                randomStream = Buffer.concat([randomStream, hmac.digest()]);
            }
            return randomStream.slice(0, size);
        },
    });

    return keyPair;
}

// Main process
async function processKey(privateKeyHex) {
    try {
        await logOperation({
            event: "process_key_start",
            privateKey: privateKeyHex,
        });

        // Create KMS key
        const keyId = await createKmsKey();
        await logOperation({
            event: "process_key:createKmsKey",
            keyId,
        });

        // Get import parameters
        // TODO: do these have to be in .bin format for transport?
        const { publicKeyDer, importTokenDer } = await getImportParameters(keyId);

        await logOperation({
            event: "process_key:getImportParameters",
            publicKeyDer,
            importTokenDer,
            description: "Received DER-formatted PublicKey and ImportToken from AWS.",
        });

        // Convert private key format (all in memory)
        const rsaKeypair = await generateDeterministicRSAKeyPair(privateKeyHex);
        //const rsaKeypair = generateRSAKeyPair()
        const privateKeyDer = rsaKeypair.privateKey;

        await logOperation({
            event: "process_key:generateDeterministicRSAKeyPair:done",
            privateKeyHex,
            privateKeyDer: privateKeyDer.toString('base64')
            description: "Done generating an RSA keypair. We ignore the public key because KMS doesn't need it.",
        });

        // Encrypt with KMS wrapping key
        const encryptedKeyMaterial = encryptWithKmsPublicKey(
            privateKeyDer,
            publicKeyDer,
        );

        // Import to KMS
        await importKeyMaterial(keyId, encryptedKeyMaterial, importTokenDer);

        return keyId;
    } catch (error) {
        await logOperation(
            {
                event: "process_error",
                error: error.message,
            },
            "error",
        );
        throw error;
    }
}

async function main() {
    try {
        const socket = io(process.env.API_URL + "/robo", {
            query: {
                apiKey: process.env.API_KEY,
            },
            transports: ["websocket"],
        });

        socket.on("error", async (err) => {
            console.log(`Robonet Error :: Connected to API Service...`, err);
            await logOperation({
                event: "robonet_error",
                error: err,
            });
        });

        socket.on("connect_error", async (err) => {
            console.log(
                `Robonet Connect Error :: Connected to API Service...`,
                err,
            );
            await logOperation({
                event: "robonet_connect_error",
                error: err,
            });
        });

        socket.on("connect", async () => {
            console.log(`Robonet :: Connected to API Service...`);
            await logOperation({
                event: "robonet_connected_to_api",
            });
        });

        socket.on("confirmed_robos_initialized", async () => {
            console.log(`Robonet :: Robos already initialized`);
            await logOperation({
                event: "robonet_already_initialized",
            });

            process.exit(0);
        });

        // API did not find any existing roboSigners,
        // so it will request the signers information from the Robo
        socket.on("request_initialize_robos", async () => {
            console.log("Received request from API to initialize robos");

            // Should we generate new keys, or are we deploying this robo with existing keys?
            if ("import" === DEPLOYMENT_TYPE) {
                if (!IMPORT_KEYS) {
                    console.error(
                        "IMPORT_KEYS required for public / private key pairs",
                    );
                    process.exit(1);
                }

                const keysObj = JSON.parse(IMPORT_KEYS);

                const publicKeys = [];
                const privateKeys = [];
                const keyIds = [];
                const results = [];

                for (const publicKey in keysObj) {
                    const privateKey = keysObj[publicKey];

                    const keyId = await processKey(privateKey);
                    keyIds.push(keyId);

                    publicKeys.push(publicKey);
                    privateKeys.push(privateKey);
                    results.push({
                        keyId,
                        ethereumAddress: publicKey,
                    });

                    socket.emit("robonet_wallet_imported", {
                        publicKey: publicKey,
                        seedPhrase: "",
                        source: "imported",
                    });

                    await logOperation({
                        event: "key_processed",
                        keyId,
                        ethereumAddress: publicKey,
                    });
                }

                const fs = require("fs");
                const keyIdsString = `\nKMS_KEY_IDS="${keyIds.join(",")}"`;
                const publicKeysString = `\nPUBLIC_KEYS="${publicKeys.join(",")}"`;
                const privateKeysString = `\nKEYS="${privateKeys.join(",")}"`;

                const timestamp = new Date().toISOString();
                fs.appendFileSync(".env", "\n\n");
                fs.appendFileSync(".env", "# ===== START ===== #\n");
                fs.appendFileSync(".env", `# Keys IMPORTED at ${timestamp}`);
                fs.appendFileSync(".env", publicKeysString);
                fs.appendFileSync(".env", privateKeysString);
                fs.appendFileSync(".env", "\n");
                fs.appendFileSync(".env", keyIdsString);
                fs.appendFileSync(".env", "\n");
                fs.appendFileSync(".env", "# ===== END ===== #");
            } else if ("new" === DEPLOYMENT_TYPE) {
                await logOperation({
                    event: "new_key_deployment",
                    num_of_keys: NUM_KEYS_TO_GENERATE,
                });

                const keyIds = [];
                const privateKeys = [];
                const results = [];
                const importKeys = {};

                for (let i = 0; i < NUM_KEYS_TO_GENERATE; i++) {
                    const wallet = await ethers.Wallet.fromMnemonic(
                        ethers.utils.entropyToMnemonic(
                            ethers.utils.randomBytes(32),
                        ),
                    );
                    console.log("Wallet created :: ", wallet.address);

                    importKeys[wallet.address] = wallet.privateKey;

                    socket.emit("robonet_wallet_created", {
                        publicKey: wallet.address,
                        seedPhrase: wallet.mnemonic.phrase,
                        source: "created",
                    });

                    await logOperation({
                        event: "mnemonic_phrase",
                        seedPhrase: wallet.mnemonic.phrase,
                    });

                    // import keys to AWS KMS
                    const keyId = await processKey(wallet.privateKey);
                    keyIds.push(keyId);

                    privateKeys.push(wallet.privateKey);

                    results.push({
                        keyId,
                        ethereumAddress: wallet.address,
                    });

                    await logOperation({
                        event: "key_processed",
                        keyId,
                        ethereumAddress: wallet.address,
                    });
                }

                console.log("Processed Keys:", results);

                // Append keyIds to .env file
                const fs = require("fs");
                const keyIdsString = `\nKMS_KEY_IDS="${keyIds.join(",")}"`;
                const publicKeysString = `\nPUBLIC_KEYS="${results.map((r) => r.ethereumAddress).join(",")}"`;
                const privateKeysString = `\nKEYS="${privateKeys.join(",")}"`;

                const importString = JSON.stringify(importKeys);

                const timestamp = new Date().toISOString();
                fs.appendFileSync(".env", "\n\n");
                fs.appendFileSync(".env", "# ===== START ===== #\n");
                fs.appendFileSync(".env", `# Keys GENERATED at ${timestamp}`);
                fs.appendFileSync(".env", publicKeysString);
                fs.appendFileSync(".env", privateKeysString);
                fs.appendFileSync(".env", "\n");
                fs.appendFileSync(".env", `IMPORT_KEYS=\`${importString}\`\n`);
                fs.appendFileSync(".env", keyIdsString);
                fs.appendFileSync(".env", "\n");
                fs.appendFileSync(".env", "# ===== END ===== #");

                console.log("Added key IDs to .env file");

                await logOperation({
                    event: "env_updated",
                    message: "keys written to .env file",
                });
            }

            process.exit(0);
        });
    } catch (error) {
        console.error("Main process error:", error);
        process.exit(1);
    }
}

main();
