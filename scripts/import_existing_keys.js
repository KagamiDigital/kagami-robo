const { KMSClient, CreateKeyCommand, GetParametersForImportCommand, ImportKeyMaterialCommand } = require('@aws-sdk/client-kms');
const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
require('dotenv').config();

const kmsClient = new KMSClient({ region: process.env.AWS_REGION || 'us-east-1' });

async function runOpenSSLCommand(args, input = null) {
    return new Promise((resolve, reject) => {
        const process = spawn('openssl', args);
        const stdout = [];
        const stderr = [];

        process.stdout.on('data', chunk => stdout.push(chunk));
        process.stderr.on('data', chunk => stderr.push(chunk));

        process.on('close', code => {
            if (code !== 0) {
                reject(new Error(`OpenSSL failed: ${Buffer.concat(stderr)}`));
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

async function generateRsaFromEthKey(ethereumPrivateKey, workDir) {
    const cleanKey = ethereumPrivateKey.replace('0x', '');
    const seedFile = path.join(workDir, 'seed.bin');
    const configFile = path.join(workDir, 'openssl.cnf');
    const keyFile = path.join(workDir, 'key.pem');

    await fs.writeFile(seedFile, Buffer.from(cleanKey, 'hex'));

    const configContent = `
openssl_conf = openssl_def
[openssl_def]
engines = engine_section
[engine_section]
rand = rand_section
[rand_section]
RAND = DRBG
[default_sect]
DRBG = drbg_sect
[drbg_sect]
digest = SHA256
seed = FILE:${seedFile}
    `.trim();

    await fs.writeFile(configFile, configContent);

    await runOpenSSLCommand([
        'genpkey',
        '-algorithm', 'RSA',
        '-pkeyopt', 'rsa_keygen_bits:2048',
        '-pkeyopt', 'rsa_keygen_pubexp:65537',
        '-out', keyFile,
        '-config', configFile
    ]);

    return runOpenSSLCommand([
        'pkcs8',
        '-topk8',
        '-nocrypt',
        '-in', keyFile,
        '-outform', 'DER'
    ]);
}

async function createKmsKey() {
    const command = new CreateKeyCommand({
        Description: 'RSA Signing Key',
        KeyUsage: 'SIGN_VERIFY',
        Origin: 'EXTERNAL',
        KeySpec: 'RSA_2048'
    });
    const response = await kmsClient.send(command);
    return response.KeyMetadata.KeyId;
}

async function getImportParameters(keyId) {
    const command = new GetParametersForImportCommand({
        KeyId: keyId,
        WrappingAlgorithm: 'RSAES_OAEP_SHA_256',
        WrappingKeySpec: 'RSA_2048'
    });
    const response = await kmsClient.send(command);
    return {
        publicKey: response.PublicKey,
        importToken: response.ImportToken
    };
}

function encryptWithKmsPublicKey(rsaKeyDer, wrappingPublicKeyBase64) {
    const wrappingKey = crypto.createPublicKey({
        key: Buffer.from(wrappingPublicKeyBase64, 'base64'),
        format: 'der',
        type: 'spki'
    });

    return crypto.publicEncrypt(
        {
            key: wrappingKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        rsaKeyDer
    );
}

async function importKeyMaterial(keyId, encryptedKeyMaterial, importToken) {
    const command = new ImportKeyMaterialCommand({
        KeyId: keyId,
        ImportToken: importToken,
        EncryptedKeyMaterial: encryptedKeyMaterial,
        ExpirationModel: 'KEY_MATERIAL_DOES_NOT_EXPIRE'
    });
    await kmsClient.send(command);
}

async function processKey(privateKey, workDir) {
    const keyId = await createKmsKey();
    const { publicKey, importToken } = await getImportParameters(keyId);
    const rsaKeyDer = await generateRsaFromEthKey(privateKey, workDir);
    const encryptedKeyMaterial = encryptWithKmsPublicKey(rsaKeyDer, publicKey);
    await importKeyMaterial(keyId, encryptedKeyMaterial, importToken);
    return keyId;
}

async function main() {
    if (!process.env.KEYS) {
        throw new Error('KEYS environment variable not set');
    }

    const privateKeys = process.env.KEYS.split(',');
    const keyIds = [];
    const workDir = path.join(__dirname, 'temp-keys');

    try {
        await fs.mkdir(workDir, { recursive: true });

        for (const privateKey of privateKeys) {
            const keyId = await processKey(privateKey.trim(), workDir);
            keyIds.push(keyId);
        }

        const keyIdsString = `\nKMS_KEY_IDS="${keyIds.join(',')}"`
        const privateKeysString = `\n` + process.env.KEYS

        const timestamp = new Date().toISOString();
        fs.appendFileSync('.env', "\n\n");
        fs.appendFileSync('.env', "# ===== START ===== #\n");
        fs.appendFileSync('.env', `# Keys IMPORTED at ${timestamp}`);
        fs.appendFileSync('.env', privateKeysString);
        fs.appendFileSync('.env', keyIdsString);
        fs.appendFileSync('.env', "\n");
        fs.appendFileSync('.env', "# ===== END ===== #");

        console.log('Added new KEY IDs to .env file');


    } finally {
        // Cleanup
        await fs.rm(workDir, { recursive: true, force: true });
    }
}

main().catch(console.error);
