const { KMS } = require('@aws-sdk/client-kms');
const { ethers } = require('ethers');

async function sign(digest, kmsCredentials) {
    const kms = new KMS(kmsCredentials);
    const params = {
        KeyId: kmsCredentials.keyId,
        Message: digest,
        SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256',
        MessageType: 'DIGEST'
    };
    const res = await kms.sign(params);
    return res;
}

async function getPublicKey(kmsCredentials) {
    const kms = new KMS(kmsCredentials);
    return kms.getPublicKey({
        KeyId: kmsCredentials.keyId
    });
}

class KMSEthereumSigner extends ethers.Signer {
    constructor(keyId, region, provider) {
        super();
        this.kmsCredentials = { keyId, region };
        this._provider = provider;
        this._address = null;
    }

    get provider() {
        return this._provider;
    }

    set provider(value) {
        this._provider = value;
    }

    async getAddress() {
        if (this._address) return this._address;
        const publicKey = await getPublicKey(this.kmsCredentials);
        // Hash the RSA public key to create Ethereum address
        const pubKeyHash = ethers.utils.keccak256(publicKey.PublicKey);
        this._address = ethers.utils.getAddress('0x' + pubKeyHash.slice(-40));
        return this._address;
    }

    async signMessage(message) {
        const messageHash = ethers.utils.hashMessage(message);
        const signature = await this.signDigest(messageHash);
        return signature;
    }

    async signTransaction(transaction) {
        const tx = await ethers.utils.resolveProperties(transaction);

        const baseTx = {
            chainId: tx.chainId || (await this.provider.getNetwork()).chainId,
            data: tx.data || "",
            to: tx.to || undefined,
            nonce: tx.nonce || await this.provider.getTransactionCount(await this.getAddress()),
            value: tx.value || 0,
            type: tx.type || 0
        };

        if (tx.type === 2 || tx.maxFeePerGas || tx.maxPriorityFeePerGas) {
            baseTx.type = 2;
            baseTx.maxPriorityFeePerGas = tx.maxPriorityFeePerGas || tx.maxFeePerGas || 0;
            baseTx.maxFeePerGas = tx.maxFeePerGas || tx.maxPriorityFeePerGas || 0;
            baseTx.gasLimit = tx.gasLimit || await this.provider.estimateGas(tx);
        } else {
            baseTx.gasPrice = tx.gasPrice || await this.provider.getGasPrice();
            baseTx.gasLimit = tx.gasLimit || await this.provider.estimateGas(tx);
        }

        const unsignedTx = ethers.utils.serializeTransaction(baseTx);
        const hash = ethers.utils.keccak256(unsignedTx);
        const signature = await this.signDigest(hash);

        return ethers.utils.serializeTransaction(baseTx, {
            r: '0x' + signature.slice(0, 64),
            s: '0x' + signature.slice(64, 128),
            v: parseInt(signature.slice(128, 130), 16)
        });
    }

    async signDigest(digestHex) {
        const digest = Buffer.from(ethers.utils.arrayify(digestHex));
        const signature = await sign(digest, this.kmsCredentials);

        if (signature.$response?.error || !signature.Signature) {
            throw new Error(`AWS KMS call failed with: ${signature.$response?.error}`);
        }

        return Buffer.from(signature.Signature).toString('hex');
    }

    connect(provider) {
        return new KMSEthereumSigner(this.kmsCredentials.keyId, this.kmsCredentials.region, provider);
    }

    async _signTypedData(domain, types, value) {
        const typedDataHash = ethers.utils._TypedDataEncoder.hash(domain, types, value);
        return this.signDigest(typedDataHash);
    }
}

module.exports = KMSEthereumSigner;


