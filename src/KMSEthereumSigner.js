const { KMS } = require('@aws-sdk/client-kms');
const { ethers } = require('ethers');
const { arrayify, hexlify, stripZeros } = ethers.utils;

class KMSEthereumSigner extends ethers.Signer {
    constructor(keyId, region, provider) {
        super();
        this.keyId = keyId;
        this.kms = new KMS({ region });
        this.provider = provider;
        this._address = null;
    }

    async getAddress() {
        if (this._address) return this._address;

        // Get the public key from KMS
        const { PublicKey } = await this.kms.getPublicKey({
            KeyId: this.keyId
        });

        // Convert KMS public key to Ethereum address
        const publicKeyBuffer = Buffer.from(PublicKey);
        const uncompressedPubKey = publicKeyBuffer.slice(publicKeyBuffer.length - 64);
        const address = ethers.utils.computeAddress(uncompressedPubKey);

        this._address = address;
        return address;
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
            gasLimit: tx.gasLimit || undefined,
            gasPrice: tx.gasPrice || undefined,
            nonce: tx.nonce ? tx.nonce : await this.provider.getTransactionCount(await this.getAddress()),
            to: tx.to || undefined,
            value: tx.value || 0,
        };

        const unsignedTx = ethers.utils.serializeTransaction(baseTx);
        const transactionHash = ethers.utils.keccak256(unsignedTx);
        const signature = await this.signDigest(transactionHash);

        return ethers.utils.serializeTransaction(baseTx, signature);
    }

    async signDigest(digestHex) {
        const digest = arrayify(digestHex);

        // Sign the digest using KMS
        const { Signature } = await this.kms.sign({
            KeyId: this.keyId,
            Message: Buffer.from(digest),
            MessageType: 'DIGEST',
            SigningAlgorithm: 'ECDSA_SHA_256'
        });

        // Convert KMS signature format to Ethereum format
        const signatureBuffer = Buffer.from(Signature);
        const r = hexlify(signatureBuffer.slice(0, 32));
        const s = hexlify(signatureBuffer.slice(32, 64));

        // Calculate recovery parameter v
        let v = 27;
        const recoveredPubKey = ethers.utils.recoverPublicKey(
            digestHex,
            { r, s, v }
        );

        if (recoveredPubKey !== await this.getAddress()) {
            v = 28;
        }

        return ethers.utils.joinSignature({ r, s, v });
    }

    connect(provider) {
        return new KMSEthereumSigner(this.keyId, this.region, provider);
    }
}

module.exports = KMSEthereumSigner