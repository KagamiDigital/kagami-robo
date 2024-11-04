const { KMS } = require('@aws-sdk/client-kms');
const { ethers } = require('ethers');
const { arrayify, hexlify } = ethers.utils;

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

        const { PublicKey } = await this.kms.getPublicKey({
            KeyId: this.keyId
        });

        // Get the raw public key bytes (skipping the ASN.1 encoding)
        const publicKeyBuffer = Buffer.from(PublicKey);
        let index = 0;
        // Skip sequence
        index++;
        index += publicKeyBuffer[index] === 0x81 ? 2 : 1;
        // Skip sequence
        index++;
        index += publicKeyBuffer[index] === 0x81 ? 2 : 1;
        // Skip OID and curve OID
        while (index < publicKeyBuffer.length && publicKeyBuffer[index] !== 0x03) {
            index++;
        }
        // Skip bitstring header
        index += 2;
        // Skip leading zero
        index++;

        // Get the raw public key (removing the 0x04 prefix)
        const rawPubKey = publicKeyBuffer.slice(index + 1);

        // Compute the Keccak-256 hash of the public key
        const hash = ethers.utils.keccak256(rawPubKey);
        // Take the last 20 bytes to get the address
        const address = '0x' + hash.slice(-40);
        // Convert to checksum address
        this._address = ethers.utils.getAddress(address);
        return this._address;
    }

    async signMessage(message) {
        const messageHash = ethers.utils.hashMessage(message);
        const signature = await this.signDigest(messageHash);
        return signature;
    }

    async signTransaction(transaction) {
        const tx = await ethers.utils.resolveProperties(transaction);

        // Default values matching the Python implementation
        const baseTx = {
            nonce: tx.nonce,
            gasPrice: tx.gasPrice || '0x0918400000',
            gasLimit: tx.gasLimit || 160000,
            to: tx.to,
            value: tx.value || 0,
            data: tx.data || '0x00',
            chainId: tx.chainId || 1
        };

        const unsignedTx = ethers.utils.serializeTransaction(baseTx);
        const transactionHash = ethers.utils.keccak256(unsignedTx);
        const signature = await this.signDigest(transactionHash);
        return ethers.utils.serializeTransaction(baseTx, signature);
    }

    async signDigest(digestHex) {
        const digest = arrayify(digestHex);

        const { Signature } = await this.kms.sign({
            KeyId: this.keyId,
            Message: Buffer.from(digest),
            MessageType: 'DIGEST',
            SigningAlgorithm: 'ECDSA_SHA_256'
        });

        // Convert DER signature to R,S format
        const signatureBuffer = Buffer.from(Signature);
        let pos = 2;
        pos += 2;
        const rLength = signatureBuffer[pos - 1];
        const r = hexlify(signatureBuffer.slice(pos, pos + rLength));
        pos += rLength;
        pos += 2;
        const sLength = signatureBuffer[pos - 1];
        const s = hexlify(signatureBuffer.slice(pos, pos + sLength));

        // Try recovery values
        for (let v = 27; v <= 28; v++) {
            try {
                const recovered = ethers.utils.recoverAddress(digest, { r, s, v });
                if (recovered.toLowerCase() === (await this.getAddress()).toLowerCase()) {
                    return ethers.utils.joinSignature({ r, s, v });
                }
            } catch (err) {
                continue;
            }
        }

        throw new Error('Failed to find correct recovery value');
    }

    async _signTypedData(domain, types, value) {
        // Get the EIP-712 signing hash
        const typedDataHash = ethers.utils._TypedDataEncoder.hash(domain, types, value);
        // Sign the hash using our existing signDigest method
        const signature = await this.signDigest(typedDataHash);
        return signature;
    }

    connect(provider) {
        return new KMSEthereumSigner(this.keyId, this.region, provider);
    }
}

module.exports = KMSEthereumSigner;