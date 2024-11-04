const { KMS } = require('@aws-sdk/client-kms');
const { ethers } = require('ethers');
const { arrayify, hexlify } = ethers.utils;

// The order of the secp256k1 curve
const SECP256K1_N = ethers.BigNumber.from('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
const SECP256K1_N_DIV_2 = SECP256K1_N.div(2);

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

        console.log('Raw KMS signature:', Buffer.from(Signature).toString('hex'));

        // Convert DER signature to R,S format
        const signatureBuffer = Buffer.from(Signature);

        // Parse DER format
        // Format: 0x30 bb 02 aa <r> 02 cc <s>
        // where bb is total length
        // aa is length of r
        // cc is length of s
        let pos = 2; // Skip 0x30 and total length

        // Get r
        const rLength = signatureBuffer[pos + 1]; // Skip 0x02 and get length
        pos += 2;
        let r = signatureBuffer.slice(pos, pos + rLength);
        // Handle potential leading zero
        if (r[0] === 0) {
            r = r.slice(1);
        }
        pos += rLength;

        // Get s
        const sLength = signatureBuffer[pos + 1]; // Skip 0x02 and get length
        pos += 2;
        let s = signatureBuffer.slice(pos, pos + sLength);
        // Handle potential leading zero
        if (s[0] === 0) {
            s = s.slice(1);
        }

        r = hexlify(r);
        s = hexlify(s);

        console.log('Parsed r:', r);
        console.log('Parsed s:', s);
        console.log('Expected address:', await this.getAddress());

        // Ensure r and s are 32 bytes each
        while (r.length < 66) r = r.replace('0x', '0x0');
        while (s.length < 66) s = s.replace('0x', '0x0');

        // Check if s is in the upper half of the curve order
        let sigS = ethers.BigNumber.from(s);
        let recovery = 0;

        // If s is in the upper half, transform it to the lower half
        if (sigS.gt(SECP256K1_N_DIV_2)) {
            sigS = SECP256K1_N.sub(sigS);
            recovery = 1;
        }

        // Try the recovery values
        const v = 27 + recovery;
        const signature = { r, s: hexlify(sigS), v };

        try {
            const recovered = ethers.utils.recoverAddress(digest, signature);
            const actual = await this.getAddress();
            if (recovered.toLowerCase() === actual.toLowerCase()) {
                return ethers.utils.joinSignature(signature);
            }
        } catch (err) {
            console.log(`Recovery attempt failed:`, err.message);
        }

        // Try the alternative recovery value
        signature.v = 28 + recovery;
        try {
            const recovered = ethers.utils.recoverAddress(digest, signature);
            const actual = await this.getAddress();
            if (recovered.toLowerCase() === actual.toLowerCase()) {
                return ethers.utils.joinSignature(signature);
            }
        } catch (err) {
            console.log(`Recovery attempt failed:`, err.message);
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