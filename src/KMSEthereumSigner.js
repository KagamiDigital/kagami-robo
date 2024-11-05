const { KMS } = require('@aws-sdk/client-kms');
const { ethers } = require('ethers');
const asn1 = require('asn1.js');
const BN = require('bn.js');

// Define ASN1 parsers
const EcdsaSigAsnParse = asn1.define('EcdsaSig', function() {
    this.seq().obj(
        this.key('r').int(),
        this.key('s').int()
    );
});

const EcdsaPubKey = asn1.define('EcdsaPubKey', function() {
    this.seq().obj(
        this.key('algo').seq().obj(
            this.key('a').objid(),
            this.key('b').objid()
        ),
        this.key('pubKey').bitstr()
    );
});

// The order of the secp256k1 curve
const SECP256K1_N = new BN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16);
const SECP256K1_N_DIV_2 = SECP256K1_N.div(new BN(2));

class KMSEthereumSigner extends ethers.Signer {
    constructor(keyId, region, provider) {
        super();
        this.keyId = keyId;
        this.kms = new KMS({ region });
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

        const { PublicKey } = await this.kms.getPublicKey({
            KeyId: this.keyId
        });

        const publicKeyBuffer = Buffer.from(PublicKey);
        const res = EcdsaPubKey.decode(publicKeyBuffer, 'der');
        let pubKeyBuffer = res.pubKey.data;

        // Remove the 0x04 prefix
        pubKeyBuffer = pubKeyBuffer.slice(1);

        // Compute Keccak-256 hash of the public key
        const address = ethers.utils.keccak256(pubKeyBuffer);
        // Take last 20 bytes as ethereum address
        this._address = ethers.utils.getAddress(`0x${address.slice(-40)}`);
        return this._address;
    }

    async signMessage(message) {
        return this.signDigest(ethers.utils.hashMessage(message));
    }

    async signTransaction(transaction) {
        const tx = await ethers.utils.resolveProperties(transaction);

        // Handle both EIP-1559 and legacy transactions
        const baseTx = {
            chainId: tx.chainId || (await this.provider.getNetwork()).chainId,
            data: tx.data || "",
            to: tx.to || undefined,
            nonce: tx.nonce ? tx.nonce : await this.provider.getTransactionCount(await this.getAddress()),
            value: tx.value || 0,
            type: tx.type || 0
        };

        // EIP-1559 transaction
        if (tx.type === 2 || tx.maxFeePerGas || tx.maxPriorityFeePerGas) {
            baseTx.type = 2;
            baseTx.maxPriorityFeePerGas = tx.maxPriorityFeePerGas || tx.maxFeePerGas || 0;
            baseTx.maxFeePerGas = tx.maxFeePerGas || tx.maxPriorityFeePerGas || 0;
            baseTx.gasLimit = tx.gasLimit || await this.provider.estimateGas(tx);
        }
        // Legacy transaction
        else {
            baseTx.gasPrice = tx.gasPrice || await this.provider.getGasPrice();
            baseTx.gasLimit = tx.gasLimit || await this.provider.estimateGas(tx);
        }

        const unsignedTx = ethers.utils.serializeTransaction(baseTx);
        const signature = await this.signDigest(ethers.utils.keccak256(unsignedTx));
        return ethers.utils.serializeTransaction(baseTx, signature);
    }

    async signDigest(digestHex) {
        const digest = Buffer.from(ethers.utils.arrayify(digestHex));

        const { Signature } = await this.kms.sign({
            KeyId: this.keyId,
            Message: digest,
            MessageType: 'DIGEST',
            SigningAlgorithm: 'ECDSA_SHA_256'
        });

        // Parse the ASN1 signature
        const decoded = EcdsaSigAsnParse.decode(Buffer.from(Signature), 'der');
        let { r, s } = decoded;

        // Convert BN to hex strings
        r = `0x${r.toString('hex')}`;
        s = `0x${s.toString('hex')}`;

        // Handle s being on the upper half of the curve per EIP-2
        let sigS = new BN(ethers.utils.arrayify(s));
        if (sigS.gt(SECP256K1_N_DIV_2)) {
            sigS = SECP256K1_N.sub(sigS);
        }
        s = `0x${sigS.toString('hex')}`;

        // Ensure r and s are 32 bytes each
        r = ethers.utils.hexZeroPad(r, 32);
        s = ethers.utils.hexZeroPad(s, 32);

        // Try recovery values
        const address = await this.getAddress();

        for (let v of [27, 28]) {
            try {
                const recovered = ethers.utils.recoverAddress(digestHex, { r, s, v });
                if (recovered.toLowerCase() === address.toLowerCase()) {
                    return ethers.utils.joinSignature({ r, s, v });
                }
            } catch (err) {
                console.log(`Recovery attempt failed with v=${v}:`, err.message);
            }
        }

        throw new Error('Failed to find correct recovery value');
    }

    connect(provider) {
        return new KMSEthereumSigner(this.keyId, this.region, provider);
    }

    async _signTypedData(domain, types, value) {
        const typedDataHash = ethers.utils._TypedDataEncoder.hash(domain, types, value);
        return this.signDigest(typedDataHash);
    }
}

module.exports = KMSEthereumSigner;
