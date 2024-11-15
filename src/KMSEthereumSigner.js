const { KMS } = require('@aws-sdk/client-kms');
const { ethers } = require('ethers');
const asn1 = require('asn1.js');
const BN = require('bn.js');

/* ASN1 parsers */
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

function getEthereumAddress(publicKey) {
    const res = EcdsaPubKey.decode(publicKey, 'der');
    let pubKeyBuffer = res.pubKey.data;
    pubKeyBuffer = pubKeyBuffer.slice(1, pubKeyBuffer.length);

    const address = ethers.utils.keccak256(pubKeyBuffer);
    const EthAddr = `0x${address.slice(-40)}`;
    return EthAddr;
}

function findEthereumSig(signature) {
    const decoded = EcdsaSigAsnParse.decode(signature, 'der');
    const { r, s } = decoded;

    const secp256k1N = new BN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16);
    const secp256k1halfN = secp256k1N.div(new BN(2));

    return {
        r,
        s: s.gt(secp256k1halfN) ? secp256k1N.sub(s) : s
    };
}

function recoverPubKeyFromSig(msg, r, s, v) {
    return ethers.utils.recoverAddress(`0x${msg.toString('hex')}`, {
        r: `0x${r.toString('hex')}`,
        s: `0x${s.toString('hex')}`,
        v
    });
}

function determineCorrectV(msg, r, s, expectedEthAddr) {
    let v = 27;
    let pubKey = recoverPubKeyFromSig(msg, r, s, v);

    if (pubKey.toLowerCase() !== expectedEthAddr.toLowerCase()) {
        v = 28;
        pubKey = recoverPubKeyFromSig(msg, r, s, v);
    }

    return { pubKey, v };
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
        const ethAddr = getEthereumAddress(Buffer.from(publicKey.PublicKey));
        this._address = ethers.utils.getAddress(ethAddr);
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
        const signature = await this.signDigest(ethers.utils.keccak256(unsignedTx));
        return ethers.utils.serializeTransaction(baseTx, signature);
    }

    async signDigest(digestHex) {
        const digest = Buffer.from(ethers.utils.arrayify(digestHex));
        const signature = await sign(digest, this.kmsCredentials);

        if (signature.$response?.error || !signature.Signature) {
            throw new Error(`AWS KMS call failed with: ${signature.$response?.error}`);
        }

        const { r, s } = findEthereumSig(Buffer.from(signature.Signature));
        const { v } = await determineCorrectV(digest, r, s, await this.getAddress());

        return ethers.utils.joinSignature({
            r: `0x${r.toString('hex')}`,
            s: `0x${s.toString('hex')}`,
            v
        });
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



