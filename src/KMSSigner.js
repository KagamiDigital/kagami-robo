const { ethers } = require('ethers');

class KMSSigner extends ethers.Signer {

    constructor(_keyId, _wrappedSigner, _ethersProvider) {
        super();
    	this.keyId = _keyId
    	this.wrappedSigner = _wrappedSigner
    	this.provider = _ethersProvider
        this._address = null;
    }

    get address() {
        if (!this._address) {
            throw new Error('No address set');
        }
        return this._address;
    }

    async getChainId() {
        const network = await this.provider.getNetwork();
        return network.chainId;
    }

	// Add signing key interface
    _signingKey() {
        // This is just a placeholder to match the Wallet interface
        return {
            signDigest: async (digest) => {
                return this.signDigest(digest);
            }
        };
    }

    // Add mnemonic interface
    _mnemonic() {
        // KMS doesn't use mnemonics, but we should match the interface
        return null;
    }

    async getPublicKey() {
    	return this.wrappedSigner.getPublicKey(this.keyId)
    }

    async getDerPublicKey() {
    	return this.wrappedSigner.getDerPublicKey(this.keyId)
    }

	async getAddress() {
        if (this._address) return this._address;

		this._address = this.wrappedSigner.wallets.getAddressHex(this.keyId)

		return this._address
    }

    async getAddressHex() {
    	return this.wrappedSigner.wallets.getAddressHex(this.keyId)
    }

    async signDigest(digestBuffer) {
    	return this.wrappedSigner.signDigest(this.keyId, digestBuffer)
    }

    async signTransaction(txData) {
    	return this.wrappedSigner.signTransaction({keyId: this.keyId}, txData)
    }

    async signMessage(message) {
    	return this.wrappedSigner({keyId: this.keyId}, message)
    }

}

module.exports = KMSSigner;
