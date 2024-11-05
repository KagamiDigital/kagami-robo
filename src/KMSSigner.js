class KMSSigner {
    constructor(_keyId, _wrappedSigner, _ethersProvider) {
    	this.keyId = _keyId
    	this.wrappedSigner = _wrappedSigner
    	this.provider = _ethersProvider
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
		return this.wrappedSigner.getAddress(this.keyId)
    }

    async getAddressHex() {
    	return this.wrappedSigner.getAddressHex(this.keyId)
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

}}

module.exports = KMSSigner;
