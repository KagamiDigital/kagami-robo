const { ethers } = require('ethers');

function deriveAccounts(mnemonics, numAccounts = 10) {

	const accounts = [];

	for (const mnemonic of mnemonics) {

	    const hdNode = ethers.utils.HDNode.fromMnemonic(mnemonic);

	    for(let i = 0; i < numAccounts; i++) {
	        const path = `m/44'/60'/0'/0/${i}`;
	        const account = hdNode.derivePath(path);
	        accounts.push({
	        	mnemonic,
	            index: i,
	            path,
	            address: account.address,
	            publicKey: account.publicKey,
	            privateKey: account.privateKey
	        });
	    }
	}

    return accounts;
}

// Usage:
const mnemonics = [
	"sentence liberty steel nephew current never exact damp staff work peanut street solution year movie call chalk grant unveil link upon evil faint unaware",
	"law fatal shed clock cup pottery eight payment better belt bunker degree own senior spy odor sentence such wrestle market stool peace rail upset",
	];
const accounts = deriveAccounts(mnemonics);

// Find matching accounts
accounts.forEach(acc => {
    console.log(`Index ${acc.index}:`);
    console.log(`Address: ${acc.address}`);
    console.log(`Private Key: ${acc.privateKey}`);
    console.log('---');
});
