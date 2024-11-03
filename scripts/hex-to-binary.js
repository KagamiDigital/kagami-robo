const fs = require('fs').promises;
const path = require('path');

// Get private key from command line argument
const privateKey = process.argv[2];

if (!privateKey) {
    console.error('Please provide a private key as a command line argument');
    console.error('Usage: node script.js <private-key-hex>');
    process.exit(1);
}

// Remove '0x' prefix if it exists
const cleanHex = privateKey.replace('0x', '');

// Validate hex string length (32 bytes = 64 characters in hex)
if (cleanHex.length !== 64) {
    console.error(`Invalid private key length. Expected 64 hex characters, got ${cleanHex.length}`);
    process.exit(1);
}

// Convert hex to binary buffer
const binaryKey = Buffer.from(cleanHex, 'hex');

// Save to file
fs.writeFile('PlaintextKeyMaterial.bin', binaryKey)
    .then(() => {
        console.log('Private key saved as binary to: PlaintextKeyMaterial.bin');
        console.log(`File size: ${binaryKey.length} bytes`);
    })
    .catch(error => {
        console.error('Error saving file:', error);
        process.exit(1);
    });