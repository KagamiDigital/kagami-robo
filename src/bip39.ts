import * as bip39 from 'bip39';

/**
 * Convert binary data to a BIP39 mnemonic seed phrase
 * @param binaryData - The binary data as a Buffer
 * @returns The mnemonic seed phrase
 */
export function binaryToMnemonic(binaryString: string): string {
    const bufferFromBinary = Buffer.from(binaryString, 'binary');
    // Convert binary data to hex string
    const hexString = bufferFromBinary.toString('hex');
    // Generate mnemonic from hex entropy
    return bip39.entropyToMnemonic(hexString);
}