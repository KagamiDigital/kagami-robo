import * as bip39 from 'bip39';

/**
 * Convert binary data to a BIP39 mnemonic seed phrase
 * @param binaryData - The binary data as a Buffer
 * @returns The mnemonic seed phrase
 */
export function base64ToMnemonic(binaryString: string): string {
    const buffer = Buffer.from(binaryString, 'base64');
    // Convert binary data to hex string
    const hexString = buffer.toString('hex');
    // Generate mnemonic from hex entropy
    return bip39.entropyToMnemonic(hexString);
}