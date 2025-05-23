import crypto from 'crypto';

export function encryptWithPublicKey(data, publicKey) {
  try {
    // Derive AES key deterministically from your public key
    const aesKey = crypto.createHash('sha256')
      .update('SEEDPHRASE_ENCRYPTION_SALT_V1') // Add a salt for domain separation
      .update(publicKey, 'hex')
      .digest();
    
    // Use a random IV for each encryption (important for security)
    const iv = crypto.randomBytes(16);
    
    // Encrypt with AES-256-CBC
    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Return IV + encrypted data (IV is not secret, can be stored with ciphertext)
    return iv.toString('hex') + ':' + encrypted;
    
  } catch (error) {
    console.error('Encryption error:', error);
    throw error;
  }
}

export function decryptWithPublicKey(encryptedData, publicKey) {
  try {
    // Split IV and encrypted data
    const [ivHex, encrypted] = encryptedData.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    
    // Derive the same AES key
    const aesKey = crypto.createHash('sha256')
      .update('SEEDPHRASE_ENCRYPTION_SALT_V1')
      .update(publicKey, 'hex')
      .digest();
    
    // Decrypt
    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
    
  } catch (error) {
    console.error('Decryption error:', error);
    throw error;
  }
}