import crypto from 'crypto';

export function encryptWithSignature(data:string, signature:string) {
  try {
    const aesKey = crypto.createHash('sha256')
      .update('SEEDPHRASE_ENCRYPTION_SALT_V1') // Add a salt for domain separation
      .update(signature, 'hex')
      .digest();

    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return iv.toString('hex') + ':' + encrypted;
    
  } catch (error) {
    console.error('Encryption error:', error);
    throw error;
  }
}

export function decryptWithSignature(encryptedData:string, signature:string) {
  try {
    // Split IV and encrypted data
    const [ivHex, encrypted] = encryptedData.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    
    // Derive the same AES key
    const aesKey = crypto.createHash('sha256')
      .update('SEEDPHRASE_ENCRYPTION_SALT_V1')
      .update(signature, 'hex')
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