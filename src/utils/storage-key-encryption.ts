/**
 * Storage Key Encryption Utility
 * 
 * Provides deterministic encryption/decryption for storage key names to prevent
 * public key exposure in Chrome storage. Uses AES-GCM with a deterministic IV
 * derived from the public key to ensure the same public key + encryption key
 * always produces the same encrypted key name (needed for key lookup).
 */

/**
 * Encrypt a public key string for use in storage key names
 * Uses deterministic AES-GCM encryption with IV derived from public key
 * Format: [IV(12 bytes)][Encrypted Data]
 * 
 * Deterministic encryption ensures same public key + encryption key = same encrypted key name,
 * which is required for storage key lookup.
 * 
 * @param publicKeyString - The public key string to encrypt
 * @param encryptionKey - The encryption key (base64 string from session key)
 * @returns Base64url-encoded encrypted key name with IV prepended
 */
export async function encryptStorageKeyName(
  publicKeyString: string,
  encryptionKey: string
): Promise<string> {
  try {
    // Decode the encryption key from base64
    const keyBytes = Uint8Array.from(atob(encryptionKey), c => c.charCodeAt(0));
    
    // Import the encryption key
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );
    
    // Derive deterministic IV from public key (first 12 bytes of SHA256 hash)
    // This ensures same public key + encryption key = same encrypted key name
    // Needed for storage key lookup - we encrypt the public key we're looking for
    const publicKeyBytes = new TextEncoder().encode(publicKeyString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', publicKeyBytes);
    const iv = new Uint8Array(hashBuffer).slice(0, 12); // AES-GCM uses 12-byte IV
    
    // Encrypt the public key string
    const dataToEncrypt = new TextEncoder().encode(publicKeyString);
    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      cryptoKey,
      dataToEncrypt
    );
    
    // Prepend IV to encrypted data: [IV(12 bytes)][Encrypted Data]
    // This allows decryption without needing to know the public key first
    const combined = new Uint8Array(iv.length + encryptedBuffer.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encryptedBuffer), iv.length);
    
    // Convert to base64url (URL-safe base64)
    const combinedArray = Array.from(combined);
    const base64 = btoa(String.fromCharCode(...combinedArray));
    const base64url = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    
    return base64url;
  } catch (error) {
    console.error('Storage key encryption error:', error);
    throw new Error('Failed to encrypt storage key name');
  }
}

/**
 * Decrypt an encrypted storage key name back to the original public key string
 * Expects format: [IV(12 bytes)][Encrypted Data] encoded as base64url
 * 
 * @param encryptedKeyName - The base64url-encoded encrypted key name
 * @param encryptionKey - The encryption key (base64 string from session key)
 * @returns The original public key string
 */
export async function decryptStorageKeyName(
  encryptedKeyName: string,
  encryptionKey: string
): Promise<string> {
  try {
    // Decode the encryption key from base64
    const keyBytes = Uint8Array.from(atob(encryptionKey), c => c.charCodeAt(0));
    
    // Import the encryption key
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    
    // Convert base64url back to base64
    const base64 = encryptedKeyName.replace(/-/g, '+').replace(/_/g, '/');
    // Add padding if needed
    const paddedBase64 = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
    const encryptedBuffer = Uint8Array.from(atob(paddedBase64), c => c.charCodeAt(0));
    
    // Extract IV from first 12 bytes and encrypted data from the rest
    if (encryptedBuffer.length < 12) {
      throw new Error('Invalid encrypted key format');
    }
    
    const iv = encryptedBuffer.slice(0, 12);
    const encryptedData = encryptedBuffer.slice(12);
    
    // Decrypt
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      cryptoKey,
      encryptedData
    );
    
    // Convert back to string
    const decrypted = new TextDecoder().decode(decryptedBuffer);
    return decrypted;
  } catch (error) {
    console.error('Storage key decryption error:', error);
    throw new Error('Failed to decrypt storage key name');
  }
}

/**
 * Check if a string is an encrypted storage key name
 * Encrypted keys are base64url encoded and have a specific length/format
 * 
 * @param keySuffix - The key suffix to check
 * @returns True if the key appears to be encrypted (base64url format with - or _)
 */
export function isEncryptedStorageKey(keySuffix: string): boolean {
  // Encrypted keys are base64url encoded (contain - or _)
  // Hashed keys are also base64url, so we need another way to distinguish
  // We can check the length - encrypted keys will be longer than hashed keys
  // Or we can use a prefix/marker
  
  // For now, check if it contains base64url characters and is longer than a hash
  // A SHA256 hash in base64url is 43 chars. Encrypted data will be longer.
  if (keySuffix.includes('-') || keySuffix.includes('_')) {
    // Could be hashed or encrypted - encrypted will typically be longer
    // But this is not reliable. Better to use a version prefix.
    return keySuffix.length > 50; // Encrypted keys are typically longer
  }
  return false;
}


