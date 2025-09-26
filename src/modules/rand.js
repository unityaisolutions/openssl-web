/**
 * Random data generation module (openssl rand equivalent).
 * Uses crypto.getRandomValues() for secure randomness.
 * 
 * @module rand
 */

import CryptoJS from 'crypto-js';

/**
 * Generate random bytes and format as specified.
 * 
 * @param {Object} options - Generation options.
 * @param {number} [options.length=32] - Number of random bytes to generate.
 * @param {boolean} [options.base64=false] - Output as base64 string.
 * @param {boolean} [options.hex=false] - Output as hexadecimal string.
 * @param {boolean} [options.raw=false] - Return raw Uint8Array (ignores other formats).
 * @returns {Promise<string|Uint8Array>} Formatted random data.
 * @throws {Error} If length is invalid or crypto unavailable.
 * 
 * @example
 * const randomBase64 = await rand({ length: 32, base64: true });
 * // Output: "SGVsbG8gV29ybGQh" (example 32 bytes base64)
 */
export async function rand(options = {}) {
  const { length = 32, base64 = false, hex = false, raw = false } = options;

  if (!Number.isInteger(length) || length <= 0) {
    throw new Error('Invalid length: must be positive integer');
  }

  if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
    // Use Web Crypto API (preferred for security)
    const randomBytes = new Uint8Array(length);
    window.crypto.getRandomValues(randomBytes);

    if (raw) return randomBytes;

    // Convert to string format
    if (base64) {
      return btoa(String.fromCharCode(...randomBytes));
    } else if (hex) {
      return Array.from(randomBytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    } else {
      // Default to base64 for OpenSSL compatibility
      return btoa(String.fromCharCode(...randomBytes));
    }
  } else {
    // Fallback to CryptoJS (less secure, for legacy environments)
    console.warn('Web Crypto unavailable; using CryptoJS fallback (reduced security)');
    const randomBytes = CryptoJS.lib.WordArray.random(length);
    const bytes = randomBytes.toString(CryptoJS.enc.Latin1).split('').map(c => c.charCodeAt(0));

    if (raw) return new Uint8Array(bytes);

    if (base64) {
      return btoa(String.fromCharCode(...bytes));
    } else if (hex) {
      return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
    } else {
      return btoa(String.fromCharCode(...bytes));
    }
  }
}

// Export for CommonJS
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { rand };
}