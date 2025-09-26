/**
 * WebOpenSSL - JavaScript emulation of OpenSSL subset for web environments
 * Uses Web Crypto API for secure operations with polyfills for gaps.
 * 
 * API mimics OpenSSL CLI commands as async methods.
 * 
 * @example
 * import webopenssl from './index.js';
 * 
 * // Generate random base64 key
 * const key = await webopenssl.rand({ base64: true, length: 32 });
 * console.log(key); // e.g., "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd"
 * 
 * @module webopenssl
 */

import { rand } from './modules/rand.js';
import { dgst } from './modules/dgst.js';
import { enc } from './modules/enc.js';
import { req } from './modules/req.js';

/**
 * Detects if Web Crypto API is available and secure.
 * @returns {boolean} True if crypto.subtle is available.
 */
function isWebCryptoAvailable() {
  return typeof window !== 'undefined' && 
         window.crypto && 
         window.crypto.subtle && 
         typeof window.crypto.getRandomValues === 'function';
}

/**
 * Main WebOpenSSL object with command methods.
 * @namespace
 */
const webopenssl = {
  /**
   * Random data generation (openssl rand equivalent).
   * @param {Object} options - Options for generation.
   * @param {number} [options.length=32] - Number of random bytes.
   * @param {boolean} [options.base64=false] - Output as base64.
   * @param {boolean} [options.hex=false] - Output as hex.
   * @returns {Promise<string>} Random data as string.
   */
  rand,

  /**
   * Message digest/hashing (openssl dgst equivalent).
   * @param {Object} options - Hashing options.
   * @param {string} options.algorithm - Hash algo (e.g., 'SHA-256', 'MD5').
   * @param {string|Uint8Array|ArrayBuffer} options.input - Data to hash.
   * @param {boolean} [options.base64=false] - Output as base64.
   * @param {boolean} [options.hex=false] - Output as hex.
   * @returns {Promise<string>} Hash digest as string.
   */
  dgst,

  /**
   * Symmetric encryption/decryption (openssl enc equivalent).
   * @param {Object} options - Encryption options.
   * @param {string} options.algorithm - Cipher algo (e.g., 'AES-256-CBC').
   * @param {string|Uint8Array} options.input - Data to encrypt/decrypt.
   * @param {boolean} [options.decrypt=false] - Decrypt mode.
   * @param {string} [options.password] - Password for key derivation.
   * @param {string} [options.iv] - Initialization vector (hex/base64).
   * @returns {Promise<{data: string, iv?: string, key?: CryptoKey}>} Encrypted/decrypted data.
   */
  enc,

  /**
   * Certificate request generation (openssl req equivalent).
   * @param {Object} options - CSR options.
   * @param {string} options.subject - DN subject (e.g., '/CN=example.com').
   * @param {string} [options.keySize=2048] - RSA key size.
   * @param {string} [options.algo='RSA'] - Key algorithm (RSA/EC).
   * @returns {Promise<{csr: string, privateKey: string}>} PEM-encoded CSR and private key.
   */
  req,

  /**
   * Utility to check Web Crypto availability.
   * @returns {boolean}
   */
  isWebCryptoAvailable
};

// Export for different environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = webopenssl;
} else if (typeof define === 'function' && define.amd) {
  define(() => webopenssl);
} else {
  // Browser global
  window.webopenssl = webopenssl;
}

export default webopenssl;