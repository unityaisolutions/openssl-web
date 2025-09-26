/**
 * Message digest/hashing module (openssl dgst equivalent).
 * Uses crypto.subtle.digest() for secure hashing with polyfills for gaps.
 * 
 * @module dgst
 */

import CryptoJS from 'crypto-js';

/**
 * Compute hash digest of input data.
 * 
 * @param {Object} options - Hashing options.
 * @param {string} options.algorithm - Hash algorithm ('SHA-1', 'SHA-256', 'SHA-384', 'SHA-512', 'MD5').
 * @param {string|Uint8Array|ArrayBuffer} options.input - Data to hash.
 * @param {boolean} [options.base64=false] - Output as base64 string.
 * @param {boolean} [options.hex=false] - Output as hexadecimal string (default for OpenSSL compatibility).
 * @param {boolean} [options.raw=false] - Return raw ArrayBuffer.
 * @returns {Promise<string|ArrayBuffer>} Hash digest in specified format.
 * @throws {Error} If algorithm unsupported or input invalid.
 * 
 * @example
 * const hash = await dgst({ algorithm: 'SHA-256', input: 'Hello World', hex: true });
 * // Output: "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
 */
export async function dgst(options = {}) {
  const { 
    algorithm = 'SHA-256', 
    input, 
    base64 = false, 
    hex = true, 
    raw = false 
  } = options;

  if (!input) {
    throw new Error('Input data required for hashing');
  }

  // Normalize input to Uint8Array
  let data;
  if (typeof input === 'string') {
    data = new TextEncoder().encode(input);
  } else if (input instanceof Uint8Array) {
    data = input;
  } else if (input instanceof ArrayBuffer) {
    data = new Uint8Array(input);
  } else {
    throw new Error('Unsupported input type; must be string, Uint8Array, or ArrayBuffer');
  }

  // Map OpenSSL-style algos to Web Crypto
  const webCryptoAlgo = {
    'SHA-1': 'SHA-1',
    'SHA1': 'SHA-1',
    'SHA-256': 'SHA-256',
    'SHA256': 'SHA-256',
    'SHA-384': 'SHA-384',
    'SHA384': 'SHA-384',
    'SHA-512': 'SHA-512',
    'SHA512': 'SHA-512',
    'MD5': null // Not supported in Web Crypto
  }[algorithm.toUpperCase()] || algorithm;

  if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
    try {
      if (webCryptoAlgo && webCryptoAlgo !== 'MD5') {
        // Use Web Crypto API for supported algorithms
        const hashBuffer = await window.crypto.subtle.digest(webCryptoAlgo, data);

        if (raw) return hashBuffer;

        const hashArray = Array.from(new Uint8Array(hashBuffer));
        if (base64) {
          return btoa(String.fromCharCode(...hashArray));
        } else if (hex) {
          return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } else {
          return hashArray; // Array of bytes
        }
      } else {
        // MD5 or unsupported algo - fallback
        throw new Error(`Algorithm ${algorithm} not supported by Web Crypto`);
      }
    } catch (error) {
      // Fallback to CryptoJS for MD5 or errors
      console.warn(`Web Crypto failed for ${algorithm}; using CryptoJS fallback`, error.message);
      return cryptoJSHash(data, algorithm, base64, hex, raw);
    }
  } else {
    // No Web Crypto available
    console.warn('Web Crypto unavailable; using CryptoJS for all hashing');
    return cryptoJSHash(data, algorithm, base64, hex, raw);
  }
}

/**
 * Internal CryptoJS hashing fallback.
 * @param {Uint8Array} data - Input bytes.
 * @param {string} algorithm - Hash algorithm.
 * @param {boolean} base64 - Base64 output.
 * @param {boolean} hex - Hex output.
 * @param {boolean} raw - Raw output.
 * @returns {Promise<string|ArrayBuffer>} Hash result.
 */
async function cryptoJSHash(data, algorithm, base64, hex, raw) {
  const cryptoJSAlgo = {
    'SHA-1': CryptoJS.algo.SHA1,
    'SHA1': CryptoJS.algo.SHA1,
    'SHA-256': CryptoJS.algo.SHA256,
    'SHA256': CryptoJS.algo.SHA256,
    'SHA-384': CryptoJS.algo.SHA384,
    'SHA384': CryptoJS.algo.SHA384,
    'SHA-512': CryptoJS.algo.SHA512,
    'SHA512': CryptoJS.algo.SHA512,
    'MD5': CryptoJS.algo.MD5
  }[algorithm.toUpperCase()] || CryptoJS.algo.SHA256;

  const wordArray = CryptoJS.lib.WordArray.create(data);
  const hash = CryptoJS[cryptoJSAlgo.create ? 'algo' : ''][cryptoJSAlgo.name || cryptoJSAlgo].create
    ? CryptoJS.algo[cryptoJSAlgo.name || 'SHA256'].create().finalize(wordArray)
    : CryptoJS[cryptoJSAlgo.name || 'SHA256'](wordArray);

  if (raw) {
    return hash.toString(CryptoJS.enc.Latin1).split('').map(c => c.charCodeAt(0)).buffer;
  }

  const result = hash.toString(base64 ? CryptoJS.enc.Base64 : (hex ? CryptoJS.enc.Hex : CryptoJS.enc.Latin1));
  
  if (base64 && !hex) {
    return result;
  } else if (hex) {
    return result;
  }

  // Default to hex for OpenSSL compatibility
  return hash.toString(CryptoJS.enc.Hex);
}

// Export for CommonJS
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { dgst };
}