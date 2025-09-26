/**
 * Symmetric encryption/decryption module (openssl enc equivalent).
 * Uses crypto.subtle.encrypt/decrypt with PBKDF2 key derivation.
 * 
 * @module enc
 */

import CryptoJS from 'crypto-js';
import forge from 'node-forge';

/**
 * Encrypt or decrypt data using symmetric cipher.
 * 
 * @param {Object} options - Encryption options.
 * @param {string} options.algorithm - Cipher algorithm (e.g., 'AES-256-CBC', 'AES-128-GCM').
 * @param {string|Uint8Array|ArrayBuffer} options.input - Data to encrypt/decrypt.
 * @param {boolean} [options.decrypt=false] - Decrypt mode.
 * @param {string} [options.password] - Password for key derivation (required for encryption).
 * @param {string} [options.salt] - Salt for PBKDF2 (auto-generated if missing).
 * @param {number} [options.iterations=10000] - PBKDF2 iterations.
 * @param {string} [options.iv] - Initialization vector (hex/base64; auto-generated if missing).
 * @param {boolean} [options.base64=false] - Output/input as base64.
 * @param {boolean} [options.hex=false] - Output/input as hex.
 * @param {boolean} [options.raw=false] - Return raw Uint8Array (ignores formatting).
 * @returns {Promise<{data: string|Uint8Array, iv?: string, salt?: string, key?: CryptoKey}>} Result with data and metadata.
 * @throws {Error} If algorithm unsupported, password missing, or crypto unavailable.
 * 
 * @example
 * const encrypted = await enc({
 *   algorithm: 'AES-256-CBC',
 *   input: 'Hello World',
 *   password: 'secret',
 *   base64: true
 * });
 * // { data: "encrypted_base64", iv: "iv_base64", salt: "salt_base64" }
 */
export async function enc(options = {}) {
  const { 
    algorithm = 'AES-256-CBC', 
    input, 
    decrypt = false, 
    password, 
    salt, 
    iterations = 10000, 
    iv, 
    base64 = false, 
    hex = false, 
    raw = false 
  } = options;

  if (!input) {
    throw new Error('Input data required');
  }

  if (decrypt && (!password || !iv)) {
    throw new Error('Password and IV required for decryption');
  }

  if (!decrypt && !password) {
    throw new Error('Password required for encryption');
  }

  // Normalize input
  let data;
  if (typeof input === 'string') {
    if (base64) {
      data = Uint8Array.from(atob(input), c => c.charCodeAt(0));
    } else if (hex) {
      data = new Uint8Array(input.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    } else {
      data = new TextEncoder().encode(input);
    }
  } else if (input instanceof Uint8Array) {
    data = input;
  } else if (input instanceof ArrayBuffer) {
    data = new Uint8Array(input);
  } else {
    throw new Error('Unsupported input type');
  }

  // Parse algorithm
  const [cipher, mode] = algorithm.split('-');
  const keyLength = parseInt(algorithm.match(/(\d+)/)?.[0]) || 256;
  const isGCM = mode === 'GCM';

  if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
    try {
      // Generate or parse salt
      const finalSalt = salt ? 
        (base64 ? Uint8Array.from(atob(salt), c => c.charCodeAt(0)) : 
         hex ? new Uint8Array(salt.match(/.{1,2}/g).map(b => parseInt(b, 16))) : 
         new TextEncoder().encode(salt)) :
        window.crypto.getRandomValues(new Uint8Array(16));

      // Derive key with PBKDF2
      const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
      );
      
      const key = await window.crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: finalSalt,
          iterations,
          hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-' + (isGCM ? 'GCM' : 'CBC'), length: keyLength },
        false,
        decrypt ? ['decrypt'] : ['encrypt']
      );

      // Generate or parse IV
      let finalIV;
      if (iv) {
        finalIV = base64 ? Uint8Array.from(atob(iv), c => c.charCodeAt(0)) :
                  hex ? new Uint8Array(iv.match(/.{1,2}/g).map(b => parseInt(b, 16))) :
                  new TextEncoder().encode(iv);
      } else {
        finalIV = window.crypto.getRandomValues(new Uint8Array(16));
      }

      let result;
      if (decrypt) {
        result = await window.crypto.subtle.decrypt(
          { name: isGCM ? 'GCM' : 'CBC', iv: finalIV },
          key,
          data
        );
      } else {
        result = await window.crypto.subtle.encrypt(
          { name: isGCM ? 'GCM' : 'CBC', iv: finalIV },
          key,
          data
        );
      }

      const resultArray = new Uint8Array(result);

      if (raw) {
        return { 
          data: resultArray,
          iv: finalIV,
          salt: finalSalt
        };
      }

      // Format output
      const formatData = (bytes) => {
        if (base64) {
          return btoa(String.fromCharCode(...bytes));
        } else if (hex) {
          return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        } else {
          return new TextDecoder().decode(bytes);
        }
      };

      return { 
        data: formatData(resultArray),
        iv: formatData(finalIV),
        salt: formatData(finalSalt)
      };

    } catch (error) {
      console.warn(`Web Crypto encryption failed for ${algorithm}; using CryptoJS fallback`, error.message);
      return cryptoJSEncrypt(data, algorithm, password, salt, iv, iterations, decrypt, base64, hex, raw);
    }
  } else {
    console.warn('Web Crypto unavailable; using CryptoJS for encryption');
    return cryptoJSEncrypt(data, algorithm, password, salt, iv, iterations, decrypt, base64, hex, raw);
  }
}

/**
 * Internal CryptoJS encryption fallback.
 */
async function cryptoJSEncrypt(data, algorithm, password, salt, iv, iterations, decrypt, base64, hex, raw) {
  const [cipher, mode] = algorithm.split('-');
  const keySize = parseInt(algorithm.match(/(\d+)/)?.[0]) / 32; // Convert bits to words

  let cryptoJSMode = CryptoJS.mode.CBC;
  if (mode === 'GCM') cryptoJSMode = CryptoJS.mode.GCM;
  else if (mode === 'CTR') cryptoJSMode = CryptoJS.mode.CTR;

  const key = CryptoJS.PBKDF2(password, salt || CryptoJS.lib.WordArray.random(16), {
    keySize,
    iterations: iterations || 10000,
    hasher: CryptoJS.algo.SHA256
  });

  let result;
  if (decrypt) {
    const ivBytes = iv ? 
      (base64 ? CryptoJS.enc.Base64.parse(iv) : 
       hex ? CryptoJS.enc.Hex.parse(iv) : 
       CryptoJS.enc.Utf8.parse(iv)) : 
      CryptoJS.lib.WordArray.random(16);

    result = CryptoJS.AES.decrypt(
      { ciphertext: CryptoJS.enc.Base64.parse(base64 ? data : hex ? CryptoJS.enc.Hex.parse(data) : data) },
      key,
      { iv: ivBytes, mode: cryptoJSMode }
    );
  } else {
    const ivBytes = iv ? 
      (base64 ? CryptoJS.enc.Base64.parse(iv) : 
       hex ? CryptoJS.enc.Hex.parse(iv) : 
       CryptoJS.enc.Utf8.parse(iv)) : 
      CryptoJS.lib.WordArray.random(16);

    result = CryptoJS.AES.encrypt(
      base64 ? CryptoJS.enc.Base64.parse(data) : 
      hex ? CryptoJS.enc.Hex.parse(data) : 
      CryptoJS.enc.Utf8.parse(data),
      key,
      { iv: ivBytes, mode: cryptoJSMode }
    );
  }

  if (raw) {
    return { 
      data: new Uint8Array(result.sigBytes),
      iv: new Uint8Array(ivBytes.sigBytes)
    };
  }

  const output = decrypt ? 
    result.toString(CryptoJS.enc.Utf8) : 
    result.toString(base64 ? CryptoJS.enc.Base64 : hex ? CryptoJS.enc.Hex : CryptoJS.enc.Utf8);

  return { 
    data: output,
    iv: ivBytes.toString(base64 ? CryptoJS.enc.Base64 : hex ? CryptoJS.enc.Hex : CryptoJS.enc.Utf8)
  };
}

// Export for CommonJS
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { enc };
}