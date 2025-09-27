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
    console.log('enc: input type=string, value=', input.substring(0, 50) + '...', 'base64=', base64, 'hex=', hex);
    if (base64) {
      try {
        const decoded = atob(input);
        console.log('enc: base64 decoded length=', decoded.length, 'first chars=', decoded.substring(0, 20));
        data = Uint8Array.from(decoded, c => {
          if (typeof c !== 'string') {
            console.error('enc: non-string char in base64 decode, type=', typeof c, 'value=', c);
            throw new Error('Invalid base64 decoding: non-string character');
          }
          return c.charCodeAt(0);
        });
      } catch (e) {
        console.error('enc: base64 decode failed for input=', input.substring(0, 50) + '...', 'error=', e.message);
        throw new Error(`Base64 decode failed: ${e.message}. Ensure input is valid base64 when base64=true.`);
      }
    } else if (hex) {
      const hexMatch = input.match(/.{1,2}/g);
      if (!hexMatch) throw new Error('Invalid hex input');
      data = new Uint8Array(hexMatch.map(byte => parseInt(byte, 16)));
    } else {
      data = new TextEncoder().encode(input);
    }
  } else if (input instanceof Uint8Array) {
    data = input;
    console.log('enc: input type=Uint8Array, length=', data.length);
  } else if (input instanceof ArrayBuffer) {
    data = new Uint8Array(input);
    console.log('enc: input type=ArrayBuffer, length=', data.length);
  } else {
    console.error('enc: unsupported input type=', typeof input, 'instanceof=', input instanceof Object ? input.constructor.name : 'n/a');
    throw new Error('Unsupported input type');
  }

  // Parse algorithm
  const [cipher, mode] = algorithm.split('-');
  const keyLength = parseInt(algorithm.match(/(\d+)/)?.[0]) || 256;
  const isGCM = mode === 'GCM';

  if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
    try {
      // Generate or parse salt
      let finalSalt;
      if (salt) {
        console.log('enc: salt provided, type=string, value=', salt.substring(0, 50) + '...', 'base64=', base64, 'hex=', hex);
        if (base64) {
          try {
            const decodedSalt = atob(salt);
            console.log('enc: salt base64 decoded length=', decodedSalt.length);
            finalSalt = Uint8Array.from(decodedSalt, c => {
              if (typeof c !== 'string') {
                console.error('enc: non-string char in salt base64 decode, type=', typeof c, 'value=', c);
                throw new Error('Invalid base64 salt: non-string character');
              }
              return c.charCodeAt(0);
            });
          } catch (e) {
            console.error('enc: salt base64 decode failed, error=', e.message);
            throw new Error(`Salt base64 decode failed: ${e.message}`);
          }
        } else if (hex) {
          const hexMatch = salt.match(/.{1,2}/g);
          if (!hexMatch) throw new Error('Invalid hex salt');
          finalSalt = new Uint8Array(hexMatch.map(b => parseInt(b, 16)));
        } else {
          finalSalt = new TextEncoder().encode(salt);
        }
      } else {
        finalSalt = window.crypto.getRandomValues(new Uint8Array(16));
        console.log('enc: auto-generated salt, length=16');
      }

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
        console.log('enc: iv provided, type=string, value=', iv.substring(0, 50) + '...', 'base64=', base64, 'hex=', hex);
        if (base64) {
          try {
            const decodedIV = atob(iv);
            console.log('enc: iv base64 decoded length=', decodedIV.length);
            finalIV = Uint8Array.from(decodedIV, c => {
              if (typeof c !== 'string') {
                console.error('enc: non-string char in iv base64 decode, type=', typeof c, 'value=', c);
                throw new Error('Invalid base64 IV: non-string character');
              }
              return c.charCodeAt(0);
            });
          } catch (e) {
            console.error('enc: iv base64 decode failed, error=', e.message);
            throw new Error(`IV base64 decode failed: ${e.message}`);
          }
        } else if (hex) {
          const hexMatch = iv.match(/.{1,2}/g);
          if (!hexMatch) throw new Error('Invalid hex IV');
          finalIV = new Uint8Array(hexMatch.map(b => parseInt(b, 16)));
        } else {
          finalIV = new TextEncoder().encode(iv);
        }
      } else {
        finalIV = window.crypto.getRandomValues(new Uint8Array(16));
        console.log('enc: auto-generated IV, length=16');
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

  // Handle salt properly
  let finalSalt;
  if (salt) {
    if (salt instanceof Uint8Array) {
      finalSalt = CryptoJS.lib.WordArray.create(salt);
    } else if (typeof salt === 'string') {
      if (base64) {
        finalSalt = CryptoJS.enc.Base64.parse(salt);
      } else if (hex) {
        finalSalt = CryptoJS.enc.Hex.parse(salt);
      } else {
        finalSalt = CryptoJS.enc.Utf8.parse(salt);
      }
    } else {
      finalSalt = CryptoJS.lib.WordArray.random(16);
    }
  } else {
    finalSalt = CryptoJS.lib.WordArray.random(16);
  }

  const key = CryptoJS.PBKDF2(password, finalSalt, {
    keySize,
    iterations: iterations || 10000,
    hasher: CryptoJS.algo.SHA256
  });

  let result;
  if (decrypt) {
    // For decrypt, data is ciphertext - must be in specified format (string)
    let ciphertext;
    if (base64) {
      ciphertext = CryptoJS.enc.Base64.parse(data);
    } else if (hex) {
      ciphertext = CryptoJS.enc.Hex.parse(data);
    } else {
      // Default to base64 for binary ciphertext
      ciphertext = CryptoJS.enc.Base64.parse(data);
    }

    const ivBytes = iv ?
      (base64 ? CryptoJS.enc.Base64.parse(iv) :
       hex ? CryptoJS.enc.Hex.parse(iv) :
       CryptoJS.enc.Utf8.parse(iv)) :
      CryptoJS.lib.WordArray.random(16);

    result = CryptoJS.AES.decrypt(
      { ciphertext },
      key,
      { iv: ivBytes, mode: cryptoJSMode }
    );
  } else {
    // For encrypt, data is plaintext - convert Uint8Array to WordArray or parse formatted
    let plaintext;
    if (data instanceof Uint8Array) {
      plaintext = CryptoJS.lib.WordArray.create(data);
    } else if (base64) {
      plaintext = CryptoJS.enc.Base64.parse(data);
    } else if (hex) {
      plaintext = CryptoJS.enc.Hex.parse(data);
    } else {
      plaintext = CryptoJS.enc.Utf8.parse(data);
    }

    const ivBytes = iv ?
      (base64 ? CryptoJS.enc.Base64.parse(iv) :
       hex ? CryptoJS.enc.Hex.parse(iv) :
       CryptoJS.enc.Utf8.parse(iv)) :
      CryptoJS.lib.WordArray.random(16);

    result = CryptoJS.AES.encrypt(
      plaintext,
      key,
      { iv: ivBytes, mode: cryptoJSMode }
    );
  }

  if (raw) {
    let outputData;
    if (decrypt) {
      // For decrypt raw, convert UTF-8 string result to bytes
      outputData = CryptoJS.enc.Utf8.parse(result.toString(CryptoJS.enc.Utf8));
    } else {
      // For encrypt raw, use ciphertext WordArray
      outputData = result.ciphertext;
    }
    return {
      data: new Uint8Array(outputData.sigBytes),
      iv: new Uint8Array(ivBytes.sigBytes),
      ...(salt && { salt: new Uint8Array(finalSalt.sigBytes) })
    };
  }

  const output = decrypt ?
    result.toString(CryptoJS.enc.Utf8) :
    result.toString(base64 ? CryptoJS.enc.Base64 : hex ? CryptoJS.enc.Hex : CryptoJS.enc.Utf8);

  const ivOutput = ivBytes.toString(base64 ? CryptoJS.enc.Base64 : hex ? CryptoJS.enc.Hex : CryptoJS.enc.Utf8);
  const saltOutput = salt ? finalSalt.toString(base64 ? CryptoJS.enc.Base64 : hex ? CryptoJS.enc.Hex : CryptoJS.enc.Utf8) : undefined;

  return {
    data: output,
    iv: ivOutput,
    ...(saltOutput && { salt: saltOutput })
  };
}

// Export for CommonJS
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { enc };
}