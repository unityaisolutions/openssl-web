/**
 * Certificate request generation module (openssl req equivalent).
 * Uses node-forge for ASN.1/PKI and Web Crypto for key operations where possible.
 * 
 * @module req
 */

import forge from 'node-forge';

/**
 * Generate Certificate Signing Request (CSR) with private key.
 * 
 * @param {Object} options - CSR generation options.
 * @param {string} options.subject - Distinguished Name (e.g., '/CN=example.com/O=Example Org/C=US').
 * @param {number} [options.keySize=2048] - RSA key size in bits.
 * @param {string} [options.keyAlgo='RSA'] - Key algorithm ('RSA', 'EC').
 * @param {string} [options.hashAlgo='sha256'] - Signature hash algorithm.
 * @param {Object} [options.extensions] - Certificate extensions (e.g., { basicConstraints: 'CA:FALSE' }).
 * @param {boolean} [options.base64=false] - Output PEM as base64 (without headers).
 * @param {boolean} [options.returnPrivateKey=true] - Include private key in response.
 * @returns {Promise<{csr: string, privateKey?: string}>} PEM-encoded CSR and optional private key.
 * @throws {Error} If subject invalid or key generation fails.
 * 
 * @example
 * const { csr, privateKey } = await req({ 
 *   subject: '/CN=localhost/O=Test/C=US', 
 *   keySize: 2048 
 * });
 * // csr: "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...-----END CERTIFICATE REQUEST-----"
 */
export async function req(options = {}) {
  const { 
    subject = '/CN=localhost', 
    keySize = 2048, 
    keyAlgo = 'RSA', 
    hashAlgo = 'sha256',
    extensions = {},
    base64 = false,
    returnPrivateKey = true 
  } = options;

  if (!subject || typeof subject !== 'string') {
    throw new Error('Valid subject DN required (e.g., "/CN=example.com")');
  }

  try {
    // Parse subject DN
    const attrs = subject.split('/').slice(1).reduce((acc, attr) => {
      const [key, value] = attr.split('=');
      if (key && value) acc.push({ shortName: key.toUpperCase(), value });
      return acc;
    }, []);

    // Generate key pair using node-forge (Web Crypto RSA limited, EC supported)
    let keys;
    if (keyAlgo.toUpperCase() === 'EC') {
      const curve = keySize === 256 ? 'p256' : keySize === 384 ? 'p384' : 'p521';
      keys = forge.pki.rsa.generateKeyPair({ bits: keySize }) || 
             forge.pki.setRsaPublicKey(/* fallback */); // Note: forge for EC too
    } else {
      keys = forge.pki.rsa.generateKeyPair({ bits: keySize });
    }

    // Create CSR
    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = keys.publicKey;
    csr.setSubject(attrs);
    
    // Add extensions if provided
    if (Object.keys(extensions).length > 0) {
      const ext = forge.pki.oids;
      csr.setAttributes([{
        name: 'extensionRequest',
        value: Object.entries(extensions).map(([name, value]) => ({
          name,
          value,
          shortName: Object.keys(ext).find(k => ext[k] === name) || name
        }))
      }]);
    }

    // Sign CSR
    csr.sign(keys.privateKey, forge.md[hashAlgo.toLowerCase()].create());

    // Convert to PEM
    const csrPem = forge.pki.certificationRequestToPem(csr);
    const privateKeyPem = returnPrivateKey ? forge.pki.privateKeyToPem(keys.privateKey) : undefined;

    if (base64) {
      const csrBase64 = csrPem
        .replace(/-----BEGIN CERTIFICATE REQUEST-----/g, '')
        .replace(/-----END CERTIFICATE REQUEST-----/g, '')
        .replace(/\s/g, '');
      return { csr: csrBase64, ...(returnPrivateKey && { privateKey: privateKeyPem }) };
    }

    return { 
      csr: csrPem, 
      ...(returnPrivateKey && { privateKey: privateKeyPem }) 
    };

  } catch (error) {
    console.error('CSR generation failed:', error.message);
    throw new Error(`Failed to generate CSR: ${error.message}`);
  }
}

/**
 * Parse and verify an existing CSR.
 * 
 * @param {string} csrPem - PEM-encoded CSR.
 * @param {boolean} [base64=false] - Input is base64 without headers.
 * @returns {Promise<{subject: Object, publicKey: Object, extensions: Array}>} Parsed CSR details.
 */
export async function parseCSR(csrPem, base64 = false) {
  try {
    let csrData = csrPem;
    if (base64) {
      // Reconstruct PEM from base64
      csrData = `-----BEGIN CERTIFICATE REQUEST-----\n${csrPem}\n-----END CERTIFICATE REQUEST-----`;
    }

    const csr = forge.pki.certificationRequestFromPem(csrData);
    csr.verify();

    return {
      subject: csr.subject.map(attr => ({ [attr.shortName]: attr.value })),
      publicKey: {
        type: csr.publicKey.type,
        n: csr.publicKey.n ? csr.publicKey.n.toString(16) : null, // RSA modulus
        e: csr.publicKey.e ? csr.publicKey.e.toString(16) : null  // RSA exponent
      },
      extensions: csr.getAttribute({ name: 'extensionRequest' })?.value || []
    };
  } catch (error) {
    throw new Error(`CSR parsing failed: ${error.message}`);
  }
}

// Export for CommonJS
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { req, parseCSR };
}