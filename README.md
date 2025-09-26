# WebOpenSSL

[![License: MIT](https://img.shields.io/badge/License-Apache2.0-yellow.svg)](https://opensource.org/license/apache-2-0)
[![Browser Support](https://img.shields.io/badge/browser-Chrome%2037%2B%20%7C%20Firefox%2034%2B%20%7C%20Safari%207.1%2B-blue.svg)](https://caniuse.com/webcrypto-api)

A JavaScript library that emulates a subset of OpenSSL functionality for web environments. Built with the [Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) for secure, hardware-backed cryptographic operations, with graceful fallbacks using CryptoJS for legacy browser support.

## Features

WebOpenSSL provides async JavaScript APIs that mirror OpenSSL CLI commands:

- **rand** - Secure random byte generation (`openssl rand -base64 32`)
- **dgst** - Message digests/hashing (`openssl dgst -sha256`)
- **enc** - Symmetric encryption/decryption (`openssl enc -aes-256-cbc`)
- **req** - Certificate Signing Request generation (`openssl req -new`)

### Security & Compliance

- **FIPS-like Security**: Uses NIST-approved algorithms via Web Crypto API (AES-256-CBC/GCM, SHA-256/384/512)
- **Hardware-backed Operations**: Leverages browser crypto engines for true randomness and secure key storage
- **Fallback Strategy**: CryptoJS polyfills for unsupported algorithms (MD5) or legacy browsers, with clear security warnings
- **No Custom Crypto**: All implementations use battle-tested libraries; no homegrown algorithms

**Browser Compatibility**:
- ✅ Chrome 37+ / Edge 12+
- ✅ Firefox 34+
- ✅ Safari 7.1+ / iOS Safari 8+
- ⚠️ IE11: CryptoJS fallback only (reduced security)
- ❌ Older browsers: Limited functionality

## Installation

```bash
npm install webopenssl-advanced
```

Or use via CDN for browser-only:

```html
<script src="https://unpkg.com/webopenssl-advanced@latest/lib/webopenssl.min.js"></script>
```

## Quick Start

### Browser Usage (UMD)

```html
<!DOCTYPE html>
<html>
<head>
    <script src="lib/webopenssl.min.js"></script>
</head>
<body>
    <script>
        // Generate random base64 key (equivalent to: openssl rand -base64 32)
        webopenssl.rand({ base64: true, length: 32 }).then(key => {
            console.log('Random Key:', key);
            // Output: "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd"
        });

        // Hash data (equivalent to: echo "Hello World" | openssl dgst -sha256)
        webopenssl.dgst({ algorithm: 'SHA-256', input: 'Hello World', hex: true }).then(hash => {
            console.log('SHA-256:', hash);
            // Output: "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
        });

        // Encrypt data (equivalent to: echo "secret" | openssl enc -aes-256-cbc -a -salt -k passphrase)
        webopenssl.enc({
            algorithm: 'AES-256-CBC',
            input: 'Secret message',
            password: 'passphrase',
            base64: true
        }).then(result => {
            console.log('Encrypted:', result.data);
            console.log('IV:', result.iv);
            console.log('Salt:', result.salt);
        });
    </script>
</body>
</html>
```

### Module Usage (ESM/CommonJS)

```javascript
import webopenssl from 'webopenssl-advanced';

// Or CommonJS
const webopenssl = require('webopenssl-advanced');

// Random generation
const randomKey = await webopenssl.rand({ base64: true, length: 32 });
console.log('Key:', randomKey);

// Hashing
const hash = await webopenssl.dgst({ 
    algorithm: 'SHA-256', 
    input: 'Hello World', 
    hex: true 
});
console.log('Hash:', hash);

// Encryption
const encrypted = await webopenssl.enc({
    algorithm: 'AES-256-CBC',
    input: 'Secret message',
    password: 'mysecretpass'
});
console.log('Encrypted:', encrypted.data);

// CSR Generation
const csr = await webopenssl.req({
    subject: '/CN=example.com/O=Example Org/C=US',
    keySize: 2048
});
console.log('CSR:', csr.csr);
console.log('Private Key:', csr.privateKey);
```

## API Reference

### `webopenssl.rand(options)`

Generate cryptographically secure random bytes.

**Parameters**:
- `options.length` (number, default: 32): Number of random bytes
- `options.base64` (boolean, default: false): Output as base64 string
- `options.hex` (boolean, default: false): Output as hexadecimal string
- `options.raw` (boolean, default: false): Return Uint8Array

**Returns**: `Promise<string|Uint8Array>`

**Example**:
```javascript
// Equivalent to: openssl rand -base64 32
const key = await webopenssl.rand({ base64: true, length: 32 });
```

### `webopenssl.dgst(options)`

Compute message digest (hash) of input data.

**Parameters**:
- `options.algorithm` (string, required): `'SHA-256'`, `'SHA-512'`, `'SHA-1'`, `'MD5'`
- `options.input` (string|Uint8Array|ArrayBuffer, required): Data to hash
- `options.base64` (boolean, default: false): Output as base64
- `options.hex` (boolean, default: true): Output as hex
- `options.raw` (boolean, default: false): Return ArrayBuffer

**Returns**: `Promise<string|ArrayBuffer>`

**Example**:
```javascript
// Equivalent to: echo "Hello" | openssl dgst -sha256 -hex
const hash = await webopenssl.dgst({ 
    algorithm: 'SHA-256', 
    input: 'Hello World', 
    hex: true 
});
```

### `webopenssl.enc(options)`

Symmetric encryption/decryption using password-based key derivation.

**Parameters**:
- `options.algorithm` (string, default: `'AES-256-CBC'`): `'AES-256-CBC'`, `'AES-128-CBC'`, `'AES-256-GCM'`
- `options.input` (string|Uint8Array|ArrayBuffer, required): Data to encrypt/decrypt
- `options.decrypt` (boolean, default: false): Decryption mode
- `options.password` (string, required): Password for key derivation
- `options.iv` (string, optional): Initialization vector (auto-generated for encryption)
- `options.salt` (string, optional): Salt for PBKDF2 (auto-generated for encryption)
- `options.iterations` (number, default: 10000): PBKDF2 iterations
- `options.base64` (boolean, default: false): Base64 input/output
- `options.hex` (boolean, default: false): Hex input/output
- `options.raw` (boolean, default: false): Raw byte output

**Returns**: `Promise<{data: string|Uint8Array, iv?: string, salt?: string}>`

**Example**:
```javascript
// Encrypt (equivalent to: echo "secret" | openssl enc -aes-256-cbc -a -salt -k mypass)
const encrypted = await webopenssl.enc({
    algorithm: 'AES-256-CBC',
    input: 'Secret message',
    password: 'mypassword',
    base64: true
});
// { data: "U2FsdGVkX1+...", iv: "abc...", salt: "xyz..." }

// Decrypt using the same parameters + IV/salt from encryption
const decrypted = await webopenssl.enc({
    algorithm: 'AES-256-CBC',
    input: encrypted.data,
    password: 'mypassword',
    iv: encrypted.iv,
    salt: encrypted.salt,
    decrypt: true,
    base64: true
});
// { data: "Secret message" }
```

### `webopenssl.req(options)`

Generate Certificate Signing Request (CSR) with private key.

**Parameters**:
- `options.subject` (string, required): Distinguished Name (e.g., `'/CN=example.com/O=Org/C=US'`)
- `options.keySize` (number, default: 2048): RSA key size in bits
- `options.keyAlgo` (string, default: `'RSA'`): `'RSA'` or `'EC'`
- `options.hashAlgo` (string, default: `'sha256'`): Signature hash algorithm
- `options.extensions` (object, optional): Certificate extensions
- `options.returnPrivateKey` (boolean, default: true): Include private key
- `options.base64` (boolean, default: false): Base64 PEM without headers

**Returns**: `Promise<{csr: string, privateKey?: string}>`

**Example**:
```javascript
// Equivalent to: openssl req -new -keyout private.pem -out req.csr -subj "/CN=test.com"
const result = await webopenssl.req({
    subject: '/CN=localhost/O=WebOpenSSL Demo/C=US',
    keySize: 2048,
    hashAlgo: 'sha256'
});
// { csr: "-----BEGIN CERTIFICATE REQUEST-----...", privateKey: "-----BEGIN PRIVATE KEY-----..." }
```

### `webopenssl.parseCSR(csrPem, base64?)`

Parse and analyze an existing CSR.

**Parameters**:
- `csrPem` (string, required): PEM-encoded CSR
- `base64` (boolean, default: false): Input is base64 without PEM headers

**Returns**: `Promise<{subject: Array, publicKey: Object, extensions: Array}>`

**Example**:
```javascript
const analysis = await webopenssl.parseCSR(csrPem);
console.log('Subject:', analysis.subject);
console.log('Public Key Type:', analysis.publicKey.type);
```

### `webopenssl.isWebCryptoAvailable()`

Check if Web Crypto API is available (secure mode).

**Returns**: `boolean`

## Security Considerations

### Algorithm Support

| Operation | Web Crypto (Secure) | Fallback (CryptoJS) | FIPS Approved |
|-----------|-------------------|-------------------|---------------|
| Random | `crypto.getRandomValues()` | `CryptoJS.lib.WordArray.random()` | ✅ |
| SHA-256/384/512 | `crypto.subtle.digest()` | `CryptoJS.SHA256()` | ✅ |
| SHA-1 | `crypto.subtle.digest()` | `CryptoJS.SHA1()` | ⚠️ (Legacy) |
| MD5 | ❌ Not supported | `CryptoJS.MD5()` | ❌ (Insecure) |
| AES-256-CBC/GCM | `crypto.subtle.encrypt()` | `CryptoJS.AES` | ✅ |
| RSA Key Gen | Limited (via node-forge) | `forge.pki.rsa.generateKeyPair()` | ✅ |
| CSR Generation | node-forge (ASN.1) | node-forge | ✅ |

### Key Derivation

- **Primary**: PBKDF2 with SHA-256 (10,000 iterations default)
- **Salt**: 16 random bytes (auto-generated for encryption)
- **IV**: 16 random bytes for CBC mode (auto-generated)

### Browser Security Features

- **Secure Context Required**: Web Crypto API only works on HTTPS or localhost
- **Same-Origin Policy**: All operations are sandboxed to the current origin
- **No Key Export**: Generated keys cannot be extracted from Web Crypto (security feature)

### Recommendations

1. **Always use HTTPS** in production
2. **Avoid MD5/SHA-1** for security-sensitive applications
3. **Use strong passwords** (≥16 characters, high entropy)
4. **Increase PBKDF2 iterations** for high-security applications (≥100,000)
5. **Store private keys securely** - never expose in client-side code
6. **Validate all inputs** before cryptographic operations

## Distribution Formats

The library ships in multiple formats for different environments:

| File | Format | Use Case | Size |
|------|--------|----------|------|
| `lib/webopenssl.min.js` | UMD | Browser `<script>` tag | ~45KB (min+gzip) |
| `lib/webopenssl.js` | UMD | Browser/CommonJS | ~120KB |
| `lib/webopenssl.mjs` | ESM | Modern bundlers (Webpack, Rollup) | ~110KB |
| `dist/` | Source maps | Development/debugging | Varies |

### CDN Usage

```html
<!-- Unpkg -->
<script src="https://unpkg.com/webopenssl-advanced@1.0.0/lib/webopenssl.min.js"></script>

<!-- jsDelivr -->
<script src="https://cdn.jsdelivr.net/npm/webopenssl-advanced@1.0.0/lib/webopenssl.min.js"></script>
```

### NPM Package Structure

```
webopenssl-advanced/
├── lib/
│   ├── webopenssl.min.js     # Production UMD (minified)
│   ├── webopenssl.js         # Development UMD
│   ├── webopenssl.mjs        # ESM module
│   └── webopenssl.d.ts       # TypeScript definitions
├── demo/
│   └── index.html            # Interactive showcase
├── src/                      # Source code
├── package.json
└── README.md
```

## Build & Development

### Prerequisites

- Node.js ≥ 14
- npm ≥ 6

### Development Workflow

```bash
# Install dependencies
npm install

# Development build (watch mode)
npm run dev

# Production build
npm run build

# Serve demo on http://localhost:3000
npm run serve

# Build and serve demo
npm start
```

### Running the Demo

The interactive demo showcases all library functionality:

```bash
# Serve demo at http://localhost:3000
npm run serve

# Or build everything and serve
npm start
```

Open [http://localhost:3000](http://localhost:3000) to try:
- 🔐 Random key generation (base64/hex)
- 🔑 Hash computation (SHA-256, MD5, etc.)
- 🔒 AES encryption/decryption with password
- 📜 CSR generation and parsing

### Custom Build

To create a custom build excluding certain modules (e.g., no CSR support):

```javascript
// In rollup.config.js, modify input to tree-shake modules
export default {
  input: 'src/index.js',
  // ... other config
  treeshake: {
    moduleSideEffects: false
  }
};
```

## Demo

Try the hosted interactive demo at [https://webopenssl-demo.vercel.app/](https://webopenssl-demo.vercel.app/) or locally [localhost:3000](localhost:3000) after running:

```bash
npm start
```

![Demo Screenshot](https://i.ibb.co/gMrb7W68/Screenshot-2025-09-26-12-07-03.png)

The demo showcases all four commands with real-time validation and Web Crypto status indicators.

## TypeScript Support

Full TypeScript definitions included:

```typescript
import webopenssl from 'webopenssl-advanced';

interface EncOptions {
  algorithm?: 'AES-256-CBC' | 'AES-128-CBC' | 'AES-256-GCM';
  input: string | Uint8Array | ArrayBuffer;
  decrypt?: boolean;
  password: string;
  iv?: string;
  salt?: string;
  iterations?: number;
  base64?: boolean;
  hex?: boolean;
  raw?: boolean;
}

const result: Promise<{
  data: string | Uint8Array;
  iv?: string;
  salt?: string;
}> = webopenssl.enc(options);
```

## Limitations

1. **No Asymmetric Signing**: Web Crypto RSA signing limited; CSR uses node-forge
2. **No X.509 Certificates**: Full certificate parsing/creation requires additional libraries
3. **Browser Sandbox**: Cannot access system crypto stores or hardware tokens
4. **Size**: Bundled dependencies (~120KB) due to comprehensive crypto support
5. **Legacy Browsers**: IE11/older Safari use CryptoJS (software-only, slower)

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -am 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Development Setup

```bash
git clone https://github.com/unityaisolutions/openssl-web.git
cd openssl-web
npm install
npm run dev  # Watch mode for development
npm start    # Build and serve demo
```

## License

This project is [Apache 2.0](LICENSE) licensed. See the [LICENSE](LICENSE) file for details.

## Security

For security issues, please contact unityaisolutions@outlook.com instead of opening GitHub issues. We take security seriously and will respond within 72 hours. If you'd like, enable encryption in Outlook for extra security.

### Responsible Disclosure

If you discover a security vulnerability:
1. Do not share it publicly
2. Contact the maintainers privately
3. We will work with you to resolve the issue

## Support

- [Documentation](README.md)
- [Demo](https://webopenssl-demo.vercel.app/)
- [API Reference](#api-reference)

---

**WebOpenSSL - Secure cryptography for the modern web** 🚀
