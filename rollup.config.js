import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import terser from '@rollup/plugin-terser';

/**
 * Rollup configuration for WebOpenSSL library.
 * Builds UMD, ESM, and minified bundles.
 * 
 * Outputs:
 * - lib/webopenssl.mjs (ESM)
 * - lib/webopenssl.js (UMD for browsers/CommonJS)
 * - lib/webopenssl.min.js (minified UMD)
 */

const config = [
  // ESM build
  {
    input: 'src/index.js',
    output: {
      file: 'lib/webopenssl.mjs',
      format: 'es',
      sourcemap: true
    },
    plugins: [
      resolve({
        browser: true,
        preferBuiltins: false
      }),
      commonjs(),
      terser({
        compress: {
          drop_console: false,
          drop_debugger: true
        },
        format: {
          comments: false
        }
      })
    ],
    external: ['crypto-js', 'node-forge', 'asn1.js']
  },

  // UMD build (browser/CommonJS compatible)
  {
    input: 'src/index.js',
    output: {
      file: 'lib/webopenssl.js',
      format: 'umd',
      name: 'webopenssl',
      sourcemap: true,
      globals: {
        'crypto-js': 'CryptoJS',
        'node-forge': 'forge',
        'asn1.js': 'asn1'
      }
    },
    plugins: [
      resolve({
        browser: true,
        preferBuiltins: false
      }),
      commonjs({
        include: ['node_modules/**']
      }),
      terser({
        compress: {
          drop_console: false,
          drop_debugger: true
        },
        format: {
          comments: 'some'
        }
      })
    ]
  },

  // Minified UMD build
  {
    input: 'src/index.js',
    output: {
      file: 'lib/webopenssl.min.js',
      format: 'umd',
      name: 'webopenssl',
      sourcemap: true,
      globals: {
        'crypto-js': 'CryptoJS',
        'node-forge': 'forge',
        'asn1.js': 'asn1'
      }
    },
    plugins: [
      resolve({
        browser: true,
        preferBuiltins: false
      }),
      commonjs({
        include: ['node_modules/**']
      }),
      terser({
        compress: {
          drop_console: true,
          drop_debugger: true,
          pure_funcs: ['console.log']
        },
        format: {
          comments: false
        },
        mangle: {
          toplevel: true
        }
      })
    ]
  }
];

export default config;