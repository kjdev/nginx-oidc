# JWT Supported Algorithms

A list of algorithms supported for JWT verification by the nginx OIDC module.

## Supported Algorithms

| Algorithm | Key Type | Curve | Recommendation |
|-----------|----------|-------|----------------|
| RS256 | RSA | — | Recommended (most widely supported) |
| RS384 | RSA | — | Supported |
| RS512 | RSA | — | Supported |
| PS256 | RSA | — | Supported |
| PS384 | RSA | — | Supported |
| PS512 | RSA | — | Supported |
| ES256 | EC | P-256 | Recommended (fast, small signatures) |
| ES256K | EC | secp256k1 | Supported |
| ES384 | EC | P-384 | Supported |
| ES512 | EC | P-521 | Supported |
| EdDSA | OKP | Ed25519 | Recommended (best performance) |
| EdDSA | OKP | Ed448 | Supported |

### RSA Algorithms (Key Type: RSA)

Both RSA-PKCS1 (RS256/RS384/RS512) and RSA-PSS (PS256/PS384/PS512) are supported. A total of 6 algorithms are available.

### ECDSA Algorithms (Key Type: EC)

The P-256, P-384, P-521, and secp256k1 curves are supported. A total of 4 algorithms are available: ES256, ES256K, ES384, and ES512.

### EdDSA Algorithms (Key Type: OKP)

The Ed25519 and Ed448 curves are supported.

## Unsupported Algorithms

### HMAC (Symmetric Key Cryptography)

HS256/HS384/HS512 are not supported. Symmetric key algorithms are not recommended for OpenID Connect, and this module implements only public key cryptography.

## at_hash Verification

When the ID Token contains an `at_hash` claim, the binding with the access token is automatically verified. This is supported for all supported algorithms (RS*/ES*/PS*/EdDSA).

## Recommended Algorithms

Recommendation order for OpenID Connect implementations:

1. **RS256** - Most widely supported
2. **ES256** - Fast, small signature size
3. **EdDSA (Ed25519)** - Best security and performance

## Related Documents

- [README.md](../README.md): Module overview
- [DIRECTIVES.md](DIRECTIVES.md): Directives and variables reference
- [EXAMPLES.md](EXAMPLES.md): Quick start and practical configuration examples
- [INSTALL.md](INSTALL.md): Installation guide (prerequisites, build instructions)
- [SECURITY.md](SECURITY.md): Security considerations (PKCE, HTTPS, cookie security, etc.)
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): Troubleshooting (common issues, log inspection)
- [COMMERCIAL_COMPATIBILITY.md](COMMERCIAL_COMPATIBILITY.md): Commercial version compatibility
