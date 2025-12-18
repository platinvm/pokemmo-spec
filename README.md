# PokéMMO Specifications

⚠️ **DISCLAIMER:** This is a work-in-progress reverse-engineered protocols documentation. This project is **NOT affiliated with PokéMMO** or its developers. This is for educational and research purposes only.

**Status:** Work in Progress

## Abstract

This document specifies the PokéMMO network protocols, including the Custom Transport Layer Security (CTLS) Protocol and application-level protocols (Login, Game, and Chat). CTLS provides confidentiality and authentication services through the use of Elliptic Curve Diffie-Hellman (ECDH) key exchange, Elliptic Curve Digital Signature Algorithm (ECDSA) authentication, and Advanced Encryption Standard in Counter mode (AES-CTR).

Unlike standard [TLS (RFC5246)](https://www.rfc-editor.org/info/rfc5246), CTLS is a simplified custom implementation. The application protocols operate over CTLS-secured connections and are currently being documented.

## Table of Contents

1. [Introduction](#introduction)
2. [Protocol Overview](#protocol-overview)
3. [Cryptographic Components](#cryptographic-components)
4. [Handshake Protocol](#handshake-protocol)
5. [Packet Structure](#packet-structure)
6. [Key Derivation](#key-derivation)
7. [Record Protocol](#record-protocol)
8. [Application Protocols](#application-protocols)

## Introduction

This specification documents the complete PokéMMO network protocol stack, including the transport security layer (CTLS) and application protocols.

The Custom Transport Layer Security (CTLS) Protocol establishes secure channels between client and server, providing server authentication, integrity protection, and confidentiality. It employs public key cryptography for server authentication and secret key cryptography for data protection.

CTLS consists of two phases:

- **Handshake Protocol** — Establishes server authentication, shared secrets, and cipher parameters.
- **Record Protocol** — Uses the negotiated keys and parameters to protect transmitted data.

Multiple application protocols (Login, Game, Chat) operate over separate CTLS-secured TCP connections.

## Protocol Overview

### Protocol Architecture

The PokéMMO protocol stack operates as follows:

```mermaid
graph TD
    A["Application Protocols<br/>(Login, Game, Chat, etc.)"]
    B["Record Framing Layer<br/>(Length prefixing, checksums)"]
    C["Transport Layer Security CTLS<br/>(Encryption, authentication)"]
    D["Transport TCP"]
    
    A --> B
    B --> C
    C --> D
```

The CTLS protocol operates at the transport layer, providing secure communication channels. Multiple TCP connections may be established, each running CTLS and supporting different application protocols.

### Handshake Process

The handshake protocol consists of three messages:

1. **ClientHello (0x00)** — Client initiates connection
2. **ServerHello (0x01)** — Server responds with public key and signature
3. **ClientReady (0x02)** — Client confirms with its public key

## Cryptographic Components

### Elliptic Curve

secp256r1 (P-256), 256-bit key size with uncompressed point format (65 bytes).

### Digital Signatures

ECDSA with SHA-256.

### Key Agreement

Elliptic Curve Diffie-Hellman (ECDH).

### Symmetric Encryption

AES in Counter (CTR) mode.

### Integrity Protection

- HMAC-SHA256
- CRC16

The checksum algorithm and size are negotiated during the ServerHello message.

## Handshake Protocol

### ClientHello

**Opcode:** 0x00

Initiates the TLS handshake with replay attack protection.

**Fields:**
- **Obfuscated Random Key** (8 bytes) — Random value XOR'd with predefined key1 constant
- **Obfuscated Timestamp** (8 bytes) — Client timestamp XOR'd with key2 and random key

**Structure:**
```c
struct ClientHello {
    int64_t obfuscated_random_key;
    int64_t obfuscated_timestamp;
};
```

### ServerHello

**Opcode:** 0x01

Contains the server's public key, authentication signature, and checksum algorithm.

**Fields:**
- **Public Key Length** (2 bytes, LE) — Length of the public key data (typically 65 bytes)
- **Server Public Key** (variable) — ECDSA public key in uncompressed point format (0x04 + X + Y coordinates)
- **Signature Length** (2 bytes, LE) — Length of the ECDSA signature (typically 64 bytes)
- **ECDSA Signature** (variable) — Digital signature of the public key using server's root private key
- **Checksum Size** (1 byte) — Size of checksums for subsequent packets (16 for HMAC-SHA256)

**Structure:**
```c
struct ServerHello {
    int16_t public_key_length;
    uint8_t  server_public_key[public_key_length];
    int16_t signature_length;
    uint8_t  ecdsa_signature[signature_length];
    int8_t  checksum_size;
};
```

### ClientReady

**Opcode:** 0x02

Completes the handshake by providing the client's public key.

**Fields:**
- **Public Key Length** (2 bytes, LE) — Length of the client's public key data (typically 65 bytes)
- **Client Public Key** (variable) — Client's ECDSA public key in uncompressed point format

**Structure:**
```c
struct ClientReady {
    int16_t public_key_length;
    uint8_t  client_public_key[public_key_length];
};
```

### State Machine

Both client and server follow this state machine:

```mermaid
sequenceDiagram
    participant Client
    participant Server
    
    Client->>Server: ClientHello<br/>(obfuscated keys)
    Note right of Client: Generate keys
    
    Note left of Server: Verify timestamp<br/>Generate keys
    Server->>Client: ServerHello<br/>(pk, signature, params)
    
    Note right of Client: Verify signature<br/>ECDH agreement<br/>Derive keys
    Client->>Server: ClientReady<br/>(client public key)
    
    Note left of Server: ECDH agreement<br/>Derive matching keys
    Note over Client,Server: Secure Channel Established<br/>Begin encryption
```

## Packet Structure

Length-prefixed format for all packets.

Handshake phase: unencrypted
Secure phase: encrypted and checksummed

## Key Derivation

Shared secret is derived using ECDH. Symmetric keys and initialization vectors are derived from the shared secret using triple-hash with SHA-256.

### Seed Values

Client and server seeds are 16-byte values derived from the ECDH shared secret.

Default values (used when _shared secret < 128 bits_):
- Client seed: `0x3f18f16272074418f46d919742a0fec9`
- Server seed: `0x1f9a803c99260a8b97ce0274ad3927b4`

If _shared secret >= 128 bits_, seeds are derived using triple-hash:
- Client seed: `triple-hash(shared_secret, "KeySalt" + 0x01)`
- Server seed: `triple-hash(shared_secret, "KeySalt" + 0x02)`

Triple-hash function:
```c
void triple_hash(unsigned char *output, 
                 const unsigned char *data1, size_t data1_len,
                 const unsigned char *data2, size_t data2_len) {
    SHA256_CTX ctx;
    unsigned char digest[32];
    
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data2, data2_len);
    SHA256_Update(&ctx, data1, data1_len);
    SHA256_Update(&ctx, data2, data2_len);
    SHA256_Final(digest, &ctx);
    
    memcpy(output, digest, 16);  // Use first 16 bytes
}
```

Note: Client uses server seed for incoming checksums, server uses client seed 
for incoming checksums (opposite of encryption key usage).

### Cipher Initialization

AES-128-CTR is used for encryption. Each endpoint maintains two cipher instances:
- Encryption cipher: uses own seed as key
- Decryption cipher: uses peer's seed as key

The IV for both ciphers is derived from the key using:
- `IV = triple-hash(seed, "IVDERIV")`

Example cipher setup (server perspective):
```c
// Encryption (outgoing): uses server seed
unsigned char encrypt_iv[16];
triple_hash(encrypt_iv, server_seed, 16, "IVDERIV", 7);
AES_CTR_init(&encrypt_cipher, server_seed, encrypt_iv);

// Decryption (incoming): uses client seed
unsigned char decrypt_iv[16];
triple_hash(decrypt_iv, client_seed, 16, "IVDERIV", 7);
AES_CTR_init(&decrypt_cipher, client_seed, decrypt_iv);
```

Client setup is reversed: encrypts with client seed, decrypts with server seed.

## Checksum Algorithms

Checksums are appended to encrypted packets and then wrapped in a length-prefixed frame (see [Record Protocol](#Record Protocol)). The PokeMMO client supports three checksum modes: NoOp, CRC16 and HMAC-SHA256.
The server decides which mode to use for this connection and sends this information to the client via the [ServerHello](#ServerHello).

|             | checksum_size      |
|-------------|--------------------|
| NoOp        | 0                  |
| CRC16       | 2                  |
| HMAC-SHA256 | 4-32 (default: 16) |

### CRC16

The CRC16 version used by PokeMMO matches the [CRC/ARC](https://reveng.sourceforge.io/crc-catalogue/16.htm) definition.

### HMAC-SHA256

This implementation uses HMAC-SHA256 with an incrementing round counter to 
authenticate messages. The checksum size can be configured between 4-32 bytes.

#### Initialization

Each endpoint maintains two checksum instances:
- Incoming: initialized with the peer's seed (client uses server seed, server uses client seed)
- Outgoing: initialized with own seed (client uses client seed, server uses server seed)
see [Seed Values](#Seed_Values).

Both instances start with _round counter = 0_.

#### Calculate

To generate a checksum for outgoing data:

1. Update HMAC with message bytes
2. Update HMAC with current round counter (4-byte big-endian integer)
3. Increment round counter
4. Finalize HMAC and truncate to configured size

Example in C:
```c
unsigned char round_bytes[4];
round_bytes[0] = (round >> 24) & 0xFF;
round_bytes[1] = (round >> 16) & 0xFF;
round_bytes[2] = (round >> 8) & 0xFF;
round_bytes[3] = round & 0xFF;

hmac_update(mac, message, message_len);
hmac_update(mac, round_bytes, 4);
round++;
hmac_final(mac, digest);
memcpy(checksum, digest, checksum_size);
```

#### Verify

To verify incoming data:

1. Update HMAC with message bytes
2. Update HMAC with current round counter (4-byte big-endian)
3. Increment round counter
4. Finalize HMAC, truncate, and compare with provided checksum

## Record Protocol

All packets are prefixed with a length field.

During handshake: `Length Prefix || Packet Data` (unencrypted)

After handshake: `Length Prefix || Encrypted Data || Checksum`

## Application Protocols

The PokéMMO system uses three main application protocols, each operating over its own dedicated TCP connection with the CTLS security layer.

**Status:** Work in progress

### Login Protocol

Documentation in progress.

### Game Protocol

Documentation in progress.

### Chat Protocol

Documentation in progress.


# References
- [openmmo](https://github.com/fiereu/openmmo)
