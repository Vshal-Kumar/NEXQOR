# QRYPTONEX Hybrid Protocol Specification & Architectural Design

## 1. Protocol Overview

The **QRYPTONEX Hybrid Cryptographic Suite** (`QRYPTONEX-HYBRID-X25519-MLKEM768-ED25519-MLDSA65`) defines a unified, defense-in-depth secure communication protocol designed to withstand both classical cryptanalytic attacks and future quantum computing threats (Harvest-Now-Decrypt-Later and quantum signature forgery).

Unlike simple wrapper architectures that layer independent handshakes sequentially, this protocol executes a single, coherent cryptographic handshake where classical and post-quantum mechanisms are tightly coupled into canonical transcript hashes, length-prefixed key material derivations, and dual signature authentication.

### Cryptographic Suite Profile

| Protocol Phase | Component | Algorithm | Standard | Key / Output Size |
|---|---|---|---|---|
| **Key Agreement (Classical)** | Ephemeral ECDH | X25519 | RFC 7748 | 32-byte public key, 32-byte shared secret |
| **Key Agreement (PQC)** | Ephemeral KEM | ML-KEM-768 | FIPS 203 | 1184-byte encapsulation key, 1088-byte ciphertext, 32-byte shared secret |
| **Authentication (Classical)** | Identity Signature | Ed25519 | RFC 8032 | 32-byte public key, 64-byte signature |
| **Authentication (PQC)** | Identity Signature | ML-DSA-65 | FIPS 204 | 1952-byte public key, 3309-byte signature |
| **Key Derivation** | Dual-Extract KDF | HKDF-SHA-384 | RFC 5869 | 48-byte PRK, 32-byte traffic keys |
| **Transcript Hashing** | Cryptographic Hash | SHA-384 | FIPS 180-4 | 48-byte digest |
| **Session Encryption** | Authenticated AEAD | ChaCha20-Poly1305 | RFC 8439 | 32-byte key, 12-byte nonce, 16-byte tag |
| **Anti-Replay Protection** | Sliding Window | RFC 6479 | RFC 6479 / IPsec | 64-packet sliding bitmap with pre-auth check |

---

## 2. Handshake State Machine

The handshake implements an explicit, fail-closed state machine. Any transition out of expected sequence, malformed payload, or verification failure transitions the context immediately to `HYBRID_STATE_FAILED` and wipes all intermediate key material.

```
                  Client                                     Server
                    |                                          |
[HYBRID_STATE_INIT] |                                          | [HYBRID_STATE_INIT]
                    |            1. CLIENT_HELLO               |
                    | ---------------------------------------> | [HYBRID_STATE_CLIENT_HELLO_RECV]
[HYBRID_STATE_CLIENT_HELLO_SENT]                               |
                    |                                          | Compute KEX (X25519 + ML-KEM)
                    |                                          | Sign Server Transcript
                    |            2. SERVER_HELLO               |
                    | <--------------------------------------- | [HYBRID_STATE_SERVER_HELLO_SENT]
[HYBRID_STATE_SERVER_HELLO_RECV]                               |
Verify Server Dual Sig                                         |
Compute KEX (X25519 + ML-KEM)                                  |
Derive Directional Keys                                        |
[HYBRID_STATE_KEY_ESTABLISHED]                                 |
Sign Client Transcript                                         |
                    |            3. CLIENT_AUTH                |
                    | ---------------------------------------> | Verify Client Dual Sig
[HYBRID_STATE_ESTABLISHED]                                     | [HYBRID_STATE_ESTABLISHED]
                    |                                          |
                    | <====== ChaCha20-Poly1305 Traffic =====> |
```

### State Definitions

1. `HYBRID_STATE_INIT`: Context freshly initialized with local identity keys and role.
2. `HYBRID_STATE_CLIENT_HELLO_SENT`: Client generated ephemeral keys and dispatched `CLIENT_HELLO`.
3. `HYBRID_STATE_CLIENT_HELLO_RECV`: Server validated offered protocol version and suite identifier.
4. `HYBRID_STATE_SERVER_HELLO_SENT`: Server encapsulated hybrid secrets, signed transcript, and sent `SERVER_HELLO`.
5. `HYBRID_STATE_KEY_ESTABLISHED`: Client verified server dual signatures, recovered hybrid secrets, and derived traffic keys.
6. `HYBRID_STATE_ESTABLISHED`: Mutual authentication confirmed by both peers; application traffic permitted.
7. `HYBRID_STATE_FAILED`: Handshake aborted due to cryptographic mismatch, downgrade attempt, or tampering.
8. `HYBRID_STATE_CLOSED`: Session terminated; secret material erased with `explicit_bzero`.

---

## 3. Handshake Wire Message Layouts

All integer fields larger than a single byte are encoded in Network Byte Order (Big-Endian).

### 3.1 `CLIENT_HELLO` (3,283 bytes)

| Offset | Field | Length | Description |
|---|---|---|---|
| `0x0000` | `version` | 2 bytes | Protocol version: `0x0100` (v1.0) |
| `0x0002` | `suite_id_len` | 2 bytes | Length of Suite ID string (`0x0031` = 49) |
| `0x0004` | `suite_id` | 49 bytes | `"QRYPTONEX-HYBRID-X25519-MLKEM768-ED25519-MLDSA65"` |
| `0x0035` | `client_nonce` | 32 bytes | Cryptographically secure random nonce |
| `0x0055` | `client_eph_x25519_pk` | 32 bytes | Ephemeral X25519 curve point |
| `0x0075` | `client_eph_mlkem_pk` | 1,184 bytes | ML-KEM-768 encapsulation public key |
| `0x0515` | `client_id_ed25519_pk` | 32 bytes | Client static Ed25519 identity public key |
| `0x0535` | `client_id_mldsa_pk` | 1,952 bytes | Client static ML-DSA-65 identity public key |

### 3.2 `SERVER_HELLO` (6,539 bytes)

| Offset | Field | Length | Description |
|---|---|---|---|
| `0x0000` | `version` | 2 bytes | Negotiated protocol version: `0x0100` |
| `0x0002` | `suite_id_len` | 2 bytes | Selected Suite ID length (49) |
| `0x0004` | `suite_id` | 49 bytes | Selected Suite ID string |
| `0x0035` | `server_nonce` | 32 bytes | Cryptographically secure random nonce |
| `0x0055` | `session_id` | 8 bytes | Globally unique 64-bit session identifier |
| `0x005D` | `server_eph_x25519_pk` | 32 bytes | Server ephemeral X25519 curve point |
| `0x007D` | `server_mlkem_ct` | 1,088 bytes | ML-KEM-768 ciphertext |
| `0x04BD` | `server_id_ed25519_pk` | 32 bytes | Server static Ed25519 identity public key |
| `0x04DD` | `server_id_mldsa_pk` | 1,952 bytes | Server static ML-DSA-65 identity public key |
| `0x0C7D` | `server_sig` | 3,378 bytes | Framed dual signature over Server Transcript Digest |

### 3.3 `CLIENT_AUTH` (3,386 bytes)

| Offset | Field | Length | Description |
|---|---|---|---|
| `0x0000` | `session_id` | 8 bytes | Session identifier bound to the connection |
| `0x0008` | `client_sig` | 3,378 bytes | Framed dual signature over Client Transcript Digest |

### 3.4 Framed Dual Signature Wire Format (3,378 bytes)

Dual signatures are framed using unambiguous length prefixes to prevent canonical serialization ambiguity:

```
+---------------+---------------------+--------------------+---------------------+--------------------+
|  version (1B) | ed25519_len (2B BE) | ed25519_sig (64B)  |  mldsa_len (2B BE)  | mldsa_sig (3309B)  |
+---------------+---------------------+--------------------+---------------------+--------------------+
```

---

## 4. Transcript Construction & Domain Separation

Transcript digests prevent man-in-the-middle tampering, parameter substitution, and replay attacks by binding all offered and negotiated parameters into a single cryptographic hash.

### 4.1 Server Transcript

The Server Transcript covers all key establishment material and identity public keys:

$$\text{Transcript}_{\text{Server}} = \text{Label}_{\text{Server}} \parallel \text{version} \parallel \text{len}(\text{suite}) \parallel \text{suite} \parallel N_c \parallel N_s \parallel \text{sid} \parallel PK_{x25519}^c \parallel PK_{\text{kem}}^c \parallel PK_{x25519}^s \parallel CT_{\text{kem}}^s \parallel ID_{\text{ed}}^c \parallel ID_{\text{dsa}}^c \parallel ID_{\text{ed}}^s \parallel ID_{\text{dsa}}^s$$

Where:
- $\text{Label}_{\text{Server}} = \text{"QRYPTONEX-HYBRID-TRANSCRIPT-v1-SERVER"}$ (37 bytes)
- $N_c, N_s$: Client and Server 32-byte nonces
- $\text{sid}$: 64-bit Big-Endian Session ID
- Digest: $\text{Digest}_{\text{Server}} = \text{SHA-384}(\text{Transcript}_{\text{Server}})$ (48 bytes)

The server signs $\text{Digest}_{\text{Server}}$ using both $SK_{\text{ed}}^s$ and $SK_{\text{dsa}}^s$.

### 4.2 Client Transcript

The Client Transcript authenticates the client's agreement to the server's parameters:

$$\text{Transcript}_{\text{Client}} = \text{Label}_{\text{Client}} \parallel \text{Digest}_{\text{Server}} \parallel \text{server\_sig}$$

Where:
- $\text{Label}_{\text{Client}} = \text{"QRYPTONEX-HYBRID-TRANSCRIPT-v1-CLIENT"}$ (37 bytes)
- Digest: $\text{Digest}_{\text{Client}} = \text{SHA-384}(\text{Transcript}_{\text{Client}})$ (48 bytes)

The client signs $\text{Digest}_{\text{Client}}$ using both $SK_{\text{ed}}^c$ and $SK_{\text{dsa}}^c$.

---

## 5. Hybrid Key Derivation Architecture

### 5.1 Combined Input Keying Material (IKM)

Both shared secrets are length-prefixed and concatenated:

$$\text{IKM}_{\text{hybrid}} = \text{uint16\_be}(32) \parallel ss_{\text{x25519}} \parallel \text{uint16\_be}(32) \parallel ss_{\text{mlkem}}$$

- Total size: $2 + 32 + 2 + 32 = 68\text{ bytes}$.
- Contributory check: If $ss_{\text{x25519}} == 0^{32}$, key derivation is aborted immediately.

### 5.2 HKDF-Extract Step

$$\text{PRK} = \text{HKDF-Extract}(\text{salt} = \text{Digest}_{\text{Server}}, \text{IKM} = \text{IKM}_{\text{hybrid}})$$

- Hash function: SHA-384 ($L = 48\text{ bytes}$).
- The transcript digest binds all negotiated public keys, nonces, and identities into the master PRK.

### 5.3 HKDF-Expand Step & Directional Traffic Keys

Directional traffic keys are derived using strict domain separation:

$$\text{Key}_{\text{C2S}} = \text{HKDF-Expand}(\text{PRK}, \text{Label}_{\text{C2S}} \parallel N_c \parallel N_s \parallel \text{sid}, 32)$$
$$\text{Key}_{\text{S2C}} = \text{HKDF-Expand}(\text{PRK}, \text{Label}_{\text{S2C}} \parallel N_c \parallel N_s \parallel \text{sid}, 32)$$

Where:
- $\text{Label}_{\text{C2S}} = \text{"QRYPTONEX-HYBRID-v1-C2S-KEY"}$ (27 bytes)
- $\text{Label}_{\text{S2C}} = \text{"QRYPTONEX-HYBRID-v1-S2C-KEY"}$ (27 bytes)
- Directional keys are strictly independent ($\text{Key}_{\text{C2S}} \neq \text{Key}_{\text{S2C}}$).

---

## 6. Application Traffic Protection

### 6.1 Wire Framing

Application packets use a 15-byte canonical header:

```
+------------+-----------+------------+--------------------+
| seq (4B)   | type (1B) | len (2B)   | session_id (8B)    |
+------------+-----------+------------+--------------------+
```

The 15-byte wire header is bound into the ChaCha20-Poly1305 authentication tag as Associated Data (AAD).

### 6.2 Nonce Construction

A 12-byte AEAD nonce is constructed monotonically per message:

$$\text{Nonce} = \text{le64}(\text{tx\_nonce\_ctr}++) \parallel 0x00000000$$

- Monotonicity: Incremented after every encryption operation.
- Exhaustion threshold: If $\text{tx\_nonce\_ctr} \ge 2^{64} - 256$, further encryption is refused with `HYBRID_ERR_NONCE_EXHAUSTED`.
- Nonce reuse is cryptographically impossible under this construction.

### 6.3 Replay Protection State Machine

Replay protection follows RFC 6479 (sliding 64-packet bitmap):

1. **Pre-Authentication Check**:
   - Compares packet sequence against the bitmap.
   - If sequence is duplicate or $> 64$ packets stale, drops packet immediately with `HYBRID_ERR_REPLAY_DETECTED` *without modifying state*.
2. **Cryptographic Tag Verification**:
   - Decrypts and authenticates ciphertext and header AAD using ChaCha20-Poly1305.
   - If tag fails, packet is discarded; state remains uncommitted.
3. **Post-Authentication Commit**:
   - Updates window base sequence and sets the bitmap bit only after tag verification succeeds.
