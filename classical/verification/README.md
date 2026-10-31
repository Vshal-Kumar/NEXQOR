# Formal Verification of the NEXQOR Classical IoT Protocol

This directory contains the formal protocol verification model for the **NEXQOR Classical IoT Cryptographic Protocol** using [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/), an automated cryptographic protocol verifier based on the Applied Pi-Calculus and Dolev-Yao attacker model.

---

## 1. Protocol Architecture & Cryptographic Primitives

The modeled classical suite consists of:
1. **Key Agreement**: Diffie-Hellman over Curve25519 (X25519, RFC 7748)
   $$\text{exp}(\text{exp}(g, x), y) = \text{exp}(\text{exp}(g, y), x)$$
2. **Digital Signatures**: Ed25519 (RFC 8032 / FIPS 186-5)
   $$\text{ed\_verify}(m, \text{ed\_sign}(m, sk), pk) = \text{true}$$
3. **Cryptographic Hash**: SHA-256 (FIPS 180-4)
4. **Key Derivation**: HKDF-SHA-256 (RFC 5869) with domain-separated directional labels (`c2s` and `s2c`)
5. **Authenticated Encryption**: AES-128-CCM (NIST SP 800-38C) with Authenticated Associated Data (AAD) binding wire header fields `(seq, type, session_id)`.

---

## 2. Handshake Phase Structure

- **Phase 1 (Client Hello)**:
  $$\text{Client} \to \text{Server}: \quad c\_eph\_pub, \; c\_id\_pk, \; c\_nonce$$
- **Phase 2 (Server Hello)**:
  $$\text{Server} \to \text{Client}: \quad s\_id\_pk, \; s\_eph\_pub, \; session\_id, \; s\_nonce, \; \sigma_{\text{Server}}$$
  where $\sigma_{\text{Server}} = \text{Sign}_{sk_S}(\text{SHA-256}(c\_nonce \mathbin{\Vert} s\_nonce \mathbin{\Vert} session\_id \mathbin{\Vert} c\_eph\_pub \mathbin{\Vert} c\_id\_pk \mathbin{\Vert} s\_id\_pk \mathbin{\Vert} s\_eph\_pub))$.
- **Phase 3 (Client Authentication)**:
  $$\text{Client} \to \text{Server}: \quad \sigma_{\text{Client}}$$
  where $\sigma_{\text{Client}} = \text{Sign}_{sk_C}(\text{SHA-256}(\text{Server\_Transcript} \mathbin{\Vert} \sigma_{\text{Server}}))$.
- **Phase 4 (Session Activation)**:
  Both endpoints derive independent directional keys:
  - $K_{\text{c2s}} = \text{HKDF-Expand}(\text{HKDF-Extract}(salt, ss), \text{"c2s traffic key"}, 16)$
  - $K_{\text{s2c}} = \text{HKDF-Expand}(\text{HKDF-Extract}(salt, ss), \text{"s2c traffic key"}, 16)$
  All subsequent application data packets are encrypted under AES-128-CCM with wire header AAD.

---

## 3. Security Properties & Queries Verified

The model formulates and proves the following security properties:

1. **Directional Traffic Key Secrecy**:
   - `query attacker(c2s_key_secret)`
   - `query attacker(s2c_key_secret)`
   The Dolev-Yao attacker cannot obtain or reconstruct either directional session key.

2. **Application Payload Secrecy**:
   - `query attacker(client_data)`
   - `query attacker(server_data)`
   Client telemetry and server commands remain confidential over active untrusted networks.

3. **Injective Mutual Authentication**:
   - `inj-event(server_accepts(...)) ==> inj-event(client_initiates(...))`
   - `inj-event(client_accepts(...)) ==> inj-event(server_initiates(...))`
   Guarantees one-to-one agreement on identity keys, nonces, session IDs, ephemeral keys, and traffic keys, preventing replay and Man-In-The-Middle (MITM) attacks.

4. **Perfect Forward Secrecy (PFS)**:
   Modeled via `phase 1` compromise of long-term identity signing keys ($s\_ed\_sk$ and $c\_ed\_sk$).
   Because ephemeral X25519 private exponents ($c\_eph\_priv$ and $s\_eph\_priv$) are never reused or leaked, past session traffic keys remain confidential even upon subsequent compromise of device signing keys.

---

## 4. Running the Verification

To run ProVerif on the classical protocol model:

```bash
# If using opam environment:
opam exec -- proverif verification/protocol.pv

# Or if proverif is in system PATH:
proverif verification/protocol.pv
```

### Verification Output:

```text
--------------------------------------------------------------
Verification summary:

Query not attacker_p1(c2s_key_secret[]) is true.
Query not attacker_p1(s2c_key_secret[]) is true.
Query not attacker_p1(client_data[]) is true.
Query not attacker_p1(server_data[]) is true.
Query inj-event(server_accepts(...)) ==> inj-event(client_initiates(...)) is true.
Query inj-event(client_accepts(...)) ==> inj-event(server_initiates(...)) is true.

--------------------------------------------------------------
```

All 6 security queries are proved **TRUE**.
