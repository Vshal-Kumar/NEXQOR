/*
 * hybrid/src/hybrid_signature.c
 *
 * Hybrid Digital Signatures combining Ed25519 (RFC 8032) and ML-DSA-65 (FIPS 204).
 */

#include "hybrid_signature.h"
#include "wrappers/dsa_wrapper.h"

#include <string.h>
#include <endian.h>
#include <openssl/evp.h>

/* ── Primitive: Ed25519 (RFC 8032) via OpenSSL 3.x EVP ─────────────── */

int hybrid_ed25519_keygen(uint8_t pk[HYBRID_ED25519_PK_BYTES],
                          uint8_t sk[HYBRID_ED25519_SK_BYTES]) {
    if (!pk || !sk) return HYBRID_ERR_INVALID_ARG;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!pctx) return HYBRID_ERR_CRYPTO_FAIL;

    if (EVP_PKEY_keygen_init(pctx) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return HYBRID_ERR_CRYPTO_FAIL;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) != 1 || !pkey) {
        EVP_PKEY_CTX_free(pctx);
        return HYBRID_ERR_CRYPTO_FAIL;
    }

    size_t pk_len = HYBRID_ED25519_PK_BYTES;
    size_t sk_len = HYBRID_ED25519_SK_BYTES;
    int rc = HYBRID_ERR_CRYPTO_FAIL;

    if (EVP_PKEY_get_raw_public_key(pkey, pk, &pk_len) == 1 &&
        EVP_PKEY_get_raw_private_key(pkey, sk, &sk_len) == 1 &&
        pk_len == HYBRID_ED25519_PK_BYTES && sk_len == HYBRID_ED25519_SK_BYTES) {
        rc = HYBRID_SUCCESS;
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

int hybrid_ed25519_sign(uint8_t sig[HYBRID_ED25519_SIG_BYTES], size_t *siglen,
                        const uint8_t *m, size_t mlen,
                        const uint8_t sk[HYBRID_ED25519_SK_BYTES]) {
    if (!sig || !sk) return HYBRID_ERR_INVALID_ARG;
    if (mlen > 0 && !m) return HYBRID_ERR_INVALID_ARG;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                  sk, HYBRID_ED25519_SK_BYTES);
    if (!pkey) return HYBRID_ERR_INVALID_KEY;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return HYBRID_ERR_CRYPTO_FAIL;
    }

    int rc = HYBRID_ERR_CRYPTO_FAIL;
    size_t slen = HYBRID_ED25519_SIG_BYTES;

    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestSign(md_ctx, sig, &slen, m ? m : (const uint8_t *)"", mlen) == 1 &&
        slen == HYBRID_ED25519_SIG_BYTES) {
        if (siglen) *siglen = slen;
        rc = HYBRID_SUCCESS;
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return rc;
}

int hybrid_ed25519_verify(const uint8_t *sig, size_t siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t pk[HYBRID_ED25519_PK_BYTES]) {
    if (!sig || siglen != HYBRID_ED25519_SIG_BYTES || !pk) return HYBRID_ERR_INVALID_ARG;
    if (mlen > 0 && !m) return HYBRID_ERR_INVALID_ARG;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                                 pk, HYBRID_ED25519_PK_BYTES);
    if (!pkey) return HYBRID_ERR_INVALID_KEY;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return HYBRID_ERR_CRYPTO_FAIL;
    }

    int rc = HYBRID_ERR_SIG_VERIFY_FAIL;
    if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) == 1) {
        int v = EVP_DigestVerify(md_ctx, sig, siglen, m ? m : (const uint8_t *)"", mlen);
        if (v == 1) {
            rc = HYBRID_SUCCESS;
        }
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return rc;
}

/* ── Primitive: ML-DSA-65 (FIPS 204) via Project Wrappers ─────────── */

int hybrid_mldsa65_keygen(uint8_t pk[HYBRID_MLDSA65_PK_BYTES],
                          uint8_t sk[HYBRID_MLDSA65_SK_BYTES]) {
    if (!pk || !sk) return HYBRID_ERR_INVALID_ARG;
    return (dsa_keypair(pk, sk) == 0) ? HYBRID_SUCCESS : HYBRID_ERR_CRYPTO_FAIL;
}

int hybrid_mldsa65_sign(uint8_t sig[HYBRID_MLDSA65_SIG_BYTES], size_t *siglen,
                        const uint8_t *m, size_t mlen,
                        const uint8_t sk[HYBRID_MLDSA65_SK_BYTES]) {
    if (!sig || !sk) return HYBRID_ERR_INVALID_ARG;
    if (mlen > 0 && !m) return HYBRID_ERR_INVALID_ARG;
    return (dsa_sign(sig, siglen, m, mlen, sk) == 0) ? HYBRID_SUCCESS : HYBRID_ERR_CRYPTO_FAIL;
}

int hybrid_mldsa65_verify(const uint8_t *sig, size_t siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t pk[HYBRID_MLDSA65_PK_BYTES]) {
    if (!sig || siglen != HYBRID_MLDSA65_SIG_BYTES || !pk) return HYBRID_ERR_INVALID_ARG;
    if (mlen > 0 && !m) return HYBRID_ERR_INVALID_ARG;
    return (dsa_verify(sig, siglen, m, mlen, pk) == 0) ? HYBRID_SUCCESS : HYBRID_ERR_SIG_VERIFY_FAIL;
}

/* ── Primary Combined Hybrid Signature Operations ─────────────────── */

int hybrid_sign_transcript(hybrid_signature_t *sig,
                           const uint8_t transcript_digest[HYBRID_SHA384_DIGEST_BYTES],
                           const hybrid_identity_sk_t *sk) {
    if (!sig || !transcript_digest || !sk) {
        return HYBRID_ERR_INVALID_ARG;
    }

    sig->version = HYBRID_SIG_FORMAT_VERSION;

    /* 1. Classical signature: Ed25519 over 48-byte transcript digest */
    size_t ed_len = 0;
    int rc = hybrid_ed25519_sign(sig->ed25519_sig, &ed_len,
                                 transcript_digest, HYBRID_SHA384_DIGEST_BYTES,
                                 sk->ed25519_sk);
    if (rc != HYBRID_SUCCESS || ed_len != HYBRID_ED25519_SIG_BYTES) {
        hybrid_cleanse(sig, sizeof(hybrid_signature_t));
        return HYBRID_ERR_CRYPTO_FAIL;
    }
    sig->ed25519_sig_len = (uint16_t)ed_len;

    /* 2. Post-quantum signature: ML-DSA-65 over the same 48-byte transcript digest */
    size_t ml_len = 0;
    rc = hybrid_mldsa65_sign(sig->mldsa_sig, &ml_len,
                             transcript_digest, HYBRID_SHA384_DIGEST_BYTES,
                             sk->mldsa_sk);
    if (rc != HYBRID_SUCCESS || ml_len != HYBRID_MLDSA65_SIG_BYTES) {
        hybrid_cleanse(sig, sizeof(hybrid_signature_t));
        return HYBRID_ERR_CRYPTO_FAIL;
    }
    sig->mldsa_sig_len = (uint16_t)ml_len;

    return HYBRID_SUCCESS;
}

int hybrid_verify_transcript(const hybrid_signature_t *sig,
                             const uint8_t transcript_digest[HYBRID_SHA384_DIGEST_BYTES],
                             const hybrid_identity_pk_t *pk) {
    if (!sig || !transcript_digest || !pk) {
        return HYBRID_ERR_INVALID_ARG;
    }

    /* Strict format and length validation */
    if (sig->version != HYBRID_SIG_FORMAT_VERSION) {
        return HYBRID_ERR_VERSION_UNSUPPORTED;
    }
    if (sig->ed25519_sig_len != HYBRID_ED25519_SIG_BYTES ||
        sig->mldsa_sig_len != HYBRID_MLDSA65_SIG_BYTES) {
        return HYBRID_ERR_SIG_VERIFY_FAIL;
    }

    /*
     * Both signatures must independently verify over the identical transcript digest.
     * If either verification fails, the connection MUST be rejected.
     */

    /* Verify Classical Ed25519 */
    int rc = hybrid_ed25519_verify(sig->ed25519_sig, sig->ed25519_sig_len,
                                   transcript_digest, HYBRID_SHA384_DIGEST_BYTES,
                                   pk->ed25519_pk);
    if (rc != HYBRID_SUCCESS) {
        return HYBRID_ERR_SIG_VERIFY_FAIL;
    }

    /* Verify Post-Quantum ML-DSA-65 */
    rc = hybrid_mldsa65_verify(sig->mldsa_sig, sig->mldsa_sig_len,
                               transcript_digest, HYBRID_SHA384_DIGEST_BYTES,
                               pk->mldsa_pk);
    if (rc != HYBRID_SUCCESS) {
        return HYBRID_ERR_SIG_VERIFY_FAIL;
    }

    return HYBRID_SUCCESS;
}

/* ── Wire Framing Serialization & Deserialization ─────────────────── */

int hybrid_signature_serialize(uint8_t *out, size_t out_cap, size_t *out_len,
                               const hybrid_signature_t *sig) {
    if (!out || !sig) return HYBRID_ERR_INVALID_ARG;
    if (out_cap < HYBRID_SIG_WIRE_BYTES) return HYBRID_ERR_BUFFER_TOO_SMALL;

    size_t off = 0;
    out[off++] = sig->version;

    uint16_t ed_len_be = htobe16(sig->ed25519_sig_len);
    memcpy(out + off, &ed_len_be, 2);
    off += 2;
    memcpy(out + off, sig->ed25519_sig, HYBRID_ED25519_SIG_BYTES);
    off += HYBRID_ED25519_SIG_BYTES;

    uint16_t ml_len_be = htobe16(sig->mldsa_sig_len);
    memcpy(out + off, &ml_len_be, 2);
    off += 2;
    memcpy(out + off, sig->mldsa_sig, HYBRID_MLDSA65_SIG_BYTES);
    off += HYBRID_MLDSA65_SIG_BYTES;

    if (out_len) *out_len = off;
    return HYBRID_SUCCESS;
}

int hybrid_signature_deserialize(hybrid_signature_t *sig,
                                 const uint8_t *in, size_t in_len) {
    if (!sig || !in) return HYBRID_ERR_INVALID_ARG;
    if (in_len != HYBRID_SIG_WIRE_BYTES) return HYBRID_ERR_BUFFER_TOO_SMALL;

    size_t off = 0;
    sig->version = in[off++];
    if (sig->version != HYBRID_SIG_FORMAT_VERSION) {
        return HYBRID_ERR_VERSION_UNSUPPORTED;
    }

    uint16_t ed_len_be;
    memcpy(&ed_len_be, in + off, 2);
    off += 2;
    sig->ed25519_sig_len = be16toh(ed_len_be);
    if (sig->ed25519_sig_len != HYBRID_ED25519_SIG_BYTES) {
        return HYBRID_ERR_SIG_VERIFY_FAIL;
    }
    memcpy(sig->ed25519_sig, in + off, HYBRID_ED25519_SIG_BYTES);
    off += HYBRID_ED25519_SIG_BYTES;

    uint16_t ml_len_be;
    memcpy(&ml_len_be, in + off, 2);
    off += 2;
    sig->mldsa_sig_len = be16toh(ml_len_be);
    if (sig->mldsa_sig_len != HYBRID_MLDSA65_SIG_BYTES) {
        return HYBRID_ERR_SIG_VERIFY_FAIL;
    }
    memcpy(sig->mldsa_sig, in + off, HYBRID_MLDSA65_SIG_BYTES);
    off += HYBRID_MLDSA65_SIG_BYTES;

    return HYBRID_SUCCESS;
}
