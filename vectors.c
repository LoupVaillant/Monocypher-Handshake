#include "monocypher.h"
#include "vectors.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

typedef uint8_t u8;

static void mix_hash(u8 next[64], const u8 pred[64],
                     const u8 *in, size_t in_size)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init  (&ctx);
    crypto_blake2b_update(&ctx, pred, 64);
    crypto_blake2b_update(&ctx, in, in_size);
    crypto_blake2b_final (&ctx, next);
}

static void mix_hash2(u8 next[64], u8 extra[64], const u8 pred[64])
{
    static const u8 zero[1] = {0};
    static const u8 one [1] = {1};
    mix_hash(next , pred, zero, 1);
    mix_hash(extra, pred, one , 1);
}

static void auth(u8 next[64], u8 *tag, const u8 pred[64])
{
    u8 tmp[64];
    mix_hash2(next, tmp, pred);
    memcpy(tag, tmp, 16);
}

static void encrypt(u8       next[64], u8       *ct,
                    const u8 pred[64], const u8 *pt, size_t size)
{
    static const u8 zero[8] = {0};

    // encrypt message
    u8 key[64];
    mix_hash2(next, key, pred);     // extract key
    crypto_chacha_ctx ctx;
    crypto_chacha20_init   (&ctx, key, zero);
    crypto_chacha20_encrypt(&ctx, ct, pt, size);
    mix_hash(next, next, ct, size); // update hash with message
    auth(next, ct + size, next);    // extract authentication tag
}

#define REC_HASH(out)      memcpy(out, hash, 64)
#define MIX_HASH(in, size) mix_hash(hash, hash, in, size)
#define SKIP(size)         m += (size);  m_size += (size)
#define ABSORB_RAW(in, size)               \
    MIX_HASH(in, size);                    \
    REC_HASH(out->message_hashes[msg_nb]); \
    memcpy(m, in, size);                   \
    SKIP(size)
#define ABSORB_ENCRYPTED(in, size)         \
    encrypt(hash, m, hash, in, size);      \
    REC_HASH(out->message_hashes[msg_nb]); \
    SKIP(size + 16)

void generate(out_vectors *out, const in_vectors *in)
{
    // public keys
    if (in->has_cse) { crypto_x25519_public_key(out->cpe, in->cse); }
    if (in->has_sse) { crypto_x25519_public_key(out->spe, in->sse); }
    if (in->has_css) { crypto_x25519_public_key(out->cps, in->css); }
    if (in->has_sss) { crypto_x25519_public_key(out->sps, in->sss); }

    // exchanges
    int has_ee = in->has_cse && in->has_sse;
    int has_es = in->has_cse && in->has_sss;
    int has_se = in->has_css && in->has_sse;
    int has_ss = in->has_css && in->has_sss;
    if (has_ee) { crypto_x25519(out->ee, in->cse, out->spe); }
    if (has_es) { crypto_x25519(out->es, in->cse, out->sps); }
    if (has_se) { crypto_x25519(out->se, in->css, out->spe); }
    if (has_ss) { crypto_x25519(out->ss, in->css, out->sps); }

    // protocol ID
    u8 hash[64]; // current hash
    memcpy(hash, in->protocol_id, 64);

    // pre shared keys
    if (in->pre_share_cps) { MIX_HASH(out->cps, 32); }
    if (in->pre_share_sps) { MIX_HASH(out->sps, 32); }
    REC_HASH(out->initial_hash);

    // prelude
    if (in->has_prelude) {
        MIX_HASH(in->prelude, in->prelude_size);
        REC_HASH(out->prelude_hash);
    }

    // pattern
    int msg_nb     = 0;
    int has_key    = 0;
    int client_msg = 1; // first message is from the client
    while (in->pattern[msg_nb][0] != STOP) {

        // core message
        u8    *m      = out->messages[msg_nb];
        size_t m_size = 0;
        int    action = 0;
        while (in->pattern[msg_nb][action] != STOP) {
            switch(in->pattern[msg_nb][action]) {
            case E : ABSORB_RAW(client_msg ? out->cpe : out->spe, 32); break;
            case S : {
                u8 *static_key = client_msg ? out->cps : out->sps;
                if (has_key) { ABSORB_ENCRYPTED(static_key, 32); }
                else         { ABSORB_RAW      (static_key, 32); }
            } break;
            case EE: MIX_HASH(out->ee, 32);  has_key = 1;              break;
            case ES: MIX_HASH(out->es, 32);  has_key = 1;              break;
            case SE: MIX_HASH(out->se, 32);  has_key = 1;              break;
            case SS: MIX_HASH(out->ss, 32);  has_key = 1;              break;
            default: fprintf(stderr, "Impossible\n"); exit(1);
            }
            action++;
        }

        // payload
        if (in->has_payload[msg_nb]) {
            const u8 *payload      = in->payloads[msg_nb];
            size_t    payload_size = in->payload_sizes[msg_nb];
            if (has_key) { ABSORB_ENCRYPTED(payload, payload_size); }
            else         { ABSORB_RAW      (payload, payload_size); }
        } else {
            if (has_key) { auth(hash, m, hash);  SKIP(16); }
        }

        // internal hash after message
        REC_HASH(out->message_hashes[msg_nb]);

        // actual message size
        out->message_sizes[msg_nb] = m_size;

        client_msg = !client_msg; // flip client/server flag
        msg_nb++;
    }
    out->nb_messages = msg_nb;

    // session keys
    memcpy(out->session_key, hash   , 32);
    memcpy(out->extra_key  , hash+32, 32);
}
