#include "monocypher.h"
#include "vectors.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

typedef uint8_t u8;

void mix_hash(u8 next[64], const u8 pred[64], const u8 *in, size_t in_size)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init  (&ctx);
    crypto_blake2b_update(&ctx, pred, 64);
    crypto_blake2b_update(&ctx, in, in_size);
    crypto_blake2b_final (&ctx, next);
}

void mix_hash2(u8 next[64], u8 extra[64], const u8 pred[64])
{
    static const u8 zero[1] = {0};
    static const u8 one [1] = {1};
    mix_hash(next , pred, zero, 1);
    mix_hash(extra, pred, one , 1);
}

void encrypt(u8 next[64], u8 *ct, const u8 pred[64], const u8 *pt, size_t size)
{
    static const u8 zero[8] = {0};

    // encrypt message
    u8 key[64];
    mix_hash2(next, key, pred); // extract key
    crypto_chacha_ctx ctx;
    crypto_chacha20_init   (&ctx, key, zero);
    crypto_chacha20_encrypt(&ctx, ct, pt, size);

    // write authentication tag
    u8 tag[64];
    mix_hash(next, next, ct, size); // authenticate message
    mix_hash2(next, tag, next);     // extract authentication tag
    memcpy(ct + size, tag, 16);
}

#define APPEND(in, size)                  \
    if (has_key) {                        \
        encrypt(hash, m, hash, in, size); \
        m      += (size) + 16;            \
        m_size += (size) + 16;            \
    } else {                              \
        mix_hash(hash, hash, in, size);   \
        memcpy(m, in, size);              \
        m      += (size);                 \
        m_size += (size);                 \
    } do {} while(0)

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

    // psrotocol ID
    u8 hash[64]; // current hash
    memcpy(hash, in->protocol_id, 64);

    // prelude
    if (in->prelude_size != -1u) {
        mix_hash(hash, in->protocol_id, in->prelude, in->prelude_size);
    }
    memcpy(out->prelude_hash, hash, 64);

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
            case E : APPEND(client_msg ? out->cpe : out->spe, 32);     break;
            case S : APPEND(client_msg ? out->cps : out->sps, 32);     break;
            case EE: mix_hash(hash, hash, out->ee, 32);  has_key = 1;  break;
            case ES: mix_hash(hash, hash, out->es, 32);  has_key = 1;  break;
            case SE: mix_hash(hash, hash, out->se, 32);  has_key = 1;  break;
            case SS: mix_hash(hash, hash, out->ss, 32);  has_key = 1;  break;
            default: fprintf(stderr, "Impossible"); exit(1);
            }
            action++;
        }

        // payload
        APPEND(in->payloads[msg_nb], in->payload_sizes[msg_nb]);

        // internal hash after message
        memcpy(out->message_hashes[msg_nb], hash, 64);
        out->message_sizes[msg_nb] = m_size;

        client_msg ^= 1; // flip client/server flag
        msg_nb++;
    }
    out->nb_messages = msg_nb;

    // session keys
    memcpy(out->session_key, out->message_hashes[msg_nb]     , 32);
    memcpy(out->extra_key  , out->message_hashes[msg_nb] + 32, 32);
}
