#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "monocypher.h"
#include "monokex.h"

typedef uint8_t  u8;
typedef uint64_t u64;

#define FOR(i, start, end) for (size_t (i) = (start); (i) < (end); (i)++)
#define RANDOM_INPUT(name, size) u8 name[size]; p_random(name, size)

// Pseudo-random 64 bit number, based on xorshift*
static u64 rand64()
{
    static u64 x = 12345; // Must be seeded with a nonzero value.
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    return x * 0x2545F4914F6CDD1D; // magic constant
}

static void p_random(u8 *stream, size_t size)
{
    FOR (i, 0, size) {
        stream[i] = (u8)rand64();
    }
}

typedef struct {
    u8 session_key[32];
    u8 extra_key  [32];
    u8 remote_key [32];
} keys;

static void step(crypto_kex_ctx *ctx, keys *keys,
                 u8       *m_out,
                 u8       *p_out, size_t p_osize,
                 const u8 *m_in ,
                 const u8 *p_in , size_t p_isize)
{
    crypto_kex_action action;
    size_t m_size;
    action = crypto_kex_next_action(ctx, &m_size);
    do {
        switch (action) {
        case CRYPTO_KEX_READ:
            assert(
                !crypto_kex_read_p(ctx, p_out, p_osize, m_in, m_size+p_osize));
            break;
        case CRYPTO_KEX_WRITE:
            crypto_kex_write_p(ctx, m_out, m_size + p_isize, p_in, p_isize);
            break;
        case CRYPTO_KEX_REMOTE_KEY:
            crypto_kex_remote_key(ctx, keys->remote_key);
            break;
        case CRYPTO_KEX_FINAL:
            crypto_kex_final(ctx, keys->session_key, keys->extra_key);
            break;
        default:
            break;
        }
        action = crypto_kex_next_action(ctx, &m_size);
    } while (action != CRYPTO_KEX_NONE &&
             action != CRYPTO_KEX_READ);
}

static int has_prelude(unsigned flags)             { return (flags >> 4) & 1; }
static int has_payload(unsigned flags, unsigned i) { return (flags >> i) & 1; }

static void session(crypto_kex_ctx *client,
                    crypto_kex_ctx *server,
                    unsigned        flags)
{
    // prelude and payloads (whether we use them or not)
    int prelude_size;
    u8  prelude[32];
    prelude_size = rand64() % 32 + 1;
    p_random(prelude, prelude_size);
    u8     pld_in [4][32];  u8 *pi [4] = {0};
    u8     pld_out[4][32];  u8 *po[4] = {0};
    size_t ps[4] = {0};
    FOR (i, 0, 4) {
        if (has_payload(flags, i)) {
            ps[i] = rand64() % 32 + 1;
            pi[i] = pld_in [i];
            po[i] = pld_out[i];
            p_random(pi[i], ps[i]);
        }
    }

    // Initial hash
    assert(!memcmp(client->hash, server->hash, 64));

    // Prelude
    if (has_prelude(flags)) {
        crypto_kex_add_prelude(client, prelude, prelude_size);
        crypto_kex_add_prelude(server, prelude, prelude_size);
        assert(!memcmp(client->hash, server->hash, 64));
    }

    // Protocol
    u8   m    [4][128]; // 32 byte payload + 96 byte message = 128
    keys client_keys;
    keys server_keys;
    assert(crypto_kex_next_action(client, 0) != CRYPTO_KEX_NONE);
    assert(crypto_kex_next_action(server, 0) != CRYPTO_KEX_NONE);

    step(client, &client_keys, m[0], 0    , 0    , 0   , pi[0], ps[0]);
    step(server, &server_keys, m[1], po[0], ps[0], m[0], pi[1], ps[1]);
    step(client, &client_keys, m[2], po[1], ps[1], m[1], pi[2], ps[2]);
    step(server, &server_keys, m[3], po[2], ps[2], m[2], pi[3], ps[3]);
    step(client, &client_keys, 0   , po[3], ps[3], m[3], 0    , 0    );

    assert(crypto_kex_next_action(client, 0) == CRYPTO_KEX_NONE);
    assert(crypto_kex_next_action(server, 0) == CRYPTO_KEX_NONE);

    // payload integrity
//    assert(!has_payload(flags, 0) || !memcmp(pi[0], po[0], ps[0]));
//    assert(!has_payload(flags, 1) || !memcmp(pi[1], po[1], ps[1]));
//    assert(!has_payload(flags, 2) || !memcmp(pi[2], po[2], ps[2]));
//    assert(!has_payload(flags, 3) || !memcmp(pi[3], po[3], ps[3]));

    // Session keys
    assert(!memcmp(client_keys.session_key, server_keys.session_key, 32));
    assert(!memcmp(client_keys.  extra_key, server_keys.  extra_key, 32));
}

static void xk1_session(unsigned nb)
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css , 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss , 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_xk1_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_xk1_server_init(&server, server_seed, sss, sps);
    session(&client, &server, nb);
}

static void x1k1_session(unsigned nb)
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css , 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss , 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_x1k1_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_x1k1_server_init(&server, server_seed, sss, sps);
    session(&client, &server, nb);
}

static void ix_session(unsigned nb)
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css , 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss , 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_ix_client_init(&client, client_seed, css, cps);
    crypto_kex_ix_server_init(&server, server_seed, sss, sps);
    session(&client, &server, nb);
}

static void nk1_session(unsigned nb)
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(sss , 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_nk1_client_init(&client, client_seed, sps);
    crypto_kex_nk1_server_init(&server, server_seed, sss, sps);
    session(&client, &server, nb);
}

static void x_session(unsigned nb)
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(css , 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss , 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_x_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_x_server_init(&server, sss, sps);
    session(&client, &server, nb);
}

int main()
{
    FOR(i, 0, 32) { xk1_session (i); } printf("xk1  session OK\n");
    FOR(i, 0, 32) { x1k1_session(i); } printf("x1k1 session OK\n");
    FOR(i, 0, 32) { ix_session  (i); } printf("ix   session OK\n");
    FOR(i, 0, 32) { nk1_session (i); } printf("nk1  session OK\n");
    FOR(i, 0, 32) { x_session   (i); } printf("x    session OK\n");
    return 0;
}
