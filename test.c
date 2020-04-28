#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "monocypher.h"
#include "monokex.h"

typedef uint8_t  u8;
typedef uint16_t u16;
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

// Context status flags
static const u16 IS_OK       =  1; // Always 1 (becomes zero when wiped)
static const u16 HAS_REMOTE  =  4; // True if we have the remote DH key
static const u16 GETS_REMOTE =  8; // True if the remote key is wanted

// message tokens
typedef enum { NOOP=0, E=1, S=2, EE=3, ES=4, SE=5, SS=6 } action;

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
            assert(ctx->flags & IS_OK);
            break;
        case CRYPTO_KEX_WRITE:
            crypto_kex_write_p(ctx, m_out, m_size + p_isize, p_in, p_isize);
            assert(ctx->flags & IS_OK);
            break;
        case CRYPTO_KEX_REMOTE_KEY:
            crypto_kex_remote_key(ctx, keys->remote_key);
            assert(ctx->flags & IS_OK);
            break;
        case CRYPTO_KEX_FINAL:
            crypto_kex_final(ctx, keys->session_key, keys->extra_key);
            assert(ctx->flags == 0);
            break;
        default:
            break;
        }
        action = crypto_kex_next_action(ctx, &m_size);
    } while (action != CRYPTO_KEX_NONE &&
             action != CRYPTO_KEX_READ);
}

static void load_pattern(action pattern[4][5], const crypto_kex_ctx *ctx)
{
    FOR (i, 0, 4) {
        u16 message = ctx->messages[i];
        FOR (j, 0, 5) {
            pattern[i][j] = message & 7;
            message >>= 3;
        }
    }
}

static void mix_hash(u8 hash[64], const u8 *in, u8 size)
{
    crypto_blake2b_general(hash, 64, hash, 64, in, size);
}

static void split_hash(u8 hash[64], u8 *extra, size_t size)
{
    static const u8 zero[1] = {0};
    static const u8 one [1] = {1};
    u8 tmp[64];
    crypto_blake2b_general(hash, 64, hash, 64, zero, 1);
    crypto_blake2b_general(tmp , 64, hash, 64, one , 1);
    memcpy(extra, tmp, size);
}

static void e_mix_hash(u8 hash[64], u8 *in, u8 size)
{
    static const u8 zero[8] = {0};
    u8 key[32];
    u8 tmp[128];
    split_hash(hash, key, 32);
    crypto_chacha20(tmp, in, size, key, zero);
    mix_hash(hash, tmp , size);  // absorb encrypted message
    mix_hash(hash, zero, 1   );  // split for authentication tag
}

static void exchange(u8 hash[64], u8 s1[32], u8 p1[32], u8 s2[32], u8 p2[32])
{
    u8 t1[32], t2[32];
    crypto_x25519(t1, s1, p2);
    crypto_x25519(t2, s2, p1);
    assert(!memcmp(t1, t2, 32));
    mix_hash(hash, t1, 32);
}

static int has_prelude(unsigned flags)             { return  flags       & 1; }
static int has_payload(unsigned flags, unsigned i) { return (flags >> i) & 2; }

static size_t nb_messages(const crypto_kex_ctx *ctx)
{
    FOR (i, 0, 4) {
        if (ctx->messages[i] == 0) {
            return i;
        }
    }
    return 4;
}

static void session(crypto_kex_ctx *client,
                    crypto_kex_ctx *server,
                    const u8        pid[64],
                    unsigned        flags)
{
    // Pattern
    action client_pattern[4][5];  load_pattern(client_pattern, client);
    action server_pattern[4][5];  load_pattern(server_pattern, server);
    FOR (i, 0, 4) {
        FOR (j, 0, 5) {
            action token = server_pattern[i][j];
            if (token == SE) { server_pattern[i][j] = ES; }
            if (token == ES) { server_pattern[i][j] = SE; }
            assert(client_pattern[i][j] == server_pattern[i][j]);
        }
    }
    size_t nb_msg = nb_messages(client);

    // keys
    int has_cs = server->flags & (HAS_REMOTE | GETS_REMOTE);
    int has_ss = client->flags & (HAS_REMOTE | GETS_REMOTE);
    int has_ce = 1; // client always sends a message
    int has_se = nb_msg >= 2;

    u8 ces[32], cep[32], ses[32], sep[32];
    u8 css[32], csp[32], sss[32], ssp[32];
    if (has_ce){memcpy(ces, client->e, 32); crypto_x25519_public_key(cep, ces);}
    if (has_se){memcpy(ses, server->e, 32); crypto_x25519_public_key(sep, ses);}
    if (has_cs){memcpy(css, client->s, 32); crypto_x25519_public_key(csp, css);}
    if (has_ss){memcpy(sss, server->s, 32); crypto_x25519_public_key(ssp, sss);}
    if (has_cs) { assert(!memcmp(client->sp, csp, 32)); }
    if (has_ss) { assert(!memcmp(server->sp, ssp, 32)); }

    // Initial hash
    u8 hash[64];
    memcpy(hash, pid, 64);
    if (server->flags & HAS_REMOTE) {
        assert(!memcmp(client->sp, server->sr, 32));
        crypto_blake2b_general(hash, 64, hash, 64, client->sp, 32);
    }
    if (client->flags & HAS_REMOTE) {
        assert(!memcmp(server->sp, client->sr, 32));
        crypto_blake2b_general(hash, 64, hash, 64, server->sp, 32);
    }
    assert(!memcmp(client->hash, hash, 64));
    assert(!memcmp(server->hash, hash, 64));

    // Generate prelude and payloads
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

    // Prelude
    if (has_prelude(flags)) {
        crypto_kex_add_prelude(client, prelude, prelude_size);
        crypto_kex_add_prelude(server, prelude, prelude_size);
        mix_hash(hash, prelude, prelude_size);
        assert(!memcmp(client->hash, hash, 64));
        assert(!memcmp(server->hash, hash, 64));
    }

    int has_key = 0; // can encrypt
    FOR (i, 0, 4) {
        if (client_pattern[i][0] == NOOP) {
            break;
        }
        FOR (j, 0, 5) {
            switch (client_pattern[i][j]) {
            case EE  : exchange(hash, ces, cep, ses, sep); has_key = 1; break;
            case ES  : exchange(hash, ces, cep, sss, ssp); has_key = 1; break;
            case SE  : exchange(hash, css, csp, ses, sep); has_key = 1; break;
            case SS  : exchange(hash, css, csp, sss, ssp); has_key = 1; break;
            case E   :
                mix_hash(hash, i%2 == 0 ? client->ep : server->ep, 32);
                break;
            case S   :
                if (has_key) { e_mix_hash(hash, i%2 == 0 ? csp : ssp, 32); }
                else         {   mix_hash(hash, i%2 == 0 ? csp : ssp, 32); }
                break;
            case NOOP: break;
            default  : assert(0);
            }
        }
        if (has_payload(flags, i)) {
            if (has_key) { e_mix_hash(hash, pld_in[i], ps[i]); }
            else         {   mix_hash(hash, pld_in[i], ps[i]); }
        } else {
            if (has_key) {
                static const u8 zero[1] = {0};
                mix_hash(hash, zero, 1);
            }
        }
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
    assert(nb_msg < 1 || !has_payload(flags, 0) || !memcmp(pi[0],po[0],ps[0]));
    assert(nb_msg < 2 || !has_payload(flags, 1) || !memcmp(pi[1],po[1],ps[1]));
    assert(nb_msg < 3 || !has_payload(flags, 2) || !memcmp(pi[2],po[2],ps[2]));
    assert(nb_msg < 4 || !has_payload(flags, 3) || !memcmp(pi[3],po[3],ps[3]));

    // Session keys
    assert(!memcmp(hash     , client_keys.session_key, 32));
    assert(!memcmp(hash     , server_keys.session_key, 32));
    assert(!memcmp(hash + 32, client_keys.  extra_key, 32));
    assert(!memcmp(hash + 32, server_keys.  extra_key, 32));
}

static void sessions(const crypto_kex_ctx *client,
                     const crypto_kex_ctx *server,
                     const u8              pid[64])
{
    size_t nb_msg   = nb_messages(client);
    size_t nb_flags = 2 << nb_msg;
    assert(nb_flags >=  4);
    assert(nb_flags <= 32);
    FOR (i, 0, nb_flags) {
        crypto_kex_ctx c = *client;
        crypto_kex_ctx s = *server;
        session(&c, &s, pid, i);
    }
    printf("OK: %s\n", pid);
}

static void session_xk1()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css , 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss , 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_xk1_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_xk1_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex XK1";
    sessions(&client, &server, pid);
}

static void session_x1k1()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css , 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss , 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_x1k1_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_x1k1_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex X1K1";
    sessions(&client, &server, pid);
}

static void session_ix()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css , 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss , 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_ix_client_init(&client, client_seed, css, cps);
    crypto_kex_ix_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex IX";
    sessions(&client, &server, pid);
}

static void session_nk1()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(sss , 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_nk1_client_init(&client, client_seed, sps);
    crypto_kex_nk1_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex NK1";
    sessions(&client, &server, pid);
}

static void session_x()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(css , 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss , 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_x_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_x_server_init(&server, sss, sps);
    u8 pid[64] = "Monokex X";
    sessions(&client, &server, pid);
}

int main()
{
    session_xk1();
    session_x1k1();
    session_ix();
    session_nk1();
    session_x();
    return 0;
}
