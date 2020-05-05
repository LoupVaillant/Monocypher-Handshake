#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "monocypher.h"
#include "monokex.h"

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint64_t u64;

#define FOR(i, start, end)       for (size_t (i) = (start); (i) < (end); (i)++)
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
    u8     prelude_buf     [32];
    u8     payload_bufs [4][32];
    u8    *prelude;           // &prelude_buf  or NULL
    u8    *payloads     [4];  // &payload_bufs or NULL
    size_t prelude_size;
    size_t payload_sizes[4];
} inputs;

typedef struct {
    u8 session_key[32];
    u8 extra_key  [32];
    u8 remote_key [32];
} outputs;

typedef struct {
    u8     buf[128];     // maximum message size
    size_t size;         // how many bytes in the buffer
    size_t corrupt_in;   // if 0, corrupt next message
    size_t corrupt_at;   // byte to corrupt
    u8     corrupt_with; // Which bits we flip (XOR)
} network;

// Context status flags
static const u16 IS_OK       =  1; // Always 1 (becomes zero when wiped)
static const u16 HAS_REMOTE  =  4; // True if we have the remote DH key
static const u16 GETS_REMOTE =  8; // True if the remote key is wanted

// message tokens
typedef enum { NOOP=0, E=1, S=2, EE=3, ES=4, SE=5, SS=6 } action;

static int has_prelude(unsigned flags)             { return  flags       & 1; }
static int has_payload(unsigned flags, unsigned i) { return (flags >> i) & 2; }

static void make_inputs(inputs *in, unsigned flags)
{
    if (has_prelude(flags)) {
        size_t size = rand64() % 32;
        p_random(in->prelude_buf, size);
        in->prelude      = in->prelude_buf;
        in->prelude_size = size;
    } else {
        in->prelude      = 0;
        in->prelude_size = 0;
    }
    FOR (i, 0, 4) {
        if (has_payload(flags, i)) {
            size_t size = rand64() % 32;
            p_random(in->payload_bufs[i], size);
            in->payloads     [i] = in->payload_bufs[i];
            in->payload_sizes[i] = size;
        } else {
            in->payloads     [i] = 0;
            in->payload_sizes[i] = 0;
        }
    }
}

static network corrupt_network(size_t msg, size_t at, u8 corruptor)
{
    network n;
    n.size = 0; // nothing written yet
    n.corrupt_in   = msg;
    n.corrupt_at   = at;
    n.corrupt_with = corruptor;
    return n;
}

static network clean_network()
{
    return corrupt_network((size_t)-1, 0, 0);
}

void network_read(network *n, u8 *buf, size_t size)
{
    if (n->size != 0) {
        assert(n->size == size); // only read exactly what has been written
        memcpy(buf, n->buf, size);
        n->size = 0;
    } else {
        // if the network is empty, fill the buffer with garbage
        memset(buf, 0, size);
    }
}

void network_write(network *n, const u8 *buf, size_t size)
{
    assert(n->size == 0);
    assert(size <= 128); // just so we don't overflow the network
    memcpy(n->buf, buf, size);
    n->size = size;
    if (n->corrupt_in == 0) {
        assert(n->corrupt_at < size); // never corrupt out of bounds
        n->buf[n->corrupt_at] ^= n->corrupt_with;
    }
    n->corrupt_in--;
}

static size_t step(crypto_kex_ctx *ctx, outputs *out,
                   network  *net,
                   u8       *p_out, size_t p_osize,
                   const u8 *p_in , size_t p_isize)
{
    crypto_kex_action action;
    size_t m_size;
    action = crypto_kex_next_action(ctx, &m_size);
    size_t message_size = 0;
    do {
        switch (action) {
        case CRYPTO_KEX_READ: {
            assert(ctx->flags & IS_OK);
            u8 m_in[128];
            network_read(net, m_in, m_size + p_osize);
            int ko = crypto_kex_read_p(ctx,p_out,p_osize,m_in,m_size+p_osize);
            if (ko) {
                assert(!(ctx->flags & IS_OK));
                return (size_t)-1; // protocol failure
            } else {
                assert(ctx->flags & IS_OK);
            }
        } break;
        case CRYPTO_KEX_WRITE: {
            u8 m_out[128];
            crypto_kex_write_p(ctx, m_out, m_size + p_isize, p_in, p_isize);
            network_write(net, m_out, m_size + p_isize);
            assert(ctx->flags & IS_OK);
            message_size = m_size + p_isize;
        } break;
        case CRYPTO_KEX_REMOTE_KEY:
            crypto_kex_remote_key(ctx, out->remote_key);
            assert(ctx->flags & IS_OK);
            break;
        case CRYPTO_KEX_FINAL:
            crypto_kex_final(ctx, out->session_key, out->extra_key);
            assert(ctx->flags == 0);
            break;
        default:
            break;
        }
        action = crypto_kex_next_action(ctx, &m_size);
    } while (action != CRYPTO_KEX_NONE &&
             action != CRYPTO_KEX_READ);
    return message_size;
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

static void e_mix_hash(u8 hash[64], const u8 *in, u8 size)
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

static size_t nb_messages(const crypto_kex_ctx *ctx)
{
    FOR (i, 0, 4) {
        if (ctx->messages[i] == 0) {
            return i;
        }
    }
    return 4;
}

static void session_vectors(outputs              *out,
                            const inputs         *in,
                            const crypto_kex_ctx *client,
                            const crypto_kex_ctx *server,
                            const u8              pid[64])
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
    assert(nb_msg == nb_messages(server));

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
    assert(!memcmp(client->hash, hash, 64)); // check client initial hash
    assert(!memcmp(server->hash, hash, 64)); // check server initial hash

    // Prelude
    if (in->prelude) {
        mix_hash(hash, in->prelude, in->prelude_size);
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
        if (in->payloads[i]) {
            const u8 *payload = in->payloads[i];
            size_t    size    = in->payload_sizes[i];
            if (has_key) { e_mix_hash(hash, payload, size); }
            else         {   mix_hash(hash, payload, size); }
        } else {
            if (has_key) {
                static const u8 zero[1] = {0};
                mix_hash(hash, zero, 1);
            }
        }
    }

    memcpy(out->session_key, hash     , 32);
    memcpy(out->extra_key  , hash + 32, 32);
}

static void session(outputs              *co, // client out
                    outputs              *so, // server out
                    u8                    payloads[4][32],
                    size_t                msg_sizes[5],
                    network              *net,
                    const inputs         *in,
                    const crypto_kex_ctx *client,
                    const crypto_kex_ctx *server)
{
    crypto_kex_ctx c = *client;
    crypto_kex_ctx s = *server;
    // Prelude
    if (in->prelude) {
        crypto_kex_add_prelude(&c, in->prelude, in->prelude_size);
        crypto_kex_add_prelude(&s, in->prelude, in->prelude_size);
        assert(!memcmp(c.hash, s.hash, 64));
    }

    // Protocol
    assert(crypto_kex_next_action(&c, 0) != CRYPTO_KEX_NONE);
    assert(crypto_kex_next_action(&s, 0) != CRYPTO_KEX_NONE);

    u8    *po[4] = {0};
    u8    *pi[4] = {0};
    size_t ps[4] = {0};
    FOR (i, 0, 4) {
        if (in->payloads[i]) {
            pi[i] = in->payloads     [i];
            ps[i] = in->payload_sizes[i];
            po[i] = payloads         [i];
        }
    }

    msg_sizes[0] = step(&c, co, net, 0    , 0    , pi[0], ps[0]);
    msg_sizes[1] = step(&s, so, net, po[0], ps[0], pi[1], ps[1]);
    msg_sizes[2] = step(&c, co, net, po[1], ps[1], pi[2], ps[2]);
    msg_sizes[3] = step(&s, so, net, po[2], ps[2], pi[3], ps[3]);
    msg_sizes[4] = step(&c, co, net, po[3], ps[3], 0    , 0    );

    assert(crypto_kex_next_action(&c, 0) == CRYPTO_KEX_NONE);
    assert(crypto_kex_next_action(&s, 0) == CRYPTO_KEX_NONE);
}

static void sessions(const crypto_kex_ctx *client,
                     const crypto_kex_ctx *server,
                     const u8              pid[64])
{
    size_t nb_msg   = nb_messages(client);
    size_t nb_flags = 2 << nb_msg;
    assert(nb_flags >=  4);
    assert(nb_flags <= 32);
    FOR (flags, 0, nb_flags) {
        // test vectors
        inputs  in;  make_inputs(&in, flags);
        outputs out_vectors;
        session_vectors(&out_vectors, &in, client, server, pid);

        // Sucessful session
        outputs out_client;
        outputs out_server;
        u8      payloads [4][32]; // transmitted payloads
        size_t  msg_sizes[5];     // size of each message in a session
        network net = clean_network();
        session(&out_client, &out_server, payloads, msg_sizes, &net,
                &in, client, server);

        // No error after sucessful session
        FOR (i, 0, 5) {
            assert(msg_sizes[i] != ((size_t)-1));
        }
        assert(msg_sizes[4] == 0); // there is no message 4
        // Sucessful session faithfully transmits payloads
        size_t nb_msg = nb_messages(client);
        FOR (i, 0, nb_msg) {
            if (in.payloads[i]) {
                assert(!memcmp(payloads        [i],
                               in.payloads     [i],
                               in.payload_sizes[i]));
            }
        }
        // Sucessful session faithfully transmits the remote key
        if (client->flags & GETS_REMOTE) {
            assert(!memcmp(server->sp, out_client.remote_key, 32));
        }
        if (server->flags & GETS_REMOTE) {
            assert(!memcmp(client->sp, out_server.remote_key, 32));
        }
        // Sucessful session agrees with the test vectors
        assert(!memcmp(out_client.session_key, out_vectors.session_key, 32));
        assert(!memcmp(out_server.session_key, out_vectors.session_key, 32));
        assert(!memcmp(out_client.  extra_key, out_vectors.  extra_key, 32));
        assert(!memcmp(out_server.  extra_key, out_vectors.  extra_key, 32));

        // Failing sessions (network corruption)
        FOR (i, 0, 4) {
            if (msg_sizes[i] == 0) {
                break;
            }
            // Corrupt last byte of each message block (of 16 bytes).
            // We chose 16 bytes because it's a divisor of all lengths
            // except payloads. This guarantee we touch every component
            // of the handshake, key, tag, or payload.
            // The paranoid may modify the loop and corrupt every byte.
            //
            // Note 1: we corrrupt the most significant bit, so we
            // sometimes flip the most significant bit of public keys.
            // This operation has no effect on the key exchanges, but
            // should still result in failure. (The protocol is supposed
            // to check the integrity of the whole transcript).
            //
            // Note 2: corrupting a payload, even if it is unencrypted,
            // should result in failure: at the end of the handshake,
            // the whole transcript is authenticated.
            u8     corrupt_with = 128;
            size_t corrupt_at   = 15;
            while (corrupt_at < msg_sizes[i] + 15) {
                if (corrupt_at >= msg_sizes[i]) {
                    corrupt_at = msg_sizes[i] - 1;
                }
                size_t  corrupt_sizes[5];
                network net = corrupt_network(i, corrupt_at, corrupt_with);
                session(&out_client, &out_server, payloads, corrupt_sizes, &net,
                        &in, client, server);
                // Check that the session failed visibly.
                int ko = 0;
                FOR (j, 0, 5) {
                    ko = ko || corrupt_sizes[j] == (size_t)-1;
                }
                assert(ko);
                corrupt_at += 16;
            }
        }
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
