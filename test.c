#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "monocypher.h"
#include "monokex.h"
#include "vectors.h"

typedef uint8_t  u8;
typedef uint64_t u64;

#define FOR(i, start, end) for (size_t (i) = (start); (i) < (end); (i)++)

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

static void check(int condition, const char *error)
{
    if (!condition) {
        fprintf(stderr, "%s\n", error);
        exit(1);
    }
}

static void check_equal(const u8 *a, const u8 *b, size_t size,
                        const char *error)
{
    check(!memcmp(a, b, size), error);
}

static void fill_inputs(in_vectors *i, unsigned nb)
{
    memset(i, 0, sizeof(*i));
    p_random(i->cse, 32);
    p_random(i->sse, 32);
    p_random(i->css, 32);
    p_random(i->sss, 32);
    memset(i->prelude    , 0x33, 32);
    memset(i->payloads[0], 0x44, 32);
    memset(i->payloads[1], 0x55, 32);
    memset(i->payloads[2], 0x66, 32);
    memset(i->payloads[3], 0x77, 32);
    i->prelude_size     = 32;
    i->payload_sizes[0] = 32;
    i->payload_sizes[1] = 32;
    i->payload_sizes[2] = 32;
    i->payload_sizes[3] = 32;
    i->has_prelude     = nb &  1 ? 1 : 0;
    i->has_payload[0]  = nb &  2 ? 1 : 0;
    i->has_payload[1]  = nb &  4 ? 1 : 0;
    i->has_payload[2]  = nb &  8 ? 1 : 0;
    i->has_payload[3]  = nb & 16 ? 1 : 0;
}

typedef struct {
    crypto_kex_ctx ctx;
    u8 session_key[ 32];
    u8 extra_key  [ 32];
    u8 remote_key [ 32];
    u8 payloads[4][ 32];
    u8 messages[4][128];
    unsigned msg_num;
} handshake_ctx;

static void step(handshake_ctx *ctx, u8 *msg,
                 const in_vectors  *i,
                 const out_vectors *o)
{
    do {
        u8 pld_size = ctx->msg_num < 4 && i->has_payload[ctx->msg_num]
                    ? i->payload_sizes[ctx->msg_num]
                    : 0;
        size_t msg_size;
        crypto_kex_action action = crypto_kex_next_action(&ctx->ctx, &msg_size);
        msg_size += pld_size;

        switch (action) {
        case CRYPTO_KEX_READ: {
            u8 *pld = i->has_payload[ctx->msg_num]
                    ? ctx->payloads[ctx->msg_num]
                    : 0;
            check(!crypto_kex_read_p(&ctx->ctx, pld, pld_size, msg, msg_size),
                  "corrupt message");
//            check_equal(ctx->ctx.hash, o->message_hashes[ctx->msg_num], 64,
//                        "Test vectors: wrong intermediate hash");
//            check(msg_size == o->message_sizes[ctx->msg_num],
//                  "Test vectors: wrong message size");
            memcpy(ctx->messages[ctx->msg_num], msg, msg_size);
            if (pld) {
//                check_equal(i->payloads[ctx->msg_num], pld, pld_size,
//                            "Test vectors: wrong payload");
            }
            ctx->msg_num++;
            break;
        }
        case CRYPTO_KEX_WRITE: {
            const u8 *pld = i->has_payload[ctx->msg_num]
                          ? i->payloads[ctx->msg_num]
                          : 0;
            crypto_kex_write_p(&ctx->ctx, msg, msg_size, pld, pld_size);
            //           check_equal(ctx->ctx.hash, o->message_hashes[ctx->msg_num], 64,
//                        "Test vectors: wrong intermediate hash");
//            check(msg_size == o->message_sizes[ctx->msg_num],
//                  "Test vectors: wrong message size");
//            check_equal(o->messages[ctx->msg_num], msg, msg_size,
//                        "Test vectors: wrong message");
            memcpy(ctx->messages[ctx->msg_num], msg, msg_size);
            if (pld) {
                memcpy(ctx->payloads[ctx->msg_num], pld, pld_size);
            }
            ctx->msg_num++;
            break;
        }
        case CRYPTO_KEX_REMOTE_KEY:
            crypto_kex_remote_key(&ctx->ctx, ctx->remote_key);
            break;
        case CRYPTO_KEX_FINAL:
            crypto_kex_final(&ctx->ctx, ctx->session_key, ctx->extra_key);
//            check_equal(o->session_key, ctx->session_key, 32,
//                        "Test vectors: wrong session key");
//            check_equal(o->extra_key, ctx->extra_key, 32,
//                        "Test vectors: wrong extra key");
            break;
        default:
            break;
        }
    } while (crypto_kex_next_action(&ctx->ctx, 0) != CRYPTO_KEX_NONE &&
             crypto_kex_next_action(&ctx->ctx, 0) != CRYPTO_KEX_READ);
}

static void session(handshake_ctx *client_ctx,
                    handshake_ctx *server_ctx,
                    const in_vectors  *i,
                    const out_vectors *o)
{
    client_ctx->msg_num = 0;
    server_ctx->msg_num = 0;
    FOR (j, 0, 4) {
        memset(client_ctx->messages[j], 255, 128);
        memset(server_ctx->messages[j], 255, 128);
        memset(client_ctx->payloads[j], 255,  32);
        memset(server_ctx->payloads[j], 255,  32);
    }

    check_equal(client_ctx->ctx.hash, o->initial_hash, 64,
                "Vectors: wrong client initial hash");
    check_equal(server_ctx->ctx.hash, o->initial_hash, 64,
                "Vectors: wrong server initial hash");

    if (i->has_prelude) {
        crypto_kex_add_prelude(&client_ctx->ctx, i->prelude, i->prelude_size);
        crypto_kex_add_prelude(&server_ctx->ctx, i->prelude, i->prelude_size);
        check_equal(client_ctx->ctx.hash, o->prelude_hash, 64,
                    "Vectors: wrong client prelude hash");
        check_equal(server_ctx->ctx.hash, o->prelude_hash, 64,
                    "Vectors: wrong server prelude hash");
    }

    u8 msg[128]; // maximum size of messages with 32 bytes payloads
    while (crypto_kex_next_action(&client_ctx->ctx, 0) != CRYPTO_KEX_NONE ||
           crypto_kex_next_action(&server_ctx->ctx, 0) != CRYPTO_KEX_NONE) {
        step(client_ctx, msg, i, o);
        step(server_ctx, msg, i, o);
    }
}

static void compare(handshake_ctx *client_ctx,
                    handshake_ctx *server_ctx,
                    const u8 client_key[32],
                    const u8 server_key[32])
{
    check_equal(client_ctx->session_key, server_ctx->session_key, 32,
          "Different session keys");
    check_equal(client_ctx->extra_key, server_ctx->extra_key, 32,
          "Different extra keys");
    if (client_key) {
        check_equal(server_ctx->remote_key, client_key, 32,
                    "Server has wrong client key");
    }
    if (server_key) {
        check_equal(client_ctx->remote_key, server_key, 32,
                    "Client has wrong server key");
    }
    check(client_ctx->msg_num == server_ctx->msg_num,
          "Message numbers don't match");
    FOR (i, 0, 4) {
        check_equal(client_ctx->messages[i], server_ctx->messages[i], 128,
                    "Message doesn't match");
        check_equal(client_ctx->payloads[i], server_ctx->payloads[i],  32,
                    "Payload doesn't match");
    }
}

#define PROTOCOL_ID(id)           \
    static const u8 pid[64] = id; \
    memcpy(i.protocol_id, pid, 64)

#define STATIC(cs)      \
    u8 cs##ps[32];      \
    i.has_##cs##ss = 1; \
    crypto_key_exchange_public_key(cs##ps, i.cs##ss)

#define EPHEMERAL(cs)   \
    u8 cs##se[32];      \
    i.has_##cs##se = 1; \
    memcpy(cs##se, i.cs##se, 32)

#define PATTERN {           \
    unsigned msg_num = -1u; \
    unsigned act_num = 0;
#define _(a)     i.pattern[msg_num][act_num] = a; act_num++
#define MESSAGE  msg_num++;                       act_num = 0
#define END      msg_num++; }                     do {} while (0)

static void xk1_session(unsigned nb)
{
    in_vectors i;
    fill_inputs(&i, nb);
    PROTOCOL_ID("Monokex XK1");
    EPHEMERAL(c);
    EPHEMERAL(s);
    STATIC(c);
    STATIC(s);
    i.pre_share_sps = 1;
    PATTERN {
        MESSAGE; _(E);
        MESSAGE; _(E); _(EE); _(ES);
        MESSAGE; _(S); _(SE);
    } END;

    out_vectors o;
    generate(&o, &i);

    handshake_ctx client_ctx, server_ctx;
    crypto_kex_xk1_client_init(&client_ctx.ctx, cse, i.css, cps, sps);
    crypto_kex_xk1_server_init(&server_ctx.ctx, sse, i.sss, sps);
    memcpy(client_ctx.remote_key, sps, 32);

    session(&client_ctx, &server_ctx, &i, &o);
    compare(&client_ctx, &server_ctx, cps, sps);
}

static void x1k1_session(unsigned nb)
{
    in_vectors i;
    fill_inputs(&i, nb);
    PROTOCOL_ID("Monokex X1K1");
    EPHEMERAL(c);
    EPHEMERAL(s);
    STATIC(c);
    STATIC(s);
    i.pre_share_sps = 1;
    PATTERN {
        MESSAGE; _(E);
        MESSAGE; _(E); _(EE); _(ES);
        MESSAGE; _(S);
        MESSAGE; _(SE);
    } END;

    out_vectors o;
    generate(&o, &i);

    handshake_ctx client_ctx, server_ctx;
    crypto_kex_x1k1_client_init(&client_ctx.ctx, cse, i.css, cps, sps);
    crypto_kex_x1k1_server_init(&server_ctx.ctx, sse, i.sss, sps);
    memcpy(client_ctx.remote_key, sps, 32);

    session(&client_ctx, &server_ctx, &i, &o);
    compare(&client_ctx, &server_ctx, cps, sps);
}

static void ix_session(unsigned nb)
{
    in_vectors i;
    fill_inputs(&i, nb);
    PROTOCOL_ID("Monokex IX");
    EPHEMERAL(c);
    EPHEMERAL(s);
    STATIC(c);
    STATIC(s);
    PATTERN {
        MESSAGE; _(E); _(S);
        MESSAGE; _(E); _(EE); _(SE); _(S); _(ES);
    } END;

    out_vectors o;
    generate(&o, &i);

    handshake_ctx client_ctx, server_ctx;
    crypto_kex_ix_client_init(&client_ctx.ctx, cse, i.css, cps);
    crypto_kex_ix_server_init(&server_ctx.ctx, sse, i.sss, sps);
    memcpy(client_ctx.remote_key, sps, 32);

    session(&client_ctx, &server_ctx, &i, &o);
    compare(&client_ctx, &server_ctx, cps, sps);
}

static void nk1_session(unsigned nb)
{
    in_vectors i;
    fill_inputs(&i, nb);
    PROTOCOL_ID("Monokex NK1");
    EPHEMERAL(c);
    EPHEMERAL(s);
    STATIC(s);
    i.pre_share_sps = 1;
    PATTERN {
        MESSAGE; _(E);
        MESSAGE; _(E); _(EE); _(ES);
    } END;

    out_vectors o;
    generate(&o, &i);

    handshake_ctx client_ctx, server_ctx;
    crypto_kex_nk1_client_init(&client_ctx.ctx, cse, sps);
    crypto_kex_nk1_server_init(&server_ctx.ctx, sse, i.sss, sps);
    memcpy(client_ctx.remote_key, sps, 32);

    session(&client_ctx, &server_ctx, &i, &o);
    compare(&client_ctx, &server_ctx, 0, sps);
}

static void x_session(unsigned nb)
{
    in_vectors i;
    fill_inputs(&i, nb);
    PROTOCOL_ID("Monokex X");
    EPHEMERAL(c);
    STATIC(c);
    STATIC(s);
    i.pre_share_sps = 1;
    PATTERN {
        MESSAGE; _(E); _(ES); _(S); _(SS);
    } END;

    out_vectors o;
    generate(&o, &i);

    handshake_ctx client_ctx, server_ctx;
    crypto_kex_x_client_init(&client_ctx.ctx, cse, i.css, cps, sps);
    crypto_kex_x_server_init(&server_ctx.ctx, i.sss, sps);
    memcpy(client_ctx.remote_key, sps, 32);

    session(&client_ctx, &server_ctx, &i, &o);
    compare(&client_ctx, &server_ctx, cps, sps);
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
