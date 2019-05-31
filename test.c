#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "monocypher.h"
#include "monokex.h"
#include "utils.h"

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

typedef struct {
    u8 client_sk  [32];
    u8 server_sk  [32];
    u8 client_seed[32];
    u8 server_seed[32];
    u8 prelude    [32]; int has_prelude;    size_t prelude_size;
    u8 payloads[4][32]; int has_payload[4]; size_t payload_size[4];
} inputs;

void fill_inputs(inputs *i, unsigned nb)
{
    p_random(i->client_sk  , 32);
    p_random(i->server_sk  , 32);
    p_random(i->client_seed, 32);
    p_random(i->server_seed, 32);
    i->prelude_size    = 32;
    i->payload_size[0] = 32;
    i->payload_size[1] = 32;
    i->payload_size[2] = 32;
    i->payload_size[3] = 32;
    i->has_prelude     = nb &  1 ? 1 : 0;
    i->has_payload[0]  = nb &  2 ? 1 : 0;
    i->has_payload[1]  = nb &  4 ? 1 : 0;
    i->has_payload[2]  = nb &  8 ? 1 : 0;
    i->has_payload[3]  = nb & 16 ? 1 : 0;
    if (i->has_prelude   ) { memset(i->prelude    , 0x33, 32); }
    if (i->has_payload[0]) { memset(i->payloads[0], 0x44, 32); }
    if (i->has_payload[1]) { memset(i->payloads[1], 0x55, 32); }
    if (i->has_payload[2]) { memset(i->payloads[2], 0x66, 32); }
    if (i->has_payload[3]) { memset(i->payloads[3], 0x77, 32); }
}

/* void print_inputs(const inputs *i) */
/* { */
/*     printf("client_sk  : "); print_vector(i->client_sk  , 32); */
/*     printf("server_sk  : "); print_vector(i->server_sk  , 32); */
/*     printf("client_seed: "); print_vector(i->client_seed, 32); */
/*     printf("server_seed: "); print_vector(i->server_seed, 32); */
/*     if (i->has_prelude) { */
/*         printf("prelude    : "); */
/*         print_vector(i->prelude, 32); */
/*     } */
/*     FOR (j, 0, 4) { */
/*         if (i->has_payload[j]) { */
/*             printf("payload[%lu]    : ", j); */
/*             print_vector(i->payloads[j], 32); */
/*         } */
/*     } */
/* } */

typedef struct {
    crypto_kex_ctx ctx;
    u8 session_key[ 32];
    u8 extra_key  [ 32];
    u8 remote_key [ 32];
    u8 payloads[4][ 32];
    u8 messages[4][128];
    unsigned msg_num;
} handshake_ctx;


/* static void print_handshake(handshake_ctx *ctx) */
/* { */
/*     printf("session key  ");  print_vector(ctx->session_key,  32); */
/*     printf("extra   key  ");  print_vector(ctx->extra_key  ,  32); */
/*     printf("remote  key  ");  print_vector(ctx->remote_key ,  32); */
/*     printf("payload 1    ");  print_vector(ctx->payloads[0],  32); */
/*     printf("payload 2    ");  print_vector(ctx->payloads[1],  32); */
/*     printf("payload 3    ");  print_vector(ctx->payloads[2],  32); */
/*     printf("payload 4    ");  print_vector(ctx->payloads[3],  32); */
/*     printf("message 1    ");  print_vector(ctx->messages[0], 128); */
/*     printf("message 2    ");  print_vector(ctx->messages[1], 128); */
/*     printf("message 3    ");  print_vector(ctx->messages[2], 128); */
/*     printf("message 4    ");  print_vector(ctx->messages[3], 128); */
/* } */

static void step(handshake_ctx *ctx, u8 *msg, const inputs *i)
{
    do {
        u8 pld_size = ctx->msg_num < 4 && i->has_payload[ctx->msg_num]
                    ? i->payload_size[ctx->msg_num]
                    : 0;
        size_t msg_size;
        crypto_kex_action action = crypto_kex_next_action(&ctx->ctx, &msg_size);
        msg_size += pld_size;
        switch (action) {
        case CRYPTO_KEX_READ: {
            u8 *pld = ctx->payloads[ctx->msg_num];
            check(!crypto_kex_read_p(&ctx->ctx, pld, pld_size, msg, msg_size),
                  "corrupt message");
            memcpy(ctx->messages[ctx->msg_num], msg, msg_size);
            ctx->msg_num++;
            break;
        }
        case CRYPTO_KEX_WRITE: {
            const u8 *pld = i->payloads[ctx->msg_num];
            crypto_kex_write_p(&ctx->ctx, msg, msg_size, pld, pld_size);
            memcpy(ctx->messages[ctx->msg_num], msg, msg_size);
            memcpy(ctx->payloads[ctx->msg_num], pld, pld_size);
            ctx->msg_num++;
            break;
        }
        case CRYPTO_KEX_REMOTE_KEY:
            crypto_kex_remote_key(&ctx->ctx, ctx->remote_key);
            break;
        case CRYPTO_KEX_FINAL:
            crypto_kex_final(&ctx->ctx, ctx->session_key, ctx->extra_key);
            break;
        default:
            break;
        }
    } while (crypto_kex_next_action(&ctx->ctx, 0) != CRYPTO_KEX_NONE &&
             crypto_kex_next_action(&ctx->ctx, 0) != CRYPTO_KEX_READ);
}

static void session(handshake_ctx *client_ctx,
                    handshake_ctx *server_ctx,
                    const inputs *i)
{
    client_ctx->msg_num = 0;
    server_ctx->msg_num = 0;
    FOR (i, 0, 4) {
        memset(client_ctx->messages[i], 255, 128);
        memset(server_ctx->messages[i], 255, 128);
        memset(client_ctx->payloads[i], 255,  32);
        memset(server_ctx->payloads[i], 255,  32);
    }
    if (i->has_prelude) {
        crypto_kex_add_prelude(&client_ctx->ctx, i->prelude, i->prelude_size);
        crypto_kex_add_prelude(&server_ctx->ctx, i->prelude, i->prelude_size);
    }

    u8 msg[128]; // maximum size of messages without 32 bytes payloads
    while (crypto_kex_next_action(&client_ctx->ctx, 0) != CRYPTO_KEX_NONE ||
           crypto_kex_next_action(&server_ctx->ctx, 0) != CRYPTO_KEX_NONE) {
        step(client_ctx, msg, i);
        step(server_ctx, msg, i);
    }

    /* printf("Client handshake\n"); */
    /* printf("----------------\n"); */
    /* print_handshake(client_ctx); */
    /* printf("\n"); */
    /* printf("Server handshake\n"); */
    /* printf("----------------\n"); */
    /* print_handshake(server_ctx); */

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

static void xk1_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_xk1_client_init(&client_ctx.ctx, client_seed,
                               i.client_sk, client_pk, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_xk1_server_init(&server_ctx.ctx, server_seed,
                               i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}

static void x1k1_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_x1k1_client_init(&client_ctx.ctx, client_seed,
                                i.client_sk, client_pk, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_x1k1_server_init(&server_ctx.ctx, server_seed,
                                i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}

static void nk1_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_nk1_client_init(&client_ctx.ctx, client_seed, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_nk1_server_init(&server_ctx.ctx, server_seed,
                               i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, 0, server_pk);
}

void x_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_x_client_init(&client_ctx.ctx, client_seed,
                             i.client_sk, client_pk, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_x_server_init(&server_ctx.ctx, i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}

int main()
{
    FOR(i, 0, 32) { xk1_session (i); } printf("xk1  session OK\n");
    FOR(i, 0, 32) { x1k1_session(i); } printf("x1k1 session OK\n");
    FOR(i, 0, 32) { nk1_session (i); } printf("nk1  session OK\n");
    FOR(i, 0, 32) { x_session   (i); } printf("x    session OK\n");
    return 0;
}
