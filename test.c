#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <monocypher.h>
#include "monokex.h"
#include "utils.h"

static void check(int condition, const char *error)
{
    if (!condition) {
        fprintf(stderr, "%s\n", error);
        exit(1);
    }
}

static void check_equal(u8 *a, u8 *b, size_t size, const char *error)
{
    check(!memcmp(a, b, size), error);
}

typedef struct {
    crypto_kex_ctx    ctx;
    crypto_kex_action action;
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

static void step(handshake_ctx *ctx, u8 *msg, u8 *pld, unsigned nb)
{
    size_t msg_size = crypto_kex_next_message_min_size(&ctx->ctx);
    ctx->action     = crypto_kex_next_action(&ctx->ctx);
    switch (ctx->action) {
    case CRYPTO_KEX_SEND: {
        pld = nb & (1 << ctx->msg_num) ? pld + ctx->msg_num * 32 : 0;
        size_t pld_size = pld ? 32 : 0;
        msg_size += pld_size;
        crypto_kex_send_p(&ctx->ctx, msg, msg_size, pld, pld_size);
        memcpy(ctx->messages[ctx->msg_num], msg, msg_size);
        if (pld) {
            memcpy(ctx->payloads[ctx->msg_num], pld, pld_size);
        }
        ctx->msg_num++;
        return;
    }
    case CRYPTO_KEX_RECEIVE: {
        pld = nb & (1 << ctx->msg_num) ? pld + ctx->msg_num * 32 : 0;
        size_t pld_size = pld ? 32 : 0;
        msg_size += pld_size;
        check(!crypto_kex_receive_p(&ctx->ctx, pld, pld_size, msg, msg_size),
              "corrupt message");
        memcpy(ctx->messages[ctx->msg_num], msg, msg_size);
        if (pld) {
            memcpy(ctx->payloads[ctx->msg_num], pld, pld_size);
        }
        ctx->msg_num++;
        return;
    }
    case CRYPTO_KEX_GET_REMOTE_KEY:
        crypto_kex_get_remote_key(&ctx->ctx, ctx->remote_key);
        return;
    case CRYPTO_KEX_GET_SESSION_KEY:
        crypto_kex_get_session_key(&ctx->ctx, ctx->session_key, ctx->extra_key);
        return;
    default: check(0, "One step too many");
    }
    return;
}

static void respond(handshake_ctx *ctx, u8 *msg, u8 *pld, unsigned nb)
{
    do {
        if (ctx->action == CRYPTO_KEX_GET_SESSION_KEY) { break; }
        step(ctx, msg, pld, nb);
    }  while (ctx->action != CRYPTO_KEX_SEND &&
              ctx->action != CRYPTO_KEX_GET_SESSION_KEY);
}

static void session(handshake_ctx *client_ctx,
                    handshake_ctx *server_ctx,
                    u8 client_key[32],
                    u8 server_key[32],
                    unsigned nb)
{
    client_ctx->action  = CRYPTO_KEX_NOTHING;
    server_ctx->action  = CRYPTO_KEX_NOTHING;
    client_ctx->msg_num = 0;
    server_ctx->msg_num = 0;
    FOR (i, 0, 4) {
        memset(client_ctx->messages[i], 255, 128);
        memset(server_ctx->messages[i], 255, 128);
        memset(client_ctx->payloads[i], 255,  32);
        memset(server_ctx->payloads[i], 255,  32);
    }
    u8 payloads[128];
    memset(payloads +  0, 0x33, 32);
    memset(payloads + 32, 0x44, 32);
    memset(payloads + 64, 0x55, 32);
    memset(payloads + 96, 0x66, 32);
    u8 prelude[32];
    memset(prelude, 0x77, 32);

    if ((nb & 16) != 0) {
        crypto_kex_add_prelude(&client_ctx->ctx, prelude, 32);
        crypto_kex_add_prelude(&server_ctx->ctx, prelude, 32);
    }

    u8 msg[128]; // maximum size of messages without 32 bytes payloads
    while (client_ctx->action != CRYPTO_KEX_GET_SESSION_KEY ||
           server_ctx->action != CRYPTO_KEX_GET_SESSION_KEY) {
        respond(client_ctx, msg, payloads, nb);
        respond(server_ctx, msg, payloads, nb);
    }

    /* printf("Client handshake\n"); */
    /* printf("----------------\n"); */
    /* print_handshake(client_ctx); */
    /* printf("\n"); */
    /* printf("Server handshake\n"); */
    /* printf("----------------\n"); */
    /* print_handshake(server_ctx); */

    check_equal(client_ctx->session_key, server_ctx->session_key, 32,
          "Different session keys");
    check_equal(client_ctx->extra_key, server_ctx->extra_key, 32,
          "Different extra keys");
    check_equal(server_ctx->remote_key, client_key, 32,
          "Server has wrong client key");
    check_equal(client_ctx->remote_key, server_key, 32,
          "Client has wrong server key");
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
    RANDOM_INPUT(client_sk, 32);
    RANDOM_INPUT(server_sk, 32);
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    u8 client_pk[32];  crypto_key_exchange_public_key(client_pk, client_sk);
    u8 server_pk[32];  crypto_key_exchange_public_key(server_pk, server_sk);

    handshake_ctx client_ctx;
    crypto_kex_xk1_init_client(&client_ctx.ctx, client_seed,
                               client_sk, client_pk, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_xk1_init_server(&server_ctx.ctx, server_seed,
                               server_sk, server_pk);

    session(&client_ctx, &server_ctx, client_pk, server_pk, nb);
}

void x_session(unsigned nb)
{
    RANDOM_INPUT(client_sk, 32);
    RANDOM_INPUT(server_sk, 32);
    RANDOM_INPUT(client_seed, 32);
    u8 client_pk[32];  crypto_key_exchange_public_key(client_pk, client_sk);
    u8 server_pk[32];  crypto_key_exchange_public_key(server_pk, server_sk);

    handshake_ctx client_ctx;
    crypto_kex_x_init_client(&client_ctx.ctx, client_seed,
                             client_sk, client_pk, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_x_init_server(&server_ctx.ctx, server_sk, server_pk);

    session(&client_ctx, &server_ctx, client_pk, server_pk, nb);
}

int main()
{
    FOR(i, 0, 32) { xk1_session(i); } printf("xk1 session OK\n");
    FOR(i, 0, 32) { x_session(i);   } printf("x   session OK\n");
    return 0;
}
