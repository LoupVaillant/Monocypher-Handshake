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

typedef struct {
    crypto_kex_ctx ctx;
    crypto_kex_action action;
    u8 session_key[32];
    u8 extra_key  [32];
    u8 remote_key [32];
} handshake_ctx;

static void step(handshake_ctx *ctx, u8 *msg)
{
    size_t msg_size = crypto_kex_next_message_min_size(&ctx->ctx);
    ctx->action     = crypto_kex_next_action(&ctx->ctx);
    switch (ctx->action) {
    case CRYPTO_KEX_SEND:
        crypto_kex_send(&ctx->ctx, msg, msg_size);
        return;
    case CRYPTO_KEX_RECEIVE:
        check(!crypto_kex_receive(&ctx->ctx, msg, msg_size), "corrupt message");
        return;
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

static void respond(handshake_ctx *ctx, u8 *msg)
{
    do {
        if (ctx->action == CRYPTO_KEX_GET_SESSION_KEY) { break; }
        step(ctx, msg);
    }  while (ctx->action != CRYPTO_KEX_SEND &&
              ctx->action != CRYPTO_KEX_GET_SESSION_KEY);
}

void session(handshake_ctx *client_ctx,
             handshake_ctx *server_ctx,
             u8 client_key[32],
             u8 server_key[32])
{
    client_ctx->action = CRYPTO_KEX_NOTHING;
    server_ctx->action = CRYPTO_KEX_NOTHING;

    u8 msg[96]; // maximum size of messages without payloads
    while (client_ctx->action != CRYPTO_KEX_GET_SESSION_KEY ||
           server_ctx->action != CRYPTO_KEX_GET_SESSION_KEY) {
        respond(client_ctx, msg);
        respond(server_ctx, msg);
    }
    check(!crypto_verify32(client_ctx->session_key, server_ctx->session_key),
          "Different session keys");
    check(!crypto_verify32(client_ctx->extra_key, server_ctx->extra_key),
          "Different extra keys");
    check(!crypto_verify32(server_ctx->remote_key, client_key),
          "Server has wrong client key");
    check(!crypto_verify32(client_ctx->remote_key, server_key),
          "Client has wrong server key");
}

void xk1_session()
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

    session(&client_ctx, &server_ctx, client_pk, server_pk);
}

void x_session()
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

    session(&client_ctx, &server_ctx, client_pk, server_pk);
}

int main()
{
    FOR(i, 0, 250) { xk1_session(); } printf("xk1 session OK\n");
    FOR(i, 0, 250) { x_session();   } printf("x   session OK\n");
    return 0;
}
