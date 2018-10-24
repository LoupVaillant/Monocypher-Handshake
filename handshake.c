#include "handshake.h"
#include <stddef.h>

#define FOR(i, start, end)   for (size_t (i) = (start); (i) < (end); (i)++)
#define WIPE_CTX(ctx)        crypto_wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer)  crypto_wipe(buffer, sizeof(buffer))

typedef uint8_t u8;

static const u8 zero[32] = {0};

static int copy32(u8 out[32], u8 in[32])
{
    FOR (i, 0, 32) {
        out[i] = in[i];
    }
}

static void encrypt32(u8 out[32], const u8 in[32], const u8 key[32])
{
    crypto_chacha_ctx ctx;
    crypto_chacha20_init   (&ctx, key, zero);
    crypto_chacha20_encrypt(&ctx, out, in, 32);
    WIPE_CTX(&ctx);
}

static handshake_update_key(crypto_handshake_ctx *ctx,
                            const u8              secret_key[32],
                            const u8              public_key[32])
{
    u8 new_key[32];
    crypto_key_exchange(new_key, secret_key, public_key);
    FOR (i, 0, 32) {
        ctx->key[i] ^= new_key[i];
    }
    WIPE_BUFFER(new_key);
}

static int handshake_record(crypto_handshake_ctx *ctx, u8 msg[32])
{
    copy32(ctx->transcript + ctx->transcript_size, msg);
    ctx->transcript_size += 32;
}

static void handshake_auth_buf(crypto_handshake_ctx *ctx, u8 block[64],
                               u8 mac[16])
{
    // block = auth_key || derived_key
    crypto_chacha_ctx ctx;
    crypto_chacha20_init  (&ctx, ctx->key, zero);
    crypto_chacha20_stream(&ctx, block, 64);
    WIPE_CTX(&ctx);
    // use the authentication key of the block
    crypto_poly1305(mac, ctx->transcript, ctx->transcript_size, block);
}

static void handshake_auth(crypto_handshake_ctx *ctx, u8 mac[16])
{
    u8 block[64];
    handshake_auth_buf(ctx, block, mac);
    WIPE_BUFFER(block);
}

static int handshake_verify_buf(crypto_handshake_ctx *ctx, u8 block[64],
                                const u8 mac[16])
{
    u8 real_mac[16];
    handshake_auth_buf(ctx, block, real_mac);
    int mismatch = crypto_verify16(real_mac, mac);
    WIPE_BUFFER(real_mac);
    return mismatch;
}

static int handshake_verify(crypto_handshake_ctx *ctx, const u8 mac[16])
{
    u8 block[64];
    int mismatch = handshake_verify_buf(ctx, block, mac);
    WIPE_BUFFER(block);
    return mismatch;
}

static void handshake_init(crypto_handshake_ctx *ctx,
                           const u8              random_seed[32],
                           const u8              local_sk  [32])
{
    copy32(ctx->key         , zero       );
    copy32(ctx->local_sk    , local_sk   );
    copy32(ctx->ephemeral_sk, random_seed);
    ctx->transcript_size = 0;
}

void crypto_handshake_request(crypto_handshake_ctx *ctx,
                              u8                    msg1       [32],
                              const u8              random_seed[32],
                              const u8              remote_pk  [32],
                              const u8              local_sk   [32],
                              const u8              local_pk   [32])
{
    // Init context
    handshake_init(ctx, random_seed, local_sk);
    copy32(ctx->remote_pk, remote_pk); // recipient's public key is known
    if (local_pk == 0) crypto_key_exchange_public_key(ctx->local_pk, local_sk);
    else               copy32                        (ctx->local_pk, local_pk);

    // Send request
    crypto_key_exchange_public_key(msg1, ctx->ephemeral_sk);
    handshake_record(ctx, msg1);
}

void crypto_handshake_respond(crypto_handshake_ctx *ctx,
                              u8                    msg2       [48],
                              const u8              msg1       [32],
                              const u8              random_seed[32],
                              const u8              local_sk   [32])
{
    // Init context
    handshake_init(ctx, random_seed, local_sk);

    // Receive request (no authentication yet)
    handshake_record(ctx, msg1);

    // Update key
    u8 *ephemeral_pk = ctx->transcript;
    handshake_update_key(ctx, ctx->ephemeral_sk, ephemeral_pk);
    handshake_update_key(ctx, ctx->local_sk    , ephemeral_pk);

    // Send & authenticate response
    crypto_key_exchange_public_key(msg2, ctx->ephemeral_sk);
    handshake_record(ctx, msg2);
    handshake_auth(ctx, msg2 + 32); // tag is not in the transcript
}

int crypto_handshake_confirm(crypto_handshake_ctx *ctx,
                             u8                    session_key[32],
                             u8                    msg3       [48],
                             const u8              msg2       [48])
{
    // Update key
    u8 *ephemeral_pk = ctx->transcript + 32;
    handshake_update_key(ctx, ctx->ephemeral_sk, ephemeral_pk);
    handshake_update_key(ctx, ctx->local_sk    , ephemeral_pk);

    // Receive & verify response
    handshake_record(ctx, msg2);
    if (handshake_verify(ctx, msg2 + 32)) {
        return -1;
    }

    // Update key (again)
    handshake_update_key(ctx, ctx->ephemeral_sk, ctx->remote_pk);

    // Send & authenticate confirmation, get session key
    u8 block[64];
    encrypt32(msg3, ctx->local_pk, ctx->key);
    handshake_record(ctx, msg3);
    handshake_auth_buf(ctx, block, msg3 + 32);
    copy32(session_key, block + 32);

    // Clean up
    WIPE_BUFFER(block);
    WIPE_CTX(ctx);
    return 0;
}

int crypto_handshake_accept(crypto_handshake_ctx *ctx,
                            u8                    session_key[32],
                            u8                    remote_pk  [32],
                            const u8              msg3       [48])
{
    // Receive & decrypt confirmation
    handshake_record(ctx, msg3);
    encrypt32(remote_pk, msg3, ctx->key);

    // Update key
    handshake_update_key(ctx, ctx->ephemeral_sk, remote_pk);

    // Verify sender, get session key
    u8 block[64];
    if (handshake_verify_buf(ctx, block, msg3 + 32)) {
        WIPE_BUFFER(block);
        return -1;
    }
    copy32(session_key, block + 32);

    // Clean up
    WIPE_BUFFER(block);
    WIPE_CTX(ctx);
    return 0;
}
