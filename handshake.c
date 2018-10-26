#include <monocypher.h>
#include "handshake.h"

#define FOR(i, start, end)   for (size_t (i) = (start); (i) < (end); (i)++)
#define WIPE_CTX(ctx)        crypto_wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer)  crypto_wipe(buffer, sizeof(buffer))

typedef uint8_t u8;

static const u8 zero[32] = {0};

static void copy32(u8 out[32], const u8 in[32])
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

static void handshake_update_key(crypto_handshake_ctx *ctx,
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

static void handshake_record(crypto_handshake_ctx *ctx, const u8 msg[32])
{
    copy32(ctx->transcript + ctx->transcript_size, msg);
    ctx->transcript_size += 32;
}

static void handshake_auth_session_key(crypto_handshake_ctx *ctx,
                                       u8 session_key[32],
                                       u8 mac        [16])
{
    u8 block[64]; // auth_key || derived_key
    // Derive the keys
    crypto_chacha_ctx chacha_ctx;
    crypto_chacha20_init  (&chacha_ctx, ctx->key, zero);
    crypto_chacha20_stream(&chacha_ctx, block, 64);
    // Authenticate & output session key
    crypto_poly1305(mac, ctx->transcript, ctx->transcript_size, block);
    copy32(session_key, block + 32);
    // Clean up
    WIPE_CTX(&chacha_ctx);
    WIPE_BUFFER(block);
}

static void handshake_auth(crypto_handshake_ctx *ctx, u8 mac[16])
{
    u8 tmp[32]; // won't leak any secret. No need to wipe
    handshake_auth_session_key(ctx, tmp, mac);
}

static int handshake_verify_session_key(crypto_handshake_ctx *ctx,
                                        u8       session_key[64],
                                        const u8 mac        [16])
{
    u8 tmp_session_key[32];
    u8 real_mac       [16];
    handshake_auth_session_key(ctx, tmp_session_key, real_mac);
    int mismatch = crypto_verify16(real_mac, mac);
    if (!mismatch) { // only copy the session key if all went well
        copy32(session_key, tmp_session_key);
    }
    WIPE_BUFFER(real_mac);
    WIPE_BUFFER(tmp_session_key);
    return mismatch;
}

static int handshake_verify(crypto_handshake_ctx *ctx, const u8 mac[16])
{
    u8 tmp[32]; // won't leak any secret. No need to wipe
    return handshake_verify_session_key(ctx, tmp, mac);
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
    const u8 *ephemeral_pk = msg2;
    handshake_update_key(ctx, ctx->ephemeral_sk, ephemeral_pk  );
    handshake_update_key(ctx, ctx->ephemeral_sk, ctx->remote_pk);

    // Receive & verify response
    handshake_record(ctx, msg2);
    if (handshake_verify(ctx, msg2 + 32)) {
        WIPE_CTX(ctx);
        return -1;
    }

    // Send confirmation, get session key
    encrypt32(msg3, ctx->local_pk, ctx->key);
    handshake_record(ctx, msg3);

    // Update key & authanticate confirmation
    handshake_update_key(ctx, ctx->local_sk, ephemeral_pk);
    handshake_auth_session_key(ctx, session_key, msg3 + 32);

    // Clean up
    WIPE_CTX(ctx);
    return 0;
}

int crypto_handshake_accept(crypto_handshake_ctx *ctx,
                            u8                    session_key[32],
                            u8                    remote_pk  [32],
                            const u8              msg3       [48])
{
    u8 tmp_remote_pk[32]; // don't touch remote_pk before we're sure

    // Receive & decrypt confirmation
    handshake_record(ctx, msg3);
    encrypt32(tmp_remote_pk, msg3, ctx->key);

    // Update key
    handshake_update_key(ctx, ctx->ephemeral_sk, tmp_remote_pk);

    // Verify sender, get session key
    if (handshake_verify_session_key(ctx, session_key, msg3 + 32)) {
        WIPE_BUFFER(tmp_remote_pk);
        WIPE_CTX(ctx);
        return -1;
    }
    copy32(remote_pk, tmp_remote_pk);

    // Clean up
    WIPE_BUFFER(tmp_remote_pk);
    WIPE_CTX(ctx);
    return 0;
}

void crypto_send(u8       session_key[32],
                 u8       msg        [80],
                 const u8 random_seed[32],
                 const u8 remote_pk  [32],
                 const u8 local_sk   [32],
                 const u8 local_pk   [32])
{
    // Init context
    crypto_handshake_ctx ctx;
    handshake_init(&ctx, random_seed, local_sk);
    if (local_pk == 0) crypto_key_exchange_public_key(ctx.local_pk, local_sk);
    else               copy32                        (ctx.local_pk, local_pk);

    // Send ephemeral key
    crypto_key_exchange_public_key(msg, random_seed);
    handshake_record(&ctx, msg);
    handshake_update_key(&ctx, ctx.ephemeral_sk, remote_pk);

    // Send long term key
    encrypt32(msg + 32, ctx.local_pk, ctx.key);
    handshake_record(&ctx, msg + 32);
    handshake_update_key(&ctx, ctx.local_sk, remote_pk);

    // Authenticate message, get session key
    handshake_auth_session_key(&ctx, session_key, msg + 64);

    // Clean up
    WIPE_CTX(&ctx);
}

int crypto_receive(u8       session_key[32],
                   u8       remote_pk  [32],
                   const u8 msg        [80],
                   const u8 random_seed[32],
                   const u8 local_sk   [32])
{
    // Init context
    crypto_handshake_ctx ctx;
    handshake_init(&ctx, random_seed, local_sk);

    // Receive ephemeral key
    handshake_record(&ctx, msg);
    const u8 *ephemeral_pk = msg;
    handshake_update_key(&ctx, local_sk, ephemeral_pk);

    // Receive long term key
    handshake_record(&ctx, msg + 32);
    u8 tmp_remote_pk[32]; // don't touch remote_pk before we're sure
    encrypt32(tmp_remote_pk, msg + 32, ctx.key);
    handshake_update_key(&ctx, ctx.local_sk, tmp_remote_pk);

    // Verify message, get session key
    if (handshake_verify_session_key(&ctx, session_key, msg + 64)) {
        WIPE_BUFFER(tmp_remote_pk);
        WIPE_CTX(&ctx);
        return -1;
    }
    copy32(remote_pk, tmp_remote_pk);

    WIPE_BUFFER(tmp_remote_pk);
    WIPE_CTX(&ctx);
    return 0;
}

