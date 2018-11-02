#include <monocypher.h>
#include "handshake.h"

#define FOR(i, start, end)   for (size_t (i) = (start); (i) < (end); (i)++)
#define WIPE_CTX(ctx)        crypto_wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer)  crypto_wipe(buffer, sizeof(buffer))

typedef uint8_t u8;

static const u8 zero[32] = {0};

static void copy32(u8 out[32], const u8 in[32]){FOR (i, 0, 32){out[i] = in[i];}}
static void xor32 (u8 out[32], const u8 in[32]){FOR (i, 0, 32){out[i]^= in[i];}}

static void handshake_encrypt32(crypto_handshake_ctx *ctx,
                                u8 out[32], const u8 in[32])
{
    copy32(out, in);
    xor32(out, ctx->derived_keys + 32);
}

static void handshake_update_key(crypto_handshake_ctx *ctx,
                                 const u8              secret_key[32],
                                 const u8              public_key[32])
{
    // Derive new key from the exchange, then absorb it
    u8 new_key[32];
    crypto_x25519(new_key, secret_key, public_key);
    crypto_chacha20_H(new_key, new_key, ctx->key_nonce);
    ctx->key_nonce[0]++;
    xor32(ctx->chaining_key, new_key);

    // Derive authentication and encryption keys
    crypto_chacha_ctx chacha_ctx;
    crypto_chacha20_init  (&chacha_ctx, ctx->chaining_key, zero);
    crypto_chacha20_stream(&chacha_ctx, ctx->derived_keys, 64);

    // Clean up
    WIPE_BUFFER(new_key);
    WIPE_CTX(&chacha_ctx);
}

static void handshake_record(crypto_handshake_ctx *ctx, const u8 msg[32])
{
    copy32(ctx->transcript + ctx->transcript_size, msg);
    ctx->transcript_size += 32;
}

static void handshake_auth(crypto_handshake_ctx *ctx, u8 mac[16])
{
    crypto_poly1305(mac, ctx->transcript, ctx->transcript_size,
                    ctx->derived_keys);
}

static int handshake_verify(crypto_handshake_ctx *ctx, const u8 mac[16])
{
    u8 real_mac[16];
    handshake_auth(ctx, real_mac);
    int mismatch = crypto_verify16(real_mac, mac);
    WIPE_BUFFER(real_mac);
    return mismatch;
}

static void handshake_init(crypto_handshake_ctx *ctx,
                           u8                    random_seed[32],
                           const u8              local_sk  [32])
{
    copy32(ctx->chaining_key, zero       );
    copy32(ctx->local_sk    , local_sk   );
    copy32(ctx->ephemeral_sk, random_seed);
    crypto_wipe(random_seed, 32); // auto wipe seed to avoid reuse
    ctx->transcript_size = 0;
    FOR (i, 0, 16) {
        ctx->key_nonce[i] = 0;
    }
}

void crypto_handshake_request(crypto_handshake_ctx *ctx,
                              u8                    random_seed[32],
                              u8                    msg1       [32],
                              const u8              remote_pk  [32],
                              const u8              local_sk   [32],
                              const u8              local_pk   [32])
{
    // Init context
    handshake_init(ctx, random_seed, local_sk);
    copy32(ctx->remote_pk, remote_pk); // recipient's public key is known
    if (local_pk == 0) crypto_x25519_public_key(ctx->local_pk, local_sk);
    else               copy32                  (ctx->local_pk, local_pk);

    // Record sender public key
    handshake_record(ctx, remote_pk);

    // Send request
    crypto_x25519_public_key(msg1, ctx->ephemeral_sk);
    handshake_record(ctx, msg1);
}

void crypto_handshake_respond(crypto_handshake_ctx *ctx,
                              u8                    random_seed[32],
                              u8                    msg2       [48],
                              const u8              msg1       [32],
                              const u8              local_sk   [32],
                              const u8              local_pk   [32])
{
    // Init context
    handshake_init(ctx, random_seed, local_sk);
    if (local_pk == 0) crypto_x25519_public_key(ctx->local_pk, local_sk);
    else               copy32                  (ctx->local_pk, local_pk);

    // Receive request (no authentication yet)
    handshake_record(ctx, local_pk);
    handshake_record(ctx, msg1);

    // Update key
    u8 *ephemeral_pk = ctx->transcript + 32;
    handshake_update_key(ctx, ctx->ephemeral_sk, ephemeral_pk);
    handshake_update_key(ctx, ctx->local_sk    , ephemeral_pk);

    // Send & authenticate response
    crypto_x25519_public_key(msg2, ctx->ephemeral_sk);
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
    handshake_encrypt32 (ctx, msg3, ctx->local_pk);
    handshake_record    (ctx, msg3);
    handshake_update_key(ctx, ctx->local_sk, ephemeral_pk);
    handshake_auth      (ctx, msg3 + 32);
    copy32(session_key, ctx->derived_keys + 32);

    // Clean up
    WIPE_CTX(ctx);
    return 0;
}

int crypto_handshake_accept(crypto_handshake_ctx *ctx,
                            u8                    session_key[32],
                            u8                    remote_pk  [32],
                            const u8              msg3       [48])
{
    // Receive sender's public key
    handshake_record    (ctx, msg3);
    handshake_encrypt32 (ctx, ctx->remote_pk, msg3);
    handshake_update_key(ctx, ctx->ephemeral_sk, ctx->remote_pk);

    // Verify sender, get session key
    if (handshake_verify(ctx, msg3 + 32)) {
        WIPE_CTX(ctx);
        return -1;
    }
    copy32(remote_pk  , ctx->remote_pk);
    copy32(session_key, ctx->derived_keys + 32);

    // Clean up
    WIPE_CTX(ctx);
    return 0;
}

void crypto_send(u8       random_seed[32],
                 u8       session_key[32],
                 u8       msg        [80],
                 const u8 remote_pk  [32],
                 const u8 local_sk   [32],
                 const u8 local_pk   [32])
{
    // Init context
    crypto_handshake_ctx ctx;
    handshake_init(&ctx, random_seed, local_sk);
    if (local_pk == 0) crypto_x25519_public_key(ctx.local_pk, local_sk);
    else               copy32                  (ctx.local_pk, local_pk);

    // Send ephemeral key
    crypto_x25519_public_key(msg, ctx.ephemeral_sk);
    handshake_record    (&ctx, msg);
    handshake_update_key(&ctx, ctx.ephemeral_sk, remote_pk);

    // Send long term key
    handshake_encrypt32 (&ctx, msg + 32, ctx.local_pk);
    handshake_record    (&ctx, msg + 32);
    handshake_update_key(&ctx, ctx.local_sk, remote_pk);

    // Authenticate message, get session key
    handshake_auth(&ctx, msg + 64);
    copy32(session_key, ctx.derived_keys + 32);

    // Clean up
    WIPE_CTX(&ctx);
}

int crypto_receive(u8       random_seed[32],
                   u8       session_key[32],
                   u8       remote_pk  [32],
                   const u8 msg        [80],
                   const u8 local_sk   [32])
{
    // Init context
    crypto_handshake_ctx ctx;
    handshake_init(&ctx, random_seed, local_sk);

    // Receive ephemeral key
    handshake_record    (&ctx, msg);
    handshake_update_key(&ctx, local_sk, msg); // msg == ephemeral_pk

    // Receive long term key
    handshake_record    (&ctx, msg + 32);
    handshake_encrypt32 (&ctx, ctx.remote_pk, msg + 32);
    handshake_update_key(&ctx, ctx.local_sk, ctx.remote_pk);

    // Verify message, get session key
    if (handshake_verify(&ctx, msg + 64)) {
        WIPE_CTX(&ctx);
        return -1;
    }
    copy32(remote_pk  , ctx.remote_pk);
    copy32(session_key, ctx.derived_keys + 32);

    WIPE_CTX(&ctx);
    return 0;
}

