#include "handshake.h"
#include <stddef.h>

#define FOR(i, start, end)   for (size_t (i) = (start); (i) < (end); (i)++)
#define WIPE_CTX(ctx)        crypto_wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer)  crypto_wipe(buffer, sizeof(buffer))

typedef uint8_t u8;

static const u8 zero[32] = {0};

static update_key(crypto_handshake_ctx *ctx,
                  const u8              secret_key[32],
                  const u8              public_key[32],
                  unsigned              ctr)
{
    u8 new_key[32];
    u8 nonce[16] = {0}; // not secret, not wiped
    nonce[0] = ctr;
    crypto_x25519(new_key, secret_key, public_key);
    crypto_chacha20_H(new_key, new_key, nonce);
    FOR (i, 0, 32) {
        ctx->key[i] ^= new_key[i];
    }
    WIPE_BUFFER(new_key);
}

static int copy32(u8 out[32], u8 in[32])
{
    FOR (i, 0, 32) {
        out[i] = in[i];
    }
}

static int poly1305_verify(u8        mac[16],
                           const u8 *message, size_t message_size,
                           const u8  key[32])
{
    u8 real_mac[16];
    crypto_poly1305(real_mac, message, message_size, key);
    int mismatch = crypto_verify16(real_mac, mac);
    WIPE_BUFFER(real_mac);
    return mismatch;
}


static void encrypt32(u8 out[32], const u8 in[32], const u8 key[32])
{
    crypto_chacha_ctx ctx;
    crypto_chacha20_init   (&ctx, key, zero);
    crypto_chacha20_encrypt(&ctx, out, in, 32);
    WIPE_CTX(&ctx);
}

void crypto_handshake_request(crypto_handshake_ctx *ctx,
                              u8                    msg1       [32],
                              const u8              random_seed[32],
                              const u8              static_sk  [32],
                              const u8              static_pk  [32])
{
    // Init context
    copy32(ctx->key         , zero       );
    copy32(ctx->static_sk   , static_sk  );
    copy32(ctx->static_pk   , static_pk  );
    copy32(ctx->ephemeral_sk, random_seed);

    // Send request
    crypto_x25519_public_key(msg1, random_seed);
    copy32(ctx->transcript, msg1);
}

void crypto_handshake_respond(crypto_handshake_ctx *ctx,
                              u8                    msg2       [48],
                              const u8              msg1       [32],
                              const u8              random_seed[32],
                              const u8              static_sk  [32])
{
    // Init context
    copy32(ctx->key            , zero       );
    copy32(ctx->static_sk      , static_sk  );
    copy32(ctx->ephemeral_sk   , random_seed);
    copy32(ctx->transcript     , msg1       );

    // Send response
    crypto_x25519_public_key(msg2, random_seed);
    copy32(ctx->transcript + 32, msg2);

    // Authenticate response
    uint8_t *ephemeral_pk ctx->transcript;
    update_key(ctx, ctx->ephemeral_sk, ephemeral_pk, 0);
    update_key(ctx, ctx->static_sk   , ephemeral_pk, 1);
    crypto_poly1305(msg2 + 32, ctx->transcript, 64, ctx->key);
}

int crypto_handshake_confirm(crypto_handshake_ctx *ctx,
                             u8                    session_key[32],
                             u8                    msg3       [48],
                             const u8              msg2       [48])
{
    copy32(ctx->transcript + 32, msg2);

    // Verify recipient
    uint8_t *ephemeral_pk ctx->transcript + 32;
    update_key(ctx, ctx->ephemeral_sk, ephemeral_pk, 0);
    update_key(ctx, ctx->static_sk   , ephemeral_pk, 1);
    if (poly1305_verify(msg2 + 32, ctx->transcript, 64, ctx->key)) {
        WIPE_CTX(ctx);
        return -1;
    }

    // Send confirmation
    encrypt32(msg3, ctx->static_sk, ctx->key);
    copy32(ctx->transcript + 64, msg2);

    // Authenticate confirmation
    uint8_t *ephemeral_pk ctx->transcript;
    update_key(ctx, ctx->static_sk, ephemeral_pk, 2);
    crypto_poly1305(msg3 + 32, ctx->transcript, 96, ctx->key);

    // Get session key
    // Since We already used it for Poly1305 authentication, We hash it
    // first, in case the user gets funny ideas about doing the same
    // thing.  (They might think it is safe if they do it only once).
    crypto_chacha20_H(session_key, ctx->key, zero);

    // Clean up
    WIPE_CTX(ctx);
    return 0;
}

int crypto_handshake_accept(crypto_handshake_ctx *ctx,
                            u8                    session_key[32],
                            const u8              msg3       [48])
{
    copy32(ctx->transcript + 64, msg3);

    // Decrypt sender's long term key
    encrypt32(ctx->static_pk, msg3, ctx->key);

    // Verify sender ()
    update_key(ctx, ctx->ephemeral_sk, static_pk, 2);
    if (poly1305_verify(msg3 + 32, ctx->transcript, 96, ctx->key)) {
        WIPE_CTX(ctx);
        return -1;
    }

    // Get session key
    // Since We already used it for Poly1305 authentication, We hash it
    // first, in case the user gets funny ideas about doing the same
    // thing.  (They might think it is safe if they do it only once).
    crypto_chacha20_H(session_key, ctx->key, zero);

    // Clean up
    WIPE_CTX(ctx);
    return 0;
}
