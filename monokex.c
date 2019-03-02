#include <monocypher.h>
#include "monokex.h"

#define WIPE_CTX(ctx)        crypto_wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer)  crypto_wipe(buffer, sizeof(buffer))

static const uint8_t zero[32] = {0};
static const uint8_t one [16] = {1};

static void copy32(uint8_t out[32], const uint8_t in[32])
{
    for (size_t i = 0; i < 32; i++) { out[i]  = in[i]; }
}
static void xor32 (uint8_t out[32], const uint8_t in[32])
{
    for (size_t i = 0; i < 32; i++) { out[i] ^= in[i]; }
}

static void kex_update_key(crypto_kex_ctx *ctx,
                           const uint8_t   secret_key[32],
                           const uint8_t   public_key[32])
{
    // Extract
    uint8_t shared_secret[32];
    crypto_x25519(shared_secret, secret_key, public_key);
    crypto_chacha20_H(shared_secret    , shared_secret    , zero);
    crypto_chacha20_H(ctx->chaining_key, ctx->chaining_key, one );
    xor32(ctx->chaining_key, shared_secret);

    // Expand (directly from chaining key)
    crypto_chacha_ctx chacha_ctx;
    crypto_chacha20_init  (&chacha_ctx, ctx->chaining_key, one);
    crypto_chacha20_stream(&chacha_ctx, ctx->derived_keys, 64);

    // Clean up
    WIPE_BUFFER(shared_secret);
    WIPE_CTX(&chacha_ctx);
}

static void kex_auth(crypto_kex_ctx *ctx, uint8_t mac[16])
{
    crypto_poly1305(mac, ctx->transcript, ctx->transcript_size,
                    ctx->derived_keys);
}

static int kex_verify(crypto_kex_ctx *ctx, const uint8_t mac[16])
{
    uint8_t real_mac[16];
    kex_auth(ctx, real_mac);
    int mismatch = crypto_verify16(real_mac, mac);
    if (mismatch) {  WIPE_CTX(ctx); }
    WIPE_BUFFER(real_mac);
    return mismatch;
}

static void kex_send(crypto_kex_ctx *ctx,
                     uint8_t msg[32], const uint8_t src[32])
{
    // Send message, encrypted if we have a key
    copy32(msg, src);
    xor32(msg, ctx->derived_keys + 32);
    // Record sent message
    copy32(ctx->transcript + ctx->transcript_size, msg);
    ctx->transcript_size += 32;
}

static void kex_receive(crypto_kex_ctx *ctx,
                        uint8_t dest[32], const uint8_t msg[32])
{
    // Record incoming message
    copy32(ctx->transcript + ctx->transcript_size, msg);
    ctx->transcript_size += 32;
    // Receive message, decrypted it if we have a key
    copy32(dest, msg);
    xor32(dest, ctx->derived_keys + 32);
}

static void kex_init(crypto_kex_ctx *ctx)
{
    copy32(ctx->chaining_key     , zero);
    copy32(ctx->derived_keys + 32, zero);  // first encryption key is zero
    ctx->transcript_size = 0;
}

static void kex_seed(crypto_kex_ctx *ctx, uint8_t random_seed[32])
{
    copy32(ctx->local_ske        , random_seed);
    crypto_wipe(random_seed, 32); // auto wipe seed to avoid reuse
    crypto_x25519_public_key(ctx->local_pke, ctx->local_ske);
}

static void kex_locals(crypto_kex_ctx *ctx,
                       const uint8_t   local_sk   [32],
                       const uint8_t   local_pk   [32])
{
    if (local_pk == 0) crypto_x25519_public_key(ctx->local_pk, local_sk);
    else               copy32                  (ctx->local_pk, local_pk);
    copy32(ctx->local_sk         , local_sk   );
}

///////////
/// XK1 ///
///////////
void crypto_kex_xk1_init_client(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   local_sk   [32],
                                const uint8_t   local_pk   [32],
                                const uint8_t   remote_pk  [32])
{
    kex_init   (ctx);
    kex_seed   (ctx, random_seed);
    kex_locals (ctx, local_sk, local_pk);
    kex_receive(ctx, ctx->remote_pk, remote_pk);
}

void crypto_kex_xk1_init_server(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   local_sk   [32],
                                const uint8_t   local_pk   [32])
{
    kex_init   (ctx);
    kex_seed   (ctx, random_seed);
    kex_locals (ctx, local_sk, local_pk);
    kex_receive(ctx, ctx->local_pk, ctx->local_pk);
}

void crypto_kex_xk1_1(crypto_kex_ctx *ctx,
                      uint8_t         msg1[32])
{
    kex_send      (ctx, msg1           , ctx->local_pke );  // -> IE
}

void crypto_kex_xk1_2(crypto_kex_ctx *ctx,
                      uint8_t         msg2[48],
                      const uint8_t   msg1[32])
{
    kex_receive   (ctx, ctx->remote_pke, msg1           );  // -> IE
    kex_send      (ctx, msg2           , ctx->local_pke );  // <- RE
    kex_update_key(ctx, ctx->local_ske , ctx->remote_pke);  //    ee
    kex_update_key(ctx, ctx->local_sk  , ctx->remote_pke);  //    es
    kex_auth      (ctx, msg2 + 32);                         // auth
}

int crypto_kex_xk1_3(crypto_kex_ctx *ctx,
                     uint8_t         session_key[32],
                     uint8_t         msg3[48],
                     const uint8_t   msg2[48])
{
    kex_receive   (ctx, ctx->remote_pke, msg2           );  // <- RE
    kex_update_key(ctx, ctx->local_ske , ctx->remote_pke);  //    ee
    kex_update_key(ctx, ctx->local_ske , ctx->remote_pk );  //    es
    if (kex_verify(ctx, msg2 + 32)) { return -1; }          // verify
    kex_send      (ctx, msg3           , ctx->local_pk  );  // -> IS
    kex_update_key(ctx, ctx->local_sk  , ctx->remote_pke);  //    se
    kex_auth      (ctx, msg3 + 32);                         // auth
    copy32(session_key, ctx->derived_keys + 32);
    WIPE_CTX(ctx);
    return 0;
}

int crypto_kex_xk1_4(crypto_kex_ctx *ctx,
                     uint8_t         session_key[32],
                     uint8_t         remote_pk[32],
                     const uint8_t   msg3[48])
{
    kex_receive   (ctx, ctx->remote_pk , msg3           );  // -> IS
    kex_update_key(ctx, ctx->local_ske , ctx->remote_pk );  //    se
    if (kex_verify(ctx, msg3 + 32)) { return -1; }          // verify
    copy32(remote_pk  , ctx->remote_pk);
    copy32(session_key, ctx->derived_keys + 32);
    WIPE_CTX(ctx);
    return 0;
}

/////////
/// X ///
/////////
void crypto_kex_x_init_client(crypto_kex_ctx *ctx,
                              uint8_t         random_seed[32],
                              const uint8_t   local_sk   [32],
                              const uint8_t   local_pk   [32],
                              const uint8_t   remote_pk  [32])
{
    kex_init   (ctx);
    kex_seed   (ctx, random_seed);
    kex_locals (ctx, local_sk, local_pk);
    kex_receive(ctx, ctx->remote_pk, remote_pk);
}

void crypto_kex_x_init_server(crypto_kex_ctx *ctx,
                              const uint8_t   local_sk   [32],
                              const uint8_t   local_pk   [32])
{
    kex_init   (ctx);
    kex_locals (ctx, local_sk, local_pk);
    kex_receive(ctx, ctx->local_pk, ctx->local_pk);
}

void crypto_kex_x_1(crypto_kex_ctx *ctx,
                    uint8_t         session_key[32],
                    uint8_t         msg1[80])
{
    kex_send      (ctx, msg1           , ctx->local_pke );  // -> IE
    kex_update_key(ctx, ctx->local_ske , ctx->remote_pk );  //    es
    kex_send      (ctx, msg1 + 32      , ctx->local_pk  );  // -> IS
    kex_update_key(ctx, ctx->local_sk  , ctx->remote_pk );  //    ss
    kex_auth      (ctx, msg1 + 64);                         // auth
    copy32(session_key, ctx->derived_keys + 32);
    WIPE_CTX(ctx);
}

int crypto_kex_x_2(crypto_kex_ctx *ctx,
                   uint8_t         session_key[32],
                   uint8_t         remote_pk[32],
                   const uint8_t   msg1[80])
{
    kex_receive   (ctx, ctx->remote_pke, msg1           );  // -> IE
    kex_update_key(ctx, ctx->local_sk  , ctx->remote_pke);  //    es
    kex_receive   (ctx, ctx->remote_pk , msg1 + 32      );  // -> IS
    kex_update_key(ctx, ctx->local_sk  , ctx->remote_pk );  //    ss
    if (kex_verify(ctx, msg1 + 64)) { return -1; }          // verify
    copy32(remote_pk  , ctx->remote_pk);
    copy32(session_key, ctx->derived_keys + 32);
    WIPE_CTX(ctx);
    return 0;
}

