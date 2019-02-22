#include <monocypher.h>
#include "handshake.h"

#define FOR(i, start, end)   for (size_t (i) = (start); (i) < (end); (i)++)
#define WIPE_CTX(ctx)        crypto_wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer)  crypto_wipe(buffer, sizeof(buffer))

typedef uint8_t u8;

static const u8 zero[32] = {0};
static const u8 one [16] = {1};

static void copy32(u8 out[32], const u8 in[32]){FOR (i, 0, 32){out[i] = in[i];}}
static void xor32 (u8 out[32], const u8 in[32]){FOR (i, 0, 32){out[i]^= in[i];}}

static void kex_update_key(crypto_kex_ctx *ctx,
                           const u8        secret_key[32],
                           const u8        public_key[32])
{
    // Extract
    u8 shared_secret[32];
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

static void kex_auth(crypto_kex_ctx *ctx, u8 mac[16])
{
    crypto_poly1305(mac, ctx->transcript, ctx->transcript_size,
                    ctx->derived_keys);
}

static int kex_verify(crypto_kex_ctx *ctx, const u8 mac[16])
{
    u8 real_mac[16];
    kex_auth(ctx, real_mac);
    int mismatch = crypto_verify16(real_mac, mac);
    if (mismatch) {  WIPE_CTX(ctx); }
    WIPE_BUFFER(real_mac);
    return mismatch;
}

static void kex_send(crypto_kex_ctx *ctx,
                     u8 msg[32], const u8 src[32])
{
    // Send message, encrypted if we have a key
    copy32(msg, src);
    xor32(msg, ctx->derived_keys + 32);
    // Record sent message
    copy32(ctx->transcript + ctx->transcript_size, msg);
    ctx->transcript_size += 32;
}

static void kex_receive(crypto_kex_ctx *ctx,
                        u8 dest[32], const u8 msg[32])
{
    // Record incoming message
    copy32(ctx->transcript + ctx->transcript_size, msg);
    ctx->transcript_size += 32;
    // Receive message, decrypted it if we have a key
    copy32(dest, msg);
    xor32(dest, ctx->derived_keys + 32);
}

static void kex_init(crypto_kex_ctx *ctx,
                     uint8_t         random_seed[32],
                     const uint8_t   local_sk   [32],
                     const uint8_t   local_pk   [32])
{
    if (local_pk == 0) crypto_x25519_public_key(ctx->local_pk, local_sk);
    else               copy32                  (ctx->local_pk, local_pk);
    copy32(ctx->chaining_key     , zero       );
    copy32(ctx->derived_keys + 32, zero       ); // first encryption key is zero
    copy32(ctx->local_sk         , local_sk   );
    copy32(ctx->local_ske        , random_seed);
    crypto_wipe(random_seed, 32); // auto wipe seed to avoid reuse
    crypto_x25519_public_key(ctx->local_pke, ctx->local_ske);
    ctx->transcript_size  = 0;
}


void crypto_kex_init_client(crypto_kex_ctx *ctx,
                            uint8_t         random_seed[32],
                            const uint8_t   local_sk   [32],
                            const uint8_t   local_pk   [32],
                            const uint8_t   remote_pk  [32])
{
    kex_init(ctx, random_seed, local_sk, local_pk);
    kex_receive(ctx, ctx->remote_pk, remote_pk);
}

void crypto_kex_init_server(crypto_kex_ctx *ctx,
                            uint8_t         random_seed[32],
                            const uint8_t   local_sk   [32],
                            const uint8_t   local_pk   [32])
{
    kex_init(ctx, random_seed, local_sk, local_pk);
    kex_receive(ctx, ctx->local_pk, local_pk);
}


void crypto_kex_request(crypto_kex_ctx *ctx, u8 msg1[32])
{
    kex_send      (ctx, msg1           , ctx->local_pke );  // -> ES
}

void crypto_kex_respond(crypto_kex_ctx *ctx, u8 msg2[48], const u8 msg1[32])
{
    kex_receive   (ctx, ctx->remote_pke, msg1           );  // -> ES
    kex_send      (ctx, msg2           , ctx->local_pke );  // <- ER
    kex_update_key(ctx, ctx->local_ske , ctx->remote_pke);  // <ee>
    kex_update_key(ctx, ctx->local_sk  , ctx->remote_pke);  // <el>
    kex_auth      (ctx, msg2 + 32);                         // auth
}

int crypto_kex_confirm(crypto_kex_ctx *ctx,
                       u8              session_key[32],
                       u8              msg3       [48],
                       const u8        msg2       [48])
{
    kex_receive   (ctx, ctx->remote_pke, msg2           );  // <- ER
    kex_update_key(ctx, ctx->local_ske , ctx->remote_pke);  // <ee>
    kex_update_key(ctx, ctx->local_ske , ctx->remote_pk );  // <el>
    if (kex_verify(ctx, msg2 + 32)) {                       // verify
        FOR (i, 0, 48) { msg3[i] = 0; }
        return -1;
    }
    kex_send      (ctx, msg3           , ctx->local_pk  );  // -> LS
    kex_update_key(ctx, ctx->local_sk  , ctx->remote_pke);  // <le>
    kex_auth      (ctx, msg3 + 32);                         // auth

    copy32(session_key, ctx->derived_keys + 32);

    WIPE_CTX(ctx);
    return 0;
}

int crypto_kex_accept(crypto_kex_ctx *ctx,
                      u8              session_key[32],
                      u8              remote_pk  [32],
                      const u8        msg3       [48])
{
    kex_receive   (ctx, ctx->remote_pk, msg3          );    // -> LS
    kex_update_key(ctx, ctx->local_ske, ctx->remote_pk);    // <le>
    if (kex_verify(ctx, msg3 + 32)) { return -1; }          // verify
    copy32(remote_pk  , ctx->remote_pk);
    copy32(session_key, ctx->derived_keys + 32);

    WIPE_CTX(ctx);
    return 0;
}

void crypto_send(crypto_kex_ctx *ctx,
                 u8              session_key[32],
                 u8              msg        [80])
{
    kex_send      (ctx, msg           , ctx->local_pke);    // -> ES
    kex_update_key(ctx, ctx->local_ske, ctx->remote_pk);    // <el>
    kex_send      (ctx, msg + 32      , ctx->local_pk );    // -> LS
    kex_update_key(ctx, ctx->local_sk , ctx->remote_pk);    // <ll>
    kex_auth      (ctx, msg + 64);                          // auth

    copy32(session_key, ctx->derived_keys + 32);

    // Clean up
    WIPE_CTX(ctx);
}

int crypto_receive(crypto_kex_ctx *ctx,
                   u8              session_key[32],
                   u8              remote_pk  [32],
                   const u8        msg        [80])
{
    kex_receive   (ctx, ctx->remote_pke, msg            );  // -> ES
    kex_update_key(ctx, ctx->local_sk  , ctx->remote_pke);  // <el>
    kex_receive   (ctx, ctx->remote_pk , msg + 32       );  // -> LS
    kex_update_key(ctx, ctx->local_sk  , ctx->remote_pk );  // <ll>
    if (kex_verify(ctx, msg + 64)) { return -1; }           // verify

    copy32(remote_pk  , ctx->remote_pk);
    copy32(session_key, ctx->derived_keys + 32);

    WIPE_CTX(ctx);
    return 0;
}
