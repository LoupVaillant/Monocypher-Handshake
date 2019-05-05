#include <monocypher.h>
#include "monokex.h"

#define WIPE_CTX(ctx)        crypto_wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer)  crypto_wipe(buffer, sizeof(buffer))

static void copy16(uint8_t out[16], const uint8_t in[16])
{
    for (size_t i = 0; i < 16; i++) { out[i]  = in[i]; }
}
static void copy32(uint8_t out[32], const uint8_t in[32])
{
    for (size_t i = 0; i < 32; i++) { out[i]  = in[i]; }
}
static void xor32 (uint8_t out[32], const uint8_t in[32])
{
    for (size_t i = 0; i < 32; i++) { out[i] ^= in[i]; }
}

static void kex_mix_hash(crypto_kex_ctx *ctx,
                         const uint8_t *buf, size_t buf_size)
{
    crypto_blake2b_ctx blake_ctx;
    crypto_blake2b_init  (&blake_ctx);
    crypto_blake2b_update(&blake_ctx, ctx->hash, 32);
    crypto_blake2b_update(&blake_ctx, buf, buf_size);
    crypto_blake2b_final (&blake_ctx, ctx->hash);
}

static void kex_update_key(crypto_kex_ctx *ctx,
                           const uint8_t   secret_key[32],
                           const uint8_t   public_key[32])
{
    uint8_t tmp[32];
    crypto_x25519(tmp, secret_key, public_key);
    kex_mix_hash(ctx, tmp, 32);
    ctx->has_key = 1;
    WIPE_BUFFER(tmp);
}

static void kex_auth(crypto_kex_ctx *ctx, uint8_t mac[16])
{
    copy16(mac, ctx->hash + 32);
    kex_mix_hash(ctx, 0, 0);
}

static int kex_verify(crypto_kex_ctx *ctx, const uint8_t mac[16])
{
    int mismatch = crypto_verify16(ctx->hash + 32, mac);
    if (mismatch) {  WIPE_CTX(ctx); }
    kex_mix_hash(ctx, 0, 0);
    return mismatch;
}

static void kex_send(crypto_kex_ctx *ctx,
                     uint8_t msg[32], const uint8_t src[32])
{
    copy32(msg, src);
    if (ctx->has_key) { xor32(msg, ctx->hash + 32); }
    kex_mix_hash(ctx, msg, 32);
}

static void kex_receive(crypto_kex_ctx *ctx,
                        uint8_t dest[32], const uint8_t msg[32])
{
    copy32(dest, msg);
    if (ctx->has_key) { xor32(dest, ctx->hash + 32); }
    kex_mix_hash(ctx, msg, 32);
}

static void kex_session_key(crypto_kex_ctx *ctx, uint8_t session_key[32])
{
    copy32(session_key, ctx->hash);
    WIPE_CTX(ctx);
}

static void kex_init(crypto_kex_ctx *ctx, const uint8_t pid[32])
{
    copy32(ctx->hash, pid);
    ctx->has_key = 0;
}

static void kex_seed(crypto_kex_ctx *ctx, uint8_t random_seed[32])
{
    copy32(ctx->local_ske, random_seed);
    crypto_wipe(random_seed, 32); // auto wipe seed to avoid reuse
    crypto_x25519_public_key(ctx->local_pke, ctx->local_ske);
}

static void kex_locals(crypto_kex_ctx *ctx,
                       const uint8_t   local_sk[32],
                       const uint8_t   local_pk[32])
{
    if (local_pk == 0) crypto_x25519_public_key(ctx->local_pk, local_sk);
    else               copy32                  (ctx->local_pk, local_pk);
    copy32(ctx->local_sk, local_sk);
}

///////////
/// XK1 ///
///////////
static const uint8_t pid_xk1[32] = "Monokex XK1";

void crypto_kex_xk1_init_client(crypto_kex_client_ctx *client_ctx,
                                uint8_t                random_seed[32],
                                const uint8_t          client_sk  [32],
                                const uint8_t          client_pk  [32],
                                const uint8_t          server_pk  [32])
{
    crypto_kex_ctx *ctx = &(client_ctx->ctx);
    kex_init   (ctx, pid_xk1);
    kex_seed   (ctx, random_seed);
    kex_locals (ctx, client_sk, client_pk);
    kex_receive(ctx, ctx->remote_pk, server_pk);
}

void crypto_kex_xk1_init_server(crypto_kex_server_ctx *server_ctx,
                                uint8_t                random_seed[32],
                                const uint8_t          server_sk  [32],
                                const uint8_t          server_pk  [32])
{
    crypto_kex_ctx *ctx = &(server_ctx->ctx);
    kex_init   (ctx, pid_xk1);
    kex_seed   (ctx, random_seed);
    kex_locals (ctx, server_sk, server_pk);
    kex_receive(ctx, ctx->local_pk, ctx->local_pk);
}

void crypto_kex_xk1_1(crypto_kex_client_ctx *client_ctx,
                      uint8_t                msg1      [48])
{
    crypto_kex_ctx *ctx = &(client_ctx->ctx);
    kex_send      (ctx, msg1           , ctx->local_pke );  // -> IE
//    for (size_t i = 32; i < 48; i++) { msg1[i] = 0; }
}

void crypto_kex_xk1_2(crypto_kex_server_ctx *server_ctx,
                      uint8_t                msg2      [48],
                      const uint8_t          msg1      [48])
{
    crypto_kex_ctx *ctx = &(server_ctx->ctx);
    kex_receive   (ctx, ctx->remote_pke, msg1           );  // -> IE
    kex_send      (ctx, msg2           , ctx->local_pke );  // <- RE
    kex_update_key(ctx, ctx->local_ske , ctx->remote_pke);  //    ee
    kex_update_key(ctx, ctx->local_sk  , ctx->remote_pke);  //    es
    kex_auth      (ctx, msg2 + 32);                         // auth
}

int crypto_kex_xk1_3(crypto_kex_client_ctx *client_ctx,
                     uint8_t                session_key[32],
                     uint8_t                msg3       [48],
                     const uint8_t          msg2       [48])
{
    crypto_kex_ctx *ctx = &(client_ctx->ctx);
    kex_receive   (ctx, ctx->remote_pke, msg2           );  // <- RE
    kex_update_key(ctx, ctx->local_ske , ctx->remote_pke);  //    ee
    kex_update_key(ctx, ctx->local_ske , ctx->remote_pk );  //    es
    if (kex_verify(ctx, msg2 + 32)) { return -1; }          // verify
    kex_send      (ctx, msg3           , ctx->local_pk  );  // -> IS
    kex_update_key(ctx, ctx->local_sk  , ctx->remote_pke);  //    se
    kex_auth      (ctx, msg3 + 32);                         // auth
    kex_session_key(ctx, session_key);
    return 0;
}

int crypto_kex_xk1_4(crypto_kex_server_ctx *server_ctx,
                     uint8_t                session_key[32],
                     uint8_t                client_pk  [32],
                     const uint8_t          msg3       [48])
{
    crypto_kex_ctx *ctx = &(server_ctx->ctx);
    kex_receive   (ctx, ctx->remote_pk , msg3           );  // -> IS
    kex_update_key(ctx, ctx->local_ske , ctx->remote_pk );  //    se
    if (kex_verify(ctx, msg3 + 32)) { return -1; }          // verify
    copy32(client_pk  , ctx->remote_pk);
    kex_session_key(ctx, session_key);
    return 0;
}

/////////
/// X ///
/////////
static const uint8_t pid_x[32] = "Monokex X";

void crypto_kex_x_init_client(crypto_kex_client_ctx *client_ctx,
                              uint8_t                random_seed[32],
                              const uint8_t          client_sk  [32],
                              const uint8_t          client_pk  [32],
                              const uint8_t          server_pk  [32])
{
    crypto_kex_ctx *ctx = &(client_ctx->ctx);
    kex_init   (ctx, pid_x);
    kex_seed   (ctx, random_seed);
    kex_locals (ctx, client_sk, client_pk);
    kex_receive(ctx, ctx->remote_pk, server_pk);
}

void crypto_kex_x_init_server(crypto_kex_server_ctx *server_ctx,
                              const uint8_t          server_sk [32],
                              const uint8_t          server_pk [32])
{
    crypto_kex_ctx *ctx = &(server_ctx->ctx);
    kex_init   (ctx, pid_x);
    kex_locals (ctx, server_sk, server_pk);
    kex_receive(ctx, ctx->local_pk, ctx->local_pk);
}

void crypto_kex_x_1(crypto_kex_client_ctx *client_ctx,
                    uint8_t                session_key[32],
                    uint8_t                msg1       [80])
{
    crypto_kex_ctx *ctx = &(client_ctx->ctx);
    kex_send      (ctx, msg1           , ctx->local_pke );  // -> IE
    kex_update_key(ctx, ctx->local_ske , ctx->remote_pk );  //    es
    kex_send      (ctx, msg1 + 32      , ctx->local_pk  );  // -> IS
    kex_update_key(ctx, ctx->local_sk  , ctx->remote_pk );  //    ss
    kex_auth      (ctx, msg1 + 64);                         // auth
    kex_session_key(ctx, session_key);
}

int crypto_kex_x_2(crypto_kex_server_ctx *server_ctx,
                   uint8_t                session_key[32],
                   uint8_t                client_pk  [32],
                   const uint8_t          msg1       [80])
{
    crypto_kex_ctx *ctx = &(server_ctx->ctx);
    kex_receive   (ctx, ctx->remote_pke, msg1           );  // -> IE
    kex_update_key(ctx, ctx->local_sk  , ctx->remote_pke);  //    es
    kex_receive   (ctx, ctx->remote_pk , msg1 + 32      );  // -> IS
    kex_update_key(ctx, ctx->local_sk  , ctx->remote_pk );  //    ss
    if (kex_verify(ctx, msg1 + 64)) { return -1; }          // verify
    copy32(client_pk  , ctx->remote_pk);
    kex_session_key(ctx, session_key);
    return 0;
}
