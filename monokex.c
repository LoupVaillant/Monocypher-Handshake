#include <monocypher.h>
#include "monokex.h"

/////////////////
/// Utilities ///
/////////////////
#define FOR(i, start, end)   for (size_t (i) = (start); (i) < (end); (i)++)
#define WIPE_CTX(ctx)        crypto_wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer)  crypto_wipe(buffer, sizeof(buffer))

// Message token bytecode
#define E   1
#define S   2
#define EE  3
#define ES  4
#define SE  5
#define SS  6

// Context status flags
#define IS_OK        1 // Allways 1 (becomes zero when wiped)
#define HAS_KEY      2 // True if we have a symmetric key
#define HAS_REMOTE   4 // True if we have the remote DH key
#define GETS_REMOTE  8 // True if the remote key is transmitted to us
#define SHOULD_SEND 16 // Send/receive toggle

typedef uint8_t u8;
typedef unsigned short ushort;

static void copy16(u8 out[16], const u8 in[16]){ FOR(i, 0, 16) out[i] = in[i]; }
static void copy32(u8 out[32], const u8 in[32]){ FOR(i, 0, 32) out[i] = in[i]; }
static void xor32 (u8 out[32], const u8 in[32]){ FOR(i, 0, 32) out[i]^= in[i]; }

static void encrypt(u8 *out, const u8 *in, size_t size, const u8 key[32])
{
    static const u8 zero[8] = {0};
    crypto_chacha_ctx ctx;
    crypto_chacha20_init   (&ctx, key + 32, zero);
    crypto_chacha20_encrypt(&ctx, out, in, size);
    WIPE_CTX(&ctx);
}

typedef crypto_kex_ctx ck_ctx;
static void kex_set        (ck_ctx*ctx,ushort f){ ctx->flags |=  f;     }
static void kex_clear      (ck_ctx*ctx,ushort f){ ctx->flags &= ~f;     }
static int  kex_is_ok      (ck_ctx *ctx) { return ctx->flags & IS_OK;       }
static int  kex_has_key    (ck_ctx *ctx) { return ctx->flags & HAS_KEY;     }
static int  kex_has_remote (ck_ctx *ctx) { return ctx->flags & HAS_REMOTE;  }
static int  kex_gets_remote(ck_ctx *ctx) { return ctx->flags & GETS_REMOTE; }
static int  kex_should_send(ck_ctx *ctx) { return ctx->flags & SHOULD_SEND; }

/////////////////////
/// State machine ///
/////////////////////
static void kex_mix_hash(crypto_kex_ctx *ctx,
                         const u8 *buf, size_t buf_size)
{
    crypto_blake2b_ctx blake_ctx;
    crypto_blake2b_init  (&blake_ctx);
    crypto_blake2b_update(&blake_ctx, ctx->hash, 32);
    crypto_blake2b_update(&blake_ctx, buf, buf_size);
    crypto_blake2b_final (&blake_ctx, ctx->hash);
}

static void kex_update_key(crypto_kex_ctx *ctx,
                           const u8        secret_key[32],
                           const u8        public_key[32])
{
    u8 tmp[32];
    crypto_x25519(tmp, secret_key, public_key);
    kex_mix_hash(ctx, tmp, 32);
    kex_set(ctx, HAS_KEY);
    WIPE_BUFFER(tmp);
}

static void kex_send(crypto_kex_ctx *ctx, u8 msg[32], const u8 src[32])
{
    copy32(msg, src);
    if (kex_has_key(ctx)) { xor32(msg, ctx->hash + 32); }
    kex_mix_hash(ctx, msg, 32);
}

static void kex_receive(crypto_kex_ctx *ctx, u8 dest[32], const u8 msg[32])
{
    copy32(dest, msg);
    if (kex_has_key(ctx)) { xor32(dest, ctx->hash + 32); }
    kex_mix_hash(ctx, msg, 32);
}

static unsigned kex_next_token(crypto_kex_ctx *ctx)
{
    unsigned token = ctx->messages[0] & 7;
    ctx->messages[0] >>= 3;
    return token;
}

static void kex_next_message(crypto_kex_ctx *ctx)
{
    FOR (i, 0, 3) {
        ctx->messages[i] = ctx->messages[i+1];
    }
}

//////////////////////
/// Initialisation ///
//////////////////////
static void kex_init(crypto_kex_ctx *ctx, const u8 pid[32])
{
    copy32(ctx->hash, pid);
    ctx->flags = IS_OK; // wiping the context sets it to false
}

static void kex_seed(crypto_kex_ctx *ctx, u8 random_seed[32])
{
    copy32(ctx->local_ske, random_seed);
    crypto_wipe(random_seed, 32); // auto wipe seed to avoid reuse
    crypto_x25519_public_key(ctx->local_pke, ctx->local_ske);
}

static void kex_locals(crypto_kex_ctx *ctx,
                       const u8   local_sk[32],
                       const u8   local_pk[32])
{
    if (local_pk == 0) crypto_x25519_public_key(ctx->local_pk, local_sk);
    else               copy32                  (ctx->local_pk, local_pk);
    copy32(ctx->local_sk, local_sk);
}

//////////////////////
/// Send & receive ///
//////////////////////
void crypto_kex_send(crypto_kex_ctx *ctx,
                     u8 *message, size_t message_size)
{
    crypto_kex_send_p(ctx, message, message_size, 0, 0);
}

int crypto_kex_receive(crypto_kex_ctx *ctx,
                        const u8 *message, size_t message_size)
{
    return crypto_kex_receive_p(ctx, 0, 0, message, message_size);
}

void crypto_kex_send_p(crypto_kex_ctx *ctx,
                       u8       *m, size_t m_size,
                       const u8 *p, size_t p_size)
{
    // Fail if we should not send (the failure is alas delayed)
    if (!crypto_kex_should_send(ctx)) {
        WIPE_CTX(ctx);
        return;
    }
    // Next time, we'll receive
    kex_clear(ctx, SHOULD_SEND);

    // Send core message
    while (ctx->messages[0] != 0) { // message not yet empty
        switch (kex_next_token(ctx)) {
        case E : kex_send(ctx, m, ctx->local_pke); m += 32; m_size -= 32; break;
        case S : kex_send(ctx, m, ctx->local_pk ); m += 32; m_size -= 32; break;
        case EE: kex_update_key(ctx, ctx->local_ske, ctx->remote_pke);    break;
        case ES: kex_update_key(ctx, ctx->local_ske, ctx->remote_pk );    break;
        case SE: kex_update_key(ctx, ctx->local_sk , ctx->remote_pke);    break;
        case SS: kex_update_key(ctx, ctx->local_sk , ctx->remote_pk );    break;
        default:; // never happens
        }
    }
    kex_next_message(ctx);

    // Send payload
    if (p != 0) {
        if (kex_has_key(ctx)) { encrypt(m, p, p_size, ctx->hash + 32); }
        else                  { FOR(i, 0, p_size) { m[i] = p[i]; }     }
        kex_mix_hash(ctx, m, p_size);
        m      += p_size;
        m_size -= p_size;
    }
    // Authenticate
    if (kex_has_key(ctx)) {
        copy16(m, ctx->hash + 32);
        kex_mix_hash(ctx, 0, 0);
        m      += 16;
        m_size -= 16;
    }
    // Pad
    FOR (i, 0, m_size) { m[i] = 0; } // should blow up if m_size underflows
}

int crypto_kex_receive_p(crypto_kex_ctx *ctx,
                         u8       *p, size_t p_size,
                         const u8 *m, size_t m_size)
{
    // Do nothing & fail if we should not receive
    if (!crypto_kex_should_receive(ctx)) {
        WIPE_CTX(ctx);
        return -1;
    }
    // Next time, we'll send
    kex_set(ctx, SHOULD_SEND);

    // receive core message
    while (ctx->messages[0] != 0) { // message not yet empty
        switch (kex_next_token(ctx)) {
        case E : kex_receive(ctx, ctx->remote_pke, m); m+=32; m_size-=32; break;
        case S : kex_receive(ctx, ctx->remote_pk , m); m+=32; m_size-=32;
                 kex_set(ctx, HAS_REMOTE);                                break;
        case EE: kex_update_key(ctx, ctx->local_ske, ctx->remote_pke);    break;
        case ES: kex_update_key(ctx, ctx->local_ske, ctx->remote_pk );    break;
        case SE: kex_update_key(ctx, ctx->local_sk , ctx->remote_pke);    break;
        case SS: kex_update_key(ctx, ctx->local_sk , ctx->remote_pk );    break;
        default:; // never happens
        }
    }
    kex_next_message(ctx);

    // Take payload into account
    if (p != 0) {
        kex_mix_hash(ctx, m, p_size);
    }
    // Verify (may fail)
    if (kex_has_key(ctx)) {
        if (crypto_verify16(ctx->hash + 32, m + p_size)) {
            WIPE_CTX(ctx);
            return -1;
        }
        kex_mix_hash(ctx, 0, 0);
    }
    // Receive payload
    if (p != 0) {
        if (kex_has_key(ctx)) { encrypt(p, m, p_size, ctx->hash + 32); }
        else                  { FOR(i, 0, p_size) { p[i] = m[i]; }     }
        m      += p_size;
        m_size -= p_size;
    }
    // Check for size overflow (only possible if we misuse the API)
    if (m_size >> ((sizeof(m_size) * 8) - 1)) {
        WIPE_CTX(ctx);
        return -1;
    }
    return 0;
}

//////////////
/// Status ///
//////////////
int crypto_kex_has_remote_key(crypto_kex_ctx *ctx)
{
    return kex_has_remote(ctx);
}

int crypto_kex_is_done(crypto_kex_ctx *ctx)
{
    return kex_is_ok(ctx)
        && ctx->messages[0] == 0
        && (!kex_gets_remote(ctx) || !kex_has_remote(ctx));
}

int crypto_kex_should_send(crypto_kex_ctx *ctx)
{
    return kex_is_ok          (ctx)
        && kex_should_send    (ctx)
        && !crypto_kex_is_done(ctx);
}

int crypto_kex_should_receive(crypto_kex_ctx *ctx)
{
    return kex_is_ok          (ctx)
        && !kex_should_send   (ctx)
        && !crypto_kex_is_done(ctx);
}

size_t crypto_kex_next_message_min_size(crypto_kex_ctx *ctx)
{
    unsigned has_key = kex_has_key(ctx);
    uint16_t message = ctx->messages[0];
    size_t   size    = 0;
    while (message != 0) {
        size    += (message & 7) <= 2 ? 32 : 0;
        has_key |= (message & 7) >= 3 ?  1 : 0;
        message >>= 3;
    }
    return size + (has_key ? 16 : 0);
}

////////////////
/// Get keys ///
////////////////
void crypto_kex_get_remote_key(crypto_kex_ctx *ctx, uint8_t key[32])
{
    if (!kex_has_remote(ctx)) {
        WIPE_CTX(ctx);
        return;
    }
    copy32(key, ctx->remote_pk);
    kex_clear(ctx, GETS_REMOTE);
}

void crypto_kex_get_session_key(crypto_kex_ctx *ctx,
                                u8 key[32], u8 extra[32])
{
    if (crypto_kex_is_done(ctx)) {
        copy32(key, ctx->hash);
        if (extra != 0) {
            copy32(extra, ctx->hash + 32);
        }
    }
    WIPE_CTX(ctx);
}

///////////
/// XK1 ///
///////////
static const u8 pid_xk1[32] = "Monokex XK1";

void crypto_kex_xk1_init_client(crypto_kex_ctx *ctx,
                                u8              random_seed[32],
                                const u8        client_sk  [32],
                                const u8        client_pk  [32],
                                const u8        server_pk  [32])
{
    kex_init   (ctx, pid_xk1);
    kex_seed   (ctx, random_seed);
    kex_locals (ctx, client_sk, client_pk);
    kex_receive(ctx, ctx->remote_pk, server_pk);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (ES << 6);
    ctx->messages[2] = S + (SE << 3);
    ctx->messages[3] = 0;
}

void crypto_kex_xk1_init_server(crypto_kex_ctx *ctx,
                                u8              random_seed[32],
                                const u8        server_sk  [32],
                                const u8        server_pk  [32])
{
    kex_init   (ctx, pid_xk1);
    kex_seed   (ctx, random_seed);
    kex_locals (ctx, server_sk, server_pk);
    kex_receive(ctx, ctx->local_pk, ctx->local_pk);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (SE << 6);;
    ctx->messages[2] = S + (ES << 3);
    ctx->messages[3] = 0;
}

/////////
/// X ///
/////////
static const u8 pid_x[32] = "Monokex X";

void crypto_kex_x_init_client(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32],
                              const u8        server_pk  [32])
{
    kex_init   (ctx, pid_x);
    kex_seed   (ctx, random_seed);
    kex_locals (ctx, client_sk, client_pk);
    kex_receive(ctx, ctx->remote_pk, server_pk);
    ctx->flags |= SHOULD_SEND;
    ctx->messages[0] = E + (ES << 3) + (S << 6) + (SS << 9);
    ctx->messages[1] = 0;
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

void crypto_kex_x_init_server(crypto_kex_ctx *ctx,
                              const u8        server_sk [32],
                              const u8        server_pk [32])
{
    kex_init   (ctx, pid_x);
    kex_locals (ctx, server_sk, server_pk);
    kex_receive(ctx, ctx->local_pk, ctx->local_pk);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (SE << 3) + (S << 6) + (SS << 9);
    ctx->messages[1] = 0;
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}
