#include "monocypher.h"
#include "monokex.h"

/////////////////
/// Utilities ///
/////////////////
#define FOR(i, start, end)  for (size_t (i) = (start); (i) < (end); (i)++)
#define WIPE_CTX(ctx)       crypto_wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer) crypto_wipe(buffer, sizeof(buffer))

// Message token bytecode
typedef enum { E=1, S=2, EE=3, ES=4, SE=5, SS=6 } action;
static int is_key     (unsigned i) { return i <= S;  }
static int is_exchange(unsigned i) { return i >= EE; }

// Context status flags
#define IS_OK        1 // Allways 1 (becomes zero when wiped)
#define HAS_KEY      2 // True if we have a symmetric key
#define HAS_REMOTE   4 // True if we have the remote DH key
#define GETS_REMOTE  8 // True if the remote key is transmitted to us
#define SHOULD_SEND 16 // Send/receive toggle

typedef uint8_t u8;

// memcpy clone
static void copy(u8 *out, const u8 *in, size_t nb)
{
    FOR(i, 0, nb) {
        out[i] = in[i];
    }
}

static void encrypt(u8 *out, const u8 *in, size_t size, const u8 key[32])
{
    static const u8 zero[8] = {0};
    crypto_chacha20(out, in, size, key, zero);
}

static void mix_hash(u8 after[64], const u8 before[64],
                     const u8 *input, size_t input_size)
{
    crypto_blake2b_general(after, 64, before, 64, input, input_size);
}

/////////////////////
/// State machine ///
/////////////////////

#define kex_mix_hash crypto_kex_add_prelude // it's the same thing

void kex_mix_hash(crypto_kex_ctx *ctx, const u8 *input, size_t input_size)
{
    mix_hash(ctx->hash, ctx->hash, input, input_size);
}

static void kex_extra_hash(crypto_kex_ctx *ctx, u8 *out)
{
    u8 zero[1] = {0};
    u8 one [1] = {1};
    mix_hash(ctx->hash, ctx->hash, zero, 1); // next chaining hash
    mix_hash(out      , ctx->hash, one , 1); // extra hash
}

static void kex_update_key(crypto_kex_ctx *ctx,
                           const u8 secret_key[32],
                           const u8 public_key[32])
{
    u8 tmp[32];
    crypto_x25519(tmp, secret_key, public_key);
    kex_mix_hash(ctx, tmp, 32);
    ctx->flags |= HAS_KEY;
    WIPE_BUFFER(tmp);
}

static void kex_auth(crypto_kex_ctx *ctx, u8 tag[16])
{
    if (!(ctx->flags & HAS_KEY)) { return; }
    u8 tmp[64];
    kex_extra_hash(ctx, tmp);
    copy(tag, tmp, 16);
    WIPE_BUFFER(tmp);
}

static int kex_verify(crypto_kex_ctx *ctx, const u8 tag[16])
{
    if (!(ctx->flags & HAS_KEY)) { return 0; }
    u8 real_tag[64]; // actually 16 useful bytes
    kex_extra_hash(ctx, real_tag);
    if (crypto_verify16(tag, real_tag)) {
        WIPE_CTX(ctx);
        WIPE_BUFFER(real_tag);
        return -1;
    }
    WIPE_BUFFER(real_tag);
    return 0;
}

static void kex_write_raw(crypto_kex_ctx *ctx, u8 *msg,
                          const u8 *src, size_t size)
{
    copy(msg, src, size);
    kex_mix_hash(ctx, msg, size);
}

static void kex_read_raw(crypto_kex_ctx *ctx, u8 *dest,
                         const u8 *msg, size_t size)
{
    kex_mix_hash(ctx, msg, size);
    copy(dest, msg, size);
}

static void kex_write(crypto_kex_ctx *ctx, u8 *msg, const u8 *src, size_t size)
{
    if (!(ctx->flags & HAS_KEY)) {
        kex_write_raw(ctx, msg, src, size);
        return;
    }
    // we have a key, we encrypt
    u8 key[64]; // actually 32 useful bytes
    kex_extra_hash(ctx, key);
    encrypt(msg, src, size, key);
    kex_mix_hash(ctx, msg, size);
    kex_auth(ctx, msg + size);
    WIPE_BUFFER(key);
}

static int kex_read(crypto_kex_ctx *ctx, u8 *dest, const u8 *msg, size_t size)
{
    if (!(ctx->flags & HAS_KEY)) {
        kex_read_raw(ctx, dest, msg, size);
        return 0;
    }
    // we have a key, we decrypt
    u8 key[64]; // actually 32 useful bytes
    kex_extra_hash(ctx, key);
    kex_mix_hash(ctx, msg, size);
    if (kex_verify(ctx, msg + size)) {
        WIPE_BUFFER(key);
        return -1;
    }
    encrypt(dest, msg, size, key);
    WIPE_BUFFER(key);
    return 0;
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
    ctx->messages[3] = 0;
}

//////////////////////
/// Initialisation ///
//////////////////////
static void kex_init(crypto_kex_ctx *ctx, const u8 pid[32])
{
    copy(ctx->hash, pid, 64);
    ctx->flags = IS_OK;
}

static void kex_seed(crypto_kex_ctx *ctx, u8 random_seed[32])
{
    copy(ctx->e, random_seed, 32);
    crypto_wipe(random_seed, 32); // auto wipe seed to avoid reuse
    crypto_x25519_public_key(ctx->ep, ctx->e);
}

static void kex_locals(crypto_kex_ctx *ctx, const u8 s[32], const u8 sp[32])
{
    if (sp == 0) { crypto_x25519_public_key(ctx->sp, s);      }
    else         { copy                    (ctx->sp, sp, 32); }
    copy(ctx->s, s, 32);
}

//////////////////////
/// Send & receive ///
//////////////////////
int crypto_kex_read (crypto_kex_ctx *ctx, const u8 *m, size_t m_size)
{
    return crypto_kex_read_p(ctx, 0, 0, m, m_size);
}

void crypto_kex_write(crypto_kex_ctx *ctx, u8 *m, size_t m_size)
{
    crypto_kex_write_p(ctx, m, m_size, 0, 0);
}

int crypto_kex_read_p(crypto_kex_ctx *ctx,
                      u8             *p, size_t p_size,
                      const u8       *m, size_t m_size)
{
    // Do nothing & fail if we should not receive
    size_t min_size;
    if (crypto_kex_next_action(ctx, &min_size) != CRYPTO_KEX_READ ||
        m_size < min_size + p_size) {
        WIPE_CTX(ctx);
        return -1;
    }
    // Next time, we'll send
    ctx->flags |= SHOULD_SEND;

    // receive core message
    while (ctx->messages[0] != 0) { // message not yet empty
        size_t tag_size = ctx->flags & HAS_KEY ? 16 : 0;
        switch (kex_next_token(ctx)) {
        case E : kex_read_raw(ctx, ctx->er, m, 32);  m += 32;  break;
        case S : if (kex_read(ctx, ctx->sr, m, 32)) { return -1; }
                 m += 32 + tag_size;
                 ctx->flags |= HAS_REMOTE;                     break;
        case EE: kex_update_key(ctx, ctx->e, ctx->er);         break;
        case ES: kex_update_key(ctx, ctx->e, ctx->sr);         break;
        case SE: kex_update_key(ctx, ctx->s, ctx->er);         break;
        case SS: kex_update_key(ctx, ctx->s, ctx->sr);         break;
        default:; // never happens
        }
    }
    kex_next_message(ctx);

    // Read payload, if any
    if (p != 0) { if (kex_read(ctx, p, m, p_size)) { return -1; } }
    else        { if (kex_verify(ctx, m)         ) { return -1; } }
    return 0;
}

void crypto_kex_write_p(crypto_kex_ctx *ctx,
                        u8             *m, size_t m_size,
                        const u8       *p, size_t p_size)
{
    // Fail if we should not send (the failure is alas delayed)
    size_t min_size;
    if (crypto_kex_next_action(ctx, &min_size) != CRYPTO_KEX_WRITE ||
        m_size < min_size + p_size) {
        WIPE_CTX(ctx);
        return;
    }
    // Next time, we'll receive
    ctx->flags &= ~SHOULD_SEND;

    // Send core message
    while (ctx->messages[0] != 0) { // message not yet empty
        size_t tag_size = ctx->flags & HAS_KEY ? 16 : 0;
        switch (kex_next_token(ctx)) {
        case E : kex_write_raw (ctx, m, ctx->ep, 32); m += 32;            break;
        case S : kex_write     (ctx, m, ctx->sp, 32); m += 32 + tag_size; break;
        case EE: kex_update_key(ctx, ctx->e, ctx->er);                    break;
        case ES: kex_update_key(ctx, ctx->e, ctx->sr);                    break;
        case SE: kex_update_key(ctx, ctx->s, ctx->er);                    break;
        case SS: kex_update_key(ctx, ctx->s, ctx->sr);                    break;
        default:; // never happens
        }
    }
    kex_next_message(ctx);

    // Write payload, if any
    size_t tag_size = ctx->flags & HAS_KEY ? 16 : 0;
    if (p != 0) { kex_write(ctx, m, p, p_size); m += tag_size + p_size; }
    else        { kex_auth (ctx, m);            m += tag_size;          }

    // Pad
    FOR (i, 0, m_size - min_size - p_size) {
        m[i] = 0;
    }
}

///////////////
/// Outputs ///
///////////////
void crypto_kex_remote_key(crypto_kex_ctx *ctx, u8 key[32])
{
    if (!(ctx->flags & HAS_REMOTE)) {
        WIPE_CTX(ctx);
        return;
    }
    copy(key, ctx->sr, 32);
    ctx->flags &= ~GETS_REMOTE;
}

void crypto_kex_final(crypto_kex_ctx *ctx, u8 key[32], u8 extra[32])
{
    if (crypto_kex_next_action(ctx, 0) == CRYPTO_KEX_FINAL) {
        copy(key, ctx->hash, 32);
        if (extra != 0) {
            copy(extra, ctx->hash + 32, 32);
        }
    }
    WIPE_CTX(ctx);
}

///////////////////
/// Next action ///
///////////////////
crypto_kex_action crypto_kex_next_action(const crypto_kex_ctx *ctx,
                                         size_t *next_message_size)
{
    // Next message size (if any)
    if (next_message_size) {
        unsigned has_key = ctx->flags & HAS_KEY ? 16 : 0;
        uint16_t message = ctx->messages[0];
        size_t   size    = 0;
        while (message != 0) {
            if (is_exchange(message & 7)) { has_key = 16;         }
            if (is_key     (message & 7)) { size += 32 + has_key; }
            message >>= 3;
        }
        *next_message_size = size + has_key;
    }
    // Next action
    int should_get_remote =
        (ctx->flags & HAS_REMOTE) &&
        (ctx->flags & GETS_REMOTE);
    return !(ctx->flags & IS_OK)    ? CRYPTO_KEX_NONE
        :  should_get_remote        ? CRYPTO_KEX_REMOTE_KEY
        :  ctx->messages[0] == 0    ? CRYPTO_KEX_FINAL
        :  ctx->flags & SHOULD_SEND ? CRYPTO_KEX_WRITE
        :                             CRYPTO_KEX_READ;
}

///////////
/// XK1 ///
///////////
static const u8 pid_xk1[64] = "Monokex XK1";

void crypto_kex_xk1_client_init(crypto_kex_ctx *ctx,
                                u8              random_seed[32],
                                const u8        client_sk  [32],
                                const u8        client_pk  [32],
                                const u8        server_pk  [32])
{
    kex_init    (ctx, pid_xk1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (ES << 6);
    ctx->messages[2] = S + (SE << 3);
    ctx->messages[3] = 0;
    kex_mix_hash(ctx, ctx->sr, 32);
}

void crypto_kex_xk1_server_init(crypto_kex_ctx *ctx,
                                u8              random_seed[32],
                                const u8        server_sk  [32],
                                const u8        server_pk  [32])
{
    kex_init    (ctx, pid_xk1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (SE << 6);
    ctx->messages[2] = S + (ES << 3);
    ctx->messages[3] = 0;
    kex_mix_hash(ctx, ctx->sp, 32);
}

////////////
/// X1K1 ///
////////////
static const u8 pid_x1k1[64] = "Monokex X1K1";

void crypto_kex_x1k1_client_init(crypto_kex_ctx *ctx,
                                 u8              random_seed[32],
                                 const u8        client_sk  [32],
                                 const u8        client_pk  [32],
                                 const u8        server_pk  [32])
{
    kex_init    (ctx, pid_x1k1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (ES << 6);
    ctx->messages[2] = S;
    ctx->messages[3] = SE;
    kex_mix_hash(ctx, ctx->sr, 32);
}

void crypto_kex_x1k1_server_init(crypto_kex_ctx *ctx,
                                 u8              random_seed[32],
                                 const u8        server_sk  [32],
                                 const u8        server_pk  [32])
{
    kex_init    (ctx, pid_x1k1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (SE << 6);
    ctx->messages[2] = S;
    ctx->messages[3] = ES;
    kex_mix_hash(ctx, ctx->sp, 32);
}

//////////
/// IX ///
//////////
static const u8 pid_ix[64] = "Monokex IX";

void crypto_kex_ix_client_init(crypto_kex_ctx *ctx,
                               u8              random_seed[32],
                               const u8        client_sk  [32],
                               const u8        client_pk  [32])
{
    kex_init    (ctx, pid_ix);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    ctx->flags |= GETS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3) + (SE << 6) + (S << 9) + (ES << 12);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

void crypto_kex_ix_server_init(crypto_kex_ctx *ctx,
                               u8              random_seed[32],
                               const u8        server_sk  [32],
                               const u8        server_pk  [32])
{
    kex_init    (ctx, pid_ix);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3) + (ES << 6) + (S << 9) + (SE << 12);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

///////////
/// NK1 ///
///////////
static const u8 pid_nk1[64] = "Monokex NK1";

void crypto_kex_nk1_client_init(crypto_kex_ctx *ctx,
                                u8              random_seed[32],
                                const u8        server_pk  [32])
{
    kex_init    (ctx, pid_nk1);
    kex_seed    (ctx, random_seed);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (ES << 6);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
    kex_mix_hash(ctx, ctx->sr, 32);
}

void crypto_kex_nk1_server_init(crypto_kex_ctx *ctx,
                                u8              random_seed[32],
                                const u8        server_sk  [32],
                                const u8        server_pk  [32])
{
    kex_init    (ctx, pid_nk1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (SE << 6);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
    kex_mix_hash(ctx, ctx->sp, 32);
}

/////////
/// X ///
/////////
static const u8 pid_x[64] = "Monokex X";

void crypto_kex_x_client_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32],
                              const u8        server_pk  [32])
{
    kex_init    (ctx, pid_x);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E + (ES << 3) + (S << 6) + (SS << 9);
    ctx->messages[1] = 0;
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
    kex_mix_hash(ctx, ctx->sr, 32);
}

void crypto_kex_x_server_init(crypto_kex_ctx *ctx,
                              const u8        server_sk[32],
                              const u8        server_pk[32])
{
    kex_init    (ctx, pid_x);
    kex_locals  (ctx, server_sk, server_pk);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (SE << 3) + (S << 6) + (SS << 9);
    ctx->messages[1] = 0;
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
    kex_mix_hash(ctx, ctx->sp, 32);
}

