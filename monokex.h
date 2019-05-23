#include <inttypes.h>
#include <stddef.h>

typedef struct {
    uint8_t  hash      [64];
    uint8_t  local_sk  [32];
    uint8_t  local_pk  [32];
    uint8_t  local_ske [32];
    uint8_t  local_pke [32];
    uint8_t  remote_pk [32];
    uint8_t  remote_pke[32];
    uint16_t messages  [ 4];
    unsigned short flags;
} crypto_kex_ctx;

typedef enum {
    CRYPTO_KEX_SEND,
    CRYPTO_KEX_RECV,
    CRYPTO_KEX_REMOTE_KEY,
    CRYPTO_KEX_FINAL,
    CRYPTO_KEX_NONE,
} crypto_kex_action;

// Basic send & receive functions
// Maximum message size is 96 bytes
// If message_size is bigger than the actual message, the message will
// be padded with zeroes.
// Padding bytes are ignored by crypto_kex_recv().
void crypto_kex_send(crypto_kex_ctx *ctx,
                     uint8_t *message, size_t message_size);
int  crypto_kex_recv(crypto_kex_ctx *ctx,
                     const uint8_t *message, size_t message_size);

// Advanced send & receive functions (with payload)
// Maximum message size is 96 bytes, plus the size of the payload.
void crypto_kex_send_p(crypto_kex_ctx *ctx,
                       uint8_t       *message, size_t message_size,
                       const uint8_t *payload, size_t payload_size);
int  crypto_kex_recv_p(crypto_kex_ctx *ctx,
                       uint8_t       *payload, size_t payload_size,
                       const uint8_t *message, size_t message_size);

// Adds a prelude to the transcript hash.
// Call once, just after crypto_kex_*_init().
void crypto_kex_add_prelude(crypto_kex_ctx *ctx,
                            const uint8_t *prelude, size_t prelude_size);

// Gets the remote key.
// MUST be called as soon as the remote key has been transmitted.
// (Sometimes the key is known in advance, and is never transmitted.)
void crypto_kex_remote_key(crypto_kex_ctx *ctx, uint8_t key[32]);

// Gets the session key and wipes the context.
// The extra key can be used as a second session key, or as a hash for
// channel binding.
void crypto_kex_final(crypto_kex_ctx *ctx,
                      uint8_t session_key[32],
                      uint8_t extra_key  [32]);

// Next action to perform.
//
// CRYPTO_KEX_SEND        call crypto_kex_send()
// CRYPTO_KEX_RECV        call crypto_kex_recv()
// CRYPTO_KEX_REMOTE_KEY  call crypto_kex_remote_key()
// CRYPTO_KEX_FINAL       call crypto_kex_final()
// CRYPTO_KEX_NONE        The context has been wiped, don't call anything.
crypto_kex_action crypto_kex_next_action(const crypto_kex_ctx *ctx,
                                         size_t *next_message_size);


///////////
/// XK1 ///
///////////
void crypto_kex_xk1_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   client_sk  [32],
                                const uint8_t   client_pk  [32],
                                const uint8_t   server_pk  [32]);

void crypto_kex_xk1_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_sk  [32],
                                const uint8_t   server_pk  [32]);

/////////
/// X ///
/////////
void crypto_kex_x_client_init(crypto_kex_ctx *ctx,
                              uint8_t         random_seed[32],
                              const uint8_t   client_sk  [32],
                              const uint8_t   client_pk  [32],
                              const uint8_t   server_pk  [32]);

void crypto_kex_x_server_init(crypto_kex_ctx *ctx,
                              const uint8_t   server_sk [32],
                              const uint8_t   server_pk [32]);
