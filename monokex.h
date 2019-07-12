#include <inttypes.h>
#include <stddef.h>

typedef struct {
    uint8_t  hash[64];    // chaining hash
    uint8_t  s [32];      // static    secret key
    uint8_t  sp[32];      // static    public key
    uint8_t  e [32];      // ephemeral secret key
    uint8_t  ep[32];      // ephemeral public key
    uint8_t  sr[32];      // static    remote key
    uint8_t  er[32];      // ephemeral remote key
    uint16_t messages[4]; // Message tokens
    unsigned short flags; // Status flags
} crypto_kex_ctx;

typedef enum {
    CRYPTO_KEX_READ,  CRYPTO_KEX_WRITE, CRYPTO_KEX_REMOTE_KEY,
    CRYPTO_KEX_FINAL, CRYPTO_KEX_NONE
} crypto_kex_action;

// Basic read & write functions
// Maximum message size is 96 bytes
//
// If message_size is bigger than the actual message, the message will
// be padded with zeroes.
//
// If message_size is smaller than the actual message, the behaviour is
// undefined.  (The implementation tries to fail loudly, though)
//
// Padding bytes are ignored by crypto_kex_read().
int  crypto_kex_read (crypto_kex_ctx *ctx, const uint8_t *msg, size_t size);
void crypto_kex_write(crypto_kex_ctx *ctx, uint8_t       *msg, size_t size);

// Advanced read & write functions (with payload)
// Maximum message size is 96 bytes, plus the size of the payload.
//
// If payload is NULL, no payload is sent. Payload_size must be zero.
// If payload_size is zero, but payload is not NULL, an empty payload is
// sent.
int crypto_kex_read_p(crypto_kex_ctx *ctx,
                      uint8_t        *payload, size_t payload_size,
                      const uint8_t  *message, size_t message_size);
void crypto_kex_write_p(crypto_kex_ctx *ctx,
                        uint8_t        *message, size_t message_size,
                        const uint8_t  *payload, size_t payload_size);

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

// Next action to perform. Can be used instead of hard coding everything.
//
// CRYPTO_KEX_READ        call crypto_kex_read()
// CRYPTO_KEX_WRITE       call crypto_kex_write()
// CRYPTO_KEX_REMOTE_KEY  call crypto_kex_remote_key()
// CRYPTO_KEX_FINAL       call crypto_kex_final()
// CRYPTO_KEX_NONE        The context has been wiped, don't call anything.
//
// If next_message_size is not NULL, the minimum size of the next
// message (without payload) will be written in it.
crypto_kex_action crypto_kex_next_action(const crypto_kex_ctx *ctx,
                                         size_t *next_message_size);
///////////
/// XK1 ///
///////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (48 bytes)
// - write (64 bytes)
// - final
void crypto_kex_xk1_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   client_sk  [32],
                                const uint8_t   client_pk  [32],
                                const uint8_t   server_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (48 bytes)
// - read  (64 bytes)
// - remote key
// - final
void crypto_kex_xk1_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_sk  [32],
                                const uint8_t   server_pk  [32]);

////////////
/// X1K1 ///
////////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (48 bytes)
// - write (64 bytes)
// - read  (16 bytes)
// - final
void crypto_kex_x1k1_client_init(crypto_kex_ctx *ctx,
                                 uint8_t         random_seed[32],
                                 const uint8_t   client_sk  [32],
                                 const uint8_t   client_pk  [32],
                                 const uint8_t   server_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (48 bytes)
// - read  (64 bytes)
// - remote key
// - write (16 bytes)
// - final
void crypto_kex_x1k1_server_init(crypto_kex_ctx *ctx,
                                 uint8_t         random_seed[32],
                                 const uint8_t   server_sk  [32],
                                 const uint8_t   server_pk  [32]);

//////////
/// IX ///
//////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (64 bytes)
// - read  (96 bytes)
// - remote key
// - final
void crypto_kex_ix_client_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   client_sk  [32],
                               const uint8_t   client_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (64 bytes)
// - remote key
// - write (96 bytes)
// - final
void crypto_kex_ix_server_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   server_sk  [32],
                               const uint8_t   server_pk  [32]);

///////////
/// NK1 ///
///////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (48 bytes)
// - final
void crypto_kex_nk1_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (48 bytes)
// - final
void crypto_kex_nk1_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_sk  [32],
                                const uint8_t   server_pk  [32]);

/////////
/// X ///
/////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (96 bytes)
// - final
void crypto_kex_x_client_init(crypto_kex_ctx *ctx,
                              uint8_t         random_seed[32],
                              const uint8_t   client_sk  [32],
                              const uint8_t   client_pk  [32],
                              const uint8_t   server_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (96 bytes)
// - remote key
// - final
void crypto_kex_x_server_init(crypto_kex_ctx *ctx,
                              const uint8_t   server_sk[32],
                              const uint8_t   server_pk[32]);

