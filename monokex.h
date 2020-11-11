#ifndef MONOKEX_H
#define MONOKEX_H

#include <inttypes.h>
#include <stddef.h>

typedef struct {
    uint8_t  pool[64];    // random pool
    uint8_t  hash[64];    // chaining hash + extra hash
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
// be padded with random data.
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
void crypto_kex_final(crypto_kex_ctx *ctx, uint8_t session_key[32]);

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
/////////
/// N ///
/////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (48 bytes)
// - final
void crypto_kex_n_client_init(crypto_kex_ctx *ctx,
                              uint8_t         random_seed[32],
                              const uint8_t   server_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (48 bytes)
// - final
void crypto_kex_n_server_init(crypto_kex_ctx *ctx,
                              const uint8_t   server_sk[32],
                              const uint8_t   server_pk[32]);

/////////
/// K ///
/////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (48 bytes)
// - final
void crypto_kex_k_client_init(crypto_kex_ctx *ctx,
                              uint8_t         random_seed[32],
                              const uint8_t   client_sk  [32],
                              const uint8_t   client_pk  [32],
                              const uint8_t   server_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (48 bytes)
// - final
void crypto_kex_k_server_init(crypto_kex_ctx *ctx,
                              const uint8_t   server_sk[32],
                              const uint8_t   server_pk[32],
                              const uint8_t   client_pk[32]);

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

//////////
/// NN ///
//////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (48 bytes)
// - final
void crypto_kex_nn_client_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (48 bytes)
// - final
void crypto_kex_nn_server_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32]);

//////////
/// NK ///
//////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (48 bytes)
// - read  (64 bytes)
// - final
void crypto_kex_nk_client_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   server_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (48 bytes)
// - write (64 bytes)
// - final
void crypto_kex_nk_server_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   server_sk  [32],
                               const uint8_t   server_pk  [32]);

//////////
/// NX ///
//////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (96 bytes)
// - remote key
// - final
void crypto_kex_nx_client_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (96 bytes)
// - final
void crypto_kex_nx_server_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   server_sk  [32],
                               const uint8_t   server_pk  [32]);

//////////
/// KN ///
//////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (48 bytes)
// - final
void crypto_kex_kn_client_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   client_sk  [32],
                               const uint8_t   client_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (48 bytes)
// - final
void crypto_kex_kn_server_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   client_pk  [32]);

//////////
/// KK ///
//////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (48 bytes)
// - read  (64 bytes)
// - final
void crypto_kex_kk_client_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   client_sk  [32],
                               const uint8_t   client_pk  [32],
                               const uint8_t   server_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (48 bytes)
// - write (64 bytes)
// - final
void crypto_kex_kk_server_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   server_sk  [32],
                               const uint8_t   server_pk  [32],
                               const uint8_t   client_pk  [32]);

//////////
/// KX ///
//////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (96 bytes)
// - remote key
// - final
void crypto_kex_kx_client_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   client_sk  [32],
                               const uint8_t   client_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (96 bytes)
// - final
void crypto_kex_kx_server_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   server_sk  [32],
                               const uint8_t   server_pk  [32],
                               const uint8_t   client_pk  [32]);

//////////
/// XN ///
//////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (48 bytes)
// - write (64 bytes)
// - final
void crypto_kex_xn_client_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   client_sk  [32],
                               const uint8_t   client_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (48 bytes)
// - read  (64 bytes)
// - remote key
// - final
void crypto_kex_xn_server_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32]);

//////////
/// XK ///
//////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (48 bytes)
// - read  (64 bytes)
// - write (64 bytes)
// - final
void crypto_kex_xk_client_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   client_sk  [32],
                               const uint8_t   client_pk  [32],
                               const uint8_t   server_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (48 bytes)
// - write (64 bytes)
// - read  (64 bytes)
// - remote key
// - final
void crypto_kex_xk_server_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   server_sk  [32],
                               const uint8_t   server_pk  [32]);

//////////
/// XX ///
//////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (96 bytes)
// - remote key
// - write (64 bytes)
// - final
void crypto_kex_xx_client_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   client_sk  [32],
                               const uint8_t   client_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (96 bytes)
// - read  (64 bytes)
// - remote key
// - final
void crypto_kex_xx_server_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   server_sk  [32],
                               const uint8_t   server_pk  [32]);

//////////
/// IN ///
//////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (64 bytes)
// - read  (48 bytes)
// - final
void crypto_kex_in_client_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   client_sk  [32],
                               const uint8_t   client_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (64 bytes)
// - remote key
// - write (48 bytes)
// - final
void crypto_kex_in_server_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32]);

//////////
/// IK ///
//////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (96 bytes)
// - read  (64 bytes)
// - final
void crypto_kex_ik_client_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   client_sk  [32],
                               const uint8_t   client_pk  [32],
                               const uint8_t   server_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (96 bytes)
// - remote key
// - write (64 bytes)
// - final
void crypto_kex_ik_server_init(crypto_kex_ctx *ctx,
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

///////////
/// NX1 ///
///////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (96 bytes)
// - remote key
// - write (16 bytes)
// - final
void crypto_kex_nx1_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (96 bytes)
// - read  (16 bytes)
// - final
void crypto_kex_nx1_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_sk  [32],
                                const uint8_t   server_pk  [32]);

///////////
/// K1N ///
///////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (48 bytes)
// - write (16 bytes)
// - final
void crypto_kex_k1n_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   client_sk  [32],
                                const uint8_t   client_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (48 bytes)
// - read  (16 bytes)
// - final
void crypto_kex_k1n_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   client_pk  [32]);

///////////
/// K1K ///
///////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (48 bytes)
// - read  (64 bytes)
// - write (16 bytes)
// - final
void crypto_kex_k1k_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   client_sk  [32],
                                const uint8_t   client_pk  [32],
                                const uint8_t   server_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (48 bytes)
// - write (64 bytes)
// - read  (16 bytes)
// - final
void crypto_kex_k1k_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_sk  [32],
                                const uint8_t   server_pk  [32],
                                const uint8_t   client_pk  [32]);

///////////
/// KK1 ///
///////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (48 bytes)
// - final
void crypto_kex_kk1_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   client_sk  [32],
                                const uint8_t   client_pk  [32],
                                const uint8_t   server_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (48 bytes)
// - final
void crypto_kex_kk1_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_sk  [32],
                                const uint8_t   server_pk  [32],
                                const uint8_t   client_pk  [32]);

////////////
/// K1K1 ///
////////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (48 bytes)
// - write (16 bytes)
// - final
void crypto_kex_k1k1_client_init(crypto_kex_ctx *ctx,
                                 uint8_t         random_seed[32],
                                 const uint8_t   client_sk  [32],
                                 const uint8_t   client_pk  [32],
                                 const uint8_t   server_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (48 bytes)
// - read  (16 bytes)
// - final
void crypto_kex_k1k1_server_init(crypto_kex_ctx *ctx,
                                 uint8_t         random_seed[32],
                                 const uint8_t   server_sk  [32],
                                 const uint8_t   server_pk  [32],
                                 const uint8_t   client_pk  [32]);

///////////
/// K1X ///
///////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (96 bytes)
// - remote key
// - write (16 bytes)
// - final
void crypto_kex_k1x_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   client_sk  [32],
                                const uint8_t   client_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (96 bytes)
// - read  (16 bytes)
// - final
void crypto_kex_k1x_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_sk  [32],
                                const uint8_t   server_pk  [32],
                                const uint8_t   client_pk  [32]);

///////////
/// KX1 ///
///////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (96 bytes)
// - remote key
// - write (16 bytes)
// - final
void crypto_kex_kx1_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   client_sk  [32],
                                const uint8_t   client_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (96 bytes)
// - read  (16 bytes)
// - final
void crypto_kex_kx1_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_sk  [32],
                                const uint8_t   server_pk  [32],
                                const uint8_t   client_pk  [32]);

////////////
/// K1X1 ///
////////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (96 bytes)
// - remote key
// - write (16 bytes)
// - final
void crypto_kex_k1x1_client_init(crypto_kex_ctx *ctx,
                                 uint8_t         random_seed[32],
                                 const uint8_t   client_sk  [32],
                                 const uint8_t   client_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (96 bytes)
// - read  (16 bytes)
// - final
void crypto_kex_k1x1_server_init(crypto_kex_ctx *ctx,
                                 uint8_t         random_seed[32],
                                 const uint8_t   server_sk  [32],
                                 const uint8_t   server_pk  [32],
                                 const uint8_t   client_pk  [32]);

///////////
/// X1N ///
///////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (48 bytes)
// - write (64 bytes)
// - read  (16 bytes)
// - final
void crypto_kex_x1n_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   client_sk  [32],
                                const uint8_t   client_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (48 bytes)
// - read  (64 bytes)
// - remote key
// - write (16 bytes)
// - final
void crypto_kex_x1n_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32]);

///////////
/// X1K ///
///////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (48 bytes)
// - read  (64 bytes)
// - write (64 bytes)
// - read  (16 bytes)
// - final
void crypto_kex_x1k_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   client_sk  [32],
                                const uint8_t   client_pk  [32],
                                const uint8_t   server_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (48 bytes)
// - write (64 bytes)
// - read  (64 bytes)
// - remote key
// - write (16 bytes)
// - final
void crypto_kex_x1k_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_sk  [32],
                                const uint8_t   server_pk  [32]);

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

///////////
/// X1X ///
///////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (96 bytes)
// - remote key
// - write (64 bytes)
// - read  (16 bytes)
// - final
void crypto_kex_x1x_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   client_sk  [32],
                                const uint8_t   client_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (96 bytes)
// - read  (64 bytes)
// - remote key
// - write (16 bytes)
// - final
void crypto_kex_x1x_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_sk  [32],
                                const uint8_t   server_pk  [32]);

///////////
/// XX1 ///
///////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (96 bytes)
// - remote key
// - write (64 bytes)
// - final
void crypto_kex_xx1_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   client_sk  [32],
                                const uint8_t   client_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (96 bytes)
// - read  (64 bytes)
// - remote key
// - final
void crypto_kex_xx1_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_sk  [32],
                                const uint8_t   server_pk  [32]);

////////////
/// X1X1 ///
////////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (32 bytes)
// - read  (96 bytes)
// - remote key
// - write (64 bytes)
// - read  (16 bytes)
// - final
void crypto_kex_x1x1_client_init(crypto_kex_ctx *ctx,
                                 uint8_t         random_seed[32],
                                 const uint8_t   client_sk  [32],
                                 const uint8_t   client_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (32 bytes)
// - write (96 bytes)
// - read  (64 bytes)
// - remote key
// - write (16 bytes)
// - final
void crypto_kex_x1x1_server_init(crypto_kex_ctx *ctx,
                                 uint8_t         random_seed[32],
                                 const uint8_t   server_sk  [32],
                                 const uint8_t   server_pk  [32]);

///////////
/// I1N ///
///////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (64 bytes)
// - read  (48 bytes)
// - write (16 bytes)
// - final
void crypto_kex_i1n_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   client_sk  [32],
                                const uint8_t   client_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (64 bytes)
// - remote key
// - write (48 bytes)
// - read  (16 bytes)
// - final
void crypto_kex_i1n_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32]);

///////////
/// I1K ///
///////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (96 bytes)
// - read  (64 bytes)
// - write (16 bytes)
// - final
void crypto_kex_i1k_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   client_sk  [32],
                                const uint8_t   client_pk  [32],
                                const uint8_t   server_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (96 bytes)
// - remote key
// - write (64 bytes)
// - read  (16 bytes)
// - final
void crypto_kex_i1k_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_sk  [32],
                                const uint8_t   server_pk  [32]);

///////////
/// IK1 ///
///////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (64 bytes)
// - read  (48 bytes)
// - final
void crypto_kex_ik1_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   client_sk  [32],
                                const uint8_t   client_pk  [32],
                                const uint8_t   server_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (64 bytes)
// - remote key
// - write (48 bytes)
// - final
void crypto_kex_ik1_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_sk  [32],
                                const uint8_t   server_pk  [32]);

////////////
/// I1K1 ///
////////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (64 bytes)
// - read  (48 bytes)
// - write (16 bytes)
// - final
void crypto_kex_i1k1_client_init(crypto_kex_ctx *ctx,
                                 uint8_t         random_seed[32],
                                 const uint8_t   client_sk  [32],
                                 const uint8_t   client_pk  [32],
                                 const uint8_t   server_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (64 bytes)
// - remote key
// - write (48 bytes)
// - read  (16 bytes)
// - final
void crypto_kex_i1k1_server_init(crypto_kex_ctx *ctx,
                                 uint8_t         random_seed[32],
                                 const uint8_t   server_sk  [32],
                                 const uint8_t   server_pk  [32]);

///////////
/// I1X ///
///////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (64 bytes)
// - read  (96 bytes)
// - remote key
// - write (16 bytes)
// - final
void crypto_kex_i1x_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   client_sk  [32],
                                const uint8_t   client_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (64 bytes)
// - remote key
// - write (96 bytes)
// - read  (16 bytes)
// - final
void crypto_kex_i1x_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_sk  [32],
                                const uint8_t   server_pk  [32]);

///////////
/// IX1 ///
///////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (64 bytes)
// - read  (96 bytes)
// - remote key
// - write (16 bytes)
// - final
void crypto_kex_ix1_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   client_sk  [32],
                                const uint8_t   client_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (64 bytes)
// - remote key
// - write (96 bytes)
// - read  (16 bytes)
// - final
void crypto_kex_ix1_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_sk  [32],
                                const uint8_t   server_pk  [32]);

////////////
/// I1X1 ///
////////////

// Initialises a handshake context for the client.
// Actions happen in the following order:
//
// - write (64 bytes)
// - read  (96 bytes)
// - remote key
// - write (16 bytes)
// - final
void crypto_kex_i1x1_client_init(crypto_kex_ctx *ctx,
                                 uint8_t         random_seed[32],
                                 const uint8_t   client_sk  [32],
                                 const uint8_t   client_pk  [32]);

// Initialises a handshake context for the server.
// Actions happen in the following order:
//
// - read  (64 bytes)
// - remote key
// - write (96 bytes)
// - read  (16 bytes)
// - final
void crypto_kex_i1x1_server_init(crypto_kex_ctx *ctx,
                                 uint8_t         random_seed[32],
                                 const uint8_t   server_sk  [32],
                                 const uint8_t   server_pk  [32]);

#endif // MONOKEX_H
