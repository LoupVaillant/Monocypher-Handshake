#include <inttypes.h>
#include <stddef.h>

typedef struct {
    uint8_t transcript [128];
    uint8_t chaining_key[32];
    uint8_t derived_keys[64];
    uint8_t key_nonce   [16];
    uint8_t remote_pk   [32];
    uint8_t local_sk    [32];
    uint8_t local_pk    [32];
    uint8_t ephemeral_sk[32];
    size_t  transcript_size;
} crypto_handshake_ctx;

///////////////////////////
/// Three way handshake ///
///////////////////////////
void crypto_handshake_request(crypto_handshake_ctx *ctx,
                              uint8_t               random_seed[32],
                              uint8_t               msg1       [32],
                              const uint8_t         remote_pk  [32],
                              const uint8_t         local_sk   [32],
                              const uint8_t         local_pk   [32]);

void crypto_handshake_respond(crypto_handshake_ctx *ctx,
                              uint8_t               random_seed[32],
                              uint8_t               msg2       [48],
                              const uint8_t         msg1       [32],
                              const uint8_t         local_sk   [32],
                              const uint8_t         local_pk   [32]);

int crypto_handshake_confirm(crypto_handshake_ctx *ctx,
                             uint8_t               session_key[32],
                             uint8_t               msg3       [48],
                             const uint8_t         msg2       [48]);

int crypto_handshake_accept(crypto_handshake_ctx *ctx,
                            uint8_t               session_key[32],
                            uint8_t               remote_pk  [32],
                            const uint8_t         msg3       [48]);

///////////////////////////////
/// Non interactive channel ///
///////////////////////////////
void crypto_send(uint8_t       random_seed[32],
                 uint8_t       session_key[32],
                 uint8_t       msg        [80],
                 const uint8_t remote_pk  [32],
                 const uint8_t local_sk   [32],
                 const uint8_t local_pk   [32]);

int crypto_receive(uint8_t       random_seed[32],
                   uint8_t       session_key[32],
                   uint8_t       remote_pk  [32],
                   const uint8_t msg        [80],
                   const uint8_t local_sk   [32],
                   const uint8_t local_pk   [32]);
