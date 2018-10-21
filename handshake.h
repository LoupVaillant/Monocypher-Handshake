#include <inttypes.h>

typedef struct {
    uint8_t transcript  [96];
    uint8_t key         [32];
    uint8_t static_pk   [32];
    uint8_t static_sk   [32];
    uint8_t ephemeral_sk[32];
} crypto_handshake_ctx;


void crypto_handshake_request(crypto_handshake_ctx *ctx,
                              uint8_t               msg1       [32],
                              const uint8_t         random_seed[32],
                              const uint8_t         static_sk  [32],
                              const uint8_t         static_pk  [32]);

void crypto_handshake_respond(crypto_handshake_ctx *ctx,
                              uint8_t               msg2       [48],
                              const uint8_t         msg1       [32],
                              const uint8_t         random_seed[32],
                              const uint8_t         static_sk  [32]);

int crypto_handshake_confirm(crypto_handshake_ctx *ctx,
                             uint8_t               session_key[32],
                             uint8_t               msg3       [48],
                             const uint8_t         msg2       [48]);

int crypto_handshake_accept(crypto_handshake_ctx *ctx,
                            uint8_t               session_key[32],
                            const uint8_t         msg3       [48]);
