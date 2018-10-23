#include <inttypes.h>

typedef struct {
    uint8_t transcript  [96];
    uint8_t key         [32];
    uint8_t remote_pk   [32];
    uint8_t local_sk    [32];
    uint8_t local_pk    [32];
    uint8_t ephemeral_sk[32];
    size_t transcript_size;
} crypto_handshake_ctx;


void crypto_handshake_request(crypto_handshake_ctx *ctx,
                              u8                    msg1       [32],
                              const u8              random_seed[32],
                              const u8              remote_pk  [32],
                              const u8              local_sk   [32],
                              const u8              local_pk   [32]);

void crypto_handshake_respond(crypto_handshake_ctx *ctx,
                              u8                    msg2       [48],
                              const u8              msg1       [32],
                              const u8              random_seed[32],
                              const u8              local_sk   [32]);

int crypto_handshake_confirm(crypto_handshake_ctx *ctx,
                             u8                    session_key[32],
                             u8                    msg3       [48],
                             const u8              msg2       [48]);

int crypto_handshake_accept(crypto_handshake_ctx *ctx,
                            u8                    session_key[32],
                            u8                    remote_pk  [32],
                            const u8              msg3       [48]);
