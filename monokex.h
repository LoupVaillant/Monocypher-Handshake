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

// Basic send & receive functions
void crypto_kex_send(crypto_kex_ctx *ctx,
                     uint8_t *message, size_t message_size);

int crypto_kex_receive(crypto_kex_ctx *ctx,
                       const uint8_t *message, size_t message_size);

// Advanced send & receive functions (with payload)
void crypto_kex_send_p(crypto_kex_ctx *ctx,
                       uint8_t       *message, size_t message_size,
                       const uint8_t *payload, size_t payload_size);

int crypto_kex_receive_p(crypto_kex_ctx *ctx,
                         uint8_t       *payload, size_t payload_size,
                         const uint8_t *message, size_t message_size);

// status
int crypto_kex_has_remote_key(crypto_kex_ctx *ctx);
int crypto_kex_is_done       (crypto_kex_ctx *ctx);
int crypto_kex_should_send   (crypto_kex_ctx *ctx);
int crypto_kex_should_receive(crypto_kex_ctx *ctx);

size_t crypto_kex_next_message_min_size(crypto_kex_ctx *ctx);

// outputs
void crypto_kex_get_remote_key(crypto_kex_ctx *ctx, uint8_t key[32]);

void crypto_kex_get_session_key(crypto_kex_ctx *ctx,
                                uint8_t key[32], uint8_t extra[32]);


///////////
/// XK1 ///
///////////
void crypto_kex_xk1_init_client(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   client_sk  [32],
                                const uint8_t   client_pk  [32],
                                const uint8_t   server_pk  [32]);

void crypto_kex_xk1_init_server(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_sk  [32],
                                const uint8_t   server_pk  [32]);

/////////
/// X ///
/////////
void crypto_kex_x_init_client(crypto_kex_ctx *ctx,
                              uint8_t         random_seed[32],
                              const uint8_t   client_sk  [32],
                              const uint8_t   client_pk  [32],
                              const uint8_t   server_pk  [32]);

void crypto_kex_x_init_server(crypto_kex_ctx *ctx,
                              const uint8_t   server_sk [32],
                              const uint8_t   server_pk [32]);
