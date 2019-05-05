#include <inttypes.h>
#include <stddef.h>

typedef struct {
    uint8_t hash       [64];
    uint8_t local_sk   [32];
    uint8_t local_pk   [32];
    uint8_t local_ske  [32];
    uint8_t local_pke  [32];
    uint8_t remote_pk  [32];
    uint8_t remote_pke [32];
    int     has_key;
} crypto_kex_ctx;

typedef struct { crypto_kex_ctx ctx; } crypto_kex_client_ctx;
typedef struct { crypto_kex_ctx ctx; } crypto_kex_server_ctx;

///////////
/// XK1 ///
///////////
void crypto_kex_xk1_init_client(crypto_kex_client_ctx *client_ctx,
                                uint8_t                random_seed[32],
                                const uint8_t          client_sk  [32],
                                const uint8_t          client_pk  [32],
                                const uint8_t          server_pk  [32]);

void crypto_kex_xk1_init_server(crypto_kex_server_ctx *server_ctx,
                                uint8_t                random_seed[32],
                                const uint8_t          server_sk  [32],
                                const uint8_t          server_pk  [32]);

void crypto_kex_xk1_1(crypto_kex_client_ctx *client_ctx,
                      uint8_t                msg1      [48]);

void crypto_kex_xk1_2(crypto_kex_server_ctx *server_ctx,
                      uint8_t                msg2      [48],
                      const uint8_t          msg1      [48]);

int crypto_kex_xk1_3(crypto_kex_client_ctx *client_ctx,
                     uint8_t                session_key[32],
                     uint8_t                msg3       [48],
                     const uint8_t          msg2       [48]);

int crypto_kex_xk1_4(crypto_kex_server_ctx *server_ctx,
                     uint8_t                session_key[32],
                     uint8_t                client_pk  [32],
                     const uint8_t          msg3       [48]);

/////////
/// X ///
/////////
void crypto_kex_x_init_client(crypto_kex_client_ctx *client_ctx,
                              uint8_t                random_seed[32],
                              const uint8_t          client_sk  [32],
                              const uint8_t          client_pk  [32],
                              const uint8_t          server_pk  [32]);

void crypto_kex_x_init_server(crypto_kex_server_ctx *server_ctx,
                              const uint8_t          server_sk [32],
                              const uint8_t          server_pk [32]);

void crypto_kex_x_1(crypto_kex_client_ctx *client_ctx,
                    uint8_t                session_key[32],
                    uint8_t                msg1       [80]);

int crypto_kex_x_2(crypto_kex_server_ctx *server_ctx,
                   uint8_t                session_key[32],
                   uint8_t                client_pk  [32],
                   const uint8_t          msg1       [80]);
