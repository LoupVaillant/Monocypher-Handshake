#include "test_core.h"
#include "monokex.h"
#include "monocypher.h"

#define RANDOM_INPUT(name, size) u8 name[size]; p_random(name, size)

typedef uint8_t u8;

static void test_xk1()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_xk1_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_xk1_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex XK1";
    test_pattern(&client, &server, pid);
}

static void test_x1k1()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_x1k1_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_x1k1_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex X1K1";
    test_pattern(&client, &server, pid);
}

static void test_ix()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_ix_client_init(&client, client_seed, css, cps);
    crypto_kex_ix_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex IX";
    test_pattern(&client, &server, pid);
}

static void test_nk1()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_nk1_client_init(&client, client_seed, sps);
    crypto_kex_nk1_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex NK1";
    test_pattern(&client, &server, pid);
}

static void test_x()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_x_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_x_server_init(&server, sss, sps);
    u8 pid[64] = "Monokex X";
    test_pattern(&client, &server, pid);
}

int main()
{
    test_xk1();
    test_x1k1();
    test_ix();
    test_nk1();
    test_x();
    return 0;
}
