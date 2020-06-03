#include "test_core.h"
#include "monokex.h"
#include "monocypher.h"

#define RANDOM_INPUT(name, size) u8 name[size]; p_random(name, size)

typedef uint8_t u8;

static void test_n()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_n_client_init(&client, client_seed, sps);
    crypto_kex_n_server_init(&server, sss, sps);
    u8 pid[64] = "Monokex N";
    test_pattern(&client, &server, pid);
}

static void test_k()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_k_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_k_server_init(&server, sss, sps, cps);
    u8 pid[64] = "Monokex K";
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

static void test_nn()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    crypto_kex_ctx client, server;
    crypto_kex_nn_client_init(&client, client_seed);
    crypto_kex_nn_server_init(&server, server_seed);
    u8 pid[64] = "Monokex NN";
    test_pattern(&client, &server, pid);
}

static void test_nk()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_nk_client_init(&client, client_seed, sps);
    crypto_kex_nk_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex NK";
    test_pattern(&client, &server, pid);
}

static void test_nx()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_nx_client_init(&client, client_seed);
    crypto_kex_nx_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex NX";
    test_pattern(&client, &server, pid);
}

static void test_kn()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    crypto_kex_ctx client, server;
    crypto_kex_kn_client_init(&client, client_seed, css, cps);
    crypto_kex_kn_server_init(&server, server_seed, cps);
    u8 pid[64] = "Monokex KN";
    test_pattern(&client, &server, pid);
}

static void test_kk()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_kk_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_kk_server_init(&server, server_seed, sss, sps, cps);
    u8 pid[64] = "Monokex KK";
    test_pattern(&client, &server, pid);
}

static void test_kx()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_kx_client_init(&client, client_seed, css, cps);
    crypto_kex_kx_server_init(&server, server_seed, sss, sps, cps);
    u8 pid[64] = "Monokex KX";
    test_pattern(&client, &server, pid);
}

static void test_xn()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    crypto_kex_ctx client, server;
    crypto_kex_xn_client_init(&client, client_seed, css, cps);
    crypto_kex_xn_server_init(&server, server_seed);
    u8 pid[64] = "Monokex XN";
    test_pattern(&client, &server, pid);
}

static void test_xk()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_xk_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_xk_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex XK";
    test_pattern(&client, &server, pid);
}

static void test_xx()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_xx_client_init(&client, client_seed, css, cps);
    crypto_kex_xx_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex XX";
    test_pattern(&client, &server, pid);
}

static void test_in()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    crypto_kex_ctx client, server;
    crypto_kex_in_client_init(&client, client_seed, css, cps);
    crypto_kex_in_server_init(&server, server_seed);
    u8 pid[64] = "Monokex IN";
    test_pattern(&client, &server, pid);
}

static void test_ik()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_ik_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_ik_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex IK";
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

static void test_nx1()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_nx1_client_init(&client, client_seed);
    crypto_kex_nx1_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex NX1";
    test_pattern(&client, &server, pid);
}

static void test_k1n()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    crypto_kex_ctx client, server;
    crypto_kex_k1n_client_init(&client, client_seed, css, cps);
    crypto_kex_k1n_server_init(&server, server_seed, cps);
    u8 pid[64] = "Monokex K1N";
    test_pattern(&client, &server, pid);
}

static void test_k1k()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_k1k_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_k1k_server_init(&server, server_seed, sss, sps, cps);
    u8 pid[64] = "Monokex K1K";
    test_pattern(&client, &server, pid);
}

static void test_kk1()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_kk1_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_kk1_server_init(&server, server_seed, sss, sps, cps);
    u8 pid[64] = "Monokex KK1";
    test_pattern(&client, &server, pid);
}

static void test_k1k1()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_k1k1_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_k1k1_server_init(&server, server_seed, sss, sps, cps);
    u8 pid[64] = "Monokex K1K1";
    test_pattern(&client, &server, pid);
}

static void test_k1x()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_k1x_client_init(&client, client_seed, css, cps);
    crypto_kex_k1x_server_init(&server, server_seed, sss, sps, cps);
    u8 pid[64] = "Monokex K1X";
    test_pattern(&client, &server, pid);
}

static void test_kx1()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_kx1_client_init(&client, client_seed, css, cps);
    crypto_kex_kx1_server_init(&server, server_seed, sss, sps, cps);
    u8 pid[64] = "Monokex KX1";
    test_pattern(&client, &server, pid);
}

static void test_k1x1()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_k1x1_client_init(&client, client_seed, css, cps);
    crypto_kex_k1x1_server_init(&server, server_seed, sss, sps, cps);
    u8 pid[64] = "Monokex K1X1";
    test_pattern(&client, &server, pid);
}

static void test_x1n()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    crypto_kex_ctx client, server;
    crypto_kex_x1n_client_init(&client, client_seed, css, cps);
    crypto_kex_x1n_server_init(&server, server_seed);
    u8 pid[64] = "Monokex X1N";
    test_pattern(&client, &server, pid);
}

static void test_x1k()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_x1k_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_x1k_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex X1K";
    test_pattern(&client, &server, pid);
}

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

static void test_x1x()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_x1x_client_init(&client, client_seed, css, cps);
    crypto_kex_x1x_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex X1X";
    test_pattern(&client, &server, pid);
}

static void test_xx1()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_xx1_client_init(&client, client_seed, css, cps);
    crypto_kex_xx1_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex XX1";
    test_pattern(&client, &server, pid);
}

static void test_x1x1()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_x1x1_client_init(&client, client_seed, css, cps);
    crypto_kex_x1x1_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex X1X1";
    test_pattern(&client, &server, pid);
}

static void test_i1n()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    crypto_kex_ctx client, server;
    crypto_kex_i1n_client_init(&client, client_seed, css, cps);
    crypto_kex_i1n_server_init(&server, server_seed);
    u8 pid[64] = "Monokex I1N";
    test_pattern(&client, &server, pid);
}

static void test_i1k()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_i1k_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_i1k_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex I1K";
    test_pattern(&client, &server, pid);
}

static void test_ik1()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_ik1_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_ik1_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex IK1";
    test_pattern(&client, &server, pid);
}

static void test_i1k1()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_i1k1_client_init(&client, client_seed, css, cps, sps);
    crypto_kex_i1k1_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex I1K1";
    test_pattern(&client, &server, pid);
}

static void test_i1x()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_i1x_client_init(&client, client_seed, css, cps);
    crypto_kex_i1x_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex I1X";
    test_pattern(&client, &server, pid);
}

static void test_ix1()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_ix1_client_init(&client, client_seed, css, cps);
    crypto_kex_ix1_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex IX1";
    test_pattern(&client, &server, pid);
}

static void test_i1x1()
{
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    RANDOM_INPUT(css, 32);  u8 cps[32];  crypto_x25519_public_key(cps, css);
    RANDOM_INPUT(sss, 32);  u8 sps[32];  crypto_x25519_public_key(sps, sss);
    crypto_kex_ctx client, server;
    crypto_kex_i1x1_client_init(&client, client_seed, css, cps);
    crypto_kex_i1x1_server_init(&server, server_seed, sss, sps);
    u8 pid[64] = "Monokex I1X1";
    test_pattern(&client, &server, pid);
}

int main()
{
    test_n();
    test_k();
    test_x();
    test_nn();
    test_nk();
    test_nx();
    test_kn();
    test_kk();
    test_kx();
    test_xn();
    test_xk();
    test_xx();
    test_in();
    test_ik();
    test_ix();
    test_nk1();
    test_nx1();
    test_k1n();
    test_k1k();
    test_kk1();
    test_k1k1();
    test_k1x();
    test_kx1();
    test_k1x1();
    test_x1n();
    test_x1k();
    test_xk1();
    test_x1k1();
    test_x1x();
    test_xx1();
    test_x1x1();
    test_i1n();
    test_i1k();
    test_ik1();
    test_i1k1();
    test_i1x();
    test_ix1();
    test_i1x1();
    return 0;
}
