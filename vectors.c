#include <stdio.h>
#include <monocypher.h>
#include "handshake.h"
#include "utils.h"

static void test_vectors_interactive(const uint8_t client_sk  [32],
                                     const uint8_t server_sk  [32],
                                     uint8_t client_seed[32],
                                     uint8_t server_seed[32])
{
    u8 client_pk[32];  crypto_key_exchange_public_key(client_pk, client_sk);
    u8 server_pk[32];  crypto_key_exchange_public_key(server_pk, server_sk);

    printf("Inputs\n");
    printf("------\n");
    printf("ls: "); print_vector(client_sk, 32);
    printf("LS: "); print_vector(client_pk, 32);
    printf("lr: "); print_vector(server_sk, 32);
    printf("LR: "); print_vector(server_pk, 32);
    printf("es: "); print_vector(client_seed, 32);
    printf("er: "); print_vector(server_seed, 32);
    printf("\n");

    u8 msg1[32];
    crypto_kex_ctx client_ctx;
    crypto_kex_request(&client_ctx, client_seed,
                       msg1, server_pk, client_sk, client_pk);

    u8 msg2[48];
    crypto_kex_ctx server_ctx;
    crypto_kex_respond(&server_ctx, server_seed,
                       msg2, msg1, server_sk, server_pk);

    u8 client_session_key[32];
    u8 msg3[48];
    if (crypto_kex_confirm(&client_ctx, client_session_key,
                           msg3, msg2)) {
        fprintf(stderr, "Cannot confirm\n");
        return;
    }

    u8 server_session_key[32];
    u8 remote_pk         [32]; // same as client_pk
    if (crypto_kex_accept(&server_ctx, server_session_key, remote_pk,
                          msg3)) {
        fprintf(stderr, "Cannot accept\n");
        return;
    }

    if (crypto_verify32(client_session_key, server_session_key)) {
        fprintf(stderr, "Different session keys\n");
        return;
    }
    if (crypto_verify32(remote_pk, client_pk)) {
        fprintf(stderr, "Server got the wrong client public key\n");
        return;
    }

    printf("Outputs\n");
    printf("--------\n");
    printf("msg1: "); print_vector(msg1, 32);
    printf("msg2: "); print_vector(msg2, 48);
    printf("msg3: "); print_vector(msg3, 48);
    printf("key : "); print_vector(client_session_key, 32);
}


int main()
{
    uint8_t client_sk  [32] = {
        0x0D, 0xAB, 0x8B, 0x40, 0xAB, 0x2B, 0x5A, 0x0F,
        0x93, 0x64, 0xA7, 0x28, 0x3E, 0x0B, 0xE9, 0xF5,
        0xCB, 0xF9, 0xC1, 0xBB, 0xBF, 0xD8, 0x77, 0xB9,
        0x5E, 0xB5, 0x36, 0x7A, 0x50, 0x14, 0x6B, 0xBF,
    };
    uint8_t server_sk  [32] = {
        0x1C, 0x02, 0x2F, 0xD8, 0x72, 0xF0, 0xAB, 0x17,
        0xC8, 0x8D, 0x39, 0x95, 0x1F, 0x38, 0x0E, 0x08,
        0xC8, 0x9B, 0x5E, 0x67, 0x6B, 0xF7, 0x03, 0xB6,
        0x31, 0xAD, 0xCA, 0xB3, 0x0F, 0x41, 0x1D, 0x9C,
    };
    uint8_t client_seed[32] = {
        0xA8, 0xAB, 0x49, 0x58, 0x18, 0xDA, 0xF8, 0x22,
        0x0E, 0x8E, 0x2C, 0x19, 0x21, 0xF4, 0x90, 0x25,
        0x33, 0xDB, 0x04, 0x75, 0x0B, 0x4A, 0x90, 0x16,
        0x50, 0xA6, 0x84, 0x75, 0x51, 0xFA, 0x31, 0x96,
    };
    uint8_t server_seed[32] = {
        0x3A, 0x9E, 0x52, 0x80, 0x74, 0x59, 0x5C, 0x18,
        0x3C, 0x52, 0xAB, 0xF5, 0x75, 0xE2, 0x16, 0x3A,
        0x47, 0x31, 0x52, 0x7A, 0x92, 0xE6, 0x0D, 0x18,
        0x73, 0xD7, 0xC3, 0xAF, 0x56, 0xA9, 0x2D, 0x09,
    };
    test_vectors_interactive(client_sk, server_sk, client_seed, server_seed);
}
