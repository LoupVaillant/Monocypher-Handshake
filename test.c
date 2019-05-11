#include <stdio.h>
#include <monocypher.h>
#include "monokex.h"
#include "utils.h"

int main()
{
    FOR(i, 0, 250) {
        RANDOM_INPUT(client_sk, 32);
        RANDOM_INPUT(server_sk, 32);
        RANDOM_INPUT(client_seed, 32);
        RANDOM_INPUT(server_seed, 32);
        u8 client_pk[32];  crypto_key_exchange_public_key(client_pk, client_sk);
        u8 server_pk[32];  crypto_key_exchange_public_key(server_pk, server_sk);

        crypto_kex_ctx client_ctx;
        crypto_kex_xk1_init_client(&client_ctx, client_seed,
                                   client_sk, client_pk, server_pk);
        crypto_kex_ctx server_ctx;
        crypto_kex_xk1_init_server(&server_ctx, server_seed,
                                   server_sk, server_pk);

        u8 msg1[32];
        crypto_kex_send       (&client_ctx, msg1, 32);
        if (crypto_kex_receive(&server_ctx, msg1, 32)) {
            fprintf(stderr, "msg1 corrupted\n");
            return 1;
        }
        u8 msg2[48];
        crypto_kex_send       (&server_ctx, msg2, 48);
        if (crypto_kex_receive(&client_ctx, msg2, 48)) {
            fprintf(stderr, "msg2 corrupted\n");
            return 1;
        }
        u8 msg3[48];
        crypto_kex_send       (&client_ctx, msg3, 48);
        if (crypto_kex_receive(&server_ctx, msg3, 48)) {
            fprintf(stderr, "msg3 corrupted\n");
            return 1;
        }

        u8 remote_pk[32]; // same as client_pk
        if (!crypto_kex_has_remote_key(&server_ctx)) {
            fprintf(stderr, "Server does not have client public key\n");
            return 1;
        }
        crypto_kex_get_remote_key(&server_ctx, remote_pk);

        u8 client_session_key1[32];
        u8 client_session_key2[32];
        if (!crypto_kex_is_done(&client_ctx)) {
            fprintf(stderr, "Client is not finished, cannot get session key\n");
            return 1;
        }
        crypto_kex_get_session_key(&client_ctx,
                                   client_session_key1,
                                   client_session_key2);

        u8 server_session_key1[32];
        u8 server_session_key2[32];
        if (!crypto_kex_is_done(&server_ctx)) {
            fprintf(stderr, "Server is not finished, cannot get session key\n");
            return 1;
        }
        crypto_kex_get_session_key(&server_ctx,
                                   server_session_key1,
                                   server_session_key2);

        if (crypto_verify32(client_session_key1, server_session_key1) ||
            crypto_verify32(client_session_key2, server_session_key2)) {
            fprintf(stderr, "Different session keys\n");
            return 1;
        }
        if (crypto_verify32(remote_pk, client_pk)) {
            fprintf(stderr, "Server got the wrong client public key\n");
            return 1;
        }
    }
    printf("OK: 3 way handshake\n");

    FOR (i, 0, 250) {
        RANDOM_INPUT(client_sk, 32);
        RANDOM_INPUT(server_sk, 32);
        RANDOM_INPUT(client_seed, 32);
        RANDOM_INPUT(server_seed, 32);
        u8 client_pk[32];  crypto_key_exchange_public_key(client_pk, client_sk);
        u8 server_pk[32];  crypto_key_exchange_public_key(server_pk, server_sk);

        crypto_kex_ctx client_ctx;
        crypto_kex_x_init_client(&client_ctx, client_seed,
                                 client_sk, client_pk, server_pk);
        crypto_kex_ctx server_ctx;
        crypto_kex_x_init_server(&server_ctx, server_sk, server_pk);

        u8 msg[80];
        crypto_kex_send       (&client_ctx, msg, 80);
        if (crypto_kex_receive(&server_ctx, msg, 80)) {
            fprintf(stderr, "msg corrupted\n");
            return 1;
        }

        u8 remote_pk[32]; // same as client_pk
        if (!crypto_kex_has_remote_key(&server_ctx)) {
            fprintf(stderr, "Server does not have client public key\n");
            return 1;
        }
        crypto_kex_get_remote_key(&server_ctx, remote_pk);

        u8 client_session_key1[32];
        u8 client_session_key2[32];
        if (!crypto_kex_is_done(&client_ctx)) {
            fprintf(stderr, "Client is not finished, cannot get session key\n");
            return 1;
        }
        crypto_kex_get_session_key(&client_ctx,
                                   client_session_key1,
                                   client_session_key2);

        u8 server_session_key1[32];
        u8 server_session_key2[32];
        if (!crypto_kex_is_done(&server_ctx)) {
            fprintf(stderr, "Server is not finished, cannot get session key\n");
            return 1;
        }
        crypto_kex_get_session_key(&server_ctx,
                                   server_session_key1,
                                   server_session_key2);

        if (crypto_verify32(client_session_key1, server_session_key1) ||
            crypto_verify32(client_session_key2, server_session_key2)) {
            fprintf(stderr, "Different session keys\n");
            return 1;
        }
        if (crypto_verify32(remote_pk, client_pk)) {
            fprintf(stderr, "Server got the wrong client public key\n");
            return 1;
        }
    }
    printf("OK: 1 way handshake\n");

    return 0;
}
