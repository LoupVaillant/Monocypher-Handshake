#include <stdio.h>
#include <monocypher.h>
#include "handshake.h"
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

        u8 msg1[32];
        crypto_handshake_ctx client_ctx;
        crypto_handshake_request(&client_ctx, msg1,
                                 client_seed, server_pk, client_sk, client_pk);

        u8 msg2[48];
        crypto_handshake_ctx server_ctx;
        crypto_handshake_respond(&server_ctx, msg2, msg1,
                                 server_seed, server_sk);

        u8 client_session_key[32];
        u8 msg3[48];
        if (crypto_handshake_confirm(&client_ctx, client_session_key,
                                     msg3, msg2)) {
            fprintf(stderr, "Cannot confirm\n");
            return 1;
        }

        u8 server_session_key[32];
        u8 remote_pk         [32]; // same as client_pk
        if (crypto_handshake_accept(&server_ctx, server_session_key, remote_pk,
                                    msg3)) {
            fprintf(stderr, "Cannot accept\n");
            return 1;
        }

        if (crypto_verify32(client_session_key, server_session_key)) {
            fprintf(stderr, "Different session keys\n");
            return 1;
        }
        if (crypto_verify32(remote_pk, client_pk)) {
            fprintf(stderr, "Server got the wrong client public key\n");
            return 1;
        }
    }
    return 0;
}
