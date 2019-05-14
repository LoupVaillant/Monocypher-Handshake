#include <stdio.h>
#include <stdlib.h>
#include <monocypher.h>
#include "monokex.h"
#include "utils.h"

void check(int condition, const char *error)
{
    if (!condition) {
        fprintf(stderr, "%s\n", error);
        exit(1);
    }
}

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

        check(!crypto_kex_should_get_remote(&client_ctx),"client remote     0");
        check(!crypto_kex_should_get_keys  (&client_ctx),"client should_key 0");
        check( crypto_kex_should_send      (&client_ctx),"client should_snd 0");
        check(!crypto_kex_should_receive   (&client_ctx),"client should_rcv 0");
        check(!crypto_kex_should_get_remote(&server_ctx),"server remote     0");
        check(!crypto_kex_should_get_keys  (&server_ctx),"server should_key 0");
        check(!crypto_kex_should_send      (&server_ctx),"server should_snd 0");
        check( crypto_kex_should_receive   (&server_ctx),"server should_rcv 0");
        u8 msg1[32];
        check(crypto_kex_next_message_min_size(&client_ctx) == 32,
              "wrong size for msg1 (client)");
        check(crypto_kex_next_message_min_size(&server_ctx) == 32,
              "wrong size for msg1 (server)");
        crypto_kex_send       (&client_ctx, msg1, 32);
        if (crypto_kex_receive(&server_ctx, msg1, 32)) {
            fprintf(stderr, "msg1 corrupted\n");
            return 1;
        }
        check(!crypto_kex_should_get_remote(&client_ctx),"client remote     1");
        check(!crypto_kex_should_get_keys  (&client_ctx),"client should_key 1");
        check(!crypto_kex_should_send      (&client_ctx),"client should_snd 1");
        check( crypto_kex_should_receive   (&client_ctx),"client should_rcv 1");
        check(!crypto_kex_should_get_remote(&server_ctx),"server remote     1");
        check(!crypto_kex_should_get_keys  (&server_ctx),"server should_key 1");
        check( crypto_kex_should_send      (&server_ctx),"server should_snd 1");
        check(!crypto_kex_should_receive   (&server_ctx),"server should_rcv 1");
        u8 msg2[48];
        check(crypto_kex_next_message_min_size(&client_ctx) == 48,
              "wrong size for msg1 (client)");
        check(crypto_kex_next_message_min_size(&server_ctx) == 48,
              "wrong size for msg1 (server)");
        crypto_kex_send       (&server_ctx, msg2, 48);
        if (crypto_kex_receive(&client_ctx, msg2, 48)) {
            fprintf(stderr, "msg2 corrupted\n");
            return 1;
        }
        check(!crypto_kex_should_get_remote(&client_ctx),"client remote     2");
        check(!crypto_kex_should_get_keys  (&client_ctx),"client should_key 2");
        check( crypto_kex_should_send      (&client_ctx),"client should_snd 2");
        check(!crypto_kex_should_receive   (&client_ctx),"client should_rcv 2");
        check(!crypto_kex_should_get_remote(&server_ctx),"server remote     2");
        check(!crypto_kex_should_get_keys  (&server_ctx),"server should_key 2");
        check(!crypto_kex_should_send      (&server_ctx),"server should_snd 2");
        check( crypto_kex_should_receive   (&server_ctx),"server should_rcv 2");
        u8 msg3[64];
        check(crypto_kex_next_message_min_size(&client_ctx) == 64,
              "wrong size for msg1 (client)");
        check(crypto_kex_next_message_min_size(&server_ctx) == 64,
              "wrong size for msg1 (server)");
        crypto_kex_send       (&client_ctx, msg3, 64);
        if (crypto_kex_receive(&server_ctx, msg3, 64)) {
            fprintf(stderr, "msg3 corrupted\n");
            return 1;
        }
        check(!crypto_kex_should_get_remote(&client_ctx),"client remote     3");
        check( crypto_kex_should_get_keys  (&client_ctx),"client should_key 3");
        check(!crypto_kex_should_send      (&client_ctx),"client should_snd 3");
        check(!crypto_kex_should_receive   (&client_ctx),"client should_rcv 3");
        check( crypto_kex_should_get_remote(&server_ctx),"server remote     3");
        check(!crypto_kex_should_get_keys  (&server_ctx),"server should_key 3");
        check(!crypto_kex_should_send      (&server_ctx),"server should_snd 3");
        check(!crypto_kex_should_receive   (&server_ctx),"server should_rcv 3");

        u8 remote_pk[32]; // same as client_pk
        crypto_kex_get_remote_key(&server_ctx, remote_pk);

        check(!crypto_kex_should_get_remote(&server_ctx),"server remote     4");
        check( crypto_kex_should_get_keys  (&server_ctx),"server should_key 4");
        check(!crypto_kex_should_send      (&server_ctx),"server should_snd 4");
        check(!crypto_kex_should_receive   (&server_ctx),"server should_rcv 4");

        u8 client_session_key1[32];
        u8 client_session_key2[32];
        crypto_kex_get_session_key(&client_ctx,
                                   client_session_key1,
                                   client_session_key2);

        check(!crypto_kex_should_get_remote(&client_ctx),"client remote     5");
        check(!crypto_kex_should_get_keys  (&client_ctx),"client should_key 5");
        check(!crypto_kex_should_send      (&client_ctx),"client should_snd 5");
        check(!crypto_kex_should_receive   (&client_ctx),"client should_rcv 5");

        u8 server_session_key1[32];
        u8 server_session_key2[32];
        crypto_kex_get_session_key(&server_ctx,
                                   server_session_key1,
                                   server_session_key2);

        check(!crypto_kex_should_get_remote(&server_ctx),"server remote     5");
        check(!crypto_kex_should_get_keys  (&server_ctx),"server should_key 5");
        check(!crypto_kex_should_send      (&server_ctx),"server should_snd 5");
        check(!crypto_kex_should_receive   (&server_ctx),"server should_rcv 5");

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

        check(!crypto_kex_should_get_remote(&client_ctx),"client remote     0");
        check(!crypto_kex_should_get_keys  (&client_ctx),"client should_key 0");
        check( crypto_kex_should_send      (&client_ctx),"client should_snd 0");
        check(!crypto_kex_should_receive   (&client_ctx),"client should_rcv 0");
        check(!crypto_kex_should_get_remote(&server_ctx),"server remote     0");
        check(!crypto_kex_should_get_keys  (&server_ctx),"server should_key 0");
        check(!crypto_kex_should_send      (&server_ctx),"server should_snd 0");
        check( crypto_kex_should_receive   (&server_ctx),"server should_rcv 0");
        u8 msg[96];
        check(crypto_kex_next_message_min_size(&client_ctx) == 96,
              "wrong size for msg1 (client)");
        check(crypto_kex_next_message_min_size(&server_ctx) == 96,
              "wrong size for msg1 (server)");
        crypto_kex_send       (&client_ctx, msg, 96);
        if (crypto_kex_receive(&server_ctx, msg, 96)) {
            fprintf(stderr, "msg corrupted\n");
            return 1;
        }

        check(!crypto_kex_should_get_remote(&client_ctx),"client remote     1");
        check( crypto_kex_should_get_keys  (&client_ctx),"client should_key 1");
        check(!crypto_kex_should_send      (&client_ctx),"client should_snd 1");
        check(!crypto_kex_should_receive   (&client_ctx),"client should_rcv 1");
        check( crypto_kex_should_get_remote(&server_ctx),"server remote     1");
        check(!crypto_kex_should_get_keys  (&server_ctx),"server should_key 1");
        check(!crypto_kex_should_send      (&server_ctx),"server should_snd 1");
        check(!crypto_kex_should_receive   (&server_ctx),"server should_rcv 1");

        u8 remote_pk[32]; // same as client_pk
        crypto_kex_get_remote_key(&server_ctx, remote_pk);

        check(!crypto_kex_should_get_remote(&server_ctx),"server remote     2");
        check( crypto_kex_should_get_keys  (&server_ctx),"server should_key 2");
        check(!crypto_kex_should_send      (&server_ctx),"server should_snd 2");
        check(!crypto_kex_should_receive   (&server_ctx),"server should_rcv 2");

        u8 client_session_key1[32];
        u8 client_session_key2[32];
        crypto_kex_get_session_key(&client_ctx,
                                   client_session_key1,
                                   client_session_key2);
        check(!crypto_kex_should_get_remote(&client_ctx),"client remote     3");
        check(!crypto_kex_should_get_keys  (&client_ctx),"client should_key 3");
        check(!crypto_kex_should_send      (&client_ctx),"client should_snd 3");
        check(!crypto_kex_should_receive   (&client_ctx),"client should_rcv 3");

        u8 server_session_key1[32];
        u8 server_session_key2[32];
        crypto_kex_get_session_key(&server_ctx,
                                   server_session_key1,
                                   server_session_key2);
        check(!crypto_kex_should_get_remote(&server_ctx),"server remote     5");
        check(!crypto_kex_should_get_keys  (&server_ctx),"server should_key 5");
        check(!crypto_kex_should_send      (&server_ctx),"server should_snd 5");
        check(!crypto_kex_should_receive   (&server_ctx),"server should_rcv 5");

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
