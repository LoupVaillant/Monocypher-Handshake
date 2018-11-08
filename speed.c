///////////////////////////////
/// speed.h from Monocypher ///
///////////////////////////////

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

typedef struct timespec timespec;

// TODO: provide a user defined buffer size
#define KILOBYTE 1024
#define MEGABYTE 1024 * KILOBYTE
#define SIZE     (256 * KILOBYTE)
#define DIV      (MEGABYTE / SIZE)

static timespec diff(timespec start, timespec end)
{
    timespec duration;
    duration.tv_sec  = end.tv_sec  - start.tv_sec;
    duration.tv_nsec = end.tv_nsec - start.tv_nsec;
    if (duration.tv_nsec < 0) {
        duration.tv_nsec += 1000000000;
        duration.tv_sec  -= 1;
    }
    return duration;
}

static timespec min(timespec a, timespec b)
{
    if (a.tv_sec < b.tv_sec ||
        (a.tv_sec == b.tv_sec && a.tv_nsec < b.tv_nsec)) {
        return a;
    }
    return b;
}

static u64 speed(timespec duration)
{
    static const u64 giga = 1000000000;
    return giga / (duration.tv_nsec + duration.tv_sec * giga);
}

static void print(const char *name, u64 speed, const char *unit)
{
    printf("%s: %5" PRIu64 " %s\n", name, speed, unit);
}

#define TIMESTAMP(t)                            \
    timespec t;                                 \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t)

#define TIMING_START                            \
    timespec duration;                          \
    duration.tv_sec = -1;                       \
    duration.tv_nsec = -1;                      \
    duration.tv_sec  = 3600 * 24;               \
    duration.tv_nsec = 0;                       \
    FOR (i, 0, 500) {                           \
        TIMESTAMP(start);

#define TIMING_END                              \
    TIMESTAMP(end);                             \
    duration = min(duration, diff(start, end)); \
    } /* end FOR*/                              \
    return speed(duration)


/////////////////////////
/// begin source file ///
/////////////////////////
#include <monocypher.h>
#include "handshake.h"

static void get_interactive_session(u8 msg1[32], u8 msg2[48], u8 msg3[48],
                                    u8 client_pk[32], u8 server_pk[32],
                                    const u8 client_sk  [32],
                                    const u8 server_sk  [32],
                                    const u8 client_seed[32],
                                    const u8 server_seed[32])
{
    crypto_key_exchange_public_key(client_pk, client_sk);
    crypto_key_exchange_public_key(server_pk, server_sk);

    u8 c_seed[32];
    u8 s_seed[32];
    FOR (i, 0, 32) {
        c_seed[i] = client_seed[i];
        s_seed[i] = server_seed[i];
    }

    crypto_handshake_ctx client_ctx;
    crypto_handshake_request(&client_ctx, c_seed,
                             msg1, server_pk, client_sk, client_pk);

    crypto_handshake_ctx server_ctx;
    crypto_handshake_respond(&server_ctx, s_seed,
                             msg2, msg1, server_sk, server_pk);

    u8 client_session_key[32];
    if (crypto_handshake_confirm(&client_ctx, client_session_key,
                                 msg3, msg2)) {
        fprintf(stderr, "Cannot confirm\n");
        return;
    }

    u8 server_session_key[32];
    u8 remote_pk         [32]; // same as client_pk
    if (crypto_handshake_accept(&server_ctx, server_session_key, remote_pk,
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
}


static u64 interactive_client(void)
{
    RANDOM_INPUT(client_sk, 32);
    RANDOM_INPUT(server_sk, 32);
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    u8 msg1[32]; u8 msg2[48]; u8 msg3[48];
    u8 client_pk[32]; u8 server_pk[32];
    get_interactive_session(msg1, msg2, msg3,
                            client_pk  , server_pk,
                            client_sk  , server_sk,
                            client_seed, server_seed);
    TIMING_START {
        u8 session_key[32];
        crypto_handshake_ctx client_ctx;
        u8 seed[32];
        FOR (i, 0, 32) {
            seed[i] = client_seed[i];
        }
        crypto_handshake_request(&client_ctx, seed,
                                 msg1, server_pk, client_sk, client_pk);
        if (crypto_handshake_confirm(&client_ctx, session_key,
                                     msg3, msg2)) {
            fprintf(stderr, "Cannot confirm\n");
            return 1;
        }
    }
    TIMING_END;
}

static u64 interactive_server(void)
{
    RANDOM_INPUT(client_sk, 32);
    RANDOM_INPUT(server_sk, 32);
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    u8 msg1[32]; u8 msg2[48]; u8 msg3[48];
    u8 client_pk[32]; u8 server_pk[32];
    get_interactive_session(msg1, msg2, msg3,
                            client_pk  , server_pk,
                            client_sk  , server_sk,
                            client_seed, server_seed);
    TIMING_START {
        u8 session_key[32];
        u8 remote_pk         [32]; // same as client_pk
        crypto_handshake_ctx server_ctx;
        u8 seed[32];
        FOR (i, 0, 32) {
            seed[i] = server_seed[i];
        }
        crypto_handshake_respond(&server_ctx, seed,
                                 msg2, msg1, server_sk, server_pk);
        if (crypto_handshake_accept(&server_ctx, session_key, remote_pk,
                                    msg3)) {
            fprintf(stderr, "Cannot accept\n");
            return 1;
        }
    }
    TIMING_END;
}

static void get_one_way_session(u8 msg[80], u8 client_pk[32], u8 server_pk[32],
                                const u8 client_sk  [32],
                                const u8 server_sk  [32],
                                const u8 client_seed[32],
                                const u8 server_seed[32])
{
    crypto_key_exchange_public_key(client_pk, client_sk);
    crypto_key_exchange_public_key(server_pk, server_sk);

    u8 c_seed[32];
    u8 s_seed[32];
    FOR (i, 0, 32) {
        c_seed[i] = client_seed[i];
        s_seed[i] = server_seed[i];
    }

    u8 client_session_key[32];
    crypto_send(c_seed, client_session_key, msg,
                server_pk, client_sk, client_pk);

    u8 server_session_key[32];
    u8 remote_pk         [32]; // same as client_pk
    if (crypto_receive(s_seed, server_session_key, remote_pk,
                       msg, server_sk, server_pk)) {
        fprintf(stderr, "Cannot receive\n");
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
}

static u64 one_way_client(void)
{
    RANDOM_INPUT(client_sk, 32);
    RANDOM_INPUT(server_sk, 32);
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    u8 msg[80]; u8 client_pk[32]; u8 server_pk[32];
    get_one_way_session(msg,
                        client_pk  , server_pk,
                        client_sk  , server_sk,
                        client_seed, server_seed);
    TIMING_START {
        u8 session_key[32];
        u8 seed[32];
        FOR (i, 0, 32) {
            seed[i] = client_seed[i];
        }
        crypto_send(seed, session_key, msg,
                    server_pk, client_sk, client_pk);
    }
    TIMING_END;
}

static u64 one_way_server(void)
{
    RANDOM_INPUT(client_sk, 32);
    RANDOM_INPUT(server_sk, 32);
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    u8 msg[80]; u8 client_pk[32]; u8 server_pk[32];
    get_one_way_session(msg,
                        client_pk  , server_pk,
                        client_sk  , server_sk,
                        client_seed, server_seed);
    TIMING_START {
        u8 session_key[32];
        u8 remote_pk         [32]; // same as client_pk
        u8 seed[32];
        FOR (i, 0, 32) {
            seed[i] = server_seed[i];
        }
        if (crypto_receive(seed, session_key, remote_pk,
                           msg, server_sk, server_pk)) {
            fprintf(stderr, "Cannot receive\n");
            return 1;
        }
    }
    TIMING_END;
}

int main()
{
    print("Interactive (client)",interactive_client(),"handshakes per second");
    print("Interactive (server)",interactive_server(),"handshakes per second");
    print("One way     (client)",one_way_client()    ,"handshakes per second");
    print("One way     (server)",one_way_server()    ,"handshakes per second");
    printf("\n");
    return 0;
}
