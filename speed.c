#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

typedef uint8_t  u8;
typedef uint64_t u64;
typedef struct timespec timespec;

#define FOR(i, start, end)       for (size_t (i) = (start); (i) < (end); (i)++)
#define RANDOM_INPUT(name, size) u8 name[size]; p_random(name, size)
#define BILLION                  1000000000

// Pseudo-random 64 bit number, based on xorshift*
u64 rand64()
{
    static u64 x = 12345; // Must be seeded with a nonzero value.
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    return x * 0x2545F4914F6CDD1D; // magic constant
}

void p_random(u8 *stream, size_t size)
{
    FOR (i, 0, size) {
        stream[i] = (u8)rand64();
    }
}

// Difference in nanoseconds
static u64 diff(timespec start, timespec end)
{
    return
        (end.tv_sec  - start.tv_sec ) * BILLION +
        (end.tv_nsec - start.tv_nsec);
}

static u64 min(u64 a, u64 b)
{
    return a < b ? a : b;
}

static void print(const char *name, u64 duration, const char *unit)
{
    if (duration == 0) {
        printf("%s: too fast to be measured\n", name);
    } else {
        u64 speed_hz = BILLION / duration;
        printf("%s: %5" PRIu64 " %s\n", name, speed_hz, unit);
    }
}

#define TIMESTAMP(t)                            \
    timespec t;                                 \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t)

#define TIMING_START                            \
    u64 duration = -1u;                         \
    FOR (i, 0, 500) {                           \
        TIMESTAMP(start);

#define TIMING_END                              \
    TIMESTAMP(end);                             \
    duration = min(duration, diff(start, end)); \
    } /* end FOR*/                              \
    return duration

/////////////////////////
/// begin source file ///
/////////////////////////
#include <monocypher.h>
#include "monokex.h"

static void get_interactive_session(u8 msg1[32], u8 msg2[48], u8 msg3[64],
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
    crypto_kex_ctx client_ctx;
    crypto_kex_xk1_client_init(&client_ctx, c_seed, client_sk, client_pk,
                               server_pk);
    crypto_kex_ctx server_ctx;
    crypto_kex_xk1_server_init(&server_ctx, s_seed, server_sk, server_pk);

    crypto_kex_write   (&client_ctx, msg1, 32);
    if (crypto_kex_read(&server_ctx, msg1, 32)) {
        fprintf(stderr, "msg1 corrupted\n");
        return;
    }
    crypto_kex_write   (&server_ctx, msg2, 48);
    if (crypto_kex_read(&client_ctx, msg2, 48)) {
        fprintf(stderr, "msg2 corrupted\n");
        return;
    }
    crypto_kex_write   (&client_ctx, msg3, 64);
    if (crypto_kex_read(&server_ctx, msg3, 64)) {
        fprintf(stderr, "msg3 corrupted\n");
        return;
    }

    u8 remote_pk[32]; // same as client_pk
    crypto_kex_remote_key(&server_ctx, remote_pk);

    u8 client_session_key1[32];
    u8 client_session_key2[32];
    crypto_kex_final(&client_ctx,
                     client_session_key1,
                     client_session_key2);

    u8 server_session_key1[32];
    u8 server_session_key2[32];
    crypto_kex_final(&server_ctx,
                     server_session_key1,
                     server_session_key2);

    if (crypto_verify32(client_session_key1, server_session_key1) ||
        crypto_verify32(client_session_key2, server_session_key2)) {
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
    u8 msg1[32]; u8 msg2[48]; u8 msg3[64];
    u8 client_pk[32]; u8 server_pk[32];
    get_interactive_session(msg1, msg2, msg3,
                            client_pk  , server_pk,
                            client_sk  , server_sk,
                            client_seed, server_seed);
    TIMING_START {
        crypto_kex_ctx client_ctx;
        u8 seed[32];
        FOR (i, 0, 32) {
            seed[i] = client_seed[i];
        }
        crypto_kex_xk1_client_init(&client_ctx, seed, client_sk, client_pk,
                                   server_pk);
        crypto_kex_write   (&client_ctx, msg1, 32);
        if (crypto_kex_read(&client_ctx, msg2, 48)) {
            fprintf(stderr, "msg2 corrupted\n");
            return 1;
        }
        crypto_kex_write(&client_ctx, msg3, 64);
    }
    TIMING_END;
}

static u64 interactive_server(void)
{
    RANDOM_INPUT(client_sk, 32);
    RANDOM_INPUT(server_sk, 32);
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    u8 msg1[32]; u8 msg2[48]; u8 msg3[64];
    u8 client_pk[32]; u8 server_pk[32];
    get_interactive_session(msg1, msg2, msg3,
                            client_pk  , server_pk,
                            client_sk  , server_sk,
                            client_seed, server_seed);
    TIMING_START {
        crypto_kex_ctx server_ctx;
        u8 seed[32];
        FOR (i, 0, 32) {
            seed[i] = server_seed[i];
        }
        crypto_kex_xk1_server_init(&server_ctx, seed, server_sk, server_pk);

        if (crypto_kex_read(&server_ctx, msg1, 32)) {
            fprintf(stderr, "msg1 corrupted\n");
            return 1;
        }
        crypto_kex_write   (&server_ctx, msg2, 48);
        if (crypto_kex_read(&server_ctx, msg3, 64)) {
            fprintf(stderr, "msg3 corrupted\n");
            return 1;
        }
    }
    TIMING_END;
}

static void get_one_way_session(u8 msg[96], u8 client_pk[32], u8 server_pk[32],
                                const u8 client_sk  [32],
                                const u8 server_sk  [32],
                                const u8 client_seed[32])
{
    crypto_key_exchange_public_key(client_pk, client_sk);
    crypto_key_exchange_public_key(server_pk, server_sk);

    u8 c_seed[32];
    FOR (i, 0, 32) {
        c_seed[i] = client_seed[i];
    }

    crypto_kex_ctx client_ctx;
    crypto_kex_x_client_init(&client_ctx, c_seed, client_sk, client_pk,
                             server_pk);
    crypto_kex_ctx server_ctx;
    crypto_kex_x_server_init(&server_ctx, server_sk, server_pk);

    crypto_kex_write   (&client_ctx, msg, 96);
    if (crypto_kex_read(&server_ctx, msg, 96)) {
        fprintf(stderr, "msg corrupted\n");
        return;
    }

    u8 remote_pk[32]; // same as client_pk
    crypto_kex_remote_key(&server_ctx, remote_pk);

    u8 client_session_key1[32];
    u8 client_session_key2[32];
    crypto_kex_final(&client_ctx,
                     client_session_key1,
                     client_session_key2);

    u8 server_session_key1[32];
    u8 server_session_key2[32];
    crypto_kex_final(&server_ctx,
                     server_session_key1,
                     server_session_key2);

    if (crypto_verify32(client_session_key1, server_session_key1) ||
        crypto_verify32(client_session_key2, server_session_key2)) {
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
    u8 msg[96]; u8 client_pk[32]; u8 server_pk[32];
    get_one_way_session(msg,
                        client_pk, server_pk,
                        client_sk, server_sk,
                        client_seed);
    TIMING_START {
        u8 seed[32];
        FOR (i, 0, 32) {
            seed[i] = client_seed[i];
        }
        crypto_kex_ctx client_ctx;
        crypto_kex_x_client_init(&client_ctx, seed, client_sk, client_pk,
                                 server_pk);

        crypto_kex_write(&client_ctx, msg, 96);
    }
    TIMING_END;
}

static u64 one_way_server(void)
{
    RANDOM_INPUT(client_sk, 32);
    RANDOM_INPUT(server_sk, 32);
    RANDOM_INPUT(client_seed, 32);
    u8 msg[96]; u8 client_pk[32]; u8 server_pk[32];
    get_one_way_session(msg,
                        client_pk, server_pk,
                        client_sk, server_sk,
                        client_seed);
    TIMING_START {
        crypto_kex_ctx server_ctx;
        crypto_kex_x_server_init(&server_ctx, server_sk, server_pk);
        if (crypto_kex_read(&server_ctx, msg, 96)) {
            fprintf(stderr, "msg corrupted\n");
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
