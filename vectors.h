#include <inttypes.h>
#include <stddef.h>

typedef enum { E, S, EE, ES, SE, SS, STOP } actions;

typedef struct {
    // secret keys
    uint8_t cse[32];  int has_cse;  // client secret key (ephemeral)
    uint8_t sse[32];  int has_sse;  // server secret key (ephemeral)
    uint8_t css[32];  int has_css;  // client secret key (static)
    uint8_t sss[32];  int has_sss;  // server secret key (static)

    // initial hash
    uint8_t protocol_id[64];

    // prelude & payloads (size == -1 means no prelude or no payload)
    uint8_t prelude    [32];  size_t prelude_size;
    uint8_t payloads[4][32];  size_t payload_sizes[4];

    // pattern
    actions pattern[5][5]; // the last message starts by STOP
} in_vectors;

typedef struct {
    // public keys
    uint8_t cpe[32]; // client public key (ephemeral)
    uint8_t spe[32]; // server public key (ephemeral)
    uint8_t cps[32]; // client public key (static)
    uint8_t sps[32]; // server public key (static)

    // exchanges
    uint8_t ee[32];
    uint8_t es[32];
    uint8_t se[32];
    uint8_t ss[32];

    // Successive hashes of the state machine
    uint8_t prelude_hash[32];      // hash   after the prelude
    uint8_t message_hashes[4][32]; // hashes after each message

    // messages
    uint8_t messages[4][128]; // 96 bytes max, plus payloads
    size_t  message_sizes[4];
    size_t  nb_messages;

    // session keys
    uint8_t session_key[32];
    uint8_t extra_key  [32];
} out_vectors;

void generate(out_vectors *out, const in_vectors *in);
