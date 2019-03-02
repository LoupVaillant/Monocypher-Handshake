#include <stdio.h>
#include <string.h>
#include <monocypher.h>
#include "monokex.h"
#include "utils.h"

static const uint8_t zero[32] = {0};
static const uint8_t one [16] = {1};

/////////////////
/// Utilities ///
/////////////////
static void xor(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
{
    for (unsigned i = 0; i < 32; i++) {
        out[i] = a[i] ^ b[i];
    }
}

static void copy(uint8_t out[32], const uint8_t in[32])
{
    for (unsigned i = 0; i < 32; i++) {
        out[i] = in[i];
    }
}

static void chacha_block(uint8_t       out[64],
                         const uint8_t key[32],
                         const uint8_t nonce[16])
{
    crypto_chacha_ctx ctx;
    crypto_chacha20_init  (&ctx, key, nonce);
    crypto_chacha20_stream(&ctx, out, 64);
}

static int assert_zero(int zero, const char *error)
{
    if (zero != 0) {
        fprintf(stderr, "%s\n", error);
        return -1;
    }
    return 0;
}

static int assert_equal(uint8_t *a, uint8_t *b, size_t n, const char *error)
{
    return assert_zero(memcmp(a, b, n), error);
}

///////////////////////////////////
/// Interactive handshake (XK1) ///
///////////////////////////////////
typedef struct {
    // Key pairs
    uint8_t is[32];  uint8_t IS[32];
    uint8_t ie[32];  uint8_t IE[32];
    uint8_t rs[32];  uint8_t RS[32];
    uint8_t re[32];  uint8_t RE[32];

    // Shared secrets
    uint8_t ee[32];
    uint8_t es[32];
    uint8_t se[32];

    // Symmetric keys
    uint8_t CK1[32];
    uint8_t CK2[32];
    uint8_t CK3[32];
    uint8_t AK2[32];
    uint8_t AK3[32];
    uint8_t EK2[32];
    uint8_t EK3[32];

    // Messages
    uint8_t msg1[32];
    uint8_t msg2[48];
    uint8_t msg3[48];
} test_vectors_xk1;

static void vectors_xk1_fill(test_vectors_xk1 *v,
                             const uint8_t client_sk  [32],
                             const uint8_t server_sk  [32],
                             const uint8_t client_seed[32],
                             const uint8_t server_seed[32])
{
    // Private keys
    copy(v->is, client_sk  );
    copy(v->ie, client_seed);
    copy(v->rs, server_sk  );
    copy(v->re, server_seed);

    // Public keys
    crypto_x25519_public_key(v->IS, v->is);
    crypto_x25519_public_key(v->IE, v->ie);
    crypto_x25519_public_key(v->RS, v->rs);
    crypto_x25519_public_key(v->RE, v->re);

    // Shared secrets
    crypto_x25519(v->ee, v->ie, v->RE);
    crypto_x25519(v->es, v->ie, v->RS);
    crypto_x25519(v->se, v->is, v->RE);

    // Keys
    uint8_t tmp1[32];
    uint8_t tmp2[32];
    crypto_chacha20_H(tmp1, v->ee , zero);
    crypto_chacha20_H(tmp2, zero  , one );
    xor(v->CK1, tmp1, tmp2);
    crypto_chacha20_H(tmp1, v->es , zero);
    crypto_chacha20_H(tmp2, v->CK1, one );
    xor(v->CK2, tmp1, tmp2);
    crypto_chacha20_H(tmp1, v->se , zero);
    crypto_chacha20_H(tmp2, v->CK2, one );
    xor(v->CK3, tmp1, tmp2);
    uint8_t tmp[64];
    chacha_block(tmp, v->CK2, one);
    copy(v->AK2, tmp     );
    copy(v->EK2, tmp + 32);
    chacha_block(tmp, v->CK3, one);
    copy(v->AK3, tmp     );
    copy(v->EK3, tmp + 32);

    // Messages
    crypto_poly1305_ctx ctx;
    uint8_t XIS[32];
    xor(XIS, v->IS, v->EK2);
    copy(v->msg1, v->IE);
    copy(v->msg2, v->RE);
    crypto_poly1305_init  (&ctx, v->AK2);
    crypto_poly1305_update(&ctx, v->RS, 32);
    crypto_poly1305_update(&ctx, v->IE, 32);
    crypto_poly1305_update(&ctx, v->RE, 32);
    crypto_poly1305_final (&ctx, v->msg2 + 32);
    copy(v->msg3, XIS);
    crypto_poly1305_init  (&ctx, v->AK3);
    crypto_poly1305_update(&ctx, v->RS, 32);
    crypto_poly1305_update(&ctx, v->IE, 32);
    crypto_poly1305_update(&ctx, v->RE, 32);
    crypto_poly1305_update(&ctx, XIS  , 32);
    crypto_poly1305_final (&ctx, v->msg3 + 32);
}

static int vectors_xk1_test(test_vectors_xk1 *v,
                             const uint8_t client_sk  [32],
                             const uint8_t server_sk  [32],
                             const uint8_t client_seed[32],
                             const uint8_t server_seed[32])
{
    copy(v->is, client_sk);
    copy(v->rs, server_sk);
    copy(v->ie, client_seed);
    copy(v->re, server_seed);
    crypto_x25519_public_key(v->IS, v->is);
    crypto_x25519_public_key(v->RS, v->rs);

    crypto_kex_ctx client_ctx;
    crypto_kex_ctx server_ctx;
    uint8_t        c_seed[32];  copy(c_seed, client_seed);
    uint8_t        s_seed[32];  copy(s_seed, server_seed);
    crypto_kex_xk1_init_client(&client_ctx, c_seed, client_sk, 0, v->RS);
    crypto_kex_xk1_init_server(&server_ctx, s_seed, server_sk, 0);

    crypto_kex_xk1_1(&client_ctx, v->msg1);
    crypto_kex_xk1_2(&server_ctx, v->msg2, v->msg1);

    u8 client_key[32];
    u8 server_key[32];
    u8 remote_pk [32]; // same as v->IS
    int ok = 0;
    ok |= assert_zero(crypto_kex_xk1_3(&client_ctx, client_key,
                                       v->msg3, v->msg2),
                      "Cannot confirm");
    ok |= assert_zero(crypto_kex_xk1_4(&server_ctx, server_key,
                                       remote_pk, v->msg3),
                      "Cannot accept");
    ok |= assert_equal(client_key, server_key, 32, "Different session keys");
    ok |= assert_equal(remote_pk, v->IS, 32,
                       "Server got the wrong client public key");
    copy(v->EK3, client_key);
    return ok;
}

static int vectors_xk1_compare(const uint8_t client_sk[32],
                               const uint8_t server_sk[32],
                               const uint8_t c_seed   [32],
                               const uint8_t s_seed   [32])
{
    int ok = 0;
    test_vectors_xk1 ref;
    test_vectors_xk1 impl;
    vectors_xk1_fill      (&ref , client_sk, server_sk, c_seed, s_seed);
    ok |= vectors_xk1_test(&impl, client_sk, server_sk, c_seed, s_seed);
    ok |= assert_equal(impl.is  , ref.is  , 32, "is"  );
    ok |= assert_equal(impl.ie  , ref.ie  , 32, "ie"  );
    ok |= assert_equal(impl.rs  , ref.rs  , 32, "rs"  );
    ok |= assert_equal(impl.re  , ref.re  , 32, "re"  );
    ok |= assert_equal(impl.IS  , ref.IS  , 32, "IS"  );
    ok |= assert_equal(impl.RS  , ref.RS  , 32, "RS"  );
    ok |= assert_equal(impl.EK3 , ref.EK3 , 32, "EK3" );
    ok |= assert_equal(impl.msg1, ref.msg1, 32, "msg1");
    ok |= assert_equal(impl.msg2, ref.msg2, 48, "msg2");
    ok |= assert_equal(impl.msg3, ref.msg3, 48, "msg3");
    return ok;
}


static void vectors_xk1_print(const uint8_t client_sk  [32],
                              const uint8_t server_sk  [32],
                              const uint8_t client_seed[32],
                              const uint8_t server_seed[32])
{
    test_vectors_xk1 v;
    vectors_xk1_fill(&v, client_sk, server_sk, client_seed, server_seed);

    printf("Private keys\n");
    printf("------------\n");
    printf("is  : "); print_vector(v.is  , 32);
    printf("ie  : "); print_vector(v.ie  , 32);
    printf("rs  : "); print_vector(v.rs  , 32);
    printf("re  : "); print_vector(v.re  , 32);
    printf("\n");
    printf("Public keys\n");
    printf("-----------\n");
    printf("IS  : "); print_vector(v.IS  , 32);
    printf("IE  : "); print_vector(v.IE  , 32);
    printf("RS  : "); print_vector(v.RS  , 32);
    printf("RE  : "); print_vector(v.RE  , 32);
    printf("\n");
    printf("Shared secrets\n");
    printf("--------------\n");
    printf("ee  : "); print_vector(v.ee  , 32);
    printf("es  : "); print_vector(v.es  , 32);
    printf("se  : "); print_vector(v.se  , 32);
    printf("\n");
    printf("Keys\n");
    printf("----\n");
    printf("CK1 : "); print_vector(v.CK1 , 32);
    printf("CK2 : "); print_vector(v.CK2 , 32);
    printf("CK3 : "); print_vector(v.CK3 , 32);
    printf("AK2 : "); print_vector(v.AK2 , 32);
    printf("AK3 : "); print_vector(v.AK3 , 32);
    printf("EK2 : "); print_vector(v.EK2 , 32);
    printf("EK3 : "); print_vector(v.EK3 , 32);
    printf("\n");
    printf("Messages\n");
    printf("--------\n");
    printf("msg1: "); print_vector(v.msg1, 32);
    printf("msg2: "); print_vector(v.msg2, 48);
    printf("msg3: "); print_vector(v.msg3, 48);
}

/////////////////////////////
/// One way handshake (X) ///
/////////////////////////////
typedef struct {
    // Key pairs
    uint8_t is[32];  uint8_t IS[32];
    uint8_t ie[32];  uint8_t IE[32];
    uint8_t rs[32];  uint8_t RS[32];

    // Shared secrets
    uint8_t es[32];
    uint8_t ss[32];

    // Symmetric Keys
    uint8_t CK1[32];
    uint8_t CK2[32];
    uint8_t AK2[32];
    uint8_t EK1[32];
    uint8_t EK2[32];

    // Messages
    uint8_t msg1[80];
} test_vectors_x;

static void vectors_x_fill(test_vectors_x *v,
                           const uint8_t client_sk  [32],
                           const uint8_t server_sk  [32],
                           const uint8_t client_seed[32])
{
    // Private keys
    copy(v->is, client_sk  );
    copy(v->ie, client_seed);
    copy(v->rs, server_sk  );

    // Public keys
    crypto_x25519_public_key(v->IS, v->is);
    crypto_x25519_public_key(v->IE, v->ie);
    crypto_x25519_public_key(v->RS, v->rs);

    // Exchanges
    crypto_x25519(v->es, v->ie, v->RS);
    crypto_x25519(v->ss, v->is, v->RS);

    // Keys
    uint8_t tmp1[32];
    uint8_t tmp2[32];
    crypto_chacha20_H(tmp1, v->es , zero);
    crypto_chacha20_H(tmp2, zero  , one );
    xor(v->CK1, tmp1, tmp2);
    crypto_chacha20_H(tmp1, v->ss , zero);
    crypto_chacha20_H(tmp2, v->CK1, one );
    xor(v->CK2, tmp1, tmp2);
    uint8_t tmp[64];
    chacha_block(tmp, v->CK1, one);
    copy(v->EK1, tmp + 32);
    chacha_block(tmp, v->CK2, one);
    copy(v->AK2, tmp     );
    copy(v->EK2, tmp + 32);

    // Messages
    crypto_poly1305_ctx ctx;
    uint8_t XIS[32];
    xor(XIS, v->IS, v->EK1);
    copy(v->msg1     , v->IE);
    copy(v->msg1 + 32, XIS  );
    crypto_poly1305_init  (&ctx, v->AK2);
    crypto_poly1305_update(&ctx, v->RS, 32);
    crypto_poly1305_update(&ctx, v->IE, 32);
    crypto_poly1305_update(&ctx, XIS  , 32);
    crypto_poly1305_final (&ctx, v->msg1 + 64);
}

static int vectors_x_test(test_vectors_x *v,
                          const uint8_t client_sk  [32],
                          const uint8_t server_sk  [32],
                          const uint8_t client_seed[32])
{
    copy(v->is, client_sk);
    copy(v->rs, server_sk);
    copy(v->ie, client_seed);
    crypto_x25519_public_key(v->IS, v->is);
    crypto_x25519_public_key(v->RS, v->rs);

    crypto_kex_ctx client_ctx;
    crypto_kex_ctx server_ctx;
    uint8_t        c_seed[32];  copy(c_seed, client_seed);
    crypto_kex_x_init_client(&client_ctx, c_seed, client_sk, 0, v->RS);
    crypto_kex_x_init_server(&server_ctx, server_sk, 0);

    u8 client_key[32];
    u8 server_key[32];
    u8 remote_pk [32]; // same as v->IS
    int ok = 0;
    crypto_kex_x_1(&client_ctx, client_key, v->msg1);
    ok |= assert_zero(crypto_kex_x_2(&server_ctx, server_key,
                                     remote_pk, v->msg1),
                      "Cannot receive");
    ok |= assert_equal(client_key, server_key, 32, "Different session keys");
    ok |= assert_equal(remote_pk, v->IS, 32,
                       "Server got the wrong client public key");
    copy(v->EK2, client_key);
    return ok;
}

static int vectors_x_compare(const uint8_t client_sk[32],
                             const uint8_t server_sk[32],
                             const uint8_t c_seed   [32])
{
    int ok = 0;
    test_vectors_x ref;
    test_vectors_x impl;
    vectors_x_fill      (&ref , client_sk, server_sk, c_seed);
    ok |= vectors_x_test(&impl, client_sk, server_sk, c_seed);
    ok |= assert_equal(impl.is  , ref.is  , 32, "is"  );
    ok |= assert_equal(impl.ie  , ref.ie  , 32, "ie"  );
    ok |= assert_equal(impl.rs  , ref.rs  , 32, "rs"  );
    ok |= assert_equal(impl.IS  , ref.IS  , 32, "IS"  );
    ok |= assert_equal(impl.RS  , ref.RS  , 32, "RS"  );
    ok |= assert_equal(impl.EK2 , ref.EK2 , 32, "EK2" );
    ok |= assert_equal(impl.msg1, ref.msg1, 80, "msg1");
    return ok;
}


static void vectors_x_print(const uint8_t client_sk  [32],
                            const uint8_t server_sk  [32],
                            const uint8_t client_seed[32])
{
    test_vectors_x v;
    vectors_x_fill(&v, client_sk, server_sk, client_seed);

    printf("Private keys\n");
    printf("------------\n");
    printf("is  : "); print_vector(v.is  , 32);
    printf("ie  : "); print_vector(v.ie  , 32);
    printf("rs  : "); print_vector(v.rs  , 32);
    printf("\n");
    printf("Public keys\n");
    printf("-----------\n");
    printf("IS  : "); print_vector(v.IS  , 32);
    printf("IE  : "); print_vector(v.IE  , 32);
    printf("RS  : "); print_vector(v.RS  , 32);
    printf("\n");
    printf("Exchanges\n");
    printf("---------\n");
    printf("es  : "); print_vector(v.es  , 32);
    printf("ss  : "); print_vector(v.ss  , 32);
    printf("\n");
    printf("Keys\n");
    printf("----\n");
    printf("CK1 : "); print_vector(v.CK1 , 32);
    printf("CK2 : "); print_vector(v.CK2 , 32);
    printf("AK2 : "); print_vector(v.AK2 , 32);
    printf("EK1 : "); print_vector(v.EK1 , 32);
    printf("EK2 : "); print_vector(v.EK2 , 32);
    printf("\n");
    printf("Messages\n");
    printf("--------\n");
    printf("msg1: "); print_vector(v.msg1, 80);
}

int main()
{
    const uint8_t client_sk  [32] = {
        0x0D, 0xAB, 0x8B, 0x40, 0xAB, 0x2B, 0x5A, 0x0F,
        0x93, 0x64, 0xA7, 0x28, 0x3E, 0x0B, 0xE9, 0xF5,
        0xCB, 0xF9, 0xC1, 0xBB, 0xBF, 0xD8, 0x77, 0xB9,
        0x5E, 0xB5, 0x36, 0x7A, 0x50, 0x14, 0x6B, 0xBF,
    };
    const uint8_t server_sk  [32] = {
        0x1C, 0x02, 0x2F, 0xD8, 0x72, 0xF0, 0xAB, 0x17,
        0xC8, 0x8D, 0x39, 0x95, 0x1F, 0x38, 0x0E, 0x08,
        0xC8, 0x9B, 0x5E, 0x67, 0x6B, 0xF7, 0x03, 0xB6,
        0x31, 0xAD, 0xCA, 0xB3, 0x0F, 0x41, 0x1D, 0x9C,
    };
    const uint8_t client_seed[32] = {
        0xA8, 0xAB, 0x49, 0x58, 0x18, 0xDA, 0xF8, 0x22,
        0x0E, 0x8E, 0x2C, 0x19, 0x21, 0xF4, 0x90, 0x25,
        0x33, 0xDB, 0x04, 0x75, 0x0B, 0x4A, 0x90, 0x16,
        0x50, 0xA6, 0x84, 0x75, 0x51, 0xFA, 0x31, 0x96,
    };
    const uint8_t server_seed[32] = {
        0x3A, 0x9E, 0x52, 0x80, 0x74, 0x59, 0x5C, 0x18,
        0x3C, 0x52, 0xAB, 0xF5, 0x75, 0xE2, 0x16, 0x3A,
        0x47, 0x31, 0x52, 0x7A, 0x92, 0xE6, 0x0D, 0x18,
        0x73, 0xD7, 0xC3, 0xAF, 0x56, 0xA9, 0x2D, 0x09,
    };

    printf("Testing interactive pattern...\n");
    if (vectors_xk1_compare(client_sk, server_sk, client_seed, server_seed)) {
        fprintf(stderr, "Reference and implementation differ!!\n");
        return -1;
    }
    printf("Testing one way pattern...\n");
    if (vectors_x_compare(client_sk, server_sk, client_seed)) {
        fprintf(stderr, "Reference and implementation differ!!\n");
        return -1;
    }
    printf("\n");
    printf("========================================================\n");
    printf("=== Victory! Implementation passed the test vectors! ===\n");
    printf("========================================================\n");

    printf("\n");
    printf("Interactive pattern\n");
    printf("===================\n\n");
    vectors_xk1_print(client_sk, server_sk, client_seed, server_seed);

    printf("\n");
    printf("One way pattern\n");
    printf("===============\n\n");
    vectors_x_print  (client_sk, server_sk, client_seed);
    return 0;
}
