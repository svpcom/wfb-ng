#include <stdio.h>
#include <sodium.h>
#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_session.hpp>

static const size_t MESSAGE_LEN = 4096; // packet
static const size_t AD_LEN = 32;        // Additional data length

static const size_t KEY_LEN = crypto_aead_chacha20poly1305_KEYBYTES;
static const size_t NPUB_LEN = crypto_aead_chacha20poly1305_NPUBBYTES;
static const size_t TAG_LEN = crypto_aead_chacha20poly1305_ABYTES;


TEST_CASE("Chacha20-Poly1305 encryption benchmark", "[benchmark]")
{
    uint8_t key[KEY_LEN];
    uint8_t nonce[NPUB_LEN];
    uint8_t message[MESSAGE_LEN];
    uint8_t ad[AD_LEN];

    uint8_t ciphertext[MESSAGE_LEN + TAG_LEN];
    uint8_t decrypted[MESSAGE_LEN];

    randombytes_buf(key, KEY_LEN);
    randombytes_buf(nonce, NPUB_LEN);
    randombytes_buf(message, MESSAGE_LEN);
    randombytes_buf(ad, AD_LEN);

    BENCHMARK("encrypt packet")
    {
        int ret = crypto_aead_chacha20poly1305_encrypt(
            ciphertext, NULL,
            message, MESSAGE_LEN,
            ad, AD_LEN,
            NULL, // nsec
            nonce, key
        );
        REQUIRE(ret == 0);
    };

    BENCHMARK("decrypt packet")
    {
        int ret = crypto_aead_chacha20poly1305_decrypt(
            decrypted, NULL,
            NULL,
            ciphertext, MESSAGE_LEN + TAG_LEN,
            ad, AD_LEN,
            nonce, key
        );
        REQUIRE(ret == 0);

        ret = memcmp(message, decrypted, MESSAGE_LEN);
        REQUIRE(ret == 0);
    };
}

int main(int argc, char* argv[])
{
    Catch::Session session;

    if (sodium_init() < 0)
    {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }

#if ((defined __x86_64__) || (defined __i386__))
    printf("libsodium runtime accelerations:\n---\n");
    printf("SSE2:      %s\n", sodium_runtime_has_sse2()     ? "yes" : "no");
    printf("SSSE3:     %s\n", sodium_runtime_has_ssse3()    ? "yes" : "no");
    printf("SSE4.1:    %s\n", sodium_runtime_has_sse41()    ? "yes" : "no");
    printf("AVX:       %s\n", sodium_runtime_has_avx()      ? "yes" : "no");
    printf("AVX2:      %s\n", sodium_runtime_has_avx2()     ? "yes" : "no");
    printf("AVX512F:   %s\n", sodium_runtime_has_avx512f()  ? "yes" : "no");
    printf("---\n");
#endif

    return session.run(argc, argv);
}
