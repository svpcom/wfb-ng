#include <stdio.h>
#include <sodium.h>
#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_session.hpp>
#include "wifibroadcast.hpp"

static const size_t SESSION_MESSAGE_LEN = sizeof(wsession_data_t); // session packet
static const size_t DATA_MESSAGE_LEN = 4096; // data packet
static const size_t AD_LEN = 32;        // Additional data length

static const size_t KEY_LEN = crypto_aead_chacha20poly1305_KEYBYTES;
static const size_t NPUB_LEN = crypto_aead_chacha20poly1305_NPUBBYTES;
static const size_t TAG_LEN = crypto_aead_chacha20poly1305_ABYTES;


TEST_CASE("Chacha20-Poly1305 encryption benchmark", "[benchmark]")
{
    uint8_t key[KEY_LEN];
    uint8_t nonce[NPUB_LEN];
    uint8_t message[DATA_MESSAGE_LEN];
    uint8_t ad[AD_LEN];

    uint8_t ciphertext[DATA_MESSAGE_LEN + TAG_LEN];
    uint8_t decrypted[DATA_MESSAGE_LEN];

    BENCHMARK_ADVANCED("encrypt data packet")(Catch::Benchmark::Chronometer meter)
    {
        randombytes_buf(key, KEY_LEN);
        randombytes_buf(message, DATA_MESSAGE_LEN);
        randombytes_buf(ad, AD_LEN);
        randombytes_buf(nonce, NPUB_LEN);

        meter.measure([&ciphertext, &message, &ad, &nonce, &key]()
            {
                int ret = crypto_aead_chacha20poly1305_encrypt(
                    ciphertext, NULL,
                    message, DATA_MESSAGE_LEN,
                    ad, AD_LEN,
                    NULL, // nsec
                    nonce, key
                    );
                REQUIRE(ret == 0);
                return ret;
            });
    };

    BENCHMARK_ADVANCED("decrypt data packet")(Catch::Benchmark::Chronometer meter)
    {
        randombytes_buf(key, KEY_LEN);
        randombytes_buf(message, DATA_MESSAGE_LEN);
        randombytes_buf(ad, AD_LEN);
        randombytes_buf(nonce, NPUB_LEN);

        int ret = crypto_aead_chacha20poly1305_encrypt(
            ciphertext, NULL,
            message, DATA_MESSAGE_LEN,
            ad, AD_LEN,
            NULL, // nsec
            nonce, key
        );
        REQUIRE(ret == 0);

        meter.measure([&message, &decrypted, &ciphertext, &ad, &nonce, &key]()
            {
                int ret = crypto_aead_chacha20poly1305_decrypt(
                    decrypted, NULL,
                    NULL,
                    ciphertext, DATA_MESSAGE_LEN + TAG_LEN,
                    ad, AD_LEN,
                    nonce, key
                    );
                REQUIRE(ret == 0);

                ret |= memcmp(message, decrypted, DATA_MESSAGE_LEN);
                REQUIRE(ret == 0);
                return ret;
            });

        return ret;
    };
}

TEST_CASE("libsodium crypto_box benchmarks", "[benchmark]")
{
    uint8_t pk_sender[crypto_box_PUBLICKEYBYTES];
    uint8_t sk_sender[crypto_box_SECRETKEYBYTES];
    uint8_t pk_recipient[crypto_box_PUBLICKEYBYTES];
    uint8_t sk_recipient[crypto_box_SECRETKEYBYTES];

    crypto_box_keypair(pk_sender, sk_sender);
    crypto_box_keypair(pk_recipient, sk_recipient);

    uint8_t message[SESSION_MESSAGE_LEN];
    uint8_t ciphertext[SESSION_MESSAGE_LEN + crypto_box_MACBYTES];
    uint8_t decrypted[SESSION_MESSAGE_LEN];
    uint8_t nonce[crypto_box_NONCEBYTES];

    BENCHMARK_ADVANCED("encrypt session packet")(Catch::Benchmark::Chronometer meter)
    {
        randombytes_buf(message, SESSION_MESSAGE_LEN);
        randombytes_buf(nonce, crypto_box_NONCEBYTES);

        meter.measure([&ciphertext, &message, &nonce, &pk_recipient, &sk_sender]()
            {
                int ret = crypto_box_easy(ciphertext, message, SESSION_MESSAGE_LEN,
                                          nonce, pk_recipient, sk_sender);
                REQUIRE(ret == 0);
                return ret;
            });
    };

    BENCHMARK_ADVANCED("decrypt session packet")(Catch::Benchmark::Chronometer meter)
    {
        randombytes_buf(message, SESSION_MESSAGE_LEN);
        randombytes_buf(nonce, crypto_box_NONCEBYTES);

        int ret = crypto_box_easy(ciphertext, message, SESSION_MESSAGE_LEN,
                                  nonce, pk_recipient, sk_sender);
        REQUIRE(ret == 0);

        meter.measure([&message, &decrypted, &ciphertext, &nonce, &sk_recipient, &pk_sender]()
            {
                int ret = crypto_box_open_easy(decrypted, ciphertext,
                                               SESSION_MESSAGE_LEN + crypto_box_MACBYTES, nonce,
                                               pk_sender, sk_recipient);
                REQUIRE(ret == 0);

                ret |= memcmp(message, decrypted, SESSION_MESSAGE_LEN);
                REQUIRE(ret == 0);
                return ret;
            });
        return ret;
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
