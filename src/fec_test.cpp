#include <stdio.h>
#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_session.hpp>
#include <cstdint>
#include <stdlib.h>

#include "zfex.h"


TEST_CASE("FEC benchmark", "[benchmark]")
{
    const int k = 8, n = 12;
    const int block_size = 4095; // test non-multiple simd size
    fec_t *fec_p;

    fec_new(k, n, &fec_p);

    REQUIRE(fec_p != NULL);

    uint8_t *block_enc[n];

    for(int i=0; i < n; i++)
    {
        int rc = posix_memalign((void**)&block_enc[i], ZFEX_SIMD_ALIGNMENT, ZFEX_ROUND_UP_SIMD(block_size));
        assert(rc == 0);

        if( i < k )
        {
            memset(block_enc[i], i, block_size);
        }
    }

    BENCHMARK("encode block")
    {
        zfex_status_code_t rc = fec_encode_simd(fec_p, (const uint8_t**)block_enc, block_enc + k, block_size);
        REQUIRE(rc == ZFEX_SC_OK);
    };

    uint8_t* block_dec_in[k];
    uint8_t* block_dec_out[n-k];
    unsigned index[k];

    for(int i = 0; i < k; i++)
    {
        if( i < 2*k - n )
        {
            block_dec_in[i] = block_enc[i];
            index[i] = i;
        } else
        {
            block_dec_in[i] = block_enc[i + n - k];
            index[i] = i + n - k;
            block_dec_out[i - 2 * k + n] = block_enc[i];
            memset(block_enc[i], 0, block_size);
        }
    }

    BENCHMARK("decode block")
    {
        zfex_status_code_t rc = fec_decode_simd(fec_p, (const uint8_t**)block_dec_in, block_dec_out, index, block_size);
        REQUIRE(rc == ZFEX_SC_OK);
    };

    for(int i=0; i < k; i++)
    {
        for(int j=0; j < block_size; j++)
        {
            REQUIRE(block_enc[i][j] == i);
        }
    }

    for(int i=0; i < n; i++)
    {
        free(block_enc[i]);
    }

    fec_free(fec_p);
}

int main(int argc, char* argv[])
{
    Catch::Session session;

    printf("FEC acceleration: %s\n", zfex_opt);
    return session.run(argc, argv);
}
