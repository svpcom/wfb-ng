#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <cstdint>

extern "C"
{
#include "fec.h"
}


TEST_CASE("FEC", "[!benchmark]")
{
    const int k = 8, n = 12;
    const int block_size = 4096;
    fec_t *fec_p = fec_new(k, n);

    REQUIRE(fec_p != NULL);

    uint8_t *block_enc[n];

    for(int i=0; i < n; i++)
    {
        block_enc[i] = new uint8_t[block_size];
        if( i < k )
        {
            memset(block_enc[i], i, block_size);
        }
    }

    BENCHMARK("test encode")
    {
        fec_encode(fec_p, (const uint8_t**)block_enc, block_enc + k, block_size);
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

    BENCHMARK("test decode")
    {
        fec_decode(fec_p, (const uint8_t**)block_dec_in, block_dec_out, index, block_size);
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
        delete[] block_enc[i];
    }

    fec_free(fec_p);
}
