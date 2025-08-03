#ifndef __ZFEX_STATUS_H
#define __ZFEX_STATUS_H

/**
 * zfex -- fast forward error correction library with Python interface
 *
 * Copyright (C) 2022 Wojciech Migda
 *
 * This file is part of zfex.
 *
 * See README.rst for licensing information.
 */

#ifdef __cplusplus
extern "C"
{
#endif


typedef enum zfex_status_code_e
{
    ZFEX_SC_OK = 0,
    ZFEX_SC_BAD_INPUT_BLOCK_ALIGNMENT,
    ZFEX_SC_BAD_OUTPUT_BLOCK_ALIGNMENT,
    ZFEX_SC_NULL_POINTER_INPUT,
    ZFEX_SC_DECODE_INVALID_BLOCK_INDEX,
} zfex_status_code_t;


#ifdef __cplusplus
}
#endif


#endif /* __ZFEX_STATUS_H */
