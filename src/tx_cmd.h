// Copyright (C) 2024 - 2026 Vasily Evseenko <svpcom@p2ptech.org>

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 3.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#pragma once
#include <stdint.h>

#define CMD_SET_FEC   1
#define CMD_SET_RADIO 2
#define CMD_GET_FEC   3
#define CMD_GET_RADIO 4

typedef struct {
    uint32_t req_id;
    uint8_t cmd_id;
    union {
        struct
        {
            uint8_t k;
            uint8_t n;
        } __attribute__ ((packed)) cmd_set_fec;

        struct
        {
            uint8_t stbc;
            bool ldpc;
            bool short_gi;
            uint8_t bandwidth;
            uint8_t mcs_index;
            bool vht_mode;
            uint8_t vht_nss;
        } __attribute__ ((packed)) cmd_set_radio;
    } __attribute__ ((packed)) u;
} __attribute__ ((packed)) cmd_req_t;


typedef struct {
    uint32_t req_id;
    uint32_t rc;
    union {
        struct
        {
            uint8_t k;
            uint8_t n;
        } __attribute__ ((packed)) cmd_get_fec;

        struct
        {
            uint8_t stbc;
            bool ldpc;
            bool short_gi;
            uint8_t bandwidth;
            uint8_t mcs_index;
            bool vht_mode;
            uint8_t vht_nss;
        } __attribute__ ((packed)) cmd_get_radio;
    } __attribute__ ((packed)) u;
} __attribute__ ((packed)) cmd_resp_t;
