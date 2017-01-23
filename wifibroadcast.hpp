#ifndef __WIFIBROADCAST_HPP__
#define __WIFIBROADCAST_HPP__

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>
#include <utime.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <endian.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>

#define MAX_PACKET_SIZE 1510
#define MAX_RX_INTERFACES 8

using namespace std;

template<typename ... Args>
string string_format( const std::string& format, Args ... args )
{
    size_t size = snprintf(nullptr, 0, format.c_str(), args ...) + 1; // Extra space for '\0'
    unique_ptr<char[]> buf(new char[ size ]);
    snprintf(buf.get(), size, format.c_str(), args ...);
    return string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
}


/* this is the template radiotap header we send packets out with */

static const uint8_t radiotap_header[] = {
    0x00, 0x00, // <-- radiotap version
    0x0c, 0x00, // <- radiotap header lengt
    0x04, 0x80, 0x00, 0x00, // <-- radiotap present flags
    0x00, // Rate, offset 0x8
    0x00,
    0x18, 0x00
};

//the last byte of the mac address is recycled as a port number
#define SRC_MAC_LASTBYTE 15
#define DST_MAC_LASTBYTE 21

static uint8_t ieee80211_header[] = {
    0x08, 0x01, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x10, 0x86,
};

typedef struct {
    uint8_t block_idx;
    uint8_t fragment_idx;
}  __attribute__ ((packed)) wblock_hdr_t;

typedef struct {
    uint32_t seq;
    uint16_t packet_size;
}  __attribute__ ((packed)) wpacket_hdr_t;


#define MAX_PAYLOAD_SIZE (MAX_PACKET_SIZE - sizeof(radiotap_header) - sizeof(ieee80211_header) - sizeof(wblock_hdr_t) - sizeof(wpacket_hdr_t))
#define MAX_FEC_PAYLOAD  (MAX_PACKET_SIZE - sizeof(radiotap_header) - sizeof(ieee80211_header) - sizeof(wblock_hdr_t))

#endif
