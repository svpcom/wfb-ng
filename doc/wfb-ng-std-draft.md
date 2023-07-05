% WFB-NG Data Transport Standard [Draft]
% Vasily Evseenko <<svpcom@p2ptech.org>>
% Sep 13, 2022

## Introduction

The purpose of this document is to standardize the data transfer protocol
via raw wifi radio over long distances. In this context, "long distance" is the distance over which the standard 802.11 ACK mechanism does not work.

Many areas of robotics require an inexpensive and long-range point-to-point or point-to-multipoint communication channel.

The proposed solution allows you to transmit arbitrary data streams at speeds up to 8mbps (MCS # 1 modulation) over a distance of tens of kilometers
using ordinary wifi adapters that support the transmission of "raw" packets. At the moment, these are adapters based on Realtek RTL8812AU chips.

## Areas of use:

- Communication between robots and ground station
- Communication of amateur satellites (CUBESAT) with the earth
- Digital radio communication on the ground
- ...

## Work principles
The main limitation of the transmission range of standard WiFi is the requirement to receive an ACK packet from the receiver in a strictly defined time interval after transmission.
When the distance between two stations exceeds ~200m, then the receiver does not have time to confirm the receipt of the packet and data transmission becomes impossible.

Some WiFi adapters have a so-called "raw" mode for receiving and transmitting packets.
In "raw" WiFi mode, the adapter can receive and transmit packets bypassing the standard 802.11 protocol stack. In particular, you can turn off the requirements for sending and receiving ACK packets.
In this case, the limitation on the maximum range is removed (the range now depends only on the sensitivity of the receiver and the power of the transmitter).
But requires to make own medium access control layer (MAC layer).

## Protocol description

The protocol supports point-to-point links. But each of two peers can simultaneously participate in an arbitrary number of links.

Each link has:

 - Own set of encryption keys
 - Up to 256 unidirectional data streams.

The last four bytes of the sender's MAC address are used to set the connection membership.
Thus the MAC address has the format: `0x57, 0x42, 0xaa, 0xbb, 0xcc, 0xdd`, where the first two bytes are the protocol header (`'W'`,`'B'`),
then three bytes - the link id and the last byte - the number of the stream inside the link.
First address byte `'W'`(0x57) has two lower bits set which means that address is multicast and locally administred.

1. The initial data transfer quantum is a UDP packet. The contents of the packet is opaque and can be any of:
  - RTP packet with video or audio.
  - Mavlink packet
  - IP tunnel data packet.
  - ...

2. Next, the packet stream is processed by the FEC codec (using [zfec](http://info.iet.unipi.it/~luigi/fec.html) -- Erasure codes based on Vandermonde matrices.)
3. FEC packets are encrypted and authenticated with the aead_chacha20poly1305 stream cipher using the libsodium library
4. The result is transmitted to the air in the form of one WiFi packet.


### Stream allocation scheme:

Down streams (vehicle to GS): 0 - 127

Up streams (GS to vehicle):   128 - 255

Stream ranges:

 * 0 - 15: video streams, 0 is default video stream
 * 16 - 31: mavlink streams, 16 is default mavlink stream
 * 32 - 47: tunnel streams, 32 is default tunnel stream

All other ranges reserved for future use


## Radio packets format

There are two packet types

1. Data packet (`packet_type = 1`, has encrypted and authenticated (using session key) FEC-encoded data)
2. Session packet (`packet_type = 2`, has encrypted and authenticated session parameters and session key, see note below)

Currently only supported FEC type is Reed-Solomon on Vandermonde matrix, but new FEC algorithms can be added in future.

  ``` .c
  // FEC types
  #define WFB_FEC_VDM_RS  0x1  // Reed-Solomon on Vandermonde matrix

  // packet flags
  #define WFB_PACKET_FEC_ONLY 0x1  // Empty packet to close FEC block
  ```

  ``` .c
  static uint8_t ieee80211_header[] = {
      0x08, 0x01, 0x00, 0x00,               // data frame, not protected, from STA to DS via an AP
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // receiver is broadcast
      0x57, 0x42, 0xaa, 0xbb, 0xcc, 0xdd,   // last four bytes will be replaced by channel_id
      0x57, 0x42, 0xaa, 0xbb, 0xcc, 0xdd,   // last four bytes will be replaced by channel_id
      0x00, 0x00,                           // (seq_num << 4) + fragment_num
  };
  ```

  ```
    radiotap_header:
       ieee_80211_header:
         1. Data packet:
            wblock_hdr_t   { packet_type = 1, nonce = (block_idx << 8) + fragment_idx }
              wpacket_hdr_t  { flags, packet_size }  #
                data                                 #
                                                     +-- encrypted and authenticated by session key
         2. Session packet:
            wsession_hdr_t { packet_type = 2, nonce = random() }
              wsession_data_t { epoch, channel_id, fec_type, fec_k, fec_n, session_key } # -- encrypted and authenticated using crypto_box_easy(rx_publickey, tx_secretkey)

    data nonce:  56bit block_idx + 8bit fragment_idx
    session nonce: crypto_box_NONCEBYTES of random bytes
  ```

  ``` .c
    // Network packet headers. All numbers are in network (big endian) format
    // Encrypted packets can be either session key or data packet.

    // Session key packet

    typedef struct {
        uint8_t packet_type; // packet_type = 2
        uint8_t session_nonce[crypto_box_NONCEBYTES];  // random data
    }  __attribute__ ((packed)) wsession_hdr_t;

    typedef struct{
        uint64_t epoch;       // It allow to drop session packets from old epoch
        uint32_t channel_id;  // (link_id << 8) + port_number
        uint8_t fec_type;     // FEC type (WFB_FEC_VDM_RS or other)
        uint8_t k;            // FEC k
        uint8_t n;            // FEC n
        uint8_t session_key[crypto_aead_chacha20poly1305_KEYBYTES];
    } __attribute__ ((packed)) wsession_data_t;

    // Data packet. Embed FEC-encoded data

    typedef struct {
        uint8_t packet_type;  // packet_type = 1
        uint64_t data_nonce;  // data_nonce = (block_idx << 8) + fragment_idx
    }  __attribute__ ((packed)) wblock_hdr_t;

    // Plain data packet after FEC decode

    typedef struct {
        uint8_t flags;
        uint16_t packet_size;
    }  __attribute__ ((packed)) wpacket_hdr_t;

  ```

## Implementation notes
### Reference implementation
[wfb-ng.org](http://wfb-ng.org) -- reference implementation of WFB-NG protocol stack (C + Python/Twisted).

License GPLv3.

### Encryption
WFB-NG encrypts data stream using libsodium.

When TX starts, it generates new session key, encrypts it using public key authenticated encryption (cryptobox) and announce it every SESSION_KEY_ANNOUNCE_MSEC (default 1s).
Session packet encryption and authentication are done using X25519 ECDH key generated from (RX public key, TX secret key) on the TX side and (TX public key, RX secret key) on the RX side.
Data packets encrypted by crypto_aead_chacha20poly1305_encrypt using session key and packet index as nonce.
TX can change FEC settings online, but it must generate a new session key to avoid invalid data on the RX side.

### RX-Ring
Due to multiple RX radios with own internal queues incoming packets can arrive out of order and you need a method to rearrange them.
RX-Ring is a circular buffer, where you store packets, grouped by FEC blocks. It has two parameters: *rx_ring_front* (index of the first allocated FEC block) and
*alloc_size* -- number of allocated blocks. So rx_ring is like a queue of FEC blocks (each block can hold up to N fragments) - you append
new fragments to block(s) in the tail and fetch them from the head.

When you receive a new packet it can belongs to:

1. New FEC block - you need to allocate it in RX ring (do nothing if block was already processed)
2. Already existing FEC block - you need to add it to them (do nothing if packet already processed)

If you successfully decode all fragments from the block then you should yield and remove ALL unfinished blocks before it.

When you allocate a new block you have following choices:

1. Add a new block to rx ring tail.
2. Override a block at rx ring head if rx ring is full.

So you can support invariant that output UDP packets will be always ordered and no duplicates will be inside.

### Mavlink mode
By default WFB-NG encapsulates one source UDP packet to one WiFi packet. But mavlink packets are very small (usually less than 100 bytes) and
send them in separate packets produces too much overhead. You can add optimized mavlink mode.
It will pack mavlink packets into one UDP packet while size < ``MAX_PAYLOAD_SIZE`` and  ``mavlink_agg_in_ms`` is not expired.

### TX FEC timeout
By default WFB-NG doesn't close TX FEC block if less than ``K`` packets was sent and no new packets available.
This can be an issue for interactive protocols or for protocols with variable data stream speed such as mavlink or IP tunnel.
In such cases TX can issue empty packets with ``WFB_PACKET_FEC_ONLY`` flag to close non-empty FEC blocks if no new packets are available in some timeout.
As alternative you can use FEC with ``K=1`` for such streams.
