# WFB-NG Data Transport Standard [Draft]

Vasily Evseenko <<svpcom@p2ptech.org>>

Jun 20, 2026

## Abstract

This document specifies the WFB-NG data transport protocol: a method for
transferring arbitrary data streams over "raw" IEEE 802.11 radio links across
distances at which the standard 802.11 acknowledgement (ACK) mechanism is not
usable. It defines the on-air packet formats, the stream addressing scheme, the
forward error correction (FEC) and the encryption used to protect the link.

## Status of This Document

This is a draft and may be updated, replaced, or made obsolete by other
documents at any time. It describes the wire format and behaviour of the
reference implementation published at [wfb-ng.org](http://wfb-ng.org).

## 1. Introduction

The purpose of this document is to standardize the data transfer protocol over
raw WiFi radio across long distances. In this context, "long distance" means a
distance over which the standard 802.11 ACK mechanism does not work.

Many areas of robotics require an inexpensive, long-range, point-to-point or
point-to-multipoint communication channel.

The protocol allows arbitrary data streams to be transmitted at rates up to
8 Mbps (MCS 1 modulation) over distances of tens of kilometers using ordinary
WiFi adapters that support the transmission of "raw" packets. At the time of
writing, these are adapters based on the Realtek RTL8812AU and RTL8812EU chips.

### 1.1. Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when,
they appear in all capitals, as shown here.

### 1.2. Terminology

  * **Link** -- a logical association between two peers, identified by a link
    id and protected by its own set of encryption keys.
  * **Stream** -- a unidirectional sequence of data packets within a link,
    identified by a radio port (0-255).
  * **Channel id** -- `(link_id << 8) + radio_port`; the value placed in the
    last four bytes of the source and destination MAC addresses.
  * **FEC block** -- a group of `n` fragments (`k` data fragments and `n - k`
    parity fragments) produced by the FEC encoder.
  * **GS** -- ground station. **Vehicle** -- the remote (airborne) peer.

## 2. Areas of Use

  * Communication between robots and a ground station
  * Communication of amateur satellites (CUBESAT) with the Earth
  * Digital radio communication on the ground
  * ...

## 3. Work Principles

The main limitation on the transmission range of standard WiFi is the
requirement to receive an ACK packet from the receiver within a strictly
defined time interval after transmission. When the distance between two stations
exceeds approximately 200 m (may vary in different implementations), the receiver 
does not have time to confirm receipt of the packet and data transmission
becomes impossible.

Some WiFi adapters provide a so-called "raw" mode for receiving and transmitting
packets. In "raw" mode, the adapter can receive and transmit packets bypassing
the standard 802.11 protocol stack; in particular, the requirement to send and
receive ACK packets can be disabled. This removes the limitation on the maximum
range, which then depends only on the sensitivity of the receiver and the power
of the transmitter, but it requires the protocol to provide its own medium
access control (MAC) layer.

## 4. Protocol Description

The protocol supports point-to-point links. Each of the two peers MAY
simultaneously participate in an arbitrary number of links.

Each link has:

  * Its own set of encryption keys.
  * Up to 256 unidirectional data streams.

The last four bytes of the sender's MAC address identify link membership. The
MAC address therefore has the format `0x57, 0x42, 0xaa, 0xbb, 0xcc, 0xdd`, where
the first two bytes are the protocol header (`'W'`, `'B'`), the next three bytes
are the link id, and the last byte is the stream (radio port) number within the
link. The first address byte, `'W'` (0x57), has its two low-order bits set,
which marks the address as multicast and locally administered.

The transport pipeline is as follows:

1. The initial unit of data transfer is a UDP packet. Its contents are opaque
   and MAY be any of:
   - An RTP packet with video or audio.
   - A MAVLink packet.
   - An IP tunnel data packet.
   - ...

2. The packet stream is processed by the FEC codec (see Section 6).

3. FEC packets are encrypted and authenticated with the
   `aead_chacha20poly1305` cipher using the libsodium library.

4. The result is transmitted on the air as a single WiFi packet.

### 4.1. Stream Allocation Scheme

Down streams (vehicle to GS): 0 - 127

Up streams (GS to vehicle): 128 - 255

Stream ranges:

  * 0 - 15: video streams; 0 is the default video stream.
  * 16 - 31: MAVLink streams; 16 is the default MAVLink stream.
  * 32 - 47: tunnel streams; 32 is the default tunnel stream.

All other ranges are reserved for future use.

## 5. Radio Packet Format

There are two packet types:

1. Data packet (`packet_type = 1`): carries encrypted and authenticated
   (using the session key) FEC-encoded data.
2. Session packet (`packet_type = 2`): carries encrypted and authenticated
   session parameters and the session key (see Section 7).

A session packet MAY carry any number of optional tags. A receiver MUST ignore
all unknown or unused tags.

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
                wsession_data_t { epoch, channel_id,       #
                                  fec_type, fec_k, fec_n,  #
                                  session_key,             #
                                  optional TLV list }      # -- encrypted and authenticated using crypto_box_easy(rx_publickey, tx_secretkey)

    Where TLV list is a list of optional tags with the following format:
         [{tag_id : tag_size : <tag_size bytes of value>}, ... ]

    data nonce:  56bit block_idx + 8bit fragment_idx
    session nonce: crypto_box_NONCEBYTES of random bytes
  ```

All multi-byte numeric fields in the on-air headers MUST be encoded in network
(big-endian) byte order.

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
        uint8_t tags[];       // Optional TLV attributes
    } __attribute__ ((packed)) wsession_data_t;

    // TLV item header
    typedef struct {
        uint8_t id;
        uint16_t len;
        uint8_t value[];
    } __attribute__ ((packed)) tlv_hdr_t;

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

## 6. Forward Error Correction (FEC)

The only FEC type currently defined is Reed-Solomon over a Vandermonde matrix
(`WFB_FEC_VDM_RS`); new FEC algorithms MAY be added in the future and are
negotiated through the `fec_type` field of the session packet. An
implementation MUST NOT decode a data packet whose session advertises an
unknown `fec_type`.

The reference implementation uses zfex (by Wojciech Migda) -- a SIMD-accelerated
implementation of the erasure code originally published as
[zfec](http://info.iet.unipi.it/~luigi/fec.html) (erasure codes based on
Vandermonde matrices). zfex provides SSSE3 (x86) and NEON (ARM) accelerated code
paths that are typically 5-10 times faster than the portable C implementation;
the wire format it produces is identical to zfec and the two are interoperable.

## 7. Implementation Notes

### 7.1. Reference Implementation

[wfb-ng.org](http://wfb-ng.org) -- reference implementation of the WFB-NG
protocol stack (C + Python/Twisted).

License: GPLv3.

### 7.2. Encryption

WFB-NG encrypts the data stream using libsodium.

When a transmitter starts, it generates a new session key, encrypts it using
public-key authenticated encryption (cryptobox), and announces it every
`SESSION_KEY_ANNOUNCE_MSEC` (default 1 s). Session-packet encryption and
authentication use an X25519 ECDH key derived from (RX public key, TX secret
key) on the transmitter side and (TX public key, RX secret key) on the receiver
side. Data packets are encrypted with `crypto_aead_chacha20poly1305_encrypt`
using the session key, with the packet index as the nonce.

A transmitter MAY change FEC settings online, but when it does so it MUST
generate a new session key to avoid presenting invalid data to the receiver.

Because public-key decryption of a session packet is expensive and session
packets are re-announced once per second, a receiver SHOULD cache the result of
the last successfully decrypted session packet and reuse it for subsequent,
identical session announcements, performing the full `crypto_box_open_easy`
operation only when the announced session changes.

### 7.3. Key Derivation From a Password (KDF)

For low-risk purposes it is possible to derive the key pairs from a
user-supplied password.

#### Reference implementation:

```
        unsigned char salt[crypto_pwhash_argon2i_SALTBYTES] = \
            {'w','i','f','i','b','r','o','a','d','c','a','s','t','k','e','y'};
        unsigned char seed[crypto_box_SEEDBYTES * 2];

        if (crypto_pwhash_argon2i
            (seed, sizeof(seed), password, strlen(password), salt,
             crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE, // Low CPU usage
             crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE, // 64MB or RAM is required
             crypto_pwhash_ALG_ARGON2I13) != 0)  // Ensure compatibility with old libsodium versions
        {
            fprintf(stderr, "Unable to derive seed from password\n");
            return 1;
        }
        if (crypto_box_seed_keypair(drone_publickey, drone_secretkey, seed) !=0 ||
            crypto_box_seed_keypair(gs_publickey, gs_secretkey, seed + crypto_box_SEEDBYTES) != 0)
        {
            fprintf(stderr, "Unable to derive keys\n");
            return 1;
        }

```

#### Test vectors:
For the password string `secret password`, the resulting key pairs MUST be:
- `gs.key` (gs sec + drone pub) sha1 checksum: `cb8d52ca7602928f67daba6ba1f308f4cfc88aa7`
- `drone.key` (drone sec + gs pub) sha1 checksum: `7a6ffb44cebc53b4538d20bdcaba8d70c9cf4095`

### 7.4. RX-Ring

Because multiple RX radios with their own internal queues are used, incoming
packets can arrive out of order, and a receiver needs a method to reorder them.

RX-Ring is a circular buffer in which packets are stored, grouped by FEC block.
It has two parameters: *rx_ring_front* (the index of the first allocated FEC
block) and *alloc_size* (the number of allocated blocks). The RX ring behaves
like a queue of FEC blocks (each block holding up to `n` fragments): new
fragments are appended to block(s) at the tail and fetched from the head.

A newly received packet belongs to either:

1. A new FEC block -- the receiver allocates it in the RX ring (and does nothing
   if the block was already processed); or
2. An already existing FEC block -- the receiver adds the fragment to that block
   (and does nothing if the packet was already processed).

When all fragments of a block have been successfully decoded, the receiver MUST
yield that block and remove ALL unfinished blocks ahead of it.

When allocating a new block, the receiver has the following choices:

1. Append a new block to the RX ring tail; or
2. Overwrite the block at the RX ring head if the RX ring is full.

This maintains the invariant that output UDP packets are always ordered and
contain no duplicates.

### 7.5. MAVLink Mode

By default WFB-NG encapsulates one source UDP packet in one WiFi packet.
However, MAVLink packets are very small (usually less than 100 bytes), and
sending each in a separate packet produces too much overhead. An optimized
MAVLink mode MAY be used: it packs MAVLink packets into one UDP packet while the
size is less than `MAX_PAYLOAD_SIZE` and the `mavlink_agg_in_ms` timeout has not
expired.

### 7.6. TX FEC Timeout

By default WFB-NG does not close a TX FEC block while fewer than `k` packets
have been sent and no new packets are available. This can be a problem for
interactive protocols or for protocols with a variable data rate, such as
MAVLink or the IP tunnel. In such cases the transmitter MAY emit empty packets
with the `WFB_PACKET_FEC_ONLY` flag to close a non-empty FEC block when no new
packets are available within some timeout. As an alternative, FEC with `k = 1`
MAY be used for such streams.

### 7.7. Injection Retry

A "raw" WiFi adapter MAY transiently refuse to accept a frame for injection
(for example, when its internal TX queue is full). To improve delivery on the
custom MAC layer, a transmitter MAY retry injection of a frame a configurable
number of times, waiting a configurable delay between attempts, before counting
the frame as dropped. Retrying injection only affects the local handoff to the
adapter; it does not change the on-air packet format and is transparent to the
receiver.
