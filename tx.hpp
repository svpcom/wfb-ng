// -*- C++ -*-
//

using namespace std;


class Transmitter
{
public:
    Transmitter(const char* wlan, int k, int m, uint8_t radio_rate, uint8_t radio_port);
    ~Transmitter();
    void send_packet(const uint8_t *buf, size_t size);

private:
    void send_block_fragment(size_t packet_size);
    string wlan;
    pcap_t *ppcap;
    fec_t* fec_p;
    int fec_k;  // RS number of primary fragments in block
    int fec_n;  // RS total number of fragments in block
    uint8_t block_idx;
    uint8_t fragment_idx;
    uint32_t seq;
    uint8_t radio_rate;
    uint8_t radio_port;
    uint8_t** block;
    size_t max_packet_size;
};
