// -*- C++ -*-
//

#define sizeof_ieee80211_header 24

class Aggregator
{
public:
    Aggregator(const string &client_addr, int client_port, int k, int n);
    ~Aggregator();
    void process_packet(const uint8_t *buf, size_t size);
private:
    int open_udp_socket(const string &client_addr, int client_port);
    void apply_fec(void);
    void send_packet(int idx);
    int sockfd;
    fec_t* fec_p;
    int fec_k;  // RS number of primary fragments in block
    int fec_n;  // RS total number of fragments in block
    uint8_t block_idx;
    uint8_t send_fragment_idx;
    uint32_t seq;
    uint8_t** fragments;
    uint8_t *fragment_map;
    uint8_t has_fragments;
    bool fragment_lost;
};

class Receiver
{
public:
    Receiver(const char* wlan, int port, Aggregator* agg);
    ~Receiver();
    void loop_iter(void);
    int getfd(void){ return fd; }
private:
    Aggregator *agg;
    int fd;
    pcap_t *ppcap;
};
