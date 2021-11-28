#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

#pragma pack(push, 1)

struct Packet{
    EthHdr eth_hdr_;
    IpHdr ip_hdr_;
    TcpHdr tcp_hdr_;

};

#pragma pack(pop)
