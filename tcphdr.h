#pragma once

#include <cstdint>

#pragma pack(push, 1)

struct TcpHdr {
    uint16_t sport_;    // source port
    uint16_t dport_;    // destination port
    uint32_t seq_;      // sequence number
    uint32_t ack_;      // acknowledgement number
    uint8_t x2_:4,      // unused
            hlen_:4;    // header length
    uint8_t flags_;     // flags
    uint16_t win_;      // window size
    uint16_t sum_;      // checksum
    uint16_t urp_;      // urgent pointer
};

#pragma pack(pop)