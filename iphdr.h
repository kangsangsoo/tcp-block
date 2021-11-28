#pragma once

#include "ip.h"

#pragma pack(push, 1)

struct IpHdr {
    uint8_t hl_:4,    // header length
            v_:4;     // version 
    uint8_t tos_;     // type of service
    uint16_t len_;    // total length
    uint16_t id_;     // identification
    uint16_t off_;    // flag + offset
    uint8_t ttl_;     // time to live
    uint8_t p_;       // protocol
    uint16_t sum_;    // checksum
    Ip src_, dst_;  // source, destination
};

#pragma pack(pop)