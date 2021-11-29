#pragma once

#include "ip.h"
#include <cstring>

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

    void test(uint8_t hl, uint16_t len, uint16_t off, uint8_t ttl, Ip src, Ip dst) {
        this->hl_ = hl;
        this->len_ = len;
        this->off_ = off;
        this->ttl_ = ttl;
        this->src_ = src;
        this->dst_ = dst;

        checksum();
    } 

    void checksum(void) {
        uint32_t sum = 0;
        uint16_t chunks[10];
        this->sum_ = 0;
        memcpy(chunks, this, 20);

        for(int i = 0; i < 10; i++) {
            sum += chunks[i];
        }

        sum = (sum & 0xffff) + (sum >> 16);
        this->sum_ = ~(uint16_t)sum;
    }
};

#pragma pack(pop)