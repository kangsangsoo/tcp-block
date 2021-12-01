#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <cstring>

#include <algorithm>
#include <fstream>

#include "mac.h"
#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

using namespace std;

struct Param {
	char* dev{0};
	char* pattern{0};
    Mac my_mac;

	bool parse(int argc, char* argv[]) {
        if(argc != 3) return false;
		dev = argv[1];
        pattern = argv[2];

	    ifstream fin;
	    string path = "/sys/class/net/" + string(dev) +"/address";
	    fin.open(path);
        if (fin.fail()) {
		    cerr << "Error: " << strerror(errno);
            return false;
        }
        string tmp;
	    fin >> tmp;
        my_mac = tmp;

	    fin.close();
        return true;
	}
} param;

void usage(void) {
    cout << "syntax : tcp-block <interface> <pattern>\n";
    cout << "sample : tcp-block wlan0 Host: test.gilgil.net\n";
}

uint16_t tcp_checksum(uint32_t sip, uint32_t dip, uint8_t reserved, uint8_t protocol, uint16_t tcp_len, TcpHdr tcp_hdr, unsigned char* payload, int payload_len) {
    struct Pseudo{
        uint32_t sip_;
        uint32_t dip_;
        uint8_t reserved_;
        uint8_t protocol_;
        uint16_t len;
    } pseudo_hdr;
    pseudo_hdr.sip_ = sip;
    pseudo_hdr.dip_ = dip;
    pseudo_hdr.reserved_ = reserved;
    pseudo_hdr.protocol_ = protocol;
    pseudo_hdr.len = tcp_len;

    uint16_t* ptr = (uint16_t*) &pseudo_hdr;

    // wrap around
    uint32_t sum = 0;

    for(int i = 0; i < 6; i++) {
        sum += ptr[i]; 
    }    

    ptr = (uint16_t*) &tcp_hdr;
    for(int i = 0; i < 10; i++) {
        sum += ptr[i]; 
    }  

    if(payload_len != NULL) {

        ptr = (uint16_t*) payload;
        for(int i = 0; i < payload_len/2; i++) {
            sum += ptr[i]; 
        } 
        if(payload_len %2 == 1) sum += payload[payload_len-1];
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~(uint16_t)sum; 
}


#define FIN 1
#define RST 4
#define ACK 16
#define FORWARD 1
#define BACKWARD -1
char MSG[56] = "HTTP/1.1 302 Redirect\r\nLocation: http://warning.or.kr\r\n";

int send_packet(pcap_t* handle, EthHdr eth_hdr, IpHdr ip_hdr, TcpHdr tcp_hdr, unsigned char* payload, int payload_len, int direction, int type) {
    
    int org_packet_tcp_data_length = ntohs(ip_hdr.len_) - (ip_hdr.hl_ << 2) - (tcp_hdr.hlen_ << 2);

    if(direction == FORWARD) {
        eth_hdr.set(eth_hdr.dmac_, param.my_mac);
        ip_hdr.set(5, htons(20+20), ip_hdr.off_, ip_hdr.ttl_, ip_hdr.src_, ip_hdr.dst_);
        tcp_hdr.set(tcp_hdr.sport_, tcp_hdr.dport_, tcp_hdr.seq_ + htonl(org_packet_tcp_data_length), tcp_hdr.ack_, 5, RST + ACK, 0);
        tcp_hdr.sum_ = tcp_checksum(ip_hdr.src_, ip_hdr.dst_, 0, ip_hdr.p_, htons(20 + payload_len), tcp_hdr, payload, payload_len);
    }

    else if(direction == BACKWARD && type == FIN+ACK) {
        eth_hdr.set(eth_hdr.smac_, param.my_mac);
        ip_hdr.set(5, htons(20+20+payload_len), ip_hdr.off_, 137, ip_hdr.dst_, ip_hdr.src_);
        tcp_hdr.set(tcp_hdr.dport_, tcp_hdr.sport_, tcp_hdr.ack_, tcp_hdr.seq_ + htonl(org_packet_tcp_data_length), 5, FIN + ACK, 0);
        tcp_hdr.sum_ = tcp_checksum(ip_hdr.src_, ip_hdr.dst_, 0, ip_hdr.p_, htons(20 + payload_len), tcp_hdr, payload, payload_len);
    }

    else if(direction == BACKWARD && type == RST+ACK) {
        eth_hdr.set(eth_hdr.smac_, param.my_mac);
        ip_hdr.set(5, htons(20+20), ip_hdr.off_, 137, ip_hdr.dst_, ip_hdr.src_);
        tcp_hdr.set(tcp_hdr.dport_, tcp_hdr.sport_, tcp_hdr.ack_, tcp_hdr.seq_ + htonl(org_packet_tcp_data_length), 5, RST + ACK, 0);
        tcp_hdr.sum_ = tcp_checksum(ip_hdr.src_, ip_hdr.dst_, 0, ip_hdr.p_, htons(20), tcp_hdr, payload, payload_len);
    }

    void* ptr = malloc(sizeof(eth_hdr) + sizeof(ip_hdr) + sizeof(tcp_hdr) + payload_len);
    if(ptr == nullptr) return 0;

    memcpy(ptr, &eth_hdr, sizeof(eth_hdr));
    memcpy(ptr+sizeof(eth_hdr), &ip_hdr, sizeof(ip_hdr));
    memcpy(ptr+sizeof(eth_hdr)+sizeof(ip_hdr), &tcp_hdr, sizeof(tcp_hdr));
    memcpy(ptr+sizeof(eth_hdr)+sizeof(ip_hdr)+sizeof(tcp_hdr), payload, payload_len);
    
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(ptr), sizeof(eth_hdr) + sizeof(ip_hdr) + sizeof(tcp_hdr) + payload_len);
    if (res != 0) {
	    fprintf(stderr, "pcap_sendpacket return %d error=%s \n", res, pcap_geterr(handle));
	    return 0;
    }
    free(ptr);
    cout << "block" << endl;
    return 1;
}



int main(int argc, char* argv[]) {
    if(!param.parse(argc, argv)) {
        usage();
        return -1;
    }
        
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(param.dev, BUFSIZ, 1, 1, errbuf);

    if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", param.dev, errbuf);
		return -1;
	}

    struct pcap_pkthdr* pkheader;
	const u_char* packet;

    while(1) {
        int res = pcap_next_ex(handle, &pkheader, &packet); 
        int len = pkheader->len;

        if(res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return -1;
		}

        #define IPv4 0x0800
        #define TCP 6
                
        EthHdr* eth_hdr = (EthHdr*)packet;
        if(eth_hdr->type_ != htons(IPv4)) continue;
        
        IpHdr* ip_hdr = (IpHdr*)(packet+14);
        if(ip_hdr->p_ != TCP) continue;

        TcpHdr* tcp_hdr = (TcpHdr*)((size_t)ip_hdr + (ip_hdr->hl_ << 2));

        const char* tcp_payload = (const char*)((size_t)tcp_hdr + (tcp_hdr->hlen_<<2));
        int tcp_len = len - ((size_t)tcp_payload - (size_t)packet);
        if(tcp_len == 0) continue;

        if(tcp_hdr->dport_ == htons(80) || tcp_hdr->sport_== htons(80)) {
            auto res = search(tcp_payload, tcp_payload + tcp_len, param.pattern, param.pattern + strlen(param.pattern));
            if(res == (tcp_payload + tcp_len)) continue;

            if(!send_packet(handle, *eth_hdr, *ip_hdr, *tcp_hdr, (unsigned char*)MSG, strlen(MSG)+1, BACKWARD, FIN+ACK)) break;
            if(!send_packet(handle, *eth_hdr, *ip_hdr, *tcp_hdr, NULL, NULL, FORWARD, RST+ACK)) break;
        } 
        
        else if(tcp_hdr->dport_ == htons(443) || tcp_hdr->sport_== htons(443)) {           
            auto res = search(tcp_payload, tcp_payload + tcp_len, param.pattern, param.pattern + strlen(param.pattern));
            if(res == (tcp_payload + tcp_len)) continue;
            
            if(!send_packet(handle, *eth_hdr, *ip_hdr, *tcp_hdr, NULL, NULL, BACKWARD, RST+ACK)) break;
            if(!send_packet(handle, *eth_hdr, *ip_hdr, *tcp_hdr, NULL, NULL, FORWARD, RST+ACK)) break;
        }
    }
}
