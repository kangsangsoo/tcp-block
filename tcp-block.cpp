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

char * strnstr(const char *s, const char *find, size_t slen)
{
	char c, sc;
	size_t len;

	if ((c = *find++) != '\0') {
		len = strlen(find);
		do {
			do {
				if (slen-- < 1 || (sc = *s++) == '\0')
					return (NULL);
			} while (sc != c);
			if (len > slen)
				return (NULL);
		} while (strncmp(s, find, len) != 0);
		s--;
	}

	return ((char *)s);
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

    uint16_t* pseudo_hdr_ = (uint16_t*) &pseudo_hdr;

    // warp around
    uint32_t sum = 0;

    for(int i = 0; i < 6; i++) {
        sum += pseudo_hdr_[i]; 
        //printf("%p + ", pseudo_hdr_[i]);
    }    

    pseudo_hdr_ = (uint16_t*) &tcp_hdr;
    for(int i = 0; i < 10; i++) {
        sum += pseudo_hdr_[i]; 
        if(pseudo_hdr_[i] == NULL) continue;
        //printf("%p + ", pseudo_hdr_[i]);
    }  

    if(payload_len != NULL) {

        pseudo_hdr_ = (uint16_t*) payload;
        for(int i = 0; i < payload_len/2; i++) {
            sum += pseudo_hdr_[i]; 
            if(pseudo_hdr_[i] == NULL) continue;

            //printf("%p + ", pseudo_hdr_[i]);
        } 
        if(payload_len %2 == 1) sum += payload[payload_len-1];
    }


    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    printf("%p\n", ~(uint16_t)sum);
    return ~(uint16_t)sum; 
}

uint16_t ip_checksum(IpHdr ip_hdr) {
    uint32_t sum = 0;
    uint16_t chunks[10];
    ip_hdr.sum_ = 0;
    memcpy(chunks, &ip_hdr, 20);

    for(int i = 0; i < 10; i++) {
        sum += chunks[i];
    }

    sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}


#define FIN 1
#define RST 4
#define ACK 16
#define FORWARD 1
#define BACKWARD -1
unsigned char* construct_packet(EthHdr eth_hdr, IpHdr ip_hdr, TcpHdr tcp_hdr, unsigned char* payload, int payload_len, int direction, int type) {
    void* ptr = malloc(sizeof(eth_hdr) + sizeof(ip_hdr) + sizeof(tcp_hdr) + payload_len);
    if(ptr == nullptr) return nullptr;

    
    if(direction == FORWARD && type == RST) {
        int org_packet_tcp_data_length = ntohs(ip_hdr.len_) - (ip_hdr.hl_ << 2) - (tcp_hdr.hlen_ << 2);
        cout << "org length " << org_packet_tcp_data_length << endl;

        // smac은 my_mac
        // dmac은 그대로
        eth_hdr.test(eth_hdr.dmac_, param.my_mac);

        // ip_len 체크
        // ttl 그대로
        // sip, dip 그대로
        // ip checksum 확인
        ip_hdr.test(5, htons(20+20), ip_hdr.off_, ip_hdr.ttl_, ip_hdr.src_, ip_hdr.dst_);


        // sport, dport 그대로
        // seq = seq + 기존 tcp.data_size
        // ack 그대로
        // hlen 체크
        // flag 체크
        // tcp checksum 확인
        tcp_hdr.test(tcp_hdr.sport_, tcp_hdr.dport_, tcp_hdr.seq_ + htonl(org_packet_tcp_data_length), tcp_hdr.ack_, 5, RST + ACK, 0);
        tcp_hdr.sum_ = tcp_checksum(ip_hdr.src_, ip_hdr.dst_, 0, ip_hdr.p_, htons(20 + payload_len), tcp_hdr, payload, payload_len);

        // tcp-payload 붙이기
    }

     else if(direction == BACKWARD && type == FIN) {
        int org_packet_tcp_data_length = ntohs(ip_hdr.len_) - (ip_hdr.hl_ << 2) - (tcp_hdr.hlen_ << 2);
        // smac은 my_mac
        // dmac은 org.smac
        eth_hdr.test(eth_hdr.smac_, param.my_mac);

        // ip_len 체크
        // ttl = 128
        // sip, dip swap
        // ip checksum 확인
        ip_hdr.test(5, htons(20+20+payload_len), ip_hdr.off_, 137, ip_hdr.dst_, ip_hdr.src_);

        // sport, dport swap
        // ack = seq + 기존 tcp.data_size
        // seq = 기존 ack 
        // hlen 체크
        // flag 체크
        // tcp checksum 확인
        tcp_hdr.test(tcp_hdr.dport_, tcp_hdr.sport_, tcp_hdr.ack_, tcp_hdr.seq_ + htonl(org_packet_tcp_data_length), 5, FIN + ACK, 0);

        tcp_hdr.sum_ = tcp_checksum(ip_hdr.src_, ip_hdr.dst_, 0, ip_hdr.p_, htons(20 + payload_len), tcp_hdr, payload, payload_len);

        

    }

    else if(direction == BACKWARD && type == RST) {
        int org_packet_tcp_data_length = ntohs(ip_hdr.len_) - (ip_hdr.hl_ << 2) - (tcp_hdr.hlen_ << 2);
        // smac은 my_mac
        // dmac은 org.smac
        eth_hdr.test(eth_hdr.smac_, param.my_mac);

        // ip_len 체크
        // ttl = 128
        // sip, dip swap
        // ip checksum 확인
        ip_hdr.test(5, htons(20+20+payload_len), ip_hdr.off_, 137, ip_hdr.dst_, ip_hdr.src_);

        // sport, dport swap
        // ack = seq + 기존 tcp.data_size
        // seq = 기존 ack 
        // hlen 체크
        // flag 체크
        // tcp checksum 확인
        tcp_hdr.test(tcp_hdr.dport_, tcp_hdr.sport_, tcp_hdr.ack_, tcp_hdr.seq_ + htonl(org_packet_tcp_data_length), 5, RST + ACK, 0);

        tcp_hdr.sum_ = tcp_checksum(ip_hdr.src_, ip_hdr.dst_, 0, ip_hdr.p_, htons(20 + payload_len), tcp_hdr, payload, payload_len);



    }



    // memcpy
    memcpy(ptr, &eth_hdr, sizeof(eth_hdr));
    memcpy(ptr+sizeof(eth_hdr), &ip_hdr, sizeof(ip_hdr));
    memcpy(ptr+sizeof(eth_hdr)+sizeof(ip_hdr), &tcp_hdr, sizeof(tcp_hdr));
    memcpy(ptr+sizeof(eth_hdr)+sizeof(ip_hdr)+sizeof(tcp_hdr), payload, payload_len);
    return (unsigned char*)ptr;
}

char MSG[56] = "HTTP/1.1 302 Redirect\r\nLocation: http://warning.or.kr\r\n";


int main(int argc, char* argv[]) {
    if(!param.parse(argc, argv)) {
        usage();
        return -1;
    }

    cout << param.pattern << endl;
    cout << param.dev << endl;
    cout << string(param.my_mac) << endl;
        
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(param.dev, BUFSIZ, 1, 1, errbuf);

    if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", param.dev, errbuf);
		return -1;
	}

    struct pcap_pkthdr* pkheader;
	const u_char* packet;

    while(1) {
        int res = pcap_next_ex(handle, &pkheader, &packet); // res는 패킷 길이

        int len = pkheader->len;

        if(res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return -1;
		}

        // 이더넷 - IP - TCP <- libnet 헤더
        #define IPv4 0x0800
        #define TCP 6
        
        
        // libnet_ethernet_hdr* eth_hdr = (libnet_ethernet_hdr*)packet;
        EthHdr* eth_hdr = (EthHdr*)packet;
        
        if(eth_hdr->type_ != htons(IPv4)) continue;
        
        // libnet_ipv4_hdr* ip_hdr = (libnet_ipv4_hdr*)(packet+14);
        IpHdr* ip_hdr = (IpHdr*)(packet+14);

        // tcp인지 체크
        if(ip_hdr->p_ != TCP) continue;

        // libnet_tcp_hdr* tcp_hdr = (libnet_tcp_hdr*)((size_t)ip_hdr + (ip_hdr->ip_hl << 2));
        TcpHdr* tcp_hdr = (TcpHdr*)((size_t)ip_hdr + (ip_hdr->hl_ << 2));


        
        // + payload
        // TCP 포트 확인
        // HTTP:80 
        if(tcp_hdr->dport_ == htons(80) || tcp_hdr->sport_== htons(80)) {
            const char* tcp_payload = (const char*)((size_t)tcp_hdr + (tcp_hdr->hlen_<<2));
            int tcp_len = len - ((size_t)tcp_payload - (size_t)packet);
            

            auto res = search(tcp_payload, tcp_payload + tcp_len, param.pattern, param.pattern + strlen(param.pattern));

            if(res == (tcp_payload + tcp_len)) continue;
            // pattern을 찾도록 하자.

            
            // 디버깅 코드
            cout << "match"<< endl;

            
            // forward는 FIN
            unsigned char* ptr = construct_packet(*eth_hdr, *ip_hdr, *tcp_hdr, (unsigned char*)MSG, strlen(MSG)+1, BACKWARD, FIN);
            
            int res_ = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(ptr), 14 + 20 + 20 + strlen(MSG)+1);
	
		    if (res_ != 0) {
		    	fprintf(stderr, "pcap_sendpacket return %d error=%s \n", res, pcap_geterr(handle));
		    	return -1;
		    }
            cout << "send packet" << endl;
            free(ptr);
            // backward는 RST
            //Packet packet(eth_hdr, ip_hdr, tcp_hdr, BACKWARD, FIN);

            //
            
            unsigned char* ptr_ = construct_packet(*eth_hdr, *ip_hdr, *tcp_hdr, NULL, NULL, FORWARD, RST);
            
            int res__ = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(ptr_), 14 + 20 + 20);
	
		    if (res__ != 0) {
		    	fprintf(stderr, "pcap_sendpacket return %d error=%s \n", res, pcap_geterr(handle));
		    	return -1;
		    }
            cout << "send packet" << endl;
            free(ptr_);

            
            
        } 

        /*
        // HTTPS: 443
        if(tcp_hdr->dport_ == htons(443) || tcp_hdr->sport_== htons(443)) {
            const char* tcp_payload = (const char*)((size_t)tcp_hdr + (tcp_hdr->hlen_<<2));

            int tcp_len = len - ((size_t)tcp_payload - (size_t)packet);

            if(tcp_len == 0) continue;
            
           
            
            auto res = search(tcp_payload, tcp_payload + tcp_len, param.pattern, param.pattern + strlen(param.pattern));

            if(res == (tcp_payload + tcp_len)) continue;
            // 처리
            cout << "match" << endl;
            
        }
        
        */


        // HTTP면 payload에서 HOST: ~~ 찾고

        // HTTPS: SNI에서 찾는다.
        // 그냥 주소를 찾기 vs
        // 위치 찾아서 하기
        // https://stackoverflow.com/questions/17832592/extract-server-name-indication-sni-from-tls-client-hello

        // checksum
        // https://securitynewsteam.tistory.com/entry/TCP%EC%B2%B4%ED%81%AC%EC%84%AC-%EA%B3%84%EC%82%B0%EB%B0%A9%EB%B2%95
    }

    // HTTP / HTTPS 구분

    // forward는 무조건 RST
    // backward는
    // HTTP는 FIN으로 warning.or.kr로 redirect
    // HTTPS는 RST

    //

    // 


}