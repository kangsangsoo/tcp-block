#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <cstring>
#include <libnet.h> // 

#include <algorithm>
#include <fstream>
#include "mac.h"
using namespace std;


void usage(void) {
    cout << "syntax : tcp-block <interface> <pattern>\n";
    cout << "sample : tcp-block wlan0 Host: test.gilgil.net\n";
}


struct Param {
	char* dev{0};
	char* pattern{0};
    Mac my_mac;

	bool parse(int argc, char* argv[]) {
        if(argc != 3) return false;
		dev = argv[1];
        pattern = argv[2];
        // my mac 찾는
        // 리눅스의 경우
	    // /sys/class/net/[dev]/address
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

#define FIN 1
#define RST 4
#define FORWARD 1
#define BACKWARD -1

// 재정의함.
struct libnet_ethernet_hdr
{
    Mac  ether_dhost;/* destination ethernet address */
    Mac  ether_shost;/* source ethernet address */
    uint16_t ether_type;                 /* protocol */
};

uint16_t checksum(uint32_t sip, uint32_t dip, uint8_t reserved, uint8_t protocol, uint16_t len) {
    
    
    // warp around
    
    // 2바이트씩

    



}

#define MSG "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n"
#pragma pack(push, 1)
class Packet{
protected:
    libnet_ethernet_hdr eth;
    libnet_ipv4_hdr ip;
    libnet_tcp_hdr tcp;
    unsigned char* payload;

public:
    Packet() {
        
    }

    Packet(libnet_ethernet_hdr* eth_, libnet_ipv4_hdr* ip_, libnet_tcp_hdr* tcp_, int dir, int type) {
        // FIN 이면서 Backward
        
        if(dir == BACKWARD && type == FIN) {
            // eth
            // smac = me
            eth.ether_shost = param.my_mac; 
            // dmac = 받은 패킷의 smac
            eth.ether_dhost = eth_->ether_shost;

            eth.ether_type = eth_->ether_type;
            
            // ip
            memcpy(&ip, ip_, sizeof(ip));

            // len = ip ~ tcp + payload
            ip.ip_len = ip.ip_len + strlen(MSG);

            // til = 128
            ip.ip_ttl = 128;

            // sip, dip
            // backward는 기존의 것을 swap하면 된다.
            ip.ip_src = ip_->ip_dst;
            ip.ip_dst = ip_->ip_src;


            // tcp
            memcpy(&tcp, tcp_, sizeof(tcp));

            // port
            // sprot <-> dport
            tcp.th_sport = tcp_->th_dport;
            tcp.th_dport = tcp_->th_sport;

            // seq
            // 원래 패킷의 ack
            tcp.th_seq = tcp_->th_ack;
            // ack
            // 원래 패킷의 seq + 원래 tcp 데이터 길이
            // ip
            tcp.th_ack = tcp_->th_seq + (ntohs(ip_->ip_len) - (ip_->ip_hl << 2) - (tcp_->th_off << 2));
            // hlen
            
            // 기존이랑 같음

            // flag
            // FIN은 1
            // RST는 4
            tcp.th_flags = FIN;

            // payload
            payload = new unsigned char[strlen(MSG) + 1];
            memcpy(payload, MSG, strlen(MSG));

            // TCP checksum
            // sip, dip, reserved, ip-protocol, tcp length
            // 4 4 1 1 2
            // 2 2 2 2 2
            
            tcp.th_sum = 

            
        }


    }

    ~Packet() {
        delete[] payload;
    }

};
#pragma pack(pop)

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
        
        
        libnet_ethernet_hdr* eth_hdr = (libnet_ethernet_hdr*)packet;
        if(eth_hdr->ether_type != htons(IPv4)) continue;
        
        libnet_ipv4_hdr* ip_hdr = (libnet_ipv4_hdr*)(packet+14);
        
        // tcp인지 체크
        if(ip_hdr->ip_p != TCP) continue;

        libnet_tcp_hdr* tcp_hdr = (libnet_tcp_hdr*)((size_t)ip_hdr + (ip_hdr->ip_hl << 2));

        
        // + payload
        // TCP 포트 확인
        // HTTP:80 
        if(tcp_hdr->th_dport == htons(80) || tcp_hdr->th_sport== htons(80)) {
            const char* tcp_payload = (const char*)((size_t)tcp_hdr + (tcp_hdr->th_off<<2));
            
            // tcp payload에서 "Host: " 찾고
            char* host_ptr = strnstr(tcp_payload, "Host:", len - ((char*)tcp_payload - (char*)packet));
            // host ptr 길이가 5 아니면 6
            if(host_ptr == NULL) continue;
            //cout << string(host_ptr) << endl;

            if(host_ptr[5] == ' ') host_ptr += 6;
            else host_ptr += 5;
            //cout << param.pattern+6 << endl;
            
            // "\r\n" 찾아서 Host 비교
            char* crlf_ptr = strnstr(host_ptr, "\r\n", len - ((char*)host_ptr - (char*)packet));

            if(crlf_ptr == NULL) continue;
            int host_len = crlf_ptr - host_ptr;
            cout << host_len << endl;
            
            if(strncmp(param.pattern+6, host_ptr, strlen(param.pattern+6)) != 0) continue;

            // 처리해줄 코드
            
            // 디버깅 코드
            cout << "match"<< endl;

            // backward는 RST
            Packet packet(eth_hdr, ip_hdr, tcp_hdr, BACKWARD, FIN);

            //
            

            // forward는 FIN
        } 

        // HTTPS: 443
        if(tcp_hdr->th_dport == htons(443) || tcp_hdr->th_sport== htons(443)) {
            const char* tcp_payload = (const char*)((size_t)tcp_hdr + (tcp_hdr->th_off<<2));

            int tcp_len = len - ((size_t)tcp_payload - (size_t)packet);

            if(tcp_len == 0) continue;
            
           
            
            auto res = search(tcp_payload, tcp_payload + tcp_len, param.pattern+6, param.pattern + 6 + strlen(param.pattern+6));

            if(res == (tcp_payload + tcp_len)) continue;
            // 처리
            cout << "match" << endl;
            
        }
        
        


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
