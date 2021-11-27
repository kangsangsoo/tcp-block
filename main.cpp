#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <cstring>
#include <libnet.h> // 

#include <algorithm>
#include <ifstream>
using namespace std;


void usage(void) {
    cout << "syntax : tcp-block <interface> <pattern>\n";
    cout << "sample : tcp-block wlan0 Host: test.gilgil.net\n";
}


struct Param {
	char* dev{0};
	char* pattern{0};
    uint8_t my_mac[6] {0};

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
#define RST 2
#define FORWARD 3
#define BACKWARD 4

#pragma pack(push, 1)
class Packet{
protected:
    libnet_ethernet_hdr eth;
    libnet_ipv4_hdr ip;
    libnet_tcp_hdr tcp;
    unsigned char* payload;

    Packet() {

    }

    Packet(libnet_ethernet_hdr* eth_, libnet_ipv4_hdr* ip_, libnet_tcp_hdr* tcp_, int dir, int type) {
        // FIN 이면서 Backward
        
        if(dir == BACKWARD && type == FIN) {
            // eth
            // smac = me
            eth.ether_shost =
            // dmac = 받은 패킷의 smac

            // ip


            // tcp    
        }


    }

    ~Packet() {
        free(payload);
    }

}
#pragma pack(pop)

int main(int argc, char* argv[]) {
    if(!param.parse(argc, argv)) {
        usage();
        return -1;
    }


    cout << param.pattern << endl;
    cout << param.dev << endl;
        
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
