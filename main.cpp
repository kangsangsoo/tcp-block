#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <cstring>
#include <libnet.h> // 

using namespace std;


void usage(void) {
    cout << "syntax : tcp-block <interface> <pattern>\n";
    cout << "sample : tcp-block wlan0 Host: test.gilgil.net\n";
}

struct Param {
	char* dev{0};
	char* pattern{0};

	bool parse(int argc, char* argv[]) {
        if(argc != 3) return false;
		dev = argv[1];
        pattern = argv[2];
        return true;
	}
} param;

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

        if(res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return -1;
		}

        // 이더넷 - IP - TCP <- libnet 헤더
        libnet_ethernet_hdr* test2;
        libnet_ipv4_hdr* test;
        libnet_tcp_hdr* test1;
        // + payload

        // IP 포트 확인
        // HTTP:80 
        // HTTPS: 443

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


}
