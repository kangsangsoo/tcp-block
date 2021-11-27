#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <cstring>
#include <libnet.h> // 

#include <algorithm>

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

        if(res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return -1;
		}

        // 이더넷 - IP - TCP <- libnet 헤더
        libnet_ethernet_hdr* eth_hdr = (libnet_ethernet_hdr*)packet;
        libnet_ipv4_hdr* ip_hdr = (libnet_ipv4_hdr*)(packet+14);
        libnet_tcp_hdr* tcp_hdr = (libnet_tcp_hdr*)(ip_hdr+(ip_hdr->ip_hl <<2));

        // + payload
        // TCP 포트 확인
        // HTTP:80 
        if(tcp_hdr->th_dport == 80 || tcp_hdr->th_sport== 80) {
            const char* tcp_payload = (const char*)(tcp_hdr + (tcp_hdr->th_off<<2));
            
            // tcp payload에서 "Host: " 찾고
            char* host_ptr = strnstr(tcp_payload, "Host:", res - ((char*)tcp_payload - (char*)packet));
            // host ptr 길이가 5 아니면 6
            if(host_ptr == NULL) continue;

            if(host_ptr[5] == ' ') host_ptr += 6;
            else host_ptr += 5;

            // "\r\n" 찾아서 Host 비교
            char* crlf_ptr = strnstr(host_ptr, "\r\n", res - ((char*)host_ptr - (char*)packet));

            if(crlf_ptr == NULL) continue;
            int host_len = crlf_ptr - host_ptr;
            
            if(strncmp(param.pattern, host_ptr, strlen(param.pattern)) != 0) continue;

            // 처리해줄 코드
            
            // 디버깅 코드
            cout << host_ptr << endl;
        } 

        // HTTPS: 443
        if(tcp_hdr->th_dport == 443 || tcp_hdr->th_sport== 443) {
            const char* tcp_payload = (const char*)(tcp_hdr + (tcp_hdr->th_off<<2));
            int tcp_len = res - ((char*)tcp_payload - (char*)packet);
            
            auto res = search(tcp_payload, tcp_payload + tcp_len, param.pattern, param.pattern + strlen(param.pattern));

            if(res == tcp_payload + tcp_len) continue;

            // 처리
            
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


}
