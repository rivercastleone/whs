#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

/* 이더넷 헤더 */
struct ethheader {
    u_char  ether_dhost[6]; /* 목적지 MAC 주소 */
    u_char  ether_shost[6]; /* 출발지 MAC 주소 */
    u_short ether_type;     /* 프로토콜 유형 (IP, ARP, RARP 등) */
};

/* IP 헤더 */
struct ipheader {
    unsigned char      iph_ihl:4, // IP 헤더 길이
                       iph_ver:4; // IP 버전
    unsigned char      iph_tos; // 서비스 유형
    unsigned short int iph_len; // IP 패킷 길이 (데이터 + 헤더)
    unsigned short int iph_ident; // 식별자
    unsigned short int iph_flag:3, // 단편화 플래그
                       iph_offset:13; // 플래그 오프셋
    unsigned char      iph_ttl; // 생존 시간
    unsigned char      iph_protocol; // 프로토콜 유형
    unsigned short int iph_chksum; // IP 데이터그램 체크섬
    struct  in_addr    iph_sourceip; // 출발지 IP 주소
    struct  in_addr    iph_destip;   // 목적지 IP 주소
};

struct tcp_header {
    unsigned short source_port;    // 출발지 포트
    unsigned short dest_port;      // 목적지 포트
    unsigned int sequence;         // 시퀀스 번호
    unsigned int acknowledge;      // 확인 번호
    unsigned char ns:1;            // NS 플래그 (ECN-nonce 숫자)
    unsigned char reserved_part1:3; // 예약된 비트 필드
    unsigned char data_offset:4;   // 데이터 오프셋 (헤더 길이)
    unsigned char fin:1;           // FIN 플래그 (연결 종료)
    unsigned char syn:1;           // SYN 플래그 (연결 설정)
    unsigned char rst:1;           // RST 플래그 (연결 재설정)
    unsigned char psh:1;           // PSH 플래그 (데이터 푸시)
    unsigned char ack:1;           // ACK 플래그 (확인 응답)
    unsigned char urg:1;           // URG 플래그 (긴급 데이터)
    unsigned char ecn:1;           // ECN 플래그 (명시적 혼잡 표시)
    unsigned char cwr:1;           // CWR 플래그 (혼잡 회피 응답)
    unsigned short window;         // 윈도우 크기
    unsigned short checksum;       // 체크섬
    unsigned short urgent_pointer; // 긴급 포인터
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    // Ethernet 프레임이 IP인 경우 처리
    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800은 IP 유형
        struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        // IP 프로토콜이 TCP인 경우 처리
        if (ip->iph_protocol == 6) { // 6은 TCP를 나타냅니다.
            // IP 헤더의 길이 계산
            int ip_header_length = ip->iph_ihl * 4;
            
            // TCP 헤더 추출
           struct tcp_header *tcp_packet = (struct tcp_header *)(packet + sizeof(struct ethheader) + ip_header_length);
            // 출발지와 목적지 IP 주소 출력
            printf("이더넷 헤더:\n");
            printf("  출발지 MAC 주소: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("  목적지 MAC 주소: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            printf("IP 헤더:\n");
            printf("  출발지 IP 주소: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("  목적지 IP 주소: %s\n", inet_ntoa(ip->iph_destip));

            printf("TCP 헤더:\n");
            printf("  출발지 포트: %d\n", ntohs(tcp_packet->source_port));
            printf("  목적지 포트: %d\n", ntohs(tcp_packet->dest_port));
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // TCP 패킷만 캡처하도록 필터 설정
    bpf_u_int32 net;

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "오류:");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
