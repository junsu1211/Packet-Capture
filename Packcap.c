#include <stdio.h>            //basic
#include <time.h>             //저장한 file 이름을 현재 날짜로 하기 위해
#include <stdlib.h>           //malloc 동적할당
#include <string.h>           //memset 초기화
#include <netinet/if_ether.h> //etherrnet 구조체
#include <netinet/ip.h>       //ip header 구조체
#include <netinet/tcp.h>      //tcp header 구조체
#include <netinet/udp.h>      //udp header 구조체
#include <netinet/ip_icmp.h>  //icmp header 구조체
#include <sys/socket.h>       //소켓의 주소 설정 (sockaddr 구조체)
#include <arpa/inet.h>        //network 정보 변환
#include <pthread.h>          //thread
#include <unistd.h>

#define PACKET_SIZE 65536

// 수집된 패킷 필터링
void filtering_packet(unsigned char* buffer, int size);

int main() {
    int raw_socket;
    struct sockaddr_in saddr;
    socklen_t saddr_size = sizeof(saddr);
    unsigned char *buffer = (unsigned char *)malloc(PACKET_SIZE);

    int mainchoice;

    // Raw socket 생성 ETH_P_ALL 설정으로 모든 종류의 패킷 수집
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (raw_socket < 0) {
        perror("Socket 생성에 실패했습니다.");
        return 1;
    }

    char dirname[100];
    //printf("저장할 디렉토리 이름을 설정 : ");
    //scanf("%s",dirname);
    printf("패킷 수집을 시작합니다.\n");
    //printf("%s 디렉토리에 수집된 패킷을 저장합니다.\n",dirname);

    while (1) {

        // 패킷 수신
        int data_size = recvfrom(raw_socket, buffer, PACKET_SIZE, 0, (struct sockaddr *)&saddr, &saddr_size);
        if (data_size < 0) {
            perror("수신에 실패했습니다.");
            return 1;
        }
        // 패킷 필터링 함수 호출
        filtering_packet(buffer, data_size);
    }

    // 소켓과 버퍼 메모리 해제
    close(raw_socket);
    free(buffer);

    return 0;
}

void filtering_packet(unsigned char* buffer, int size){
    // IP 헤더 구조체
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

    // IP 헤더 길이 계산
    unsigned short iphdrlen = iph->ihl * 4;

    // 데이터 시작 위치 계산
    //unsigned char *data = buffer + iphdrlen + tcph->doff * 4;

    // 송신지 및 수신지 IP 주소를 문자열로 변환
    //char source_ip[INET_ADDRSTRLEN];
    //har dest_ip[INET_ADDRSTRLEN];
    //inet_ntop(AF_INET, &(iph->saddr), source_ip, INET_ADDRSTRLEN);
    //inet_ntop(AF_INET, &(iph->daddr), dest_ip, INET_ADDRSTRLEN);

    if(iph->protocol == 6){//TCP인 경우
        // TCP 헤더 구조체
        struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
        if((ntohs(tcph->dest) == 80 || ntohs(tcph->source) == 80) && (ntohs(tcph->dest) != 443 && ntohs(tcph->source) != 443)){
            printf("http 프로토콜 입니다\n");
        }
        else if(ntohs(tcph->dest)==22||ntohs(tcph->source)==22){
            printf("ssh 프로토콜 입니다\n");
        }

    }
    else if(iph->protocol == 17){//UDP인 경우
        // UDP 헤더 구조체
        struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
        if(ntohs(udph->dest)==53||ntohs(udph->source)==53){
            printf("dns 프로토콜 입니다\n");
        }

    }
    else if(iph->protocol == 1){//ICMP인 경우
        printf("icmp 프로토콜 입니다\n");
    }
}