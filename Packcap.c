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

int main() {
    int raw_socket;
    unsigned char buffer[PACKET_SIZE];

    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (raw_socket == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    while (1) {
        ssize_t packet_size = recvfrom(raw_socket, buffer, PACKET_SIZE, 0, NULL, NULL);

        if (packet_size == -1) {
            perror("Packet reception failed");
            exit(EXIT_FAILURE);
        }

        printf("Received a packet of size %zd bytes\n", packet_size);
    }

    close(raw_socket);

    return 0;
}