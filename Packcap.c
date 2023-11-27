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
#include <sys/stat.h>

#define PACKET_SIZE 65536

// 수집된 패킷 필터링
void filtering_packet(unsigned char* buffer, int size);
void pathset();
void printHTTPInfo(const unsigned char* buffer,int size);

char path[50];
char dirname[50];
char fullpath[120];

char http[200];
char ssh[200];
char dns[200];
char icmp[200];


void getCurrentTime(char *timeStr) {
    time_t t;
    struct tm *tm_info;

    time(&t);
    tm_info = localtime(&t);

    strftime(timeStr, 20, "%Y%m%d%H%M%S", tm_info);
}// 현재 시간을 반환하는 함수

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

    
    pathset(); // 디렉토리의 경로 및 이름 설정 함수

    printf("패킷 수집을 시작합니다.\n");
    //printf("%s 디렉토리에 수집된 패킷을 저장합니다.\n",dirname);
    int count=0;
    while (1) {

        // 패킷 수신
        int data_size = recvfrom(raw_socket, buffer, PACKET_SIZE, 0, (struct sockaddr *)&saddr, &saddr_size);
        if (data_size < 0) {
            perror("수신에 실패했습니다.");
            return 1;
        }
        // 패킷 필터링 함수 호출
        filtering_packet(buffer, data_size);
        count++;
        if(count > 100)
          break;
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
            printHTTPInfo(buffer, size);
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

void pathset(){ // 디렉토리 경로 및 이름 지정후 생성 함수

    printf("디렉토리의 이름을 입력하세요 : ");
    scanf("%s", dirname);

    printf("디렉토리를 생성할 경로를 입력하세요 : ");
    scanf("%s", path);

    snprintf(fullpath, sizeof(fullpath), "%s/%s", path, dirname);

    if(mkdir(fullpath, 0777) == 0 ){
        printf("디렉토리 생성 성공!");
        snprintf(http, sizeof(http), "%s/%s", fullpath, "http");
        mkdir(http, 0777); // http 디렉토리 생성
        snprintf(ssh, sizeof(ssh), "%s/%s", fullpath, "ssh");
        mkdir(ssh, 0777); // ssh 디렉토리 생성
        snprintf(dns, sizeof(dns), "%s/%s", fullpath, "dns");
        mkdir(dns, 0777); // dns 디렉토리 생성
        snprintf(icmp, sizeof(icmp), "%s/%s", fullpath, "icmp");
        mkdir(icmp, 0777); // icmp 디렉토리 생성
    }
    else{
        printf("디렉토리 생성 실패");
        perror("Error");
    }

}

void printHTTPInfo(const unsigned char *buffer, int size) {
    // HTTP 헤더 검출을 위한 간단한 체크
    const char *httpCheck = "HTTP";
    if (strstr((const char *)buffer, httpCheck) != NULL) {
        // 현재 날짜 및 시간 정보를 얻어옴
        char timeStr[20];
        getCurrentTime(timeStr);

        // 파일명 구성
        char fileName[300];
        snprintf(fileName, sizeof(fileName), "%s/%s_%s%s", fullpath, "http", "http_packet", timeStr);

        // 파일 열기
        FILE *file = fopen(fileName, "a");
        if (file == NULL) {
            perror("파일 열기에 실패했습니다.");
            return;
        }

        // HTTP 헤더가 시작하는 위치를 찾음
        const char *httpHeader = strstr((const char *)buffer, "\r\n\r\n");
        if (httpHeader != NULL) {
            // HTTP 버전 정보 출력
            fprintf(file, "HTTP Version: %.*s\n", 8, httpHeader);
            
            // 상태 코드 및 설명 출력
            const char *statusLineEnd = strchr(httpHeader, '\r');
            if (statusLineEnd != NULL) {
                fprintf(file, "Status Line: %.*s\n", (int)(statusLineEnd - httpHeader), httpHeader);
            }

            // HTTP 헤더의 나머지 부분 출력
            fprintf(file, "HTTP Headers:\n%s", httpHeader);

            // HTTP 페이로드 부분 출력
            const char *httpPayload = httpHeader + strlen(httpHeader) + 4; // "\r\n\r\n" 이후의 위치
            fprintf(file, "HTTP Payload:\n%s", httpPayload);
        }

        // 파일 닫기
        fclose(file);

        printf("HTTP 패킷 정보를 파일로 저장했습니다.\n");
    }
}
