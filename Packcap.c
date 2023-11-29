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

int http_count = 0;
int ssh_count = 0;
int dns_count = 0;
int icmp_count = 0;

volatile int  stopPacketCapture = 0; // 패킷 수집 쓰레드 종료 여부 검사 플래그

int menuset(){
  int index=0;
   printf("메인 메뉴를 실행합니다......\n");
    printf("--------------메인메뉴--------------\n\n");
    printf("1. 패킷 수집 시작\n");
    printf("2. 패킷 수집 종료\n");
    printf("3. 수집한 패킷이 저장된 경로들 확인하기\n");// 
    printf("4. 프로그램 종료\n\n");
    printf("------------------------------------\n\n");
    printf(">> 숫자를 입력해주세요 : ");

    scanf("%d",&index); // ******예외처리 할것
    return index;
}

void *packetCaptureThread(void *arg) { // 패킷 수집 루프를 실행하는 스레드
    int raw_socket;
    struct sockaddr_in saddr;
    socklen_t saddr_size = sizeof(saddr);
    unsigned char *buffer = (unsigned char *)malloc(PACKET_SIZE);

    // Raw socket 생성 ETH_P_ALL 설정으로 모든 종류의 패킷 수집
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (raw_socket < 0) {
        perror("Socket 생성에 실패했습니다.");
        return NULL;
    }
    // 1번 메뉴 루프
    while (!stopPacketCapture) {
        // 패킷 수신
        int data_size = recvfrom(raw_socket, buffer, PACKET_SIZE, 0, (struct sockaddr *)&saddr, &saddr_size);
        if (data_size < 0) {
            perror("수신에 실패했습니다.");
            return NULL;
        }
        // 패킷 필터링 함수 호출
        filtering_packet(buffer, data_size);
    }
    // 소켓과 버퍼 메모리 해제
    close(raw_socket);
    free(buffer);

    pthread_exit(NULL); // 쓰레드 종료
    return NULL;
}

void getCurrentTime(char *timeStr) {
    time_t t;
    struct tm *tm_info;

    time(&t);
    tm_info = localtime(&t);

    strftime(timeStr, 20, "%Y%m%d%H%M%S", tm_info);
}// 현재 시간을 반환하는 함수

int main() { // 메인 쓰레드
  pathset();
  pthread_t packetCaptureThreadId; // 패킷 캡쳐 쓰레드 생성
    
    // 메인 메뉴 루프
    while (1) {
        // 메뉴 표시 및 선택
        int mainchoice = menuset();
        if (mainchoice == 1){ // 패킷 수집 쓰레드
          printf("\n\n----------------------\n");
          printf(" 패킷 수집을 시작합니다! \n");
          printf("----------------------\n\n\n");
          if (pthread_create(&packetCaptureThreadId, NULL, packetCaptureThread, NULL) != 0) {
          perror("패킷 수집 스레드 생성에 실패했습니다.");
          return 1;
          }
        }
        else if (mainchoice == 2 ) { // 패킷 수집 종료 플래그 설정 -> 패킷 수집 쓰레드에 종료 시그널 ( 강제종료 아님. 받고있던 패킷까지는 다 받고 종료 )
            // 2번 메뉴 또는 4번 메뉴 선택 시 종료
            stopPacketCapture = 1; // 쓰레드 종료 플래그 설정
            printf("\n\n----------------------------------\n");
            printf("패킷 수집 종료...\n 정리 작업중 ... \n잠시만 기다려주세요...\n\n\n");
            printf("----------------------------------\n\n\n");
            if (pthread_join(packetCaptureThreadId, NULL) != 0) { // 쓰레드 종료 대기
                perror("패킷 수집 스레드 종료 대기에 실패했습니다.");
                return 1;
            }
        } else if (mainchoice == 3) {
            // 3번 메뉴 선택 시 저장된 경로 확인
            // ...
        }
        else if (mainchoice == 4){
          break;
        }
    }

    return 0;
}

void filtering_packet(unsigned char* buffer, int size){
    // IP 헤더 구조체
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

    // IP 헤더 길이 계산
    unsigned short iphdrlen = iph->ihl * 4;

    if(iph->protocol == 6){//TCP인 경우
        // TCP 헤더 구조체
        struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
        if((ntohs(tcph->dest) == 80 || ntohs(tcph->source) == 80) && (ntohs(tcph->dest) != 443 && ntohs(tcph->source) != 443)){
            //printf("http 프로토콜 입니다\n");
            printHTTPInfo(buffer,size);
        }
        
        else if(ntohs(tcph->dest)==22||ntohs(tcph->source)==22){
            printf("ssh 프로토콜 입니다\n");
        }

    }
    else if(iph->protocol == 17){//UDP인 경우
        // UDP 헤더 구조체
        struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
        if(ntohs(udph->dest)==53||ntohs(udph->source)==53){
            //printf("dns 프로토콜 입니다\n");
        }

    }
    else if(iph->protocol == 1){//ICMP인 경우
        printf("icmp 프로토콜 입니다\n");
    }
}

void pathset(){ // 디렉토리 경로 및 이름 지정후 생성 함수
    printf("패킷 수집 프로그램을 실행합니다......\n\n");
    printf("패킷을 저장할 디렉토리의 이름을 지어주세요 : ");
    scanf("%s", dirname);

    printf("디렉토리를 생성할 경로를 입력하세요 : ");
    scanf("%s", path);

    snprintf(fullpath, sizeof(fullpath), "%s/%s", path, dirname);

    if(mkdir(fullpath, 0777) == 0 ){
        printf("디렉토리 생성 성공!\n");
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

void printHTTPInfo(const unsigned char *buffer, int size) { // 이부분이 아직안됨

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct tcphdr *tcph = (struct tcphdr *) (buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;

    // source, dest ip 가져오기
    char dest_ipaddress[100];
    inet_ntop(AF_INET,&(iph->daddr),dest_ipaddress,INET_ADDRSTRLEN);
    char source_ipaddress[100];
    inet_ntop(AF_INET,&(iph->saddr),source_ipaddress,INET_ADDRSTRLEN);

    http_count += 1;

        char timeStr[20];
        getCurrentTime(timeStr);
        // 파일명 구성
        char fileName[10000];

        snprintf(fileName, sizeof(fileName), "%s/HTTP NO.%d_%s_%s", http, http_count, dest_ipaddress, source_ipaddress);


        // 파일 열기
        FILE *logfile = fopen(fileName, "a");
        if (logfile == NULL) {
            perror("파일 열기에 실패했습니다.");
            return;
        }
        else{
      fprintf(logfile, "\n\n- - - - - - - - - - - HTTP Packet - - - - - - - - - - - - \n");  

        fprintf(logfile, "\n");
        fprintf(logfile, "TCP Header\n");
        //fprintf(logfile, " | Source IP            : %s\n", source_ipaddress);
        //fprintf(logfile, " | Destination IP       : %s\n", dest_ipaddress);
        fprintf(logfile, " | Source Port          : %u\n", ntohs(tcph->source));
        fprintf(logfile, " | Destination Port     : %u\n", ntohs(tcph->dest));
        fprintf(logfile, " | Sequence Number      : %u\n", ntohl(tcph->seq));
        fprintf(logfile, " | Acknowledge Number   : %u\n", ntohl(tcph->ack_seq));
        fprintf(logfile, " | Header Length        : %d BYTES\n", (unsigned int) tcph->doff * 4);
        fprintf(logfile, " | Acknowledgement Flag : %d\n", (unsigned int) tcph->ack);
        fprintf(logfile, " | Finish Flag          : %d\n", (unsigned int) tcph->fin);
        fprintf(logfile, " | Checksum             : %d\n", ntohs(tcph->check));
        fprintf(logfile, "\n");
        fprintf(logfile, "                        DATA dump                         ");
        fprintf(logfile, "\n");
        fprintf(logfile, "\n- - - - - - - - - - - - - - - - - - - - - -");
        // 파일 닫기
        fclose(logfile);

        //printf("HTTP 패킷 정보를 파일로 저장했습니다.\n");
        }
}
