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
#include <dirent.h>

pthread_mutex_t Mutex = PTHREAD_MUTEX_INITIALIZER;
#define PACKET_SIZE 65536

// 수집된 패킷 필터링
void filtering_packet(unsigned char* buffer, int size);
void pathset();
void printHTTPInfo(const unsigned char* buffer,int size);
void printSSHInfo(const unsigned char* buffer, int size);
void printDNSInfo(const unsigned char *buffer, int size);
void printICMPInfo(const unsigned char *buffer, int size);
void LogData(const unsigned char *buffer, int size,FILE *logfile);

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
int key = 1;
volatile int  stopPacketCapture = 0; // 패킷 수집 쓰레드 종료 여부 검사 플래그

int compareNames(const void *a, const void *b) {
    const char *strA = *(const char **)a;
    const char *strB = *(const char **)b;

    // "NO." 다음의 숫자 부분을 추출하여 비교
    int numA = atoi(strstr(strA, "NO.") + 3);
    int numB = atoi(strstr(strB, "NO.") + 3);

    return numA - numB;
}

int menuset(){
   int index=0;
   printf("메인 메뉴를 실행합니다......\n");
   sleep(1);
    printf("--------------메인메뉴--------------\n\n");
    printf("1. 패킷 수집 시작\n");
    printf("2. 패킷 수집 종료\n");
    printf("3. 패킷 정보 확인\n");// 
    printf("4. 프로그램 종료\n\n");
    printf("------------------------------------\n\n");
    printf(">> 숫자를 입력해주세요 : ");

    scanf("%d",&index); // ******예외처리 할것
    return index;
}

void listFiles(const char *path) { // 경로 내의 파일 목록 출력 함수
   DIR *dir;
    struct dirent *entry;
    int count = 0;

    // 디렉토리 열기
    dir = opendir(path);
    // 디렉토리 열기에 실패한 경우
    if (dir == NULL) {
        perror("디렉토리를 찾을 수 없습니다.");
        return;
    }

    // 디렉토리 내부의 파일 개수 세기
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            count++;
        }
    }

    // 다시 디렉토리를 열어서 파일 이름들을 배열에 저장
    closedir(dir);
    dir = opendir(path);

    if (dir == NULL) {
        perror("디렉토리를 찾을 수 없습니다.");
        return;
    }

    char **fileNames = (char **)malloc(count * sizeof(char *));
    int index = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            fileNames[index] = strdup(entry->d_name);
            index++;
        }
    }

    // 파일 이름들을 정렬
    qsort(fileNames, count, sizeof(char *), compareNames);

    // 정렬된 파일 이름들을 출력
    for (int i = 0; i < count; i++) {
        printf("%s\n", fileNames[i]);
        free(fileNames[i]);
    }

    free(fileNames);
    int countsum = http_count + dns_count + ssh_count + icmp_count;
     printf("--------------------------------------\n");
      printf("수집된 총 패킷 개수 : %d\n",countsum);
      printf("수집된 HTTP 패킷 개수 : %d\n",http_count);
      printf("수집된 SSH  패킷 개수 : %d\n",ssh_count);
      printf("수집된 DNS  패킷 개수 : %d\n",dns_count);
      printf("수집된 ICMP 패킷 개수 : %d\n",icmp_count);
      printf("-------------------------------------\n");
    // 디렉토리 닫기
    closedir(dir);
}

void viewFile(const char *path, const char *filename) { // 파일 열람 함수
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/%s", path, filename);  
    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
      perror("존재하지 않는 파일입니다...\n");
      return;
    }
    printf("\nContent of %s:\n", filename);
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
      printf("%s", buffer);
    }
    fclose(file);
    return;
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
        pthread_mutex_lock(&Mutex); // 뮤텍스 획득
        filtering_packet(buffer, data_size);
        pthread_mutex_unlock(&Mutex); // 뮤텍스 해제
    }
    // 소켓과 버퍼 메모리 해제
    close(raw_socket);
    free(buffer);

    pthread_exit(NULL); // 쓰레드 종료
    return NULL;
}

int main() { // 메인 쓰레드
  pathset();
  pthread_t packetCaptureThreadId; // 패킷 캡쳐 쓰레드 생성
  char viewF[50];  // 파일 이름 입력 배열
    // 메인 메뉴 루프
    while (1) {
        // 메뉴 표시 및 선택
        int mainchoice = menuset();
        if (mainchoice == 1){ // 패킷 수집 쓰레드
          //stopPacketCapture = 0; // 쓰레드 종료 플래그의 부정
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
            printf("패킷 수집 종료...\n 정리 작업중 ... \n잠시만 기다려주세요...\n");
            printf("----------------------------------\n\n\n");
            if (pthread_join(packetCaptureThreadId, NULL) != 0) { // 쓰레드 종료 대기
                printf("패킷 수집 스레드 종료 대기에 실패했습니다.");
                return 1;
            }
            stopPacketCapture = 0; // 다시 쓰레드 종료 플래그
        } else if (mainchoice == 3) {
          int sele=0;
            // 3번 메뉴 선택 시 저장된 경로 확인
            // ...
            printf("현재 패킷이 저장된 경로 : %s\n",fullpath);
            printf("확인할 프로토콜의 번호를 선택하세요 \n");
            printf("---------------------------------\n");
            printf("1. http\n2. ssh\n3. dns\n4. icmp\n");
            printf("---------------------------------\n\n");
            printf(">>");
            
            scanf("%d",&sele); // 내부 프로토콜들 입력
            if(sele == 1){
              pthread_mutex_lock(&Mutex);
              listFiles(http); // 파일 출력
              printf("\n\n열람할 파일명을 입력하세요\n");
              printf(">>");
              scanf("%s", viewF);
              viewFile(http,viewF);     
              pthread_mutex_unlock(&Mutex);     
            }
            else if(sele == 2){
              pthread_mutex_lock(&Mutex);
              listFiles(ssh); // 파일 출력
              printf("\n\n열람할 파일명을 입력하세요\n");
              printf(">>");
              scanf("%s", viewF);
              viewFile(ssh,viewF); 
               pthread_mutex_unlock(&Mutex);
            }
            else if(sele == 3){
              pthread_mutex_lock(&Mutex);
              listFiles(dns); // 파일 출력
               printf("\n\n열람할 파일명을 입력하세요\n");
              printf(">>");
              scanf("%s", viewF);
              viewFile(dns,viewF); 
             pthread_mutex_unlock(&Mutex);
            }
            else if(sele == 4){
             pthread_mutex_lock(&Mutex);
              listFiles(icmp); // 파일 출력
               printf("\n\n열람할 파일명을 입력하세요\n");
              printf(">>");
              scanf("%s", viewF);
              viewFile(icmp,viewF); 
              pthread_mutex_unlock(&Mutex);
            }
            else {
              printf("번호를 정확히 입력해 주세요");
            }
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
            printHTTPInfo(buffer,size);
        }
        
        else if(ntohs(tcph->dest)==22||ntohs(tcph->source)==22){
            printSSHInfo(buffer,size);
        }

    }
    else if(iph->protocol == 17){//UDP인 경우
        // UDP 헤더 구조체
        struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
        if(ntohs(udph->dest)==53||ntohs(udph->source)==53){
          printDNSInfo(buffer,size);
        }

    }
    else if(iph->protocol == 1){//ICMP인 경우
      printICMPInfo(buffer,size);
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
        printf("디렉토리 생성 실패\n\n ");
        exit(1);
    }

}

void printHTTPInfo(const unsigned char *buffer, int size) { // 이부분이 아직안됨

    unsigned short iphdrlen;
    struct ethhdr *ethHeader = (struct ethhdr *)buffer;

    struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct tcphdr *tcph = (struct tcphdr *) (buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof(struct tcphdr);

        // source, dest ip 가져오기
    char dest_ipaddress[100];
    inet_ntop(AF_INET,&(iph->daddr),dest_ipaddress,INET_ADDRSTRLEN);
    char source_ipaddress[100];
    inet_ntop(AF_INET,&(iph->saddr),source_ipaddress,INET_ADDRSTRLEN);

        http_count += 1;

        // 파일명 구성
        char fileName[1000];
        snprintf(fileName, sizeof(fileName), "%s/NO.%d_%s->%s", http, http_count, source_ipaddress,dest_ipaddress);

        // 파일 열기
        FILE *logfile = fopen(fileName, "a");
        if (logfile == NULL) {
            printf("파일 열기에 실패했습니다.");
            return;
        }
        else{
          fprintf(logfile, "\n\n- - - - - - - - - - - HTTP Packet - - - - - - - - - - - - \n\n");
          fprintf(logfile, "Ehternet Header\n\n");
          fprintf(logfile, " | Destination MAC      : %02X:%02X:%02X:%02X:%02X:%02X\n",
          ethHeader->h_dest[0],ethHeader->h_dest[1],ethHeader->h_dest[2],
          ethHeader->h_dest[3],ethHeader->h_dest[4],ethHeader->h_dest[5]);
          fprintf(logfile, " | Source MAC           : %02X:%02X:%02X:%02X:%02X:%02X\n",
          ethHeader->h_source[0],ethHeader->h_source[1],ethHeader->h_source[2],
          ethHeader->h_source[3],ethHeader->h_source[4],ethHeader->h_source[5]);
          fprintf(logfile, " | Ethernet Type        : %04X\n\n", ntohs(ethHeader->h_proto));
          fprintf(logfile, "IP Header\n\n");
          fprintf(logfile, " | IP Version           : %d\n", (unsigned int)iph->version);
	        fprintf(logfile, " | IP Header Length     : %d Bytes\n", ((unsigned int)(iph->ihl)) * 4);
	        fprintf(logfile, " | Type Of Service      : %d\n", (unsigned int)iph->tos);
	        fprintf(logfile, " | IP Total Length      : %d  Bytes (FULL SIZE)\n", ntohs(iph->tot_len));
	        fprintf(logfile, " | TTL                  : %d\n", (unsigned int)iph->ttl);
	        fprintf(logfile, " | Protocol             : %d\n", (unsigned int)iph->protocol);
	        fprintf(logfile, " | Checksum             : %d\n", ntohs(iph->check));
          fprintf(logfile, " | Source IP            : %s\n", source_ipaddress);
          fprintf(logfile, " | Destination IP       : %s\n\n", dest_ipaddress);
          fprintf(logfile, "TCP Header\n\n");
          fprintf(logfile, " | Source Port          : %u\n", ntohs(tcph->source));
          fprintf(logfile, " | Destination Port     : %u\n", ntohs(tcph->dest));
          fprintf(logfile, " | Sequence Number      : %u\n", ntohl(tcph->seq));
          fprintf(logfile, " | Acknowledge Number   : %u\n", ntohl(tcph->ack_seq));
          fprintf(logfile, " | Header Length        : %d BYTES\n", (unsigned int) tcph->doff * 4);
          fprintf(logfile, " | Acknowledgement Flag : %d\n", (unsigned int) tcph->ack);
          fprintf(logfile, " | Finish Flag          : %d\n", (unsigned int) tcph->fin);
          fprintf(logfile, " | Checksum             : %d\n", ntohs(tcph->check));
          fprintf(logfile, "\n");
          fprintf(logfile, "                        DATA dump                         \n");
          fprintf(logfile, "\n");
          fprintf(logfile, "Ehternet Header\n\n");
          LogData(buffer, 14,logfile);  
          fprintf(logfile, "\n");
          fprintf(logfile, "IP Header\n\n");  
          LogData(buffer + 14, iphdrlen,logfile);      
          fprintf(logfile, "\n");
          fprintf(logfile, "TCP Header\n\n");
          LogData(buffer + 14 + iphdrlen, sizeof(struct tcphdr),logfile);
          fprintf(logfile, "\n");
          fprintf(logfile, "Data Payload\n\n");
          LogData(buffer + header_size, size - header_size,logfile);
          fprintf(logfile, "\n");
          fprintf(logfile, "\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n\n");
          // 파일 닫기
          fclose(logfile);

        }
}

void printSSHInfo(const unsigned char *buffer, int size) { // 이부분이 아직안됨

    unsigned short iphdrlen;
    struct ethhdr *ethHeader = (struct ethhdr *)buffer;

    struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct tcphdr *tcph = (struct tcphdr *) (buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof(struct tcphdr);

        // source, dest ip 가져오기
    char dest_ipaddress[100];
    inet_ntop(AF_INET,&(iph->daddr),dest_ipaddress,INET_ADDRSTRLEN);
    char source_ipaddress[100];
    inet_ntop(AF_INET,&(iph->saddr),source_ipaddress,INET_ADDRSTRLEN);

        ssh_count += 1;
        // 파일명 구성
        char fileName[1000];
        snprintf(fileName, sizeof(fileName), "%s/NO.%d_%s->%s", ssh, ssh_count, source_ipaddress, dest_ipaddress);

        // 파일 열기
        FILE *logfile = fopen(fileName, "a");
        if (logfile == NULL) {
            printf("파일 열기에 실패했습니다.");
            return;
        }
        else{
          fprintf(logfile, "\n\n- - - - - - - - - - - SSH Packet - - - - - - - - - - - - -\n\n");
          fprintf(logfile, "Ehternet Header\n\n");
          fprintf(logfile, " | Destination MAC      : %02X:%02X:%02X:%02X:%02X:%02X\n",
          ethHeader->h_dest[0],ethHeader->h_dest[1],ethHeader->h_dest[2],
          ethHeader->h_dest[3],ethHeader->h_dest[4],ethHeader->h_dest[5]);
          fprintf(logfile, " | Source MAC           : %02X:%02X:%02X:%02X:%02X:%02X\n",
          ethHeader->h_source[0],ethHeader->h_source[1],ethHeader->h_source[2],
          ethHeader->h_source[3],ethHeader->h_source[4],ethHeader->h_source[5]);
          fprintf(logfile, " | Ethernet Type        : %04X\n\n", ntohs(ethHeader->h_proto));
          fprintf(logfile, "IP Header\n\n");
          fprintf(logfile, " | IP Version           : %d\n", (unsigned int)iph->version);
	        fprintf(logfile, " | IP Header Length     : %d Bytes\n", ((unsigned int)(iph->ihl)) * 4);
	        fprintf(logfile, " | Type Of Service      : %d\n", (unsigned int)iph->tos);
	        fprintf(logfile, " | IP Total Length      : %d  Bytes (FULL SIZE)\n", ntohs(iph->tot_len));
	        fprintf(logfile, " | TTL                  : %d\n", (unsigned int)iph->ttl);
	        fprintf(logfile, " | Protocol             : %d\n", (unsigned int)iph->protocol);
	        fprintf(logfile, " | Checksum             : %d\n", ntohs(iph->check));
          fprintf(logfile, " | Source IP            : %s\n", source_ipaddress);
          fprintf(logfile, " | Destination IP       : %s\n\n", dest_ipaddress);
          fprintf(logfile, "TCP Header\n\n");
          fprintf(logfile, " | Source Port          : %u\n", ntohs(tcph->source));
          fprintf(logfile, " | Destination Port     : %u\n", ntohs(tcph->dest));
          fprintf(logfile, " | Sequence Number      : %u\n", ntohl(tcph->seq));
          fprintf(logfile, " | Acknowledge Number   : %u\n", ntohl(tcph->ack_seq));
          fprintf(logfile, " | Header Length        : %d BYTES\n", (unsigned int) tcph->doff * 4);
          fprintf(logfile, " | Acknowledgement Flag : %d\n", (unsigned int) tcph->ack);
          fprintf(logfile, " | Finish Flag          : %d\n", (unsigned int) tcph->fin);
          fprintf(logfile, " | Checksum             : %d\n", ntohs(tcph->check));
          fprintf(logfile, "\n");
          fprintf(logfile, "                        DATA dump                         \n");
          fprintf(logfile, "\n");
          fprintf(logfile, "Ehternet Header\n\n");
          LogData(buffer, 14,logfile);  
          fprintf(logfile, "\n");
          fprintf(logfile, "IP Header\n\n");  
          LogData(buffer + 14, iphdrlen,logfile);      
          fprintf(logfile, "\n");
          fprintf(logfile, "TCP Header\n\n");
          LogData(buffer + 14 + iphdrlen, sizeof(struct tcphdr),logfile);
          fprintf(logfile, "\n");
          fprintf(logfile, "Data Payload\n\n");
          LogData(buffer + header_size, size - header_size,logfile);
          fprintf(logfile, "\n");
          fprintf(logfile, "\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n\n");
          // 파일 닫기
          fclose(logfile);
        }
}

void printDNSInfo(const unsigned char *buffer, int size) { // 이부분이 아직안됨

    unsigned short iphdrlen;
    struct ethhdr *ethHeader = (struct ethhdr *)buffer;

    struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct udphdr *udph = (struct udphdr *) (buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr);

        // source, dest ip 가져오기
    char dest_ipaddress[100];
    inet_ntop(AF_INET,&(iph->daddr),dest_ipaddress,INET_ADDRSTRLEN);
    char source_ipaddress[100];
    inet_ntop(AF_INET,&(iph->saddr),source_ipaddress,INET_ADDRSTRLEN);

        dns_count += 1;
        // 파일명 구성
        char fileName[1000];
        snprintf(fileName, sizeof(fileName), "%s/NO.%d_%s->%s", dns, dns_count, source_ipaddress, dest_ipaddress);

        // 파일 열기
        FILE *logfile = fopen(fileName, "a");
        if (logfile == NULL) {
            printf("파일 열기에 실패했습니다.");
            return;
        }
        else{
          fprintf(logfile, "\n\n- - - - - - - - - - - DNS Packet - - - - - - - - - - - - -\n\n");
          fprintf(logfile, "Ehternet Header\n\n");
          fprintf(logfile, " | Destination MAC      : %02X:%02X:%02X:%02X:%02X:%02X\n",
          ethHeader->h_dest[0],ethHeader->h_dest[1],ethHeader->h_dest[2],
          ethHeader->h_dest[3],ethHeader->h_dest[4],ethHeader->h_dest[5]);
          fprintf(logfile, " | Source MAC           : %02X:%02X:%02X:%02X:%02X:%02X\n",
          ethHeader->h_source[0],ethHeader->h_source[1],ethHeader->h_source[2],
          ethHeader->h_source[3],ethHeader->h_source[4],ethHeader->h_source[5]);
          fprintf(logfile, " | Ethernet Type        : %04X\n\n", ntohs(ethHeader->h_proto));
          fprintf(logfile, "IP Header\n\n");
          fprintf(logfile, " | IP Version           : %d\n", (unsigned int)iph->version);
	        fprintf(logfile, " | IP Header Length     : %d Bytes\n", ((unsigned int)(iph->ihl)) * 4);
	        fprintf(logfile, " | Type Of Service      : %d\n", (unsigned int)iph->tos);
	        fprintf(logfile, " | IP Total Length      : %d  Bytes (FULL SIZE)\n", ntohs(iph->tot_len));
	        fprintf(logfile, " | TTL                  : %d\n", (unsigned int)iph->ttl);
	        fprintf(logfile, " | Protocol             : %d\n", (unsigned int)iph->protocol);
	        fprintf(logfile, " | Checksum             : %d\n", ntohs(iph->check));
          fprintf(logfile, " | Source IP            : %s\n", source_ipaddress);
          fprintf(logfile, " | Destination IP       : %s\n\n", dest_ipaddress);
          fprintf(logfile, "UDP Header\n\n");
          fprintf(logfile, " | Source Port          : %u\n", ntohs(udph->source));
          fprintf(logfile, " | Destination Port     : %u\n", ntohs(udph->dest));
          fprintf(logfile, " | UDP Length           : %u\n", ntohs(udph->len));
          fprintf(logfile, " | UDP Checksum         : %u\n", ntohs(udph->check));
          fprintf(logfile, "\n");
          fprintf(logfile, "                        DATA dump                         \n");
          fprintf(logfile, "\n");
          fprintf(logfile, "Ehternet Header\n\n");
          LogData(buffer, 14,logfile);  
          fprintf(logfile, "\n");
          fprintf(logfile, "IP Header\n\n");  
          LogData(buffer + 14, iphdrlen,logfile);      
          fprintf(logfile, "\n");
          fprintf(logfile, "UDP Header\n\n");
          LogData(buffer + 14 + iphdrlen, sizeof(struct udphdr),logfile);
          fprintf(logfile, "\n");
          fprintf(logfile, "Data Payload\n\n");
          LogData(buffer + header_size, size - header_size,logfile);
          fprintf(logfile, "\n");
          fprintf(logfile, "\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n\n");
          // 파일 닫기
          fclose(logfile);
        }
}

void printICMPInfo(const unsigned char *buffer, int size) { // 이부분이 아직안됨

    unsigned short iphdrlen;
    struct ethhdr *ethHeader = (struct ethhdr *)buffer;

    struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct icmphdr *icmph = (struct icmphdr *) (buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr);

        // source, dest ip 가져오기
    char dest_ipaddress[100];
    inet_ntop(AF_INET,&(iph->daddr),dest_ipaddress,INET_ADDRSTRLEN);
    char source_ipaddress[100];
    inet_ntop(AF_INET,&(iph->saddr),source_ipaddress,INET_ADDRSTRLEN);

        icmp_count += 1;
        // 파일명 구성
        char fileName[1000];
        snprintf(fileName, sizeof(fileName), "%s/NO.%d_%s->%s", icmp, icmp_count, source_ipaddress, dest_ipaddress);

        // 파일 열기
        FILE *logfile = fopen(fileName, "a");
        if (logfile == NULL) {
            printf("파일 열기에 실패했습니다.");
            return;
        }
        else{
          fprintf(logfile, "\n\n- - - - - - - - - - - ICMP Packet - - - - - - - - - - - - -\n\n");
          fprintf(logfile, "Ehternet Header\n\n");
          fprintf(logfile, " | Destination MAC      : %02X:%02X:%02X:%02X:%02X:%02X\n",
          ethHeader->h_dest[0],ethHeader->h_dest[1],ethHeader->h_dest[2],
          ethHeader->h_dest[3],ethHeader->h_dest[4],ethHeader->h_dest[5]);
          fprintf(logfile, " | Source MAC           : %02X:%02X:%02X:%02X:%02X:%02X\n",
          ethHeader->h_source[0],ethHeader->h_source[1],ethHeader->h_source[2],
          ethHeader->h_source[3],ethHeader->h_source[4],ethHeader->h_source[5]);
          fprintf(logfile, " | Ethernet Type        : %04X\n\n", ntohs(ethHeader->h_proto));
          fprintf(logfile, "IP Header\n\n");
          fprintf(logfile, " | IP Version           : %d\n", (unsigned int)iph->version);
	        fprintf(logfile, " | IP Header Length     : %d Bytes\n", ((unsigned int)(iph->ihl)) * 4);
	        fprintf(logfile, " | Type Of Service      : %d\n", (unsigned int)iph->tos);
	        fprintf(logfile, " | IP Total Length      : %d  Bytes (FULL SIZE)\n", ntohs(iph->tot_len));
	        fprintf(logfile, " | TTL                  : %d\n", (unsigned int)iph->ttl);
	        fprintf(logfile, " | Protocol             : %d\n", (unsigned int)iph->protocol);
	        fprintf(logfile, " | Checksum             : %d\n", ntohs(iph->check));
          fprintf(logfile, " | Source IP            : %s\n", source_ipaddress);
          fprintf(logfile, " | Destination IP       : %s\n\n", dest_ipaddress);
          fprintf(logfile, "ICMP Header\n\n");
          fprintf(logfile, " | Type                 : %d\n", icmph->type);
          fprintf(logfile, " | Code                 : %d\n", icmph->code);
            fprintf(logfile, " | Checksum             : 0x%04x\n", ntohs(icmph->checksum));
          if (icmph->type == ICMP_ECHO || icmph->type == ICMP_ECHOREPLY) {
            fprintf(logfile, " | Identifier           : %d\n", ntohs(icmph->un.echo.id));
            fprintf(logfile, " | Sequence Number      : %d\n", ntohs(icmph->un.echo.sequence));
          }          
          fprintf(logfile, "\n");
          fprintf(logfile, "                        DATA dump                         \n");
          fprintf(logfile, "\n");
          fprintf(logfile, "Ehternet Header\n\n");
          LogData(buffer, 14,logfile);  
          fprintf(logfile, "\n");
          fprintf(logfile, "IP Header\n\n");  
          LogData(buffer + 14, iphdrlen,logfile);      
          fprintf(logfile, "\n");
          fprintf(logfile, "ICMP Header\n\n");
          LogData(buffer + 14 + iphdrlen, sizeof(struct icmphdr),logfile);
          fprintf(logfile, "\n");
          fprintf(logfile, "Data Payload\n\n");
          LogData(buffer + header_size, size - header_size,logfile);
          fprintf(logfile, "\n");
          fprintf(logfile, "\n");
          fprintf(logfile, "\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n\n");
          // 파일 닫기
          fclose(logfile);
        }
}

void LogData(const unsigned char *buffer, int size,FILE *logfile)
{
    int i, j;
    for (i = 0; i < size; i++) {  //패킷은 16비트씩 구성되있다.
        if (i != 0 && i % 16 == 0) { // 한줄씩 찍는데 i가 16비트 배수로 떨어지면 문자니까

            for (j = i - 16; j < i; j++) {
                if (buffer[j] >= 32 && buffer[j] <= 128) {
                    fprintf(logfile, " %c", (unsigned char) buffer[j]); // 사람 문자로 변환.
                } else {
                    fprintf(logfile, " *"); // 없으면 공백찍는다.
                }
            }
            fprintf(logfile,"\t\n");
        }

        if (i % 16 == 0) {
            fprintf(logfile, " ");
        }
        fprintf(logfile, " %02X", (unsigned int) buffer[i]);//바이트코드 찍어줌

        if (i == size - 1) { //공간채워주고
            for(j = 0; j < 15 - i % 16; j++)  {
                fprintf(logfile, "  "); //여백
            }

            for(j = i - i % 16; j <= i; j++) { 
                if(buffer[j] >= 32 && buffer[j] <= 128) {
                    fprintf(logfile, " %c", (unsigned char) buffer[j]);
                } else {
                    fprintf(logfile, " *");
                }
            }

            fprintf(logfile,  "\n");
        }
    }
}