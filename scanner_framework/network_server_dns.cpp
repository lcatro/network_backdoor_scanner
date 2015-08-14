
#include <malloc.h>
#include <memory.h>
#include <stdio.h>
#include <string.h>

#include <string>
#include <vector>

#include <windows.h>
#include <winsock.h>

#include "local_network.h"
#include "network_server_dns.h"

using std::string;
using std::vector;

#define DNS_PORT 53
#define DNS_QUERY_TYPE 0x1
#define DNS_SEND_BUFFER 1024
#define DNS_RECV_BUFFER 1024

#pragma comment (lib,"ws2_32")

#pragma pack(1)

typedef struct {
    unsigned short id;
    unsigned short flags;
    unsigned short quests;
    unsigned short answers;
    unsigned short author;
    unsigned short addition;
} dns,*point_dns;

typedef struct {
    unsigned char *name;
    unsigned short type;
    unsigned short classes;
} query,*point_query;

typedef struct {
    unsigned short name;
    unsigned short type;
    unsigned short classes;
    unsigned long  ttl;
    unsigned short length;
    unsigned long  addr;
} response,*point_response;

#pragma pack(4)

typedef struct {
    string host;
    string ip;
} dns_host_entry;
typedef vector<dns_host_entry> dns_host_entry_list;

SOCKET dns_sock=SOCKET_ERROR;
HANDLE dns_thread_handle=INVALID_HANDLE_VALUE;
CRITICAL_SECTION dns_thread_signal={0};
dns_host_entry_list dns_host_list;
bool loop_flag=true;

static char* conver_host(char* input_host) {
    if (NULL==input_host) return NULL;

    char* output_string=NULL;
    char* host=input_host;
    unsigned short alloc_length=0;
    while ('\0'!=*host) {
        alloc_length+=*(unsigned char*)host+1;
        host=(char*)(input_host+alloc_length);
    }
    output_string=(char*)malloc(alloc_length);
    memset(output_string,0,alloc_length);
    unsigned short read_point=0;
    while ('\0'!=*input_host) {
        unsigned char read_length=*input_host++;
        memcpy((char*)(output_string+read_point),input_host,read_length);
        *(char*)(output_string+read_point+read_length)='.';
        read_point+=read_length+1;
        input_host+=read_length;
    }
    *(char*)(output_string+read_point-1)='\0';

    return output_string;
}

static void network_server_dns_thread(void) {
    while (loop_flag) {
        char recv_buffer[DNS_RECV_BUFFER]={0};
        sockaddr_in remote;
        int remote_length=sizeof(remote);
        int recv_length=recvfrom(dns_sock,recv_buffer,DNS_RECV_BUFFER,0,(sockaddr*)&remote,&remote_length);
        if (SOCKET_ERROR!=recv_length) {
            point_dns dns_=(point_dns)recv_buffer;
            point_query query_=(point_query)&recv_buffer[sizeof(dns)];
            unsigned short query_type=ntohs(*(unsigned short*)((unsigned long)query_+strlen((const char*)query_)+1));
            if (DNS_QUERY_TYPE==query_type) {
                bool hijack_flag=false;
                char* query_host=conver_host((char*)query_);
                unsigned int query_total=ntohs(dns_->quests);

                string host_ip;
                EnterCriticalSection(&dns_thread_signal);
                for (dns_host_entry_list::iterator entry_list_iterator=dns_host_list.begin();
                                                   entry_list_iterator!=dns_host_list.end();
                                                   ++entry_list_iterator) {
                    string query_host_(query_host);
                    if (entry_list_iterator->host==query_host_) {
                        host_ip=entry_list_iterator->ip;
                        hijack_flag=true;
                        break;
                    }
                }
                LeaveCriticalSection(&dns_thread_signal);
                free(query_host);

                if (hijack_flag) {
                    char send_buffer[DNS_SEND_BUFFER]={0};
                    response response;
                    if (host_ip.empty())
                        response.addr=inet_addr(local_ip);
                    else
                        response.addr=inet_addr(host_ip.c_str());
                    response.length=htons(4);
                    response.classes=htons(1);
                    response.ttl=htonl(300);
                    response.type=htons(query_type);
                    response.name=htons(0xC00C);
                    dns_->flags=htons(0x8180);
                    dns_->answers=htons(1);
                    memcpy(send_buffer,recv_buffer,recv_length);
                    memcpy(&send_buffer[recv_length],&response,sizeof(response));
                    sendto(dns_sock,send_buffer,recv_length+sizeof(response),0,(const sockaddr*)&remote,sizeof(remote));
                }
            }
        } else
            break;
    }
}

bool network_server_dns_start(void) {
    SOCKET sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);

    sockaddr_in local;
    local.sin_addr.S_un.S_addr=0;
    local.sin_family=AF_INET;
    local.sin_port=htons(DNS_PORT);
    if (SOCKET_ERROR==bind(sock,(const sockaddr*)&local,sizeof(sockaddr_in)))
        return false;

    dns_thread_handle=CreateThread(NULL,NULL,(LPTHREAD_START_ROUTINE)&network_server_dns_thread,NULL,NULL,NULL);
    if (INVALID_HANDLE_VALUE==dns_thread_handle) {
        closesocket(sock);
        return false;
    }
    InitializeCriticalSection(&dns_thread_signal);
    dns_sock=sock;
    return true;
}

void network_server_dns_add(const char* host,const char* ip) {
    EnterCriticalSection(&dns_thread_signal);
    for (dns_host_entry_list::iterator entry_list_iterator=dns_host_list.begin();
                                       entry_list_iterator!=dns_host_list.end();
                                       ++entry_list_iterator) {
        if (entry_list_iterator->host==host) {
            entry_list_iterator->ip=ip;
            goto EXIT;
        }
    }{
    dns_host_entry new_entry;
    new_entry.host=host;
    new_entry.ip=ip;
    dns_host_list.push_back(new_entry);}
EXIT:
    LeaveCriticalSection(&dns_thread_signal);
}

void network_server_dns_delete(const char* host) {
    EnterCriticalSection(&dns_thread_signal);
    for (dns_host_entry_list::iterator entry_list_iterator=dns_host_list.begin();
                                       entry_list_iterator!=dns_host_list.end();
                                       ++entry_list_iterator) {
        if (entry_list_iterator->host==host) {
            dns_host_list.erase(entry_list_iterator);
            goto EXIT;
        }
    }
EXIT:
    LeaveCriticalSection(&dns_thread_signal);
}

void network_server_dns_close(void) {
    DeleteCriticalSection(&dns_thread_signal);
    CloseHandle(dns_thread_handle);
    dns_thread_handle=INVALID_HANDLE_VALUE;
    closesocket(dns_sock);
    dns_sock=SOCKET_ERROR;
}
