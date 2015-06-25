
#include <math.h>
#include <stdio.h>

#include <string>

#include <windows.h>

#include "network_encoder.h"
#include "scan_tcp.h"

using std::pair;

typedef pair<unsigned int,unsigned int> pair_handle;

#define PACKET_RECV_BUFFER 1024

static long string_to_number(const char* input_string) {
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

void network_tunnal_init(void) {
    WSADATA init;
    WSAStartup(1,&init);
}

void network_tunnal_close(void) {
    WSACleanup();
}

static void network_route_thread_tunnal(pair_handle* pair_socket) {
    char recv_buffer[PACKET_RECV_BUFFER]={0};

    while (true) {
        unsigned int recv_length=scan_tcp_recv(pair_socket->first,recv_buffer,PACKET_RECV_BUFFER);
        
        if (-1==recv_length || !recv_length)
            break;

        network_decode(recv_buffer,recv_length);
        scan_tcp_send(pair_socket->second,recv_buffer,recv_length);
        memset(recv_buffer,0,recv_length);
    }

    delete pair_socket;
}

static void network_route_thread_local(pair_handle* pair_socket) {
    char recv_buffer[PACKET_RECV_BUFFER]={0};

    while (true) {
        unsigned int recv_length=scan_tcp_recv(pair_socket->first,recv_buffer,PACKET_RECV_BUFFER);
        
        if (-1==recv_length || !recv_length)
            break;

        recv_length=network_encode(recv_buffer,recv_length);
        scan_tcp_send(pair_socket->second,recv_buffer,recv_length);
        memset(recv_buffer,0,recv_length);
    }

    delete pair_socket;
}

static void network_route_thread_main(unsigned int local_port) {
    unsigned int local_listen=scan_tcp_bind(local_port);

    if (-1!=local_listen) {
        unsigned int reverse_connect=scan_tcp_accept(local_listen);
        unsigned int local_connect  =scan_tcp_accept(local_listen);

        if (-1!=reverse_connect && -1!=local_listen) {
            HANDLE thread_listen=INVALID_HANDLE_VALUE,thread_connect=INVALID_HANDLE_VALUE;

            thread_listen=CreateThread(NULL,NULL,(LPTHREAD_START_ROUTINE)&network_route_thread_local,new pair_handle(local_connect,reverse_connect),NULL,NULL);
            thread_connect=CreateThread(NULL,NULL,(LPTHREAD_START_ROUTINE)&network_route_thread_tunnal,new pair_handle(reverse_connect,local_connect),NULL,NULL);

            if (INVALID_HANDLE_VALUE!=thread_listen && INVALID_HANDLE_VALUE!=thread_connect) {
                WaitForSingleObject(thread_listen,INFINITE);
                WaitForSingleObject(thread_connect,INFINITE);
                return;
            }
        }
    }
}

bool network_tunnal_open(unsigned int local_port) {
    HANDLE thread=CreateThread(NULL,NULL,(LPTHREAD_START_ROUTINE)&network_route_thread_main,(void*)local_port,NULL,NULL);

    if (INVALID_HANDLE_VALUE!=thread)
        return true;
    return false;
}







