
#pragma warning (disable:4786)

#include <memory.h>

#include <string>
#include <vector>

#include <windows.h>

#include "network_encoder.h"
#include "network_route.h"
#include "scan_tcp.h"


using std::string;
using std::pair;
using std::vector;


typedef pair<HANDLE,HANDLE> pair_thread;
typedef pair<unsigned int,unsigned int> pair_handle;
typedef pair<pair_thread,pair_handle> port;
typedef vector<port> port_list;


port_list route_list;


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

//    delete pair_socket;
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

//    delete pair_socket;
}

bool network_route(const char* remote_ip,unsigned int remote_port,const char* reverse_ip,unsigned int reverse_port) {
    unsigned int remote_handle=scan_tcp_connect(remote_ip,remote_port);
    unsigned int reverse_handle=scan_tcp_connect(reverse_ip,reverse_port);

    if (-1!=remote_handle && -1!=reverse_handle) {
        HANDLE remote_thread=CreateThread(NULL,NULL,(LPTHREAD_START_ROUTINE)&network_route_thread_local,new pair_handle(remote_handle,reverse_handle),NULL,NULL);
        HANDLE reverse_thread=CreateThread(NULL,NULL,(LPTHREAD_START_ROUTINE)&network_route_thread_tunnal,new pair_handle(reverse_handle,remote_handle),NULL,NULL);

        if (INVALID_HANDLE_VALUE!=remote_thread && INVALID_HANDLE_VALUE!=reverse_thread) {
            // no static but you can custom it ! ..
            return true;
        }
    }
    scan_tcp_disconnect(remote_handle);
    scan_tcp_disconnect(reverse_handle);
    return false;
}
