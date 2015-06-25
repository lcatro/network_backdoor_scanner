
#include <malloc.h>
#include <memory.h>
#include <stdio.h>

#include <winsock.h>

#include "scan_tcp.h"

#pragma comment (lib,"ws2_32")

unsigned int scan_tcp_connect(const char* target_ip,unsigned short target_port) {
    if (NULL==target_ip || !(0<target_port && target_port<=65535)) return false;

    SOCKET sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

    if (SOCKET_ERROR!=sock) {
        sockaddr_in remote={0};
        remote.sin_addr.S_un.S_addr=inet_addr(target_ip);
        remote.sin_family=AF_INET;
        remote.sin_port=htons(target_port);
        
        if (SOCKET_ERROR!=connect(sock,(const sockaddr*)&remote,sizeof(remote)))
            return sock;
        closesocket(sock);
    }
    return -1;
}

unsigned int scan_tcp_bind(unsigned short local_port) {
    if (!(0<=local_port && local_port<=65535)) return false;

    SOCKET sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

    if (SOCKET_ERROR!=sock) {
        sockaddr_in local={0};
        local.sin_family=AF_INET;
        local.sin_port=htons(local_port);

        if (SOCKET_ERROR!=bind(sock,(const sockaddr*)&local,sizeof(local))) {
            listen(sock,1);
            return sock;
        }
        closesocket(sock);
    }
    return -1;
}

unsigned int scan_tcp_accept(unsigned int tcp_handle) {
    SOCKET sock=accept(tcp_handle,NULL,NULL);

    return (SOCKET_ERROR!=sock)?sock:-1;
}

bool scan_tcp_set_recv_block(unsigned int tcp_handle,unsigned int block_time) {
    int time_out=block_time;
    return (SOCKET_ERROR!=setsockopt(tcp_handle,SOL_SOCKET,SO_RCVTIMEO,(const char*)&time_out,sizeof(time_out)))?true:false;
}

void scan_tcp_send(unsigned int tcp_handle,const char* buffer,unsigned int buffer_length) {
    send(tcp_handle,buffer,buffer_length,0);
}

unsigned int scan_tcp_recv(unsigned int tcp_handle,char* buffer,unsigned int buffer_length) {
    int recv_length=0;
    recv_length=recv(tcp_handle,buffer,buffer_length,0);
    return (SOCKET_ERROR!=recv_length)?recv_length:-1;
}

void scan_tcp_disconnect(unsigned int tcp_handle) {
    closesocket(tcp_handle);
}
