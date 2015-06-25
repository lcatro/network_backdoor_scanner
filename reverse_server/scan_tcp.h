
#ifndef _SCAN_TCP_H__
#define _SCAN_TCP_H__

#define PACKET_SEND_BUFFER  1024
#define PACKET_RECV_BUFFER  1024
#define PAGE_BUFFER_LENGTH  1024*10

#define SCAN_TCP_PORT 443  //  https 

unsigned int scan_tcp_bind(unsigned short local_port);
unsigned int scan_tcp_accept(unsigned int tcp_handle);
unsigned int scan_tcp_connect(const char* target_ip,unsigned short target_port);
bool scan_tcp_set_recv_block(unsigned int tcp_handle,unsigned int block_time);
void scan_tcp_send(unsigned int tcp_handle,const char* buffer,unsigned int buffer_length);
unsigned int scan_tcp_recv(unsigned int tcp_handle,char* buffer,unsigned int buffer_length);
void scan_tcp_disconnect(unsigned int tcp_handle);

#endif
