
#ifndef _SCAN_TCP_H__
#define _SCAN_TCP_H__

#define ADAPTER_INDEX 1

#define PACKET_SEND_BUFFER  1024
#define PACKET_RECV_BUFFER  1024
#define PAGE_BUFFER_LENGTH  1024*10

#define SCAN_TCP_PORT_TIMEOUT   500
#define SCAN_TCP_GET_DATA_TIME 5000

#define SCAN_TCP_PORT 443  //  https 

typedef struct {
    unsigned short port;
    char  proto[10];
    unsigned int   data_length;
    char* data;
} scan_tcp_port_information;

bool scan_tcp_init(void);
bool scan_tcp(const char* target_ip,unsigned short target_port);
bool scan_tcp_fake_ip(const char* target_ip,unsigned short target_port,const char* fake_ip,unsigned short fake_port);
bool scan_tcp_get_data(const char* target_ip,unsigned short target_port,const char* path,scan_tcp_port_information* output_data);
void scan_tcp_clean(void);

unsigned int scan_tcp_bind(unsigned short local_port);
unsigned int scan_tcp_accept(unsigned int tcp_handle);
unsigned int scan_tcp_connect(const char* target_ip,unsigned short target_port);
bool scan_tcp_set_recv_block(unsigned int tcp_handle,unsigned int block_time);
void scan_tcp_send(unsigned int tcp_handle,const char* buffer,unsigned int buffer_length);
unsigned int scan_tcp_recv(unsigned int tcp_handle,char* buffer,unsigned int buffer_length);
void scan_tcp_disconnect(unsigned int tcp_handle);

#endif
