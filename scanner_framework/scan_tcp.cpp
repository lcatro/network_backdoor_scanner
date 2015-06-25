
#include <malloc.h>
#include <memory.h>
#include <stdio.h>

#include <string>

#include <pcap.h>

#include "local_network.h"
#include "scan_arp.h"
#include "scan_tcp.h"
#include "scan_tcp_header.h"

using std::string;

#define ETH_ADDRESS_LENGTH 6
#define ETH_PROTO_IP 0x800

#pragma pack(1)

typedef struct {
    unsigned char dest[ETH_ADDRESS_LENGTH];
    unsigned char source[ETH_ADDRESS_LENGTH];
    unsigned short proto;
} eth_header,*point_eth_header;

typedef struct {
    unsigned char h_lenver;
    unsigned char tos;
    unsigned short total_len;
    unsigned short ident;
    unsigned short frag_and_flags;
    unsigned char ttl;
    unsigned char proto;
    unsigned short checksum;
    unsigned int sourceIP;
    unsigned int destIP;
} ip_header,*point_ip_header; 

#define TH_FIN 0x01   
#define TH_SYN 0x02   
#define TH_RST 0x04   
#define TH_PUSH 0x08   
#define TH_ACK 0x10   
#define TH_URG 0x20

typedef struct {  
    unsigned short th_sorc_port;  
    unsigned short th_dest_port;  
    unsigned int th_seq;  
    unsigned int th_ack;  
    unsigned char th_length;
    unsigned char th_flags;  
    unsigned short th_win;  
    unsigned short th_sum;  
    unsigned short th_urp;  
} tcp_header,*point_tcp_header;

typedef struct { 
    unsigned long sorc_addr;
    unsigned long dest_addr;
    unsigned char mbz;
    unsigned char protocal;
    unsigned short length;
} tcp_psdheader,*point_tcp_psdheader;

#pragma pack(4)

static pcap_t* adapter=NULL;

static unsigned short checksum( unsigned short *buf, int size) {
    unsigned long cksum = 0;
    while( size > 1) {
        cksum += *buf++;    
        size -= sizeof( unsigned short);    
    }    
       
    if(size)
        cksum += *( unsigned char *)buf;
    
    cksum = ( cksum >> 16) + ( cksum & 0xffff);
    cksum += (cksum >>16);
    return ( unsigned short)(~cksum);    
}

static bool check_subnet(const char* targe_ip) {
	string local(local_ip);
	string remote(targe_ip);

	local=local.substr(0,local.find_last_of("."));
	remote=remote.substr(0,remote.find_last_of("."));

	if (local==remote)
		return true;
	return false;
}

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

bool scan_tcp_get_data(const char* target_ip,unsigned short target_port,const char* path,scan_tcp_port_information* output_data) {
    unsigned int tcp_handle=scan_tcp_connect(target_ip,target_port);
    SOCKET sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

    if (-1!=tcp_handle) {
        char send_buffer[PACKET_SEND_BUFFER]={0};
        sprintf(send_buffer,SCAN_TCP_HEADER_HTTP,path);

        scan_tcp_set_recv_block(tcp_handle,SCAN_TCP_GET_DATA_TIME);
        scan_tcp_send(tcp_handle,send_buffer,strlen(send_buffer));

        int recv_return=SOCKET_ERROR;
        unsigned int recv_length=0;
        char recv_packet_buffer[PACKET_RECV_BUFFER]={0};
        char* recv_buffer=(char*)malloc(PAGE_BUFFER_LENGTH);
        memset(recv_buffer,0,PAGE_BUFFER_LENGTH);
        
        while (SOCKET_ERROR!=(recv_return=scan_tcp_recv(tcp_handle,recv_packet_buffer,PACKET_RECV_BUFFER))) {
            memcpy((void*)(recv_buffer+recv_length),recv_packet_buffer,recv_return);
            recv_length+=recv_return;

            if (recv_return<PACKET_RECV_BUFFER) {
                output_data->port=target_port;
                output_data->proto[0]='H';
                output_data->data_length=recv_length;
                output_data->data=recv_buffer;
                scan_tcp_disconnect(tcp_handle);
                return true;
            }
            memset(recv_packet_buffer,0,PACKET_RECV_BUFFER);
        }

        free(recv_buffer);
        scan_tcp_disconnect(tcp_handle);
    }
    return false;
}

bool scan_tcp_init(void) {
    pcap_if_t *devsin;
    pcap_if_t *d;
    int i=0;
    char errorbuf[PCAP_ERRBUF_SIZE]={0};

    if (pcap_findalldevs(&devsin, errorbuf) == -1)
        return false;

    for(d=devsin, i=0; i< ADAPTER_INDEX-1 ;d=d->next, i++);

    if ((adapter= pcap_open_live(d->name, 65536, 1,1000, errorbuf )) == NULL)
        return false;
    return true;
}

bool scan_tcp_fake_ip(const char* target_ip,unsigned short target_port,const char* fake_ip,unsigned short fake_port) {

    if (NULL!=adapter) {
        char remote_mac[ETH_ADDRESS_LENGTH]={0};
        if (check_subnet(target_ip)) {
            if (!scan_arp(target_ip,remote_mac))
                return false;
        } else
            memcpy(remote_mac,gateway_mac,ETH_ADDRESS_LENGTH);

        char send_packet_options[]={0x02,0x04,0x05,0xb4,0x01,0x03,0x03,0x02,0x01,0x01,0x04,0x02};
        char send_packet[PACKET_SEND_BUFFER]={0};
        char recv_packet[PACKET_RECV_BUFFER]={0};
        char send_packet_calcu_checksum[PACKET_RECV_BUFFER]={0};

        point_eth_header eth_header_=(point_eth_header)send_packet;
        memcpy(eth_header_->source,local_mac,ETH_ADDRESS_LENGTH);
        memcpy(eth_header_->dest,remote_mac,ETH_ADDRESS_LENGTH);
        eth_header_->proto=htons(ETH_PROTO_IP);
        
        point_ip_header ip_header_=(point_ip_header)(send_packet+sizeof(eth_header));
        ip_header_->h_lenver=(4<<4 | sizeof(ip_header)/sizeof(unsigned long));
        ip_header_->total_len=htons(sizeof(ip_header)+sizeof(tcp_header)+sizeof(send_packet_options));
        ip_header_->ident=10;
        ip_header_->frag_and_flags=1<<6;
        ip_header_->ttl=128;
        ip_header_->proto=IPPROTO_TCP;
        ip_header_->sourceIP=inet_addr(fake_ip);
        ip_header_->destIP=inet_addr(target_ip); 

        point_tcp_header tcp_header_=(point_tcp_header)(send_packet+sizeof(eth_header)+sizeof(ip_header));
        tcp_header_->th_dest_port=htons(target_port);
        tcp_header_->th_sorc_port=htons(fake_port);
        tcp_header_->th_seq=0x1234432;
        tcp_header_->th_ack=0;
        tcp_header_->th_length=0x80;
        tcp_header_->th_flags=TH_SYN;
        tcp_header_->th_win=htons(4096);
        tcp_header_->th_urp=0;
        memcpy((void*)(send_packet+sizeof(eth_header)+sizeof(ip_header)+sizeof(tcp_header)),send_packet_options,sizeof(send_packet_options));
        
        point_tcp_psdheader tcp_psdheader_=(point_tcp_psdheader)send_packet_calcu_checksum;
        tcp_psdheader_->dest_addr=inet_addr(target_ip);
        tcp_psdheader_->sorc_addr=inet_addr(fake_ip);
        tcp_psdheader_->mbz=0;
        tcp_psdheader_->protocal=IPPROTO_TCP;
        tcp_psdheader_->length=htons(sizeof(tcp_header)+sizeof(send_packet_options));
        memcpy(&send_packet_calcu_checksum[sizeof(tcp_psdheader)],tcp_header_,sizeof(tcp_header));
        memcpy(&send_packet_calcu_checksum[sizeof(tcp_psdheader)+sizeof(tcp_header)],send_packet_options,sizeof(send_packet_options));
        tcp_header_->th_sum=checksum((unsigned short*)send_packet_calcu_checksum,sizeof(tcp_psdheader)+sizeof(tcp_header)+sizeof(send_packet_options));
        ip_header_->checksum=checksum((unsigned short*)ip_header_,sizeof(ip_header));

        pcap_sendpacket(adapter,(const unsigned char *)send_packet,sizeof(eth_header)+sizeof(ip_header)+sizeof(tcp_header)+sizeof(send_packet_options));
 
        unsigned long old_tick=GetTickCount();
        unsigned long new_tick=old_tick;
        do {
            pcap_pkthdr* header=NULL;
            unsigned char* data=NULL;
            int return_code=pcap_next_ex(adapter,&header,(const unsigned char**)&data);

            if (-1==return_code || 0==return_code) continue;
            eth_header_=(point_eth_header)data;
            if (htons(ETH_PROTO_IP)==eth_header_->proto) {
                ip_header_=(point_ip_header)(data+sizeof(eth_header));
                tcp_header_=(point_tcp_header)(data+sizeof(eth_header)+sizeof(ip_header));
                if (inet_addr(target_ip)==ip_header_->sourceIP && IPPROTO_TCP==ip_header_->proto && htons(target_port)==tcp_header_->th_sorc_port)
                    if ((tcp_header_->th_flags & TH_SYN) && (tcp_header_->th_flags & TH_ACK))
                        return true;
            }
            new_tick=GetTickCount();
        } while ((new_tick-old_tick)<=SCAN_TCP_PORT_TIMEOUT);
    }
    return false;
}

bool scan_tcp(const char* target_ip,unsigned short target_port) {
    return scan_tcp_fake_ip(target_ip,target_port,local_ip,SCAN_TCP_PORT);
}

void scan_tcp_clean(void) {
    pcap_close(adapter);
    adapter=NULL;
}
