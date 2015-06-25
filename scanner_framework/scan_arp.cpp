
#include <memory>

#include <pcap.h>

#include "local_network.h"
#include "scan_arp.h"

#pragma comment (lib,"wpcap")

#define ETH_ADDRESS_LENGTH 6
#define ETH_PROTO_ARP 0x806
#define ETH_TRAILER_LENGTH 0x12

#pragma pack(1)

typedef struct {
    unsigned char dest[ETH_ADDRESS_LENGTH];
    unsigned char source[ETH_ADDRESS_LENGTH];
    unsigned short proto;
} eth,*point_eth;

typedef struct {
    USHORT    arp_hrd;
    USHORT    arp_pro;
    UCHAR     arp_hln;
    UCHAR     arp_pln;
    USHORT    arp_op;
    UCHAR     arp_sha[6];
    ULONG     arp_spa;
    UCHAR     arp_tha[6];
    ULONG     arp_tpa;
} arp,*point_arp;

#pragma pack(4)

static pcap_t* adapter=NULL;

bool scan_arp_init(void) {
    char buffer[64]={0};
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

void scan_arp_clean(void) {
    pcap_close(adapter);
}

bool scan_arp(const char* targe_ip,char* output_mac) {
	char send_packet[ARP_PING_SEND_BUFFER_LENGTH]={0};

	point_eth peth=(point_eth)send_packet;
	peth->dest[0]=0xFF;
	peth->dest[1]=0xFF;
	peth->dest[2]=0xFF;
	peth->dest[3]=0xFF;
	peth->dest[4]=0xFF;
	peth->dest[5]=0xFF;
	memcpy(&peth->source,local_mac,ETH_ADDRESS_LENGTH);
	peth->proto=htons(ETH_PROTO_ARP);

	point_arp parp=(point_arp)(send_packet+sizeof(eth));
	parp->arp_hrd=htons(0x0001);
	parp->arp_pro=htons(0x0800);
	parp->arp_hln=0x6;
	parp->arp_pln=0x4;
	parp->arp_op=htons(0x0001);
	memcpy(&parp->arp_sha,local_mac,ETH_ADDRESS_LENGTH);
	parp->arp_spa=inet_addr(local_ip);
	parp->arp_tha[0]=0x00;
	parp->arp_tha[1]=0x00;
	parp->arp_tha[2]=0x00;
	parp->arp_tha[3]=0x00;
	parp->arp_tha[4]=0x00;
	parp->arp_tha[5]=0x00;
	parp->arp_tpa=inet_addr(targe_ip);

	char* eth_trailer=(char*)(send_packet+sizeof(eth)+sizeof(arp));
	for (int i=0;i<ETH_TRAILER_LENGTH;++i,++eth_trailer)
		*eth_trailer=0x11;

    pcap_sendpacket(adapter,(const unsigned char *)send_packet,sizeof(eth)+sizeof(arp)+ETH_TRAILER_LENGTH);

    DWORD old_tick=GetTickCount();
    DWORD new_tick=old_tick;

    do {
        pcap_pkthdr* header=NULL;
        unsigned char* data=NULL;
        int return_code=pcap_next_ex(adapter,&header,(const unsigned char**)&data);

        if (-1==return_code || 0==return_code) continue;
        parp=(point_arp)(data+sizeof(eth));
        if (parp->arp_spa==inet_addr(targe_ip)) {
			memcpy(output_mac,parp->arp_sha,ETH_ADDRESS_LENGTH);
			return true;
        }
        new_tick=GetTickCount();
    } while ((new_tick-old_tick)<=ARP_PING_WAIT_TIME);
	
	return false;
}
