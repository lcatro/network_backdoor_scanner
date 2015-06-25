
#ifndef _SCAN_ARP_H__
#define _SCAN_ARP_H__

#define ADAPTER_INDEX 1

#define ARP_PING_SEND_BUFFER_LENGTH 512

#define ARP_PING_WAIT_TIME 200

bool scan_arp_init(void);
bool scan_arp(const char* targe_ip,char* output_mac);
void scan_arp_clean(void);

#endif
