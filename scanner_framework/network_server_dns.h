
#ifndef _NETWORK_SERVER_DNS_
#define _NETWORK_SERVER_DNS_

bool network_server_dns_start(void);
void network_server_dns_add(const char* host,const char* ip);
void network_server_dns_delete(const char* host);
void network_server_dns_close(void);

#endif
