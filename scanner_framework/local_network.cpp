
#include <time.h>

#include <windows.h>
#include <winsock.h>

#include "local_network.h"
#include "scan_arp.h"
#include "scan_tcp.h"
#include "scan_icmp.h"

#pragma comment (lib,"ws2_32")


#define MAX_ADAPTER_NAME_LENGTH 256
#define MAX_ADAPTER_DESCRIPTION_LENGTH 128
#define MAX_ADAPTER_ADDRESS_LENGTH 8

typedef struct {
    char String[4 * 4];
} IP_ADDRESS_STRING, *PIP_ADDRESS_STRING, IP_MASK_STRING, *PIP_MASK_STRING;
 
typedef struct _IP_ADDR_STRING {
    struct _IP_ADDR_STRING* Next;
    IP_ADDRESS_STRING IpAddress;
    IP_MASK_STRING IpMask;
    DWORD Context;
} IP_ADDR_STRING, *PIP_ADDR_STRING;

typedef struct _IP_ADAPTER_INFO {  
  struct _IP_ADAPTER_INFO *Next;
  DWORD ComboIndex;  
  char AdapterName[MAX_ADAPTER_NAME_LENGTH + 4];
  char Description[MAX_ADAPTER_DESCRIPTION_LENGTH + 4];
  UINT AddressLength;  
  BYTE Address[MAX_ADAPTER_ADDRESS_LENGTH];
  DWORD Index;
  UINT Type;  
  UINT DhcpEnabled;
  PIP_ADDR_STRING CurrentIpAddress;
  IP_ADDR_STRING IpAddressList;
  IP_ADDR_STRING GatewayList;
  IP_ADDR_STRING DhcpServer;
  BOOL HaveWins;
  IP_ADDR_STRING PrimaryWinsServer;
  IP_ADDR_STRING SecondaryWinsServer;
  time_t LeaseObtained;
  time_t LeaseExpires;
} IP_ADAPTER_INFO,  *PIP_ADAPTER_INFO;

typedef DWORD (__stdcall *_GetAdaptersInfo)(PIP_ADAPTER_INFO,PULONG);

char local_host_name[HOST_NAME_LENGTH]={0};
char local_ip[IPV4_IP_LENGTH]={0};
unsigned char local_mac[ETH_ADDRESS_LENGTH]={0};
char gateway_ip[IPV4_IP_LENGTH]={0};
unsigned char gateway_mac[ETH_ADDRESS_LENGTH]={0};
char dhcp_server[IPV4_IP_LENGTH]={0};
char network_mask[IPV4_IP_LENGTH]={0};
char network_session[IPV4_IP_LENGTH]={0};
char network_session_last[IPV4_IP_LENGTH]={0};
unsigned long network_session_size=0;

static void get_ip(void) {
    gethostname(local_host_name,64);
    hostent* host=gethostbyname(local_host_name);
    char* ip=inet_ntoa(*(in_addr*)host->h_addr_list[0]);
    memcpy(local_ip,ip,strlen(ip));
}

static void get_local_network_information(void) {
	HMODULE dll_iphlpapi=NULL;
    dll_iphlpapi=LoadLibrary("iphlpapi.dll");
    _GetAdaptersInfo GetAdaptersInfo_=(_GetAdaptersInfo)GetProcAddress(dll_iphlpapi,"GetAdaptersInfo");

	IP_ADAPTER_INFO local_network_data;
	unsigned long output_local_network_data_length=sizeof(local_network_data);
    DWORD return_code=GetAdaptersInfo_(&local_network_data,&output_local_network_data_length);

	if (ERROR_BUFFER_OVERFLOW==return_code) {
		return_code=GetAdaptersInfo_(&local_network_data,&output_local_network_data_length);
	}
	if (NO_ERROR==return_code) {
		memcpy(local_mac,&local_network_data.Address,ETH_ADDRESS_LENGTH);

        if (local_network_data.DhcpEnabled)
		    memcpy(dhcp_server,&local_network_data.DhcpServer.IpAddress.String,IPV4_IP_LENGTH-1);
		memcpy(network_mask,&local_network_data.IpAddressList.IpMask.String,IPV4_IP_LENGTH-1);
		memcpy(gateway_ip,&local_network_data.GatewayList.IpAddress.String,IPV4_IP_LENGTH-1);

        unsigned long network_mask_=inet_addr(network_mask),local_ip_=inet_addr(local_ip);
        unsigned long network_session_=local_ip_&network_mask_;
        in_addr network_session___;
        network_session___.S_un.S_addr=network_session_;
        char* network_session__=inet_ntoa(network_session___);
		memcpy(network_session,network_session__,IPV4_IP_LENGTH-1);

        network_session_size=~htonl(network_mask_);

        network_session_=htonl(network_session_);
        network_session_+=network_session_size;
        network_session_=htonl(network_session_);
        network_session___.S_un.S_addr=network_session_;
        char* network_session_last_=inet_ntoa(network_session___);
		memcpy(network_session_last,network_session_last_,IPV4_IP_LENGTH-1);

		scan_arp(gateway_ip,(char*)gateway_mac);
	}
}

bool check_ip(const char* ip) {
    if (-1==inet_addr(ip))
        return false;
    return true;
}

void local_network_init(void) {
    WSADATA init;
    WSAStartup(2,&init);
    scan_arp_init();
    scan_tcp_init();
    scan_icmp_init();
    get_ip();
    get_local_network_information();
}

void local_network_clean(void) {
    scan_icmp_clean();
    scan_tcp_clean();
    scan_arp_clean();
    WSACleanup();
}

void sleep(unsigned int time) {
    Sleep(time);
}

bool get_host(const char* input_host,char* output_ip) {
    hostent* host=gethostbyname(input_host);
    if (NULL!=host) {
        char* copy_ip=inet_ntoa(*(in_addr*)host->h_addr_list[0]);
        memcpy(output_ip,copy_ip,IPV4_IP_LENGTH);
        return true;
    }
    return false;
}
