
#pragma warning (disable:4786)

#include <memory.h>

#include <windows.h>
#include <winsock.h>

#include "scan_icmp.h"

#define ICMP_TTL_TRANSIT 11013

typedef unsigned long IPAddr;

typedef struct ip_option_information {
  UCHAR  Ttl;
  UCHAR  Tos;
  UCHAR  Flags;
  UCHAR  OptionsSize;
  PUCHAR OptionsData;
} IP_OPTION_INFORMATION, *PIP_OPTION_INFORMATION;

typedef struct icmp_echo_reply {
  IPAddr                       Address;
  ULONG                        Status;
  ULONG                        RoundTripTime;
  USHORT                       DataSize;
  USHORT                       Reserved;
  PVOID                        Data;
  struct ip_option_information  Options;
} ICMP_ECHO_REPLY, *PICMP_ECHO_REPLY;

typedef DWORD  (__stdcall *IcmpSendEcho)(HANDLE,IPAddr,LPVOID,WORD,PIP_OPTION_INFORMATION,LPVOID,DWORD,DWORD);
typedef HANDLE (__stdcall *IcmpCreateFile)(void);
typedef BOOL   (__stdcall *IcmpCloseHandle)(HANDLE);

static HMODULE lModl=NULL;

static IcmpCreateFile  fIcmpCreateFile=NULL;
static IcmpSendEcho    fIcmpSendEcho=NULL;
static IcmpCloseHandle fIcmpCloseHandle=NULL;
static HANDLE          fHandle=INVALID_HANDLE_VALUE;

bool scan_icmp_init(void) {
    lModl=(HMODULE)LoadLibrary ("iphlpapi.dll");
    if (lModl==NULL)
        return false;
    else{
        fIcmpCreateFile=(IcmpCreateFile)GetProcAddress (lModl,"IcmpCreateFile");
        fIcmpSendEcho=(IcmpSendEcho)GetProcAddress (lModl,"IcmpSendEcho");
        fIcmpCloseHandle=(IcmpCloseHandle)GetProcAddress (lModl,"IcmpCloseHandle");
        if (fIcmpCreateFile==NULL || fIcmpSendEcho==NULL || fIcmpCloseHandle==NULL)
            return false;
        
        fHandle=fIcmpCreateFile();
        return true;
    }
}

bool scan_icmp(const char* target_ip,reply* output_information) {
    IPAddr pAddr;
    pAddr=(IPAddr)inet_addr ((char *)target_ip);
    icmp_echo_reply pData;
    memset(&pData,0,sizeof(icmp_echo_reply));
    bool Rtn=false;
    int state=0;
    reply output={0};
    output.count=ICMP_PING_LOOP_COUNT;

	for (int i=0;i<output.count;++i) {
	    DWORD result=fIcmpSendEcho(fHandle,pAddr,NULL,0,NULL,(LPVOID)&pData,sizeof(icmp_echo_reply),ICMP_PING_TIMEOUT);

        if (!pData.Status && 1==result) {
            ++state;
            output.delay+=pData.RoundTripTime;
        } else
            ++output.lost;
	}
    if (output.count==output.lost)
        output.delay=-1;
    else
        output.delay/=(output.count-output.lost);

    if (NULL!=output_information)
        memcpy(output_information,&output,sizeof(output));
	if (state>=2) Rtn=true;

    return Rtn;
}

tracert_list scan_icmp_tracert(const char* target_ip) {
    tracert_list result;
    IPAddr target_addr=(IPAddr)inet_addr(target_ip);
    icmp_echo_reply reply={0};
    ip_option_information icmp_options;
    icmp_options.Flags=0;
    icmp_options.OptionsData=NULL;
    icmp_options.OptionsSize=0;
    icmp_options.Tos=0;
    unsigned int lost_ping_index=0;

    for (unsigned index=1;index<=255;++index) {
        icmp_options.Ttl=index;
	    fIcmpSendEcho(fHandle,target_addr,NULL,0,&icmp_options,(LPVOID)&reply,sizeof(icmp_echo_reply),ICMP_PING_TIMEOUT);

        in_addr addr;
        addr.S_un.S_addr=reply.Address;
        if (ICMP_TTL_TRANSIT==reply.Status) {
            result.push_back(inet_ntoa(addr));
            lost_ping_index=0;
        } else if (!reply.Status) {
            result.push_back(inet_ntoa(addr));
            break;
        } else {
            result.push_back("*");
            ++lost_ping_index;

            if (lost_ping_index>=6)
                break;
        }
    }
    return result;
}

void scan_icmp_clean(void) {
    fIcmpCloseHandle(fHandle);
	FreeLibrary (lModl);
	lModl=NULL;
    fIcmpCreateFile   =NULL;
    fIcmpSendEcho     =NULL;
    fIcmpCloseHandle  =NULL;
}
