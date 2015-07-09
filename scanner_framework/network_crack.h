
#ifndef _NETWORK_CRACK_H__
#define _NETWORK_CRACK_H__

#include "resolver_dictionary.h"
#include "resolver_http.h"

#ifndef _STRING_

#include <string>

using std::string;
using std::pair;

#endif

#ifndef _VECTOR_

#include <vector>

using std::vector;

#endif

#define NETWORK_CRACK_TIMEOUT 5000
#define NETWORK_CRACK_RECV_BUFFER_LENGTH 1024*10


typedef vector<string> crack_packet_raw;
typedef vector<http_packet> crack_packet_http;
typedef pair<string,string> crack_index;

crack_packet_raw network_crack_init(const string crack_packet,...);
crack_packet_http network_crack_init(const http_packet& crack_packet,...);

crack_index network_crack_online(const string target_ip,const unsigned int target_port,const crack_packet_raw& crack_packet,const string crack_term,bool first_recv);
crack_index network_crack_online(const string target_ip,const unsigned int target_port,const crack_packet_http& crack_packet,const string crack_term,bool first_recv);

crack_index network_crack_telnet(const string target_ip,const unsigned int target_port,const dictionary& crack_dictionary);
crack_index network_crack_http(const string target_ip,const unsigned int target_port,dictionary crack_dictionary,const string crack_express,const string crack_term);


#endif

