
#ifndef _RESOLVER_HTTP_H__
#define _RESOLVER_HTTP_H__

#ifndef _STRING_

#include <string>

using std::string;

#endif

#ifndef _PAIR_
#define _PAIR_

using std::pair;

#endif

#ifndef _MAP_

#include <map>

using std::map;

#endif

#ifndef _VECTOR_

#include <vector>

using std::vector;

#endif


#define HTTP_HEADER_MODE    "HTTP_MODE"
#define HTTP_HEADER_PATH    "HTTP_PATH"
#define HTTP_HEADER_VERSION "HTTP_VERSION"
#define HTTP_CONTEXT        "HTTP_CONTEXT"

typedef map<string,string> http_packet;
typedef vector<string> http_packet_element_list;

http_packet              resolve_http_to_packet(const string http_header_string);
string                   resolve_http_to_string(const http_packet& output_packet);
http_packet              resolve_http_combind(const http_packet& http_packet_1,const http_packet& http_packet_2);

unsigned int             resolve_http_get_element_count(const http_packet& output_packet);
http_packet_element_list resolve_http_get_element_list(const http_packet& output_packet);
string                   resolve_http_get_element(const http_packet& output_packet,const string element_name);
void                     resolve_http_set_element(http_packet& output_packet,const string element_name,const string element_value);
void                     resolve_http_delete_element(http_packet& output_packet,const string element_name);

#endif
