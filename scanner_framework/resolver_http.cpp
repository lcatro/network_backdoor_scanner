
#pragma warning (disable:4786)

#include "resolver_http.h"
#include "resolver_string.h"

#define HTTP_HEADER_LINE "\r\n"
#define HTTP_HEADER_END  "\r\n\r\n"

unsigned int resolve_http_get_element_count(const http_packet& output_packet) {
    return output_packet.size();
}

http_packet_element_list resolve_http_get_element_list(const http_packet& output_packet) {
    http_packet_element_list list;
    for (http_packet::const_iterator iterator=output_packet.begin();
         iterator!=output_packet.end();
         ++iterator)
        list.push_back(iterator->first);
    return list;
}

string resolve_http_get_element(const http_packet& output_packet, string element_name) {
    http_packet::const_iterator find_iterator=output_packet.find(element_name);
    if (find_iterator!=output_packet.end())
        return find_iterator->second;
    return "";
}

void resolve_http_set_element(http_packet& output_packet,const string element_name,const string element_value) {
    output_packet[element_name]=element_value;
}

void resolve_http_delete_element(http_packet& output_packet,const string element_name) {
    http_packet::const_iterator find_iterator=output_packet.find(element_name);
    if (find_iterator!=output_packet.end())
        output_packet.erase(element_name);
}

http_packet resolve_http_to_packet(const string http_header_string) {
    http_packet result;
 
    split_result split(split_string(http_header_string,find_string(http_header_string,HTTP_HEADER_END)));
    string resolve_string(split.first);

    while (true) {
        split_result line(split_string(resolve_string,find_string(resolve_string,HTTP_HEADER_LINE)));

        if (-1!=find_string(line.first,"HTTP/")) {
            split_result http_information(split_string(line.first,find_string(line.first," ")));
            string http_mode(http_information.first);
            left_remove_space(http_information.second);
            http_information=split_string(http_information.second,find_string(http_information.second," "));
            string http_path(http_information.first);
            left_remove_space(http_information.second);
            left_move_string(http_information.second,5);
            right_remove_space(http_information.second);
            string http_version(http_information.second);
            resolve_http_set_element(result,HTTP_HEADER_MODE,http_mode);
            resolve_http_set_element(result,HTTP_HEADER_PATH,http_path);
            resolve_http_set_element(result,HTTP_HEADER_VERSION,http_version);
            left_move_string(line.second,2);
            resolve_string=line.second;
            continue;
        }

        split_result element(split_string(line.first,find_string(line.first,":")));
        left_move_string(element.second,1);
        left_remove_space(element.second);
        right_remove_space(element.second);
        left_remove_space(element.first);
        right_remove_space(element.first);
        resolve_http_set_element(result,element.first,element.second);
        left_move_string(line.second,2);
        resolve_string=line.second;
        if (-1==find_string(resolve_string,HTTP_HEADER_LINE)) {
            element=split_string(resolve_string,find_string(line.first,":"));
            left_remove_space(element.second);
            right_remove_space(element.second);
            resolve_http_set_element(result,element.first,element.second);
            break;
        }
    }
    return result;
}

string resolve_http_to_string(const http_packet& input_packet) {
    if (input_packet.empty()) return "";
    string null_string,string_mode(HTTP_HEADER_MODE),string_path(HTTP_HEADER_PATH),string_version(HTTP_HEADER_VERSION),string_context(HTTP_CONTEXT);

    if (null_string==resolve_http_get_element(input_packet,HTTP_HEADER_MODE) ||
        null_string==resolve_http_get_element(input_packet,HTTP_HEADER_PATH) ||
        null_string==resolve_http_get_element(input_packet,HTTP_HEADER_VERSION)) return "";

    string result,context;
    unsigned int element_count=resolve_http_get_element_count(input_packet);
    http_packet_element_list element(resolve_http_get_element_list(input_packet));

    result=resolve_http_get_element(input_packet,HTTP_HEADER_MODE);
    result+=" ";
    result+=resolve_http_get_element(input_packet,HTTP_HEADER_PATH);
    result+=" HTTP/";
    result+=resolve_http_get_element(input_packet,HTTP_HEADER_VERSION);
    result+=HTTP_HEADER_LINE;

    for (unsigned int index=0;index<element_count;++index) {
        if (string_mode==element[index] || string_path==element[index] || string_version==element[index]) continue;
        if (string_context==element[index]) context=resolve_http_get_element(input_packet,element[index]);
        result+=element[index];
        result+=": ";
        result+=resolve_http_get_element(input_packet,element[index]);
        result+=HTTP_HEADER_LINE;
    }

    result+=HTTP_HEADER_END;

    if (!context.empty()) result+=context;

    return result;
}

http_packet resolve_http_combind(const http_packet& http_packet_1,const http_packet& http_packet_2) {
    http_packet result;
    unsigned int http_packet_1_length=resolve_http_get_element_count(http_packet_1);
    unsigned int http_packet_2_length=resolve_http_get_element_count(http_packet_2);

    if (-1!=http_packet_1_length && -1!=http_packet_2_length) {
        http_packet_element_list http_packet_element_list_1(resolve_http_get_element_list(http_packet_1));
        http_packet_element_list http_packet_element_list_2(resolve_http_get_element_list(http_packet_2));

        for (unsigned int index=0;index<http_packet_1_length;++index)
            resolve_http_set_element(result,http_packet_element_list_1[index],resolve_http_get_element(http_packet_1,http_packet_element_list_1[index]));
        for (index=0;index<http_packet_2_length;++index)
            resolve_http_set_element(result,http_packet_element_list_2[index],resolve_http_get_element(http_packet_2,http_packet_element_list_2[index]));
    }
    return result;
}
