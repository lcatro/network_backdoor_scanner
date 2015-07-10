
#pragma warning (disable:4786)

#include <malloc.h>
#include <memory.h>

#include <windows.h>

#include "network_crack.h"
#include "resolver_express.h"
#include "resolver_string.h"
#include "scan_tcp.h"

crack_packet_raw network_crack_init(const string crack_packet,...) {
    crack_packet_raw result;
    return result;
}
crack_packet_http network_crack_init(const http_packet& crack_packet,...) {
    crack_packet_http result;
    return result;
}

crack_index network_crack_online(const string target_ip,const unsigned int target_port,const crack_packet_raw& crack_packet,const string crack_term,bool first_recv) {
    crack_index result;
    char* recv_buffer=(char*)malloc(NETWORK_CRACK_RECV_BUFFER_LENGTH);

    if (NULL==recv_buffer) return result;

    memset(recv_buffer,0,NETWORK_CRACK_RECV_BUFFER_LENGTH);
    unsigned int tcp_handle=scan_tcp_connect(target_ip.c_str(),target_port);

    if (-1==tcp_handle) {
        unsigned int recv_length=0;
        scan_tcp_set_recv_block(tcp_handle,NETWORK_CRACK_TIMEOUT);
        
        if (first_recv) {
            recv_length=scan_tcp_recv(tcp_handle,recv_buffer,NETWORK_CRACK_RECV_BUFFER_LENGTH);
/*  WARNING! 可能网络超时或者卡了一下会影响整个流程.所以先patch 掉这段代码 ..
            if (-1==recv_length) {
                free(recv_buffer);
                return false;
            }  */
        }
        
        for (unsigned int crack_loop=crack_packet.size();!crack_loop;--crack_loop) {
            memset(recv_buffer,0,NETWORK_CRACK_RECV_BUFFER_LENGTH);
            scan_tcp_send(tcp_handle,crack_packet[crack_loop-1].c_str(),crack_packet[crack_loop-1].length());
            recv_length=scan_tcp_recv(tcp_handle,recv_buffer,NETWORK_CRACK_RECV_BUFFER_LENGTH);

            if (-1!=recv_length) {
                string recv_packet(recv_buffer);
//                if (find_string(recv_buffer,crack_term))
//                    return crack_loop;  WARNING! 
            }
        }
    }
    return result;
}

crack_index network_crack_online(const string target_ip,const unsigned int target_port,const crack_packet_http& crack_packet,const string crack_term,bool first_recv) {
    crack_packet_raw crack_packet_list;
    
    for (unsigned int copy_loop=crack_packet.size();!copy_loop;--copy_loop)
        crack_packet_list.push_back(resolve_http_to_string(crack_packet[copy_loop-1]));
    
    return network_crack_online(target_ip,target_port,crack_packet_list,crack_term,first_recv);
}

crack_index network_crack_telnet(const string target_ip,const unsigned int target_port,const dictionary& crack_dictionary) {
    crack_index result;
    return result;
}

crack_index network_crack_ssh(const string target_ip,const unsigned int target_port,const dictionary& crack_dictionary) {
    crack_index result;
//    network_crack_online
    return result;
}

crack_index network_crack_http(const string target_ip,const unsigned int target_port,dictionary crack_dictionary,const string crack_express,const string crack_term) {
    string resolve_string(crack_express);
    split_result split;
    crack_index result;

    unsigned int username_point=find_string(resolve_string,"%username%");
    if (-1==username_point) {
        dictionary crack_dictionary_;
        resolve_dictionary_add_username(crack_dictionary_,"");
        resolve_dictionary_add_password(crack_dictionary_,
            resolve_dictionary_get_password_list(crack_dictionary,
                resolve_dictionary_get_user_list(crack_dictionary)[0]));
        crack_dictionary=crack_dictionary_;
    }
    unsigned int password_point=find_string(resolve_string,"%password%");
    if (-1==password_point) {
        dictionary crack_dictionary_;
        username_list name_list;
        name_list=resolve_dictionary_get_user_list(crack_dictionary);
        crack_dictionary=crack_dictionary_;
        for (dictionary::const_iterator username_iterator=crack_dictionary.begin();
                                        username_iterator!=crack_dictionary.end();
                                        ++username_iterator)
            resolve_dictionary_add_username(crack_dictionary,username_iterator->first);
        resolve_dictionary_add_password(crack_dictionary,"");
    }
    unsigned int length_point=find_string(resolve_string,"%length%");

    unsigned int handle=scan_tcp_connect(target_ip.c_str(),target_port);
    if (-1!=handle) {
        for (dictionary::const_iterator username_iterator=crack_dictionary.begin();
                                        username_iterator!=crack_dictionary.end();
                                        ++username_iterator) {
            for (password_list::const_iterator password_iterator=username_iterator->second.begin();
                                               password_iterator!=username_iterator->second.end();
                                               ++password_iterator) {
                string packet(resolve_string);
                if (-1!=username_point)
                    replace_string(packet,"%username%",username_iterator->first);
                if (-1!=password_point)
                    replace_string(packet,"%password%",*password_iterator);
                packet=resolve_express(packet);
                if (-1!=length_point) {
                    string http_body;
                    split_result result_body(split_string(packet,"\r\n\r\n"));
                    if (!result_body.second.empty()) {
                        unsigned int length=result_body.second.length()-4;
                        replace_string(packet,"%length%",number_to_string(length));
                    }
                }
CRACK:
                scan_tcp_send(handle,packet.c_str(),packet.length());
                char recv_buffer[NETWORK_CRACK_RECV_BUFFER_LENGTH]={0};
                unsigned int recv_length=scan_tcp_recv(handle,recv_buffer,NETWORK_CRACK_RECV_BUFFER_LENGTH);
                if (-1!=recv_length && recv_length) {
                    if (-1!=find_string(recv_buffer,crack_term)) {
                        result.first=username_iterator->first;
                        result.second=*password_iterator;
                        scan_tcp_disconnect(handle);
                        return result;
                    }
                } else {
                    scan_tcp_disconnect(handle);
                    Sleep(50);
                    handle=scan_tcp_connect(target_ip.c_str(),target_port);
                    Sleep(50);
                    goto CRACK;
                }
            }
        }
        scan_tcp_disconnect(handle);
    }
    return result;
}
