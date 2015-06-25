
#pragma warning (disable:4786)

#include <malloc.h>
#include <memory.h>

#include "network_crack.h"
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
    char* recv_buffer=(char*)malloc(NETWORK_CRACK_RECV_BUFFER_LENGTH);

    if (NULL==recv_buffer) return -1;

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
                if (find_string(recv_buffer,crack_term))
                    return crack_loop;
            }
        }
    }
    return -1;
}

crack_index network_crack_online(const string target_ip,const unsigned int target_port,const crack_packet_http& crack_packet,const string crack_term,bool first_recv) {
    crack_packet_raw crack_packet_list;
    
    for (unsigned int copy_loop=crack_packet.size();!copy_loop;--copy_loop)
        crack_packet_list.push_back(resolve_http_to_string(crack_packet[copy_loop-1]));
    
    return network_crack_online(target_ip,target_port,crack_packet_list,crack_term,first_recv);
}

crack_index network_crack_telnet(const string target_ip,const unsigned int target_port,const dictionary& crack_dictionary) {
    return false;
}

crack_index network_crack_ssh(const string target_ip,const unsigned int target_port,const dictionary& crack_dictionary) {
//    network_crack_online
    return false;
}

crack_index network_crack_http(const string target_ip,const unsigned int target_port,const dictionary& crack_dictionary,const string crack_express,const string crack_term) {
    string express,resolve_string(crack_express);
    split_result split;
    
    while (-1!=find_string(resolve_string,"%username%") || -1!=find_string(resolve_string,"%password%")) {
        split=split_string(resolve_string,"%");
        express+=split.first;
        express+="%string%,";
        split=split_string(split.second,",");
        left_move_string(split.second,1);
        resolve_string=split.second;
    }
    if (!express.empty()) {
        express=express.substr(0,express.length()-1);
        express+=";";
        resolve_string=express;

    }

    return false;
}
