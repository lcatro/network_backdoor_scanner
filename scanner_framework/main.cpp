
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "local_network.h"
#include "network_crack.h"
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

enum execute_state {
    ERROR=0,
    OK,
    EXIT
};

static void default_tcp_scan_fake_ip_(string target_ip,unsigned int target_port,split_block_result fake_ip,string& output_information);
static void default_tcp_scan_fake_ip(string target_ip,split_block_result fake_ip,string& output_information);
static void default_tcp_scan_(string target_ip,unsigned int target_port,string& output_information);
static void default_tcp_scan (string target_ip,string& output_information);

static string control_ip;

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
                    //  using:crack %ip% %port% [-D %dictionary_path%] [-E %express%]
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

static execute_state execute_command(const string command,string& output_result) {
    if (!command.empty()) {
        split_block_result split(split_block(command," "));
        unsigned int result_length=split.size();
        output_result="ERROR!\r\n";

        if (result_length) {
            if (command_arplist==split[0]) {
                output_result="arp discover :\r\n";

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
                            output_result+="live:";
                            output_result+=machine_index_.c_str();
                            output_result+=" mac:";
                            output_result+=mac;
                            output_result+="\r\n";
                        }
                    }
                    return OK;
                }  //  WARNING! 没有补全

                return ERROR;
            } else if (command_network_information==split[0]) {
                char mac[0x20]={0};
                output_result="local network information :\r\n";
                output_result+="local_ip:";
                output_result+=local_ip;
                output_result+="\r\nlocal_mac:";
                sprintf(mac,"%X-%X-%X-%X-%X-%X",local_mac[0],local_mac[1],local_mac[2],local_mac[3],local_mac[4],local_mac[5]);
                output_result+=mac;
                output_result+="\r\nnetwork_mask:";
                output_result+=network_mask;
                output_result+="\r\ngateway_ip:";
                output_result+=gateway_ip;
                output_result+="\r\ngateway_mac:";
                sprintf(mac,"%X-%X-%X-%X-%X-%X",gateway_mac[0],gateway_mac[1],gateway_mac[2],gateway_mac[3],gateway_mac[4],gateway_mac[5]);
                output_result+=mac;
                output_result+="\r\ndhcp_server:";
                output_result+=dhcp_server;
                output_result+="\r\n";

                return OK;
            } else if (command_ping==split[0]) {
                if (2!=result_length) return ERROR;

                reply ping_reply;
                output_result="ping - target:";
                output_result+=split[1];
                output_result+="\r\n";

                if (scan_icmp(split[1].c_str(),&ping_reply)) {
                    output_result+="target live \r\n";
                    output_result+="ping count:";
                    output_result+=number_to_string(ping_reply.count);
                    output_result+="  ping lost:";
                    output_result+=number_to_string(ping_reply.lost);
                    output_result+="  ping average delay:";
                    output_result+=number_to_string(ping_reply.delay);
                    output_result+="\r\n";
                } else
                    output_result+="target dead \r\n";

                return OK;
            } else if (command_scan_port==split[0]) {
                string flag_port("-P"),flag_fake("-F");

                if (2==result_length) {
                    output_result="scan default port:\r\n";
                    default_tcp_scan(split[1],output_result);

                    return OK;
                } else if (3==result_length) {
                    string ip(split[1]);
                    split_result resolve_flag(split_string(split[2],":"));
                    string flag(resolve_flag.first),arg_list_string(separate_string(split[2],"[","]"));
                    split_block_result arg_list_(split_block(arg_list_string,","));

                    if (!flag.empty() && !arg_list_string.empty()) {

                        if (flag_port==flag) {
                            output_result="scan custom port:\r\n";

                            for (split_block_result::const_iterator iterator=arg_list_.begin();
                                                                    iterator!=arg_list_.end();
                                                                    ++iterator) {
                                unsigned int port=string_to_number(iterator->c_str());
                                default_tcp_scan_(ip,port,output_result);
                            }
                            return OK;
                        } else if (flag_fake==flag) {
                            output_result="scan port for fake ip:\r\n";
                            default_tcp_scan_fake_ip(ip,arg_list_,output_result);

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
                        output_result="scan custom port for fake ip:\r\n";

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
                            default_tcp_scan_fake_ip_(ip,port,fake_ip_list,output_result);
                        }
                        return OK;
                    }
                }

                return ERROR;
            } else if (command_flood==split[0]) {
            } else if (command_crack==split[0]) {
            } else if (command_tracert==split[0]) {
                tracert_list result=scan_icmp_tracert(split[1].c_str());
                unsigned int tracert_index=0;
                output_result="tracert route - target:";
                output_result+=split[1];
                output_result+="\r\n";

                for (tracert_list::const_iterator iterator=result.begin();
                                                  iterator!=result.end();
                                                  ++iterator,++tracert_index) {
                    string number=number_to_string(tracert_index);
                    output_result+=number;
                    output_result+=":";
                    output_result+=*iterator;
                    output_result+="\r\n";
                }

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
                    output_result="getpage port(";
                    output_result+=number_to_string(port_information.port);
                    output_result+=") page-length(";
                    output_result+=number_to_string(port_information.data_length);
                    output_result+=") pagedata:\r\n";
                    output_result+=port_information.data;
                    output_result+="\r\n";
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
                        output_result="route turn on => (remote ";
                        output_result+=remote_ip.c_str();
                        output_result+=":";
                        output_result+=number_to_string(remote_port);
                        output_result+=",local ";
                        output_result+=local_ip.c_str();
                        output_result+=":";
                        output_result+=number_to_string(local_port);
                        output_result+=")\r\n";

                        return OK;
                    }
                }

                return ERROR;
            } else if (command_help==split[0]) {
                output_result="help:\r\n";
                output_result+="扫描当前网段存活的主机,并且自动搜集数据\r\n";
                output_result+="using:arp\r\n";
                output_result+="获取当前主机的网络信息\r\n";
                output_result+="using:local\r\n";
                output_result+="测试主机是否连通\r\n";
                output_result+="TCP SYN 扫描主机\r\n";
                output_result+="using:scan %ip% [-P:[port1,port2,port3,...]] [-F:[fake_ip1,fake_ip2,...]]\r\n";
                output_result+="洪水攻击主机\r\n";
                output_result+="using:flood %ip% [-P:[port1,...]] [-F:[fake_ip1,...]]\r\n";
                output_result+="在线破解\r\n";
                output_result+="using:crack %ip% %port% [-D %dictionary_path%] [-E %express%]\r\n";
                output_result+="路由跟踪\r\n";
                output_result+="using:tracert %ip%\r\n";
                output_result+="抓取页面\r\n";
                output_result+="using:getpage %ip% [-PORT:%port%] [-PATH:%path%]\r\n";
                output_result+="启动端口转发功能\r\n";
                output_result+="using:route -R:[%remote_ip%,%remote_port%] -L:[[%local_ip%,]%local_port%]\r\n";
                output_result+="退出\r\n";
                output_result+="using:quit\r\n";

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

            if (EXIT==execute_command(command_buffer,output_infomation)) {
                printf("user exit!\n");
                goto EXIT;
            }
            printf("output:\n%s\n",output_infomation.c_str());
            memset(command_buffer,0,COMMAND_BUFFER_LENGTH);
        }
    } else {
        if (!strcmp(arg_list[1],LANUCH_COMMAND_BIND)) {
            //scanner.exe -bind | scanner.exe -bind %port%
            unsigned int tcp_handle=-1;
            unsigned int client_handle=-1;
            if (2==arg_count) {
                tcp_handle=scan_tcp_bind(DEFAULT_BIND_PORT);
                if (-1==tcp_handle) {
                    printf("create bind error!\n");
                    goto EXIT;
                }

                client_handle=scan_tcp_accept(tcp_handle);
                if (-1==client_handle) {
                    printf("accept connect error!\n");
                    scan_tcp_disconnect(tcp_handle);
                    goto EXIT;
                }
            } else if (3==arg_count) {
                tcp_handle=scan_tcp_bind(string_to_number(arg_list[2]));
                if (-1==tcp_handle) {
                    printf("create bind error!\n");
                    goto EXIT;
                }

                client_handle=scan_tcp_accept(tcp_handle);
                if (-1==client_handle) {
                    printf("accept connect error!\n");
                    scan_tcp_disconnect(tcp_handle);
                    goto EXIT;
                }
            } else {
                printf("use command \"-bind\":-bind or -bind %port%\n");
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

                if (EXIT==execute_command(command_buffer,output_infomation)) {
                    scan_tcp_disconnect(tcp_handle);
                    printf("user exit!\n");
                    goto EXIT;
                }
                unsigned send_length=output_infomation.length();
                char* send_buffer=new char[send_length];
                memcpy(send_buffer,output_infomation.c_str(),send_length);
                send_length=network_encode(send_buffer,send_length);
                scan_tcp_send(tcp_handle,send_buffer,send_length);
                delete send_buffer;
                memset(command_buffer,0,COMMAND_BUFFER_LENGTH);
            }
        }
        if (!strcmp(arg_list[1],LANUCH_COMMAND_REVERSE_CONNENT)) {
            string ip(arg_list[2]),port_("80");

            if (4==arg_count || 3==arg_count) {
                //scanner.exe -recon %ip% [%port%]
                if (4==arg_count)
                    port_=arg_list[3];
                unsigned short port=string_to_number(port_.c_str());
                unsigned int tcp_handle=scan_tcp_connect(ip.c_str(),port);

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

                        if (EXIT==execute_command(command_buffer,output_infomation)) {
                            scan_tcp_disconnect(tcp_handle);
                            printf("user exit!\n");
                            goto EXIT;
                        }
                        unsigned send_length=output_infomation.length();
                        char* send_buffer=new char[send_length];
                        memcpy(send_buffer,output_infomation.c_str(),send_length);
                        send_length=network_encode(send_buffer,send_length);
                        scan_tcp_send(tcp_handle,send_buffer,send_length);
                        delete send_buffer;
                        memset(command_buffer,0,COMMAND_BUFFER_LENGTH);
                    }
                } else {
                    printf("reverse tcp connect error!\n");
                    goto EXIT;
                }
            } else
                printf("using:scanner.exe -recon %%ip%% [%%port%%]\n");
        }
    }
    printf("ERR COMMAND!\n");

EXIT:
    local_network_clean();


    /* test module -- local_network.cpp scan_tcp.cpp
    local_network_init();

    printf("local_ip:%s\n",local_ip);
    printf("local_mac:%s\n",local_mac);
    printf("gateway_ip:%s\n",gateway_ip);
    printf("gateway_mac:%s\n",gateway_mac);
/*
    for (unsigned int index=70;index<=65535;++index) {
        if (scan_tcp(gateway_ip,index))
            printf("Port Open:%d\n",index);
        else
            printf("Port Down:%d\n",index);
    }

    scan_tcp_port_information test={0};
    if (scan_tcp_get_data("192.168.1.1",80,&test))
        printf("OK\n");
    else
        printf("ERROR\n");

    local_network_clean();
    */
    /* test module -- resolver_string.cpp

#define TEST_STRING "Hello world!:test"

    printf("find_string:source string:%s output:%d \n",TEST_STRING,find_string(TEST_STRING," "));
    split_result split(split_string(TEST_STRING,find_string(TEST_STRING," ")));
    printf("split_string:source string:%s output:left=%s right=%s \n",TEST_STRING,split.first.c_str(),split.second.c_str());
    string output_string(TEST_STRING);
    erase_string(output_string,find_string(TEST_STRING,"w"),7);
    printf("erase_string:source string:%s output:%s \n",TEST_STRING,output_string.c_str());
    printf("count_string:source string:%s output:%d \n",TEST_STRING,count_string(TEST_STRING,"l"));
    string output_left_string(TEST_STRING);
    left_move_string(output_left_string,6);
    printf("left_move_string:source string:%s output:%s \n",TEST_STRING,output_left_string.c_str());
    string output_rught_string(TEST_STRING);
    right_move_string(output_rught_string,6);
    printf("right_move_string:source string:%s output:%s \n",TEST_STRING,output_rught_string.c_str());
    printf("separate_string:source string:%s output:%s \n",TEST_STRING,separate_string(TEST_STRING," ","!").c_str());

#define TEST_SPACE_STRING "  TEST  "

    string test_left(TEST_SPACE_STRING);
    string test_right(TEST_SPACE_STRING);
    string test(TEST_SPACE_STRING);
    left_remote_space(test_left);
    printf("left_remote_space:%s|\n",test_left.c_str());
    right_remote_space(test_right);
    printf("right_remote_space:%s|\n",test_right.c_str());
    left_remote_space(test);
    right_remote_space(test);
    printf("all_remote:%s|\n",test.c_str());
    */
    /* test module -- resolver_http.cpp 

#define TEST_HTTP "GET /social/api/2.0/topic/info?callback=xnJSONP43195094&app_id=3629560&third_source_id=3629560 HTTP/1.1\r\n" \
                  "Host: openapi.baidu.com\r\n" \
                  "Connection: keep-alive\r\n" \
                  "Accept: *\r\n" \
                  "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.152 Safari/537.36\r\n" \
                  "Referer: http://blog.csdn.net/xywlpo/article/details/6458867\r\n" \
                  "Accept-Encoding: gzip, deflate, sdch\r\n" \
                  "Accept-Language: zh-CN,zh;q=0.8\r\n" \
                  "Cookie: BIDUPSID=91D3B032890586777BD77FFAEE53BA56; PSTM=1433413904; BDUSS=5PTW1DTVdxNXVGYUp4ZmNZVzRzaUlIWThRakNOcUhLdzhHaDhvdXJuM3A2WjlWQVFBQUFBJCQAAAAAAAAAAAEAAADCMpgaTENhdHJvAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOlceFXpXHhVc2; BAIDUID=BFE4E7C0060B706AE31730D400C2233C:FG=1; H_PS_PSSID=12609_14802_1442_14412_14497_14510_14444_14734_12824_10213_12867_14622_13201_14669_12722_14547_14625_14485_11803_13935_14181_10633\r\n" \
                  "\r\n" \
                  "\r\n"

    http_packet packet(resolve_http_to_packet(TEST_HTTP));
    printf("resolve_http_get_element_count element count:%d\n",resolve_http_get_element_count(packet));
    resolve_http_set_element(packet,HTTP_CONTEXT,"<html>Hello world!</html>");
    string result(resolve_http_to_string(packet));
    printf("resolve_http_to_string:\n%s\n",result.c_str());
    */
    /* test module -- resolver_html.cpp 

#define TEST_HTML "<html><body><form method=\"post\" action=\"test.php\"><input type=\"submit\" value=\"\" /></form></body></html>" 

    printf("separate_string:%s\n",separate_string(TEST_HTML,1,4).c_str());

    tag html_tag(resolve_html_to_tag(TEST_HTML));
    printf("resolve_html_to_tag:%s\n",resolve_html_get_tag_name(html_tag).c_str());
    printf("resolve_html_get_tag_subtag:\n%s\n",resolve_html_get_tag_subtag(html_tag).c_str());
    printf("resolve_html_to_string:\n%s\n\n\n",resolve_html_to_string(html_tag).c_str());

    tag body(resolve_html_to_tag(html_tag));
    printf("resolve_html_to_tag:%s\n",resolve_html_get_tag_name(body).c_str());
    printf("resolve_html_get_tag_subtag:\n%s\n\n\n",resolve_html_get_tag_subtag(body).c_str());
    printf("resolve_html_to_string:\n%s\n",resolve_html_to_string(body).c_str());

    tag form(resolve_html_to_tag(body));
    printf("resolve_html_to_tag:%s\n",resolve_html_get_tag_name(form).c_str());
    printf("resolve_html_get_tag_subtag:\n%s\n\n\n",resolve_html_get_tag_subtag(form).c_str());
    printf("resolve_html_to_string:\n%s\n",resolve_html_to_string(form).c_str());
    unsigned int count=resolve_html_get_tag_element_count(form);
    printf("resolve_html_get_tag_element_count:%d\n",count);
    tag_element_list element_list=resolve_html_get_tag_element_list(form);
    for (unsigned int index=0;index<count;++index)
        printf("resolve_html_get_tag_element_list:index:%d name:%s value:%s\n",index,element_list[index].c_str(),resolve_html_get_tag_element(form,element_list[index]).c_str());
    */
    /* test module -- resolver_express.cpp 
#define TEST_HTTP "Host: %string%,Connection: keep-alive,Accept: %string%,Cookie: BIDUPSID=91D33;www.baidu.com,TEST_LINK"

    printf("resolve_express_http:\n%s\n",resolve_express_http("accept:%string%,test:123,test2:%value%;fuck,4321").c_str());
    printf("resolve_express_http:\n%s\n",resolve_express_http(TEST_HTTP).c_str());
    printf("resolve_express_function:%s\n",resolve_express_function("rnd([rnd([20-40])-rnd([100-200])])").c_str());
    

    network_crack_http("192.168.1.1",80,resolve_dictionary_open("C:\123.txt","C:\123.txt"),"username:%username%,password:%password%","success");*/
}

static void default_tcp_scan_(string target_ip,unsigned int target_port,string& output_information) {
    output_information+=number_to_string(target_port);
    output_information+=":";
    if (scan_tcp(target_ip.c_str(),target_port))
        output_information+="open\r\n";
    else
        output_information+="close\r\n";
}

static void default_tcp_scan_fake_ip_(string target_ip,unsigned int target_port,split_block_result fake_ip,string& output_information) {
    for (split_block_result::const_iterator iterator=fake_ip.begin();
                                            iterator!=fake_ip.end();
                                            ++iterator) {
        scan_tcp_fake_ip(target_ip.c_str(),target_port,iterator->c_str(),SCAN_TCP_PORT);
    }
    default_tcp_scan_(target_ip,target_port,output_information);
}

static void default_tcp_scan(string target_ip,string& output_information) {
    // 80,8080,3128,8081,9080,1080,21,23,443,69,22,25,110,7001,9090,3389,1521,1158,2100,1433,135,139,445,1025
    default_tcp_scan_(target_ip,22,output_information);
    default_tcp_scan_(target_ip,23,output_information);
    default_tcp_scan_(target_ip,25,output_information);
    default_tcp_scan_(target_ip,69,output_information);
    default_tcp_scan_(target_ip,80,output_information);
    default_tcp_scan_(target_ip,110,output_information);
    default_tcp_scan_(target_ip,135,output_information);
    default_tcp_scan_(target_ip,139,output_information);
    default_tcp_scan_(target_ip,443,output_information);
    default_tcp_scan_(target_ip,445,output_information);
    default_tcp_scan_(target_ip,1025,output_information);
    default_tcp_scan_(target_ip,1080,output_information);
    default_tcp_scan_(target_ip,1158,output_information);
    default_tcp_scan_(target_ip,1433,output_information);
    default_tcp_scan_(target_ip,1521,output_information);
    default_tcp_scan_(target_ip,2100,output_information);
    default_tcp_scan_(target_ip,3128,output_information);
    default_tcp_scan_(target_ip,3389,output_information);
    default_tcp_scan_(target_ip,7001,output_information);
    default_tcp_scan_(target_ip,8080,output_information);
    default_tcp_scan_(target_ip,8081,output_information);
    default_tcp_scan_(target_ip,9080,output_information);
    default_tcp_scan_(target_ip,9090,output_information);
}

static void default_tcp_scan_fake_ip(string target_ip,split_block_result fake_ip,string& output_information) {
    default_tcp_scan_fake_ip_(target_ip,22,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,23,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,25,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,69,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,80,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,110,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,135,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,139,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,443,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,445,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,1025,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,1080,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,1158,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,1433,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,1521,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,2100,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,3128,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,3389,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,7001,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,8080,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,8081,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,9080,fake_ip,output_information);
    default_tcp_scan_fake_ip_(target_ip,9090,fake_ip,output_information);
}
