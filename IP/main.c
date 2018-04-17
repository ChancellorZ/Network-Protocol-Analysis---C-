#include "pcap.h"
#include <string.h>
#include<arpa/inet.h>
#include <stdio.h>

struct ether_header
{
    u_int8_t ether_dhost[6];

    u_int8_t ether_shost[6];
    /**/
    u_int16_t ether_type;
};
/*网络掩码*/
bpf_u_int32 net_mask;
/*网络地址*/
bpf_u_int32 net_ip;

typedef u_int32_t in_addr_t;

char s_net_ip[20], s_net_mask[20];
//网络号及其掩码

struct ip_header
{
#ifdef WORDS_BIGENDIAN
    u_int8_t ip_version:4;/*IP版本*/
    ip_header_length:4;/*IP首部长度*/
#else
    u_int8_t ip_header_length:4,ip_version:4;
#endif
    /*TOS服务质量*/
    u_int8_t ip_tos;
    /*总长度*/
    u_int16_t ip_length;
    /*标识*/
    u_int16_t ip_id;
   /*偏移*/
    u_int16_t ip_off;
    /*生存空间*/
    u_int8_t ip_ttl;
    /*协议类型*/
    u_int8_t ip_protocol;
    /*校验和*/
    u_int16_t ip_checksum;
    /*源IP地址*/
    struct in_addr ip_source_address;
    /*目的IP地址*/
    struct in_addr ip_destination_address;

};

struct arp_header
{
    //硬件类型
    u_int16_t arp_hardware_type;
    //协议类型
    u_int16_t arp_protocol_type;
    //硬件地址长度
    u_int8_t arp_hardware_length;
    //协议地址长度
    u_int8_t arp_protocol_length;
    //操作码
    u_int16_t operation_code;
    //源以太网地址
    u_int8_t arp_source_ethernet_adress[6];
    //源以太网IP地址
    u_int8_t arp_source_ip_address[4];
    //目的以太网地址
    u_int8_t arp_destination_ethernet_address[6];
    //目的以太网IP地址
    u_int8_t arp_destination_ip_address[4];

};

struct udp_header
{
    /*源端口号*/
    u_int16_t udp_source_port;
    /*目的端口号*/
    u_int16_t udp_destination_port;
    /*长度*/
    u_int16_t udp_length;
    /*校验和*/
    u_int16_t udp_checksum;
};

void arp_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
    //arp协议头
    struct arp_header *arp_protocol;
    //协议类型
    u_short protocol_type;
    //硬件类型
    u_short hardware_type;
    //操作码
    u_short operation_code;
    //mac地址
    u_char *mac_string;
    //源IP地址
    struct in_addr source_ip_address;
    //目的IP地址
    struct in_addr destination_ip_address;
    //硬件地址长度（这里默指以太网的地址长度）
    u_char hardware_length;
    //协议地址长度
    u_char protocol_length;
    printf("当前时间戳：%ld\n",packet_header->ts.tv_sec);
    printf("--------    ARP Protocol (Network Layer)    --------\n");
    //提示，以太网头部14个字节
    arp_protocol =(struct arp_header*)(packet_content + 14);

    hardware_type = ntohs(arp_protocol->arp_hardware_type);

    protocol_type = ntohs(arp_protocol->arp_protocol_type);

    operation_code = ntohs(arp_protocol->operation_code);

    hardware_length =arp_protocol->arp_hardware_length;

    protocol_length = arp_protocol->arp_protocol_length;

    printf("ARP 硬件类型为:%d\n",hardware_type);

    printf("ARP 协议类型为:%d\n",protocol_type);

    printf("ARP 硬件地址长度:%d\n",hardware_length);

    printf("ARP 协议地址长度:%d\n",protocol_length);

    printf("ARP 操作码:%d\n",operation_code);

    switch(operation_code)
    {
        case 1:
            printf("ARP 请求协议\n");
            break;

        case 2:
            printf("ARP 回复协议\n");
            break;

        case 3:
            printf("RARP 请求协议\n");
            break;

        case 4:
            printf("RARP 回复协议\n");
            break;

        default:
            break;
    }
    printf("源以太网地址是:\n");

    mac_string = arp_protocol->arp_source_ethernet_adress;

    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));

    memcpy((void*)&source_ip_address,(void*)&arp_protocol->arp_source_ip_address,sizeof(struct in_addr));

    printf("源IP地址是:%s\n",inet_ntoa(source_ip_address));

    //char FAR * inet_ntoa(struct in_addr in);

    printf("目的以太网地址是:\n");

    mac_string = arp_protocol->arp_destination_ethernet_address;

    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));

    memcpy((void*)&destination_ip_address,(void*)&arp_protocol->arp_destination_ip_address,sizeof(struct in_addr));

    printf("目的IP地址是:%s\n",inet_ntoa(destination_ip_address));

    argument++;

}

void udp_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
    /*UDP协议数据变量*/
    struct udp_header *udp_protocol;
    /*源端口号*/
    u_short source_port;
    /*目的端口号*/
    u_short destination_port;
    /*长度*/
    u_short length;
    /*获得udp协议数据内容*/
    udp_protocol = (struct udp_header*)(packet_content+14+20);
    /*获得源端口号*/
    source_port = ntohs(udp_protocol->udp_source_port);
    /*获得目的端口号*/
    destination_port = ntohs(udp_protocol->udp_destination_port);
    /*获取长度*/
    length = ntohs(udp_protocol->udp_length);

    printf("当前时间戳：%ld\n",packet_header->ts.tv_sec);
    printf("---------   UDP Protocol (Transport Layer)   ---------\n");
    printf("源端口:%d\n",source_port);
    printf("目的端口号:%d\n",destination_port);
    switch(destination_port)
    {
        case 138:/*数据报服务*/
            printf("NETBIOS Datagram Service\n");
            break;

        case 137:/*名字服务*/
            printf("NETBIOS Name Service\n");
            break;

        case 139:/*会话服务*/
            printf("NETBIOS session Service\n");
            break;

        case 53:/*上层服务为域名服务*/
            printf("name-domain server");
            break;

        default:
            break;

    }
    printf("长度:%d\n",length);
    printf("校验和:%d\n",ntohs(udp_protocol->udp_checksum));
    argument=argument+1;
}

/**/
void ip_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
    struct ip_header *ip_protocol;
    /*IP协议变量*/
    u_int header_length;
    /*首部长度*/
    u_int offset;
    /*偏移*/
    u_char tos;
    /*服务质量*/
    u_int16_t checksum;
    ip_protocol=(struct ip_header*)(packet_content+14);
    /*校验和*/
    checksum=ntohs(ip_protocol->ip_checksum);
    /*头部长度*/
    header_length=ip_protocol->ip_header_length *4;
    /*服务质量*/
    tos=ip_protocol->ip_tos;
    /*片偏移*/
    offset=ntohs(ip_protocol->ip_off);
    printf("当前时间戳：%ld\n",packet_header->ts.tv_sec);
    printf("---------   IP Protocol (Network Layer)   ---------\n");
    printf("IP 版本:%d\n",ip_protocol->ip_version);
    printf("头部长度:%d\n",header_length);
    printf("服务质量:%d\n",tos);
    printf("总长度:%d\n",ntohs(ip_protocol->ip_length));
    /**/
    printf("标识:%d\n",ntohs(ip_protocol->ip_id));
    /**/
    printf("片偏移:%d\n",(offset &0x1fff) *8);
    printf("生存时间:%d\n",ip_protocol->ip_ttl);
    /*TTL*/
    printf("协议类型:%d\n",ip_protocol->ip_protocol);
    /**/


    switch(ip_protocol->ip_protocol)/**/
    {
    case 6:
        printf("传输层协议是 TCP 协议\n");
        //printf("The Transport Layer Protocol is TCP\n");
        break;
    case 17:
        printf("传输层协议是 UDP 协议\n");
        //udp_protocol_packet_callback(argument,packet_header,packet_content);
        break;
    case 1:
        printf("传输层协议是 ICMP 协议\n");
        printf("The Transport Layer Protocol is ICMP\n");
        break;
    default:
        break;
    }
    printf("首部校验和:%d\n",checksum);
    printf("源IP地址:%s\n",inet_ntoa(ip_protocol->ip_source_address));
    printf("目的IP地址:%s\n",inet_ntoa(ip_protocol->ip_destination_address));
    argument=argument+1;
}
/**/

void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)
{
    //以太网类型
    u_short ethernet_type;
    //以太网协议头部
    struct ether_header *ethernet_protocol;
    //mac地址
    u_char *mac_string;

    static int packet_number = 1;

    printf("****************************************************\n");

    sprintf(s_net_ip,"%.3d %.3d %.3d",(net_ip%256),(net_ip/256%256),(net_ip/256/256));

    sprintf(s_net_mask,"%.3d %.3d %.3d",(net_mask%256),(net_mask/256%256),(net_mask/256/256));

    printf("获得的网络地址是：%s\n",s_net_ip);

    printf("获得的网络掩码是：%s\n",s_net_mask);

    printf("第%d个ARP包被捕获:\n",packet_number);

    printf("---------    Ethernet Protocol (Link Layer)    ---------\n");
    //以太网协议
    ethernet_protocol = (struct ether_header*)packet_content;

    //printf("以太网类型是：%d\n",ethernet_protocol->ether_type);

    printf("以太网类型是:\n");

    ethernet_type = ntohs(ethernet_protocol->ether_type);
    //获得以太网类型，表示上层协议类型，即网路层协议类型
    //ntohs是将一个无符号short型数从网络字节序转化为主机字节顺序

    printf("%04x\n",ethernet_type);

    switch(ethernet_type)
    {
        case 0x0800:
            printf("该网络层协议是IP协议\n");
            break;
            //如果以太网类型是0x0800,就表示IP协议

        case 0x0806:
            printf("该网络层协议是ARP协议\n");
            break;
            //如果以太网类型是0x0806,就表示ARP协议

        case 0x8035:
            printf("该网络层协议是RARP协议\n");
            break;

        default:
            break;
            //其他类型没有分析
    }

    printf("源MAC地址是:");

    mac_string = ethernet_protocol->ether_shost;
    //获得源以太网地址

    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string+1), *(mac_string+2), *(mac_string+3), *(mac_string+4), *(mac_string+5));
    //要对以太网地址进行转换，使它变成字符串形式进行显示，例如11：11：11：11：11：11。因为读到的源以太网地址是字节流顺序的。

    printf("目的MAC地址是:");

    mac_string = ethernet_protocol->ether_dhost;
    //获得目的以太网地址

    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string+1), *(mac_string+2), *(mac_string+3), *(mac_string+4), *(mac_string+5));
    //要对以太网地址进行转换，使它变成字符串形式进行显示，例如11：11：11：11：11：11。因为独到的源以太网地址是字节流顺序的。

    switch(ethernet_type)
    {
        case 0x0806:
            arp_protocol_packet_callback(argument,packet_header,packet_content);
            break;
        case 0x0800:
            ip_protocol_packet_callback(argument,packet_header,packet_content);
        default:
            break;

    }
    printf("****************************************************\n");
    packet_number++;
}

int main()
{
    /*libpcap句柄*/
    pcap_t *pcap_handle;
    /*存储错误信息*/
    char error_content[PCAP_ERRBUF_SIZE];
    /*网络接口*/
    char *net_interface;
    /*BPF过滤规则*/
    struct bpf_program bpf_filter;
    /*过滤规则字符串*/
    char bpf_filter_string[]="ip";
    /*获得网络接口*/
    net_interface=pcap_lookupdev(error_content);
    /*获得网络掩码和网络接口*/
    pcap_lookupnet(net_interface,&net_ip,&net_mask,error_content);
    /*打开网络接口*/
    pcap_handle=pcap_open_live(net_interface,BUFSIZ,1,0,error_content);
    //编译过滤规则
    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);/*net_adress*/
    /*设置过滤规则*/
    pcap_setfilter(pcap_handle,&bpf_filter);
    /*获得网络掩码和网络接口*/
    if(pcap_datalink(pcap_handle)!=DLT_EN10MB)
        return 0;
    pcap_loop(pcap_handle,-1,ethernet_protocol_packet_callback,NULL);
    /**/
    pcap_close(pcap_handle);
    /**/
    return 0;
}

