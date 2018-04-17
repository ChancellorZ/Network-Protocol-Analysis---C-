#include "pcap.h"
#include<arpa/inet.h>
#include <stdio.h>

struct ether_header
{
    u_int8_t ether_dhost[6];

    u_int8_t ether_shost[6];
    /**/
    u_int16_t ether_type;
};
/**/
typedef u_int32_t in_addr_t;

/*网络掩码*/
bpf_u_int32 net_mask;
/*网络地址*/
bpf_u_int32 net_ip;
//网络号及其掩码
char s_net_ip[20], s_net_mask[20];

/*struct in_addr
{
    in_addr_t s_addr;
};*/
/**/
struct ip_header
{
#ifdef WORDS_BIGENDIAN
    u_int8_t ip_version:4;/*IP*/
    ip_header_length:4;/*IP*/
#else
    u_int8_t ip_header_length:4,ip_version:4;
    /*版本号和首部长度*/
#endif
    u_int8_t ip_tos;
    /*TOS服务质量*/
    u_int16_t ip_length;
    /*总长度*/
    u_int16_t ip_id;
    /*标识*/
    u_int16_t ip_off;
    /*偏移*/
    u_int8_t ip_ttl;
    /*生存时间*/
    u_int8_t ip_protocol;
    /*协议类型*/
    u_int16_t ip_checksum;
    /*校验和*/
    struct in_addr ip_source_address;
    /*源IP地址*/
    struct in_addr ip_destination_address;
    /*目的IP地址*/

};
struct icmp_header
{
  u_int8_t icmp_type;
  /*icmp类型*/
  u_int8_t icmp_code;
  /*icmp代码*/
  u_int16_t icmp_checksum;
  /*校验和*/
  u_int16_t icmp_id;
  /*标识符*/
  u_int16_t icmp_sequence;
  /*序列号*/
};

void icmp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)
{
    struct icmp_header *icmp_protocol;
    /*icmp协议变量*/
    icmp_protocol =(struct icmp_header*)(packet_content+14+20);
    printf("--------- ICMP Protocol (Transport Layer) --------\n");
    /*获得协议内容，跳过以太网和ip协议部分*/
    printf("ICMP Type:%d\n",icmp_protocol->icmp_type);
    /*获得ICMP类型*/
    argument=argument+1;
    printf("时间戳：%ld\n",packet_header->ts.tv_sec);
    switch(icmp_protocol->icmp_type)
    {
        case 8:
            /*类型为8,回显请求报文*/
            printf("ICMP 请求协报文\n");
            printf("ICMP 代码:%d\n",icmp_protocol->icmp_code);
            /*获取ICMP代码*/
            printf("ICMP 标识符:%d\n",icmp_protocol->icmp_id);
            /*获得标识符*/
            printf("ICMP 序列号:%d\n",icmp_protocol->icmp_sequence);
            /*获得序列号*/
            break;

        case 0:
            /*显示类型为0,表示是回显应答报文*/
            printf("ICMP 回显应答报文\n");
            printf("ICMP 代码:%d\n",icmp_protocol->icmp_code);
            /*获得ICMP代码*/
            printf("ICMP 标识符:%d\n",icmp_protocol->icmp_id);
            /*获得标识符*/
            printf("ICMP 序列号:%d\n",icmp_protocol->icmp_sequence);
            /*获得序列号*/
            break;

        default:
            break;
            /*其他类型，暂不分析*/
    }
    printf("ICMP 校验和:%d\n",ntohs(icmp_protocol->icmp_checksum));
    /*获得校验和*/
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
        icmp_protocol_packet_callback(argument,packet_header,packet_content);
        //printf("传输层协议是 ICMP 协议\n");
        //printf("The Transport Layer Protocol is ICMP\n");
        break;
    default:
        break;
    }
    printf("首部校验和:%d\n",checksum);
    printf("源IP地址:%s\n",inet_ntoa(ip_protocol->ip_source_address));
    printf("目的IP地址:%s\n",inet_ntoa(ip_protocol->ip_destination_address));
    argument=argument+1;
}

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
            printf("该网络层协议是ARP协议\n");
            //arp_protocol_packet_callback(argument,packet_header,packet_content);
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
    char bpf_filter_string[]="icmp";
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
