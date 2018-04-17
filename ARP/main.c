#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
struct ether_header
{
    u_int8_t ether_dhost[6];

    u_int8_t ether_shost[6];

    u_int16_t ether_type;

};

bpf_u_int32 net_mask;
//网络掩码

bpf_u_int32 net_ip;
//网络地址

char s_net_ip[20], s_net_mask[20];
//char s_net_ip1[4], s_net_ip2[4], s_net_ip3[4];
//网络号及其掩码

typedef u_int32_t in_addr_t;

struct in_addr_t
{
    in_addr_t s_addr;

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

    printf("--------    Ethernet Protocol (Link Layer)    --------\n");
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
        default:
            break;

    }
    printf("****************************************************\n");
    packet_number++;
}


int main()
{
    char error_content[PCAP_ERRBUF_SIZE];
    //错误信息

    pcap_t *pcap_handle;
    //Libpcap句柄

    char *net_interface;
    //网络接口

    struct bpf_program bpf_filter;
    //bpf过滤规则

    char bpf_filter_string[]="arp";

    /*
    bpf_u_int32 net_mask;
    //网络掩码

    bpf_u_int32 net_ip;
    //网络地址
    */

    net_interface = pcap_lookupdev(error_content);
    //获取网络接口

    pcap_lookupnet(net_interface, &net_ip, &net_mask, error_content);
    //获取网络地址和网络掩码

    pcap_handle = pcap_open_live(net_interface, BUFSIZ, 1, 0,error_content);/**/
    //打开网络接口

    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);/*net_adress*/
    //编译过滤规则

    pcap_setfilter(pcap_handle, &bpf_filter);/**/
    //设置过滤规则

    if(pcap_datalink(pcap_handle)!=DLT_EN10MB)
        return 0;

    pcap_loop(pcap_handle, -1, ethernet_protocol_packet_callback,NULL);
    //注册回调函数，循环捕捉数据包

    pcap_close(pcap_handle);

    return 0;
}

