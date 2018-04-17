#include "pcap.h"
#include <arpa/inet.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
struct ether_header
{
    u_int8_t ether_dhost[6];
    //目的以太网地址
    u_int8_t ether_shost[6];
    //源以太网地址
    u_int16_t ether_type;
    //以太网类型
};
void main()
{
    char s_net_ip[20], s_net_mask[20];
    //char s_net_ip1[4], s_net_ip2[4], s_net_ip3[4];
    //网络号及其掩码

    int total=0;
    //总长度

    int hours,minutes,seconds;

    struct timeval tmp,firsttime,endtime;
    //替换用的时间戳

    char s[24];
    //自己定义的时间字符串数组

    struct tm *p;

    char error_content[PCAP_ERRBUF_SIZE];
    //错误信息

    pcap_t *pcap_handle;
    //Libpcap句柄

    const u_char *packet_content;
    //数据包缓存

    u_char *mac_string;
    //以太网地址，指向一个字节

    u_short ethernet_type;
    //以太网类型

    bpf_u_int32 net_mask;
    //网络掩码

    bpf_u_int32 net_ip;
    //网络地址

    char *net_interface;
    //网络接口

    struct pcap_pkthdr protocol_header;
    //数据包信息

    struct ether_header *ethernet_protocol;
    //以太网协议变量

    struct bpf_program bpf_filter;
    //bpf过滤规则

    char bpf_filter_string[]="";

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
        return;

    for(int i=0;i<10000;i++)
    {
        printf("这是第%d个数据包：\n",i+1);
        packet_content=pcap_next(pcap_handle, /*句柄*/&protocol_header);
        /*数据包信息*/

        total+=protocol_header.len;



        printf("------------*****------------\n");
        sprintf(s_net_ip,"%.3d %.3d %.3d",(net_ip%256),(net_ip/256%256),(net_ip/256/256));
        sprintf(s_net_mask,"%.3d %.3d %.3d",(net_mask%256),(net_mask/256%256),(net_mask/256/256));

        printf("获得的网络地址是：%s\n",s_net_ip);

        printf("获得的网络掩码是：%s\n",s_net_mask);

        //printf("错误内容为:%d\n",*error_content);

        printf("BUFSIZ(缓冲区大小) is :%d\n",BUFSIZ);

        printf("从 %s 捕获一个数据包\n",net_interface);

        printf("数据包长度是 :%d\n",protocol_header.len);

        printf("数据包的时间戳是 :%ld\n",protocol_header.ts.tv_sec);

        p=localtime(&protocol_header.ts.tv_sec);

        if(i==0)
        {
            tmp=protocol_header.ts;
            firsttime=protocol_header.ts;
        }
        else
        {
            printf("与上一个包的时间差是：%ld μs\n",(protocol_header.ts.tv_sec-tmp.tv_sec)*1000000+(protocol_header.ts.tv_usec-tmp.tv_usec));
            tmp=protocol_header.ts;
        }
        strftime(s,sizeof(s),"%Y-%m-%d %H:%M:%S",p);

        printf("捕获包的本地时间是 :%s\n",s);

        //printf("The packet data is :%d\n",*packet_content);

        ethernet_protocol = (struct ether_header*)packet_content;
        //把数据包缓存强制转换成以太网协议格式的数据类型，然后就可以对它的各个字段进行访问了。

        printf("Ethernet type is:");

        ethernet_type = ntohs(ethernet_protocol->ether_type);
        //获得以太网类型，表示上层协议类型，即网路层协议类型
        //ntohs是将一个无符号short型数从网络字节序转化为主机字节顺序

        printf("%04x\n",ethernet_type);

        switch(ethernet_type)
        {
            case 0x0800:
                printf("网络层的是 IP 协议\n");
                break;
                //如果以太网类型是0x0800,就表示IP协议

            case 0x0806:
                printf("网络层的是 ARP 协议\n");
                break;
                //如果以太网类型是0x0806,就表示ARP协议

            case 0x8035:
                printf("网络层的是 RARP 协议\n");
                break;

            default:
                break;
                //其他类型没有分析
        }

        printf("源MAC地址是 : ");

        mac_string = ethernet_protocol->ether_shost;
        //获得源以太网地址

        printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string+1), *(mac_string+2), *(mac_string+3), *(mac_string+4), *(mac_string+5));
        //要对以太网地址进行转换，使它变成字符串形式进行显示，例如11：11：11：11：11：11。因为独到的源以太网地址是字节流顺序的。

        printf("目的MAC地址 : ");

        mac_string = ethernet_protocol->ether_dhost;
        //获得目的以太网地址

        printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string+1), *(mac_string+2), *(mac_string+3), *(mac_string+4), *(mac_string+5));
        //同样进行转换

        printf("------------*****------------\n");
    }
    endtime=protocol_header.ts;

    hours=(endtime.tv_sec-firsttime.tv_sec)/3600;
    minutes=(endtime.tv_sec-firsttime.tv_sec)%3600/60;
    seconds=(endtime.tv_sec-firsttime.tv_sec)%60;


    printf("耗费的总时间是 :%2dh %2dm %2ds\n",hours,minutes,seconds);

    printf("总的数据包长度是 :%d\n",total);

    pcap_close(pcap_handle);
    /*关闭Libpcap操作*/
}




