#include <winsock.h>
#include <stdlib.h>
#define HAVE_REMOTE
#include <pcap.h>

//#include "remote_ext.h"

pcap_t *adhandle;

/* 4�ֽڵ�IP��ַ*/
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 �ײ�*/
typedef struct ip_header{
    u_char ver_ihl; // �汾(4 bits) + �ײ�����(4 bits)

    u_char tos; // ��������(Type of service)

    u_short tlen; // �ܳ�(Total length)

    u_short identification; // ��ʶ(Identification)

    u_short flags_fo; // ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)

    u_char ttl; // ���ʱ��(Time to live)

    u_char proto; // Э��(Protocol)

    u_short crc; // �ײ�У���(Header checksum)

    ip_address saddr; // Դ��ַ(Source address)

    ip_address daddr; // Ŀ�ĵ�ַ(Destination address)

    u_int op_pad; // ѡ�������(Option + Padding)

}ip_header;
/*TCP �ײ�*/
typedef struct tcp_header{
    u_short th_sport; //16λԴ�˿�

    u_short th_dport; //16λĿ�Ķ˿�

    u_int th_seq; //32λ���к�

    u_int th_ack; //32λȷ�Ϻ�

    u_char th_lenres; //4λ�ײ�����/6λ������

    u_char th_flag; //6λ��־λ

    u_short th_win; //16λ���ڴ�С

    u_short th_sum; //16λУ���

    u_short th_urp; //16λ��������ƫ����

}tcp_header;

/* UDP �ײ�*/
typedef struct udp_header{
    u_short sport; // Դ�˿�(Source port)

    u_short dport; // Ŀ�Ķ˿�(Destination port)

    u_short len; // UDP���ݰ�����(Datagram length)

    u_short crc; // У���(Checksum)

}udp_header;


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    int inum;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask;
    char packet_filter[] = "ip and tcp";
    struct bpf_program fcode;

    if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf)==-1)
    {
        printf("find all devs err:%s", errbuf);
        exit(1);
    }

    for(d=alldevs; d; d=d->next)
    {
        if(d->description)
            printf("%d. %s\n", ++i, d->description);
        else
            printf("%d. no description\n", ++i);
    }

    printf("enter the interface number u wanna choose:");
    scanf("%d", &inum);
    if(inum<1||inum>i)
    {
        printf("interface number out of range.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    for(d=alldevs,i=0;i<inum-1;d=d->next,++i);

    if((adhandle=pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf))==NULL)
    {
        printf("can't open the adapter.%s is not supported by winpcap\n", d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }

    if(d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask=0xffffff;

     //compile the filter

    if(pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 ){
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    //set the filter

    if(pcap_setfilter(adhandle, &fcode)<0){
        fprintf(stderr,"\nError setting the filter.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("lsitening on %s\n", d->description);
    pcap_freealldevs(alldevs);
    pcap_loop(adhandle, 0, packet_handler, NULL);

    return 0;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    time_t local_tv_sec;
    char timestr[16];
    ip_header *ih;
    tcp_header *th;
    u_int ip_len;
    u_int tcp_len;
    u_short sport,dport;


    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
    printf("%s, %.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
    ih=(ip_header *)(pkt_data+14);
    ip_len = (ih->ver_ihl & 0xf) * 4; /* ���TCP�ײ���λ��*/
    th = (tcp_header *) ((u_char*)ih + ip_len);
    tcp_len = (th->th_lenres & 0xf0)>>2;/* ���TCP�ײ��ĳ���*/
     /* �������ֽ�����ת���������ֽ�����*/
    sport = ntohs(th->th_sport);
    dport = ntohs(th->th_dport);

    /* ��ӡIP��ַ��UDP�˿�*/
    printf("src:%d.%d.%d.%d:%d -> des:%d.%d.%d.%d:%d\n",
        ih->saddr.byte1,
        ih->saddr.byte2,
        ih->saddr.byte3,
        ih->saddr.byte4,
        sport,
        ih->daddr.byte1,
        ih->daddr.byte2,
        ih->daddr.byte3,
        ih->daddr.byte4,
        dport);
}
