#include <iostream>
#define HAVE_REMOTE
#include <pcap.h>
#include <iomanip>
#include <string>
#include <stdio.h>
using namespace std;

/*Ethernet Heder*/
struct ether_header
{
    u_int8_t  ether_dhost[6];      /* destination eth addr */
    u_int8_t  ether_shost[6];      /* source ether addr    */
    u_int16_t ether_type;          /* packet type ID field */
};

/* 4 bytes IP address */
struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

/* IPv4 header */
struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
};

/* UDP header*/
struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
};

/*TCP Header*/
struct tcp_header
{
    u_int16_t th_sport;         /* source port */
    u_int16_t th_dport;         /* destination port */
    u_int32_t th_seq;             /* sequence number */
    u_int32_t th_ack;             /* acknowledgement number */
    u_int16_t th_len_resv_code; //   Datagram   length and reserved code
    u_int16_t th_win;           /* window */
    u_int16_t th_sum;           /* checksum */
    u_int16_t th_urp;           /* urgent pointer */
};

int main()
{
    //retrieve the devices list
    pcap_if_t *all_devs;
    char err_buff[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &all_devs,err_buff) == -1){
        cerr<<"Error in pcap_findalldevs_ex "<<err_buff<<endl;
        return -1;
    }

    //get the device index,default is the first one
    int dev_idx = 2;
    pcap_if_t *dev=all_devs;
    for(int i=0;i<dev_idx;++i,dev=dev->next);//jump to the device of the specified index
    cout<<"Listen on: "<<dev->name<<endl;
    cout<<"****************************************"<<endl;

    //get the netcard adapter
    pcap_t *adpt_hdl = pcap_open(dev->name,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,NULL,err_buff);
    if(adpt_hdl==NULL){
        cerr<<"Unable to open adapter "<<dev->name<<endl;
        pcap_freealldevs(all_devs);
        return -1;
    }

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(all_devs);

    //analyze each packet
    struct pcap_pkthdr *header;
    const u_char *pkt_data;

    int rst=0;
    char x;
    FILE *fp,*fq;
    fp=fopen("http.txt","w+");
    fq=fopen("ac.txt","w+");
    while((rst=pcap_next_ex(adpt_hdl,&header,&pkt_data))>=0)
    {
        if(rst==0){
            //time out and not packet captured
            continue;
        }

        ether_header *eh = (ether_header*)pkt_data;

        if(ntohs(eh->ether_type)==0x0800){ // ip packet only

            ip_header *ih = (ip_header*)(pkt_data+14);

            if(ntohs(ih->proto) == 0x0600){ // tcp packet only

                int ip_len = ntohs(ih->tlen);//ip_len = ip_body + ip_header

                bool find_http = false;

                string http_txt = "";
                //char* http;
                char* ip_pkt_data = (char*)ih;

                for(int i=0;i<ip_len;++i){

                    //check the http request

                    if(!find_http && (n+3<ip_len && strncmp(ip_pkt_data+i,"GET",strlen("GET")) ==0 )

                       || (i+4<ip_len && strncmp(ip_pkt_data+i,"POST",strlen("POST")) == 0) ){

                        find_http = true;

                    }

                    //check the http response

                    if(!find_http && i+8<ip_len && strncmp(ip_pkt_data+i,"HTTP/1.1",strlen("HTTP/1.1"))==0){

                        find_http = true;
                    }

                    //collect the http text

                    if(find_http){

                        http_txt += ip_pkt_data[i];
                        fputc(ip_pkt_data[i],fp);
                        if((ip_pkt_data[i]>'A'&&ip_pkt_data[i]<'Z')||(ip_pkt_data[i]>'a'&&ip_pkt_data[i]<'z'))
                        {
                            if((ip_pkt_data[i]>'A'&&ip_pkt_data[i]<'Z'))
                                x=ip_pkt_data[i]-'A'+'a';
                            else x=ip_pkt_data[i];
                            fputc(x,fq);
                        }
                    }
                }
                //print the http request or response
                if(http_txt != ""){
                    cout<<http_txt;
                    cout<<endl<<"***********************************************************"<<endl<<endl;
                }
            }
        }
    }
    return 0;
}
