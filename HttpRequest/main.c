#include <stdio.h>
#include <stdlib.h>
#define HAVE_REMOTE
#include <pcap.h>
#include "pheader.h"

/*
* function: a simple program to analyze http
* author: blacksword
* date: Wed March 21 2012
*/
int main()
{
    pcap_if_t* alldevs; // list of all devices
    pcap_if_t* d; // device you chose

    pcap_t* adhandle;

    char errbuf[PCAP_ERRBUF_SIZE]; //error buffer
    int i=0;
    int inum;

    struct pcap_pkthdr *pheader; /* packet header */
    const u_char * pkt_data; /* packet data */
    int res;

    /* pcap_findalldevs_ex got something wrong */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed*/, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }

    /* print the list of all devices */
    for(d = alldevs; d != NULL; d = d->next)
    {
        printf("%d. %s", ++i, d->name); // print device name , which starts with "rpcap://"
        if(d->description)
            printf(" (%s)\n", d->description); // print device description
        else
            printf(" (No description available)\n");
    }

    /* no interface found */
    if (i == 0)
    {
        printf("\nNo interface found! Make sure Winpcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &inum);

    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    for(d=alldevs, i=0; i < inum-1; d=d->next, i++); /* jump to the selected interface */

    /* open the selected interface*/
    if((adhandle = pcap_open(d->name, /* the interface name */
                 65536, /* length of packet that has to be retained */
                 PCAP_OPENFLAG_PROMISCUOUS, /* promiscuous mode */
                 1000, /* read time out */
                 NULL, /* auth */
                 errbuf /* error buffer */
                 )) == NULL)
                 {
                     fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Winpcap\n",
                             d->description);
                     return -1;
                 }

    printf("\nListening on %s...\n", d->description);

    pcap_freealldevs(alldevs); // release device list

    /* capture packet */
    while((res = pcap_next_ex(adhandle, &pheader, &pkt_data)) >= 0) {

        if(res == 0)
            continue; /* read time out*/

        ether_header * eheader = (ether_header*)pkt_data; /* transform packet data to ethernet header */
        if(eheader->ether_type == htons(ETHERTYPE_IP)) { /* ip packet only */
            ip_header * ih = (ip_header*)(pkt_data+14); /* get ip header */

            if(ih->proto == htons(TCP_PROTOCAL)) { /* tcp packet only */
                    int ip_len = ntohs(ih->tlen); /* get ip length, it contains header and body */

                    int find_http = false;
                    char* ip_pkt_data = (char*)ih;
                    int n = 0;
                    char buffer[BUFFER_MAX_LENGTH];
                    int bufsize = 0;

                    for(; n<ip_len; n++)
                    {
                        /* http get or post request */
                        if(!find_http && ((n+3<ip_len && strncmp(ip_pkt_data+n,"GET",strlen("GET")) ==0 )
                       || (n+4<ip_len && strncmp(ip_pkt_data+n,"POST",strlen("POST")) == 0)) )
                                find_http = true;

                        /* http response */
                        if(!find_http && i+8<ip_len && strncmp(ip_pkt_data+i,"HTTP/1.1",strlen("HTTP/1.1"))==0)
                               find_http = true;

                        /* if http is found */
                        if(find_http)
                        {
                            buffer[bufsize] = ip_pkt_data[n]; /* copy http data to buffer */
                            bufsize ++;
                        }
                    }
                    /* print http content */
                    if(find_http) {
                        buffer[bufsize] = '\0';
                        printf("%s\n", buffer);
                        printf("\n**********************************************\n\n");
                    }
            }
        }
    }

    return 0;
}
