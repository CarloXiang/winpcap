#include <stdlib.h>
#include <stdio.h>

//
// NOTE: remember to include WPCAP and HAVE_REMOTE among your
// preprocessor definitions.
//
#define HAVE_REMOTE
#include <pcap.h>

#define LINE_LEN 16

main(int argc, char **argv)
{
pcap_if_t *alldevs, *d;
pcap_t *fp;
u_int inum, i=0;
char errbuf[PCAP_ERRBUF_SIZE];
int res;
struct pcap_pkthdr *header;
const u_char *pkt_data;

    printf("pktdump_ex: prints the packets of the network using WinPcap.\n");
    printf("   Usage: pktdump_ex [-s source]\n\n"
           "   Examples:\n"
           "      pktdump_ex -s file://c:/temp/file.acp\n"
           "      pktdump_ex -s rpcap://\\Device\\NPF_{C8736017-F3C3-4373-94AC-9A34B7DAD998}\n\n");

    if(argc < 3)
    {

        printf("\nNo adapter selected: printing the device list:\n");
        /* The user didn't provide a packet source: Retrieve the local device list */
        if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
        {
            fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
            return -1;
        }

        /* Print the list */
        for(d=alldevs; d; d=d->next)
        {
            printf("%d. %s\n    ", ++i, d->name);

            if (d->description)
                printf(" (%s)\n", d->description);
            else
                printf(" (No description available)\n");
        }

        if (i==0)
        {
            fprintf(stderr,"No interfaces found! Exiting.\n");
            return -1;
        }

        printf("Enter the interface number (1-%d):",i);
        scanf("%d", &inum);

        if (inum < 1 || inum > i)
        {
            printf("\nInterface number out of range.\n");

            /* Free the device list */
            pcap_freealldevs(alldevs);
            return -1;
        }

        /* Jump to the selected adapter */
        for (d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

        /* Open the device */
        if ( (fp= pcap_open(d->name,
                            100 /*snaplen*/,
                            PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
                            20 /*read timeout*/,
                            NULL /* remote authentication */,
                            errbuf)
                            ) == NULL)
        {
            fprintf(stderr,"\nError opening adapter\n");
            return -1;
        }
    }
    else
    {
        // Do not check for the switch type ('-s')
        if ( (fp= pcap_open(argv[2],
                            100 /*snaplen*/,
                            PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
                            20 /*read timeout*/,
                            NULL /* remote authentication */,
                            errbuf)
                            ) == NULL)
        {
            fprintf(stderr,"\nError opening source: %s\n", errbuf);
            return -1;
        }
    }

    /* Read the packets */
    while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0)
    {

        if(res == 0)
            /* Timeout elapsed */
            continue;

        /* print pkt timestamp and pkt len */
        printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

        /* Print the packet */
        for (i=1; (i < header->caplen + 1 ) ; i++)
        {
            printf("%.2x ", pkt_data[i-1]);
            if ( (i % LINE_LEN) == 0) printf("\n");
        }

        printf("\n\n");
    }

    if(res == -1)
    {
        fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(fp));
        return -1;
    }

    return 0;
}
