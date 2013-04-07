#include <stdio.h>
#include <stdlib.h>
#define HAVE_REMOTE
#include <pcap.h>

int main()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    char* errbuf[PCAP_ERRBUF_SIZE];
    int inum;
    int i = 0;
    pcap_t* adhandle;

    if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, &errbuf) == -1)
    {
        fprint(stderr, "Error in pcap_findalldevs_ex: %s", errbuf);
        exit(1);
    }

    for(d=alldevs; d!=NULL; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if(d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if(i == 0)
    {
        printf("\nNo interface found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &inum);

    if(inum <1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    for(d=alldevs, i=0; i<inum-1; i++, d=d->next);

    if((adhandle = pcap_open(d->name,
                            65536,
                            PCAP_OPENFLAG_PROMISCUOUS,
                            1000,
                            NULL,
                            errbuf)) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->description);
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nListening on %s ...\n", d->description);

    pcap_freealldevs(alldevs);
    return 0;
}
