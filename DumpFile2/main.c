#define HAVE_REMOTE
#define WPCAP
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>

int main(int argc, char **argv)
{

    pcap_if_t *alldevs, *d;
    pcap_t *fp;
    u_int inum, i=0;
    char errbuf[PCAP_ERRBUF_SIZE];

    printf("kdump: saves the network traffic to file using WinPcap kernel-level dump faeature.\n");
    printf("\t Usage: %s [adapter] | dump_file_name max_size max_packs\n", argv[0]);
    printf("\t Where: max_size is the maximum size that the dump file will reach (0 means no limit)\n");
    printf("\t Where: max_packs is the maximum number of packets that will be saved (0 means no limit)\n\n");


    if(argc < 5)
    {

        /* �û�û���ṩ����Դ����ȡ�豸�б� */
        if (pcap_findalldevs(&alldevs, errbuf) == -1)
        {
            fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
            exit(1);
        }

        /* ��ӡ�б� */
        for(d=alldevs; d; d=d->next)
        {
            printf("%d. %s", ++i, d->name);
            if (d->description)
                printf(" (%s)\n", d->description);
            else
                printf(" (No description available)\n");
        }

        if(i==0)
        {
            printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
            return -1;
        }

        printf("Enter the interface number (1-%d):",i);
        scanf("%d", &inum);

        if(inum < 1 || inum > i)
        {
            printf("\nInterface number out of range.\n");
            /* �ͷ��б� */
            return -1;
        }

        /* ��ת����ѡ���豸 */
        for(d=alldevs, i=0; i< inum-1 ; d=d->next, i++);

        /* ���豸 */
        if ( (fp = pcap_open_live(d->name, 100, 1, 20, errbuf) ) == NULL)
        {
            fprintf(stderr,"\nError opening adapter\n");
            return -1;
        }

        /* �ͷ��豸�б� */
        pcap_freealldevs(alldevs);

        /* ��ʼ�ѹ��� */
        if(pcap_live_dump(fp, argv[1], atoi(argv[2]), atoi(argv[3]))==-1)
        {
            printf("Unable to start the dump, %s\n", pcap_geterr(fp));
            return -1;
        }
    }
    else
    {

        /* ���豸 */
        if ( (fp= pcap_open_live(argv[1], 100, 1, 20, errbuf) ) == NULL)
        {
            fprintf(stderr,"\nError opening adapter\n");
            return -1;
        }

        /* ��ʼ�ѹ��� */
        if(pcap_live_dump(fp, argv[2], atoi(argv[3]), atoi(argv[4]))==-1)
        {
            printf("Unable to start the dump, %s\n", pcap_geterr(fp));
            return -1;
        }
    }

    /* �ȴ���֪���ѹ�����ɣ�Ҳ���ǵ����ݵ���max_size��max_packs��ʱ�� */
    pcap_live_dump_ended(fp, TRUE);

    /* �ر����������������Ϳ��Խ���������������ļ��� */
    pcap_close(fp);

    return 0;
}
