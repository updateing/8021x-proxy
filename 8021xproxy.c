#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>

#define DEV_LAN "eth0"
#define DEV_WAN "eth1"
#define OFFSET_SRC_MAC 6
#define OFFSET_DEST_MAC 0

u_char PC_MAC[] = {0x3c, 0x97, 0x0e, 0xa6, 0x62, 0x61};
u_char ROUTER_MAC[] = {0x44, 0x94, 0xfc, 0x82, 0xd2, 0x93};

void getPacket_lan(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
    int * id = (int *)arg;
    char errBuf[PCAP_ERRBUF_SIZE];

    printf("Thread 1 (LAN) CAPTURED:\n");
    printf("ID: %d\n", ++(*id));
    printf("Packet length on wire: %d\n", pkthdr->len);
    printf("Number of bytes captured: %d\n", pkthdr->caplen);
    printf("Received time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));

    //*************lan2wan*****************
    // If source MAC is PC's, send it to WAN
    if (!memcmp(packet + OFFSET_SRC_MAC, PC_MAC, 6))
    {
        printf(">>> This packet is from specific PC, routing to WAN\n");
        //sendpacket
        static pcap_t * device;
        if(device == NULL)
        {
            // TODO use global var for *device
            // no need to open it twice
            pcap_t * device = pcap_open_live(DEV_WAN, 65535, 1, 0, errBuf);
            pcap_sendpacket(device, packet ,pkthdr->len);
        }
        else
        {
            pcap_sendpacket(device, packet ,pkthdr->len);
        }
    }
    //*****************************
    printf("\n\n");
}

void getPacket_wan(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
    int * id = (int *)arg;
    char errBuf[PCAP_ERRBUF_SIZE];
    printf("Thread 2 (WAN) CAPTURED:\n");
    printf("ID: %d\n", ++(*id));
    printf("Packet length on wire: %d\n", pkthdr->len);
    printf("Number of bytes captured: %d\n", pkthdr->caplen);
    printf("Received time: %s\n", ctime((const time_t *)&pkthdr->ts.tv_sec));

    //*************wan2lan*****************
    // If destination MAC is specific PC, send it to LAN
    if (!memcmp(packet + OFFSET_DEST_MAC, PC_MAC, 6))
    {
        printf(">>> This packet is to specific PC, routing to LAN\n");
        //sendpacket
        static pcap_t * device;
        if(device == NULL)
        {
            pcap_t * device = pcap_open_live(DEV_LAN, 65535, 1, 0, errBuf);
            pcap_sendpacket(device, packet ,pkthdr->len) ;
            //pcap_close(device);
        }
        else
        {
            pcap_sendpacket(device, packet ,pkthdr->len) ;
        }
    }
}

void *thread_lan ()//监听lan
{
    char errBuf[PCAP_ERRBUF_SIZE];
    int id = 0;
    /* get a device */
    pcap_t * device = pcap_open_live(DEV_LAN, 65535, 1, 0, errBuf);

    if(!device)
    {
        printf("error: pcap_open_live(): %s\n", errBuf);
        exit(1);
    }
    else
    {
        printf("success: using %s as LAN interface\n", DEV_LAN);
    }

    /* construct a filter */
    struct bpf_program filter;
    pcap_compile(device, &filter, "ether proto 0x888E", 1, 0);
    pcap_setfilter(device, &filter);

    /* wait loop forever */
    pcap_loop(device, -1, getPacket_lan, (u_char*)&id);  //使用回调 调用发包函数

    pcap_close(device);

    return 0;
}

void *thread_wan ()//监听wan
{
    
    char errBuf[PCAP_ERRBUF_SIZE];
    int id = 0;
    /* get a device */
    pcap_t * device = pcap_open_live(DEV_WAN, 65535, 1, 0, errBuf);

    if(!device)
    {
        printf("error: pcap_open_live(): %s\n", errBuf);
        exit(1);
    }
    else
    {
        printf("success: using %s as WAN interface\n", DEV_WAN);
    }

    /* construct a filter */
    struct bpf_program filter;
    pcap_compile(device, &filter, "ether proto 0x888E", 1, 0);
    pcap_setfilter(device, &filter);

    /* wait loop forever */
    pcap_loop(device, -1, getPacket_wan, (u_char*)&id);  //回调函数

    pcap_close(device);

    return 0;
}

int main()
{
    pthread_t th_lan, th_wan;
    void *retval;
    pthread_create(&th_lan, NULL, thread_lan, 0);
    pthread_create(&th_wan, NULL, thread_wan, 0);
    pthread_join(th_lan, &retval);
    pthread_join(th_wan, &retval);
    return 0;
}
