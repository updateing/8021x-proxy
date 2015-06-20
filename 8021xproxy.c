#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>

#define ENABLE_ALTERING_MAC
#define DEBUG
#define DEBUG_MOD_PACKET

#define DEV_LAN "eth0"
#define DEV_WAN "eth1"
#define OFFSET_SRC_MAC 6
#define OFFSET_DEST_MAC 0

u_char PC_MAC[] = {0x3c, 0x97, 0x0e, 0xa6, 0x62, 0x61};
u_char ROUTER_MAC[] = {0x44, 0x94, 0xfc, 0x82, 0xd2, 0x93};

pcap_t * lan_device;
pcap_t * wan_device;

void print_hex(const u_char * data, int len, int wrap_elements) {
    int i;
    for(i = 0; i < len; ++i) {
        printf("%02x ", data[i]);
        if(!wrap_elements && (i + 1) % wrap_elements == 0 ) {
            printf("\n");
        }
    }
    if (!wrap_elements && len % wrap_elements != 0) printf("\n");
}

void getPacket_lan(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
    int * id = (int *)arg;
#ifdef ENABLE_MAC_ALTERING
    u_char * mod_packet;
#endif

    printf("Thread 1 (LAN) CAPTURED:\n");
    printf("Packet ID: %d\n", ++(*id));
    printf("Packet length on wire: %d\n", pkthdr->len);
    printf("Number of bytes captured: %d\n", pkthdr->caplen);
    printf("Received time: %s\n", ctime((const time_t *)&pkthdr->ts.tv_sec));

#ifdef DEBUG
    print_hex(packet, pkthdr->len, 16);
#endif

    //*************lan2wan*****************
    // If source MAC is PC's, send it to WAN
    if (!memcmp(packet + OFFSET_SRC_MAC, PC_MAC, 6))
    {
#ifdef ENABLE_MAC_ALTERING
        printf(">>> This packet is from specific PC, modifying source MAC and routing to WAN\n");
#else
        printf(">>> This packet is from specific PC, routing to WAN\n");
#endif
        if(wan_device == NULL)
        {
            // How could that happen?
            printf("!!! ERROR: WAN Device is NULL!\n");
        }
        else
        {
#ifdef ENABLE_MAC_ALTERING
            mod_packet = malloc(pkthdr->len);
            if (mod_packet == NULL) {
                printf("!!! Error creating buffer for modified packet, dropping!\n");
                return;
            } else {
                memcpy(mod_packet, packet, pkthdr->len);
                memcpy(mod_packet + OFFSET_SRC_MAC, ROUTER_MAC, 6); // Overwrite source MAC with router's
                printf(">>> Source MAC has been modified to router.\n");
            }
#ifdef DEBUG_MOD_PACKET
            printf(">>> Debug: modded packet is\n");
            print_hex(mod_packet, pkthdr->len, 16);
#endif
            pcap_sendpacket(wan_device, mod_packet, pkthdr->len);
#else
            pcap_sendpacket(wan_device, packet, pkthdr->len);
#endif
        }
    }
    //*****************************
    printf("\n\n");
}

void getPacket_wan(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
    int * id = (int *)arg;
#ifdef ENABLE_MAC_ALTERING
    u_char * mod_packet;
#endif

    printf("Thread 2 (WAN) CAPTURED:\n");
    printf("Packet ID: %d\n", ++(*id));
    printf("Packet length on wire: %d\n", pkthdr->len);
    printf("Number of bytes captured: %d\n", pkthdr->caplen);
    printf("Received time: %s\n", ctime((const time_t *)&pkthdr->ts.tv_sec));

#ifdef DEBUG
    print_hex(packet, pkthdr->len, 16);
#endif

    //*************wan2lan*****************
    // If destination MAC is specific PC, send it to LAN
#ifdef ENABLE_MAC_ALTERING
    if (!memcmp(packet + OFFSET_DEST_MAC, ROUTER_MAC, 6))
    {
        printf(">>> This packet is to router, modifying destination MAC and routing to LAN\n");
#else
    if (!memcmp(packet + OFFSET_DEST_MAC, PC_MAC, 6))
    {
        printf(">>> This packet is to specific PC, routing to LAN\n");
#endif

        if(lan_device == NULL)
        {
            // How could that happen?
            printf("!!! ERROR: LAN Device is NULL!\n");
        }
        else
        {
#ifdef ENABLE_MAC_ALTERING
            mod_packet = malloc(pkthdr->len);
            if (mod_packet == NULL) {
                printf("!!! Error creating buffer for modified packet, dropping!\n");
                return;
            } else {
                memcpy(mod_packet, packet, pkthdr->len);
                memcpy(mod_packet + OFFSET_DEST_MAC, PC_MAC, 6); // Overwrite source MAC with router's
                printf(">>> Destination MAC has been modified to PC.\n");
            }
#ifdef DEBUG_MOD_PACKET
            printf(">>> Debug: modded packet is\n");
            print_hex(mod_packet, pkthdr->len, 16);
#endif
            pcap_sendpacket(lan_device, mod_packet, pkthdr->len);
#else
            pcap_sendpacket(lan_device, packet, pkthdr->len);
#endif
        }
    }
}

void *thread_lan ()//监听lan
{
    char errBuf[PCAP_ERRBUF_SIZE];
    int id = 0;
    /* get a device */
    lan_device = pcap_open_live(DEV_LAN, 65535, 1, 0, errBuf);

    if(!lan_device)
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
    pcap_compile(lan_device, &filter, "ether proto 0x888E", 1, 0);
    pcap_setfilter(lan_device, &filter);

    /* wait loop forever */
    pcap_loop(lan_device, -1, getPacket_lan, (u_char*)&id);  //使用回调 调用发包函数

    pcap_close(lan_device);

    return 0;
}

void *thread_wan ()//监听wan
{
    
    char errBuf[PCAP_ERRBUF_SIZE];
    int id = 0;
    /* get a device */
    wan_device = pcap_open_live(DEV_WAN, 65535, 1, 0, errBuf);

    if(!wan_device)
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
    pcap_compile(wan_device, &filter, "ether proto 0x888E", 1, 0);
    pcap_setfilter(wan_device, &filter);

    /* wait loop forever */
    pcap_loop(wan_device, -1, getPacket_wan, (u_char*)&id);  //回调函数

    pcap_close(wan_device);

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
