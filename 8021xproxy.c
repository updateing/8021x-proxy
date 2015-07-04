#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#include "proxy_cmdline.h"
#include "proxy_misc.h"
#include "proxy_const.h"
#include "eap_packet.h"

#define OFFSET_SRC_MAC 6
#define OFFSET_DEST_MAC 0

/* These are set in main() */
u_char* DEV_LAN;
u_char* DEV_WAN;
u_char* run_on_success_cmd;
u_char PC_MAC[6];
u_char ROUTER_MAC[6];
bool mac_alter = true;
int success_count_req;

pcap_t * lan_device;
pcap_t * wan_device;

/* Set & read in WAN thread */
int current_success_count = 0;

void do_run_on_success_cmd() {
    if (run_on_success_cmd != NULL) {
        current_success_count++;
        if (current_success_count >= success_count_req) {
            printf(">>> Ready to run shell command: %s\n", run_on_success_cmd);
            system(run_on_success_cmd);
            current_success_count = 0;
        }
    }
}

void getPacket_lan(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
    int * id = (int *)arg;
    u_char * mod_packet;

    printf("==========\n");
    printf("Thread 1 (LAN) CAPTURED:\n");
    printf("Packet ID: %d\n", ++(*id));
    printf("Packet length on wire: %d\n", pkthdr->len);
    printf("Number of bytes captured: %d\n", pkthdr->caplen);
    printf("Received time: %s\n", ctime((const time_t *)&pkthdr->ts.tv_sec));
    if (load_packet(packet, pkthdr->len) == RESULT_FAIL)
        fprintf(stderr, "!!! load_packet() failed. Trigger won't work.\n");
    
#ifdef DEBUG
    print_hex(packet, pkthdr->len, 16);
#endif
    dump_packet_eap_info();
    
    //*************lan2wan*****************
    // If source MAC is PC's, send it to WAN
    if(wan_device == NULL)
    {
        // How could that happen?
        printf("!!! ERROR: WAN Device is NULL!\n");
        return;
    }
    
    if (!memcmp(packet + OFFSET_SRC_MAC, PC_MAC, 6))
    {
        if (mac_alter) {
            printf(">>> This packet is from specific PC, modifying source MAC and routing to WAN\n");
            mod_packet = malloc(pkthdr->len);
            if (mod_packet == NULL) {
                printf("!!! Error creating buffer for modified packet, dropping!\n");
                return;
            } else {
                memcpy(mod_packet, packet, pkthdr->len);
                memcpy(mod_packet + OFFSET_SRC_MAC, ROUTER_MAC, 6); // Overwrite source MAC with router's
            }
#ifdef DEBUG_MOD_PACKET
            printf(">>> Debug: modded packet is\n");
            print_hex(mod_packet, pkthdr->len, 16);
#endif
            pcap_sendpacket(wan_device, mod_packet, pkthdr->len);
        } else {
            printf(">>> This packet is from specific PC, routing to WAN\n");
            pcap_sendpacket(wan_device, packet, pkthdr->len);
        }
    }
}

void getPacket_wan(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
    int * id = (int *)arg;
    u_char * mod_packet;

    printf("==========\n");
    printf("Thread 2 (WAN) CAPTURED:\n");
    printf("Packet ID: %d\n", ++(*id));
    printf("Packet length on wire: %d\n", pkthdr->len);
    printf("Number of bytes captured: %d\n", pkthdr->caplen);
    printf("Received time: %s\n", ctime((const time_t *)&pkthdr->ts.tv_sec));
    if (load_packet(packet, pkthdr->len) == RESULT_FAIL)
        fprintf(stderr, "!!! load_packet() failed. Trigger won't work.\n");
    
#ifdef DEBUG
    print_hex(packet, pkthdr->len, 16);
#endif
    dump_packet_eap_info();
    
    //*************wan2lan*****************
    // If destination MAC is specific PC, send it to LAN
    if(lan_device == NULL)
    {
        // How could that happen?
        printf("!!! ERROR: LAN Device is NULL!\n");
        return;
    }
    
    if (mac_alter) {
        if (!memcmp(packet + OFFSET_DEST_MAC, ROUTER_MAC, 6))
        {
            printf(">>> This packet is to router, modifying destination MAC and routing to LAN\n");
            mod_packet = malloc(pkthdr->len);
            if (mod_packet == NULL) {
                printf("!!! Error creating buffer for modified packet, dropping!\n");
                return;
            } else {
                memcpy(mod_packet, packet, pkthdr->len);
                memcpy(mod_packet + OFFSET_DEST_MAC, PC_MAC, 6); // Overwrite source MAC with router's
            }
#ifdef DEBUG_MOD_PACKET
            printf(">>> Debug: modded packet is\n");
            print_hex(mod_packet, pkthdr->len, 16);
#endif
            pcap_sendpacket(lan_device, mod_packet, pkthdr->len);
        }
    } else {
        if (!memcmp(packet + OFFSET_DEST_MAC, PC_MAC, 6))
        {
            printf(">>> This packet is to specific PC, routing to LAN\n");
            pcap_sendpacket(lan_device, packet, pkthdr->len);
        }
    }
    
    if (get_packet_eap_code() == EAP_SUCCESS)
        do_run_on_success_cmd();
}

void *thread_lan ()//监听lan
{
    char errBuf[PCAP_ERRBUF_SIZE];
    int id = 0;
    /* get a device */
    lan_device = pcap_open_live((const char*)DEV_LAN, 65535, 1, 0, errBuf);

    if(!lan_device)
    {
        printf("error: pcap_open_live(): %s\n", errBuf);
        exit(1);
    }
    else
    {
        printf("Successfully opened LAN interface\n");
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
    wan_device = pcap_open_live((const char*)DEV_WAN, 65535, 1, 0, errBuf);

    if(!wan_device)
    {
        printf("error: pcap_open_live(): %s\n", errBuf);
        exit(1);
    }
    else
    {
        printf("Successfully opened WAN interface\n");
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

void start_proxy() {
    pthread_t th_lan, th_wan;
    void *retval;
    pthread_create(&th_lan, NULL, thread_lan, 0);
    pthread_create(&th_wan, NULL, thread_wan, 0);
    pthread_join(th_lan, &retval);
    pthread_join(th_wan, &retval);
}

int main(int argc, char* argv[])
{
    print_header();
    process_cmdline(argc, argv); // Will exit if needed (-h)
    
    DEV_LAN = get_lan_interface();
    DEV_WAN = get_wan_interface();
    
    memcpy(ROUTER_MAC, get_router_mac(), 6);
    memcpy(PC_MAC, get_client_mac(), 6);
    
    mac_alter = get_mac_cloning_enabled();
    
    run_on_success_cmd = get_run_on_success_cmd();
    success_count_req = get_required_success_count();
    
    start_proxy();
    return 0;
}
