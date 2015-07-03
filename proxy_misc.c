/**
 * Misc functions
 *
 * Author: Hamster Tian <haotia@gmail.com>
 * Date: 2015/07
 */


#include "proxy_const.h"
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>

/* Converts a 6-bytes array to hex string "xx:xx:xx:xx:xx:xx" */
void hex_to_str(unsigned char* dest, unsigned char* src) {
	sprintf(dest, "%02x:%02x:%02x:%02x:%02x:%02x", src[0], src[1], src[2], src[3], src[4], src[5]);
}

/* Get MAC address for specific interface */
int get_mac_address(unsigned char* dest, char* ifname) {
	struct ifreq ifreq;
    int sock;
	
    if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        fprintf(stderr, "Socket error, WAN MAC address auto-discover failed.\n");
        return RESULT_FAIL;
    }
    strcpy(ifreq.ifr_name, ifname);
    if(ioctl(sock, SIOCGIFHWADDR, &ifreq)<0)
    {
        fprintf(stderr, "ioctl error, WAN MAC address auto-discover failed.\n");
        return RESULT_FAIL;
    }
	memcpy(dest, ifreq.ifr_hwaddr.sa_data, 6);
	return RESULT_OK;
}

void print_hex(const unsigned char * data, int len, int wrap_elements) {
    int i;
    for(i = 0; i < len; ++i) {
        printf("%02x ", data[i]);
        if(wrap_elements && (i + 1) % wrap_elements == 0 ) {
            printf("\n");
        }
    }
    if (!wrap_elements || (wrap_elements && len % wrap_elements != 0)) printf("\n");
}