/**
 * EAP Packet Analyzer
 *
 * Determine the type of packet (EAP-Success, EAP-Failure etc)
 * Maybe some more. Currently only type is supported.
 * Supports EAP in VLAN as well.
 *
 * Author: Hamster Tian <haotia@gmail.com>
 * Date: 2015/07
 */

#include "packet_const.h"
#include "proxy_const.h"
#include <string.h>
#include <stdio.h>

/* 12th and 13th bytes are protocol. Used to identify if 802.1Q VLAN */
#define PROTOCOL_OFFSET 12
#define VLAN_HEADER_SIZE 4
#define PACKET_MIN_LENGTH (sizeof(ETHERNET_HEADER) + sizeof(EAPOL_HEADER))
#define PACKET_NO_VLAN_HEADER_SIZE (PACKET_MIN_LENGTH + sizeof(EAP_HEADER))
#define PACKET_VLAN_HEADER_SIZE (PACKET_NO_VLAN_HEADER_SIZE + VLAN_HEADER_SIZE)

PACKET_HEADER packet_hdr;

/* load_packet will ensure that the packet is long enough for is_* */
/* This is bad practice though :-( */
static inline int is_8021q_encap(const unsigned char* pkt) {
	return (pkt[PROTOCOL_OFFSET] == 0x81 && pkt[PROTOCOL_OFFSET + 1] == 0x00);
}

/* After loading packet, we can do these */
int get_packet_eap_code() {
	return packet_hdr.eap_hdr.code[0];
}

int get_packet_eap_type() {
	return packet_hdr.eap_hdr.type[0];
}

int get_packet_eapol_type() {
	return packet_hdr.eapol_hdr.type[0];
}

/* Load the packet into struct */
int load_packet(const unsigned char* pkt, int pkt_len) {
	memset((void*)&packet_hdr, 0xFF, sizeof(PACKET_HEADER));
	
	if (pkt_len < PACKET_MIN_LENGTH) {
		// The packet we care about has at least these parts
		return RESULT_FAIL;
	}

	if (is_8021q_encap(pkt)) {
		if (pkt_len < PACKET_MIN_LENGTH + VLAN_HEADER_SIZE)
			return RESULT_FAIL;
		
		memcpy(&packet_hdr.eth_hdr, pkt, sizeof(ETHERNET_HEADER));
		memcpy(&packet_hdr.eapol_hdr,
			pkt + sizeof(ETHERNET_HEADER) + VLAN_HEADER_SIZE,
			sizeof(EAPOL_HEADER));
		
		// EAP Packet may not appear in EAPOL-Start and Logiff
		if (get_packet_eapol_type() == EAP_PACKET) {
			if (pkt_len < PACKET_VLAN_HEADER_SIZE)
				return RESULT_FAIL;
			
			memcpy(&packet_hdr.eap_hdr,
				pkt + PACKET_MIN_LENGTH + VLAN_HEADER_SIZE,
				sizeof(EAP_HEADER));
		}
	} else {
		memcpy(&packet_hdr, pkt, PACKET_MIN_LENGTH); // Read 2 headers
	
		if (get_packet_eapol_type() == EAP_PACKET) {
			if (pkt_len < PACKET_NO_VLAN_HEADER_SIZE)
				return RESULT_FAIL;
			
			memcpy(&packet_hdr.eap_hdr,
				pkt + PACKET_MIN_LENGTH,
				sizeof(EAP_HEADER));
		}	
	}
	
	return RESULT_OK;
}

void dump_packet_eap_info() {
    // It's a little strange that we use get_* in C ...?
    int eapol_type = get_packet_eapol_type();
    int eap_code = get_packet_eap_code();
    int eap_type = get_packet_eap_type();
    
    char* eapol_str[5] = {
        "EAPOL Type: EAP Packet\n",
        "EAPOL Type: EAPOL-Start\n",
        "EAPOL Type: EAPOL-Logoff\n",
        "EAPOL Type: EAPOL-RJ-Proprietary-KeepAlive\n"
        "!!! Unknown EAPOL Type: %d\n" // %d!
    };

    char* eap_code_str[5] = {
        "EAP Code: Request\n",
        "EAP Code: Response\n",
        "EAP Code: Success\n",
        "EAP Code: Failure\n"
        "!!! Unknown EAP Code: %d\n"
    }; // eap_code starts from 1 while the array is 0

    if (eapol_type < EAPOL_TYPE_MIN || eapol_type > EAPOL_TYPE_MAX) {
        fprintf(stderr, eapol_str[4], eapol_type);
    } else if (eapol_type == EAPOL_RJ_PROPRIETARY_KEEPALIVE
        || eapol_type == EAPOL_START
        || eapol_type == EAPOL_LOGOFF) {
        printf(eapol_str[eapol_type == EAPOL_RJ_PROPRIETARY_KEEPALIVE ?
                            3 : eapol_type]); // Fu RJ
        goto NEWLINE_END;
    } else {
        printf(eapol_str[eapol_type]);
    }
    
    if (eap_code < EAP_CODE_MIN || eap_code > EAP_CODE_MAX)
        fprintf(stderr, eap_code_str[4], eap_code);
    else {
        printf(eap_code_str[eap_code - 1]); // eap_code starts from 1
        if (eap_code == EAP_SUCCESS || eap_code == EAP_FAILURE)
            goto NEWLINE_END;
    }
    
    switch (eap_type) {
        case IDENTITY:
            printf("EAP Type: Identity\n");
            break;
        case MD5_CHALLENGE:
            printf("EAP Type: MD5 Challenge\n");
            break;
         default:
            fprintf(stderr, "!!! Unknown EAP Type: %d\n", eap_type);
    }

NEWLINE_END:
    printf("\n");
}