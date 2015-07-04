/**
 * Header for eap_packet.c
 *
 * Author: Hamster Tian <haotia@gmail.com>
 * Date: 2015/07
 */

#include "packet_const.h"

int load_packet(const unsigned char* pkt, int pkt_len);
int get_packet_eap_code();
int get_packet_eap_type();
int get_packet_eapol_type();
void dump_packet_eap_info();