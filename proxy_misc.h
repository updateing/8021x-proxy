/**
 * Misc functions
 *
 * Author: Hamster Tian <haotia@gmail.com>
 * Date: 2015/07
 */

#ifndef PROXY_MISC_H
#define PROXY_MISC_H

void hex_to_str(unsigned char* dest, unsigned char* src);
int get_mac_address(unsigned char* dest, char* ifname);
void print_hex(const unsigned char * data, int len, int wrap_elements);

#endif