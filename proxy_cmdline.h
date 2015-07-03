/**
 * Header for proxy_cmdline.c
 *
 * Author: Hamster Tian <haotia@gmail.com>
 * Date: 2015/07
 */

// hate "extern"
#include <stdbool.h>
typedef unsigned char u_char;

u_char* get_lan_interface();
u_char* get_wan_interface();
u_char* get_client_mac();
u_char* get_router_mac();
bool get_mac_cloning_enabled();

void print_header();
void process_cmdline(int argc, char* argv[]);
