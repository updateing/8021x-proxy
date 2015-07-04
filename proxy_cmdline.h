/**
 * Header for proxy_cmdline.c
 *
 * Author: Hamster Tian <haotia@gmail.com>
 * Date: 2015/07
 */

// hate "extern"

#ifndef PROXY_CMDLINE_H
#define PROXY_CMDLINE_H

#include <stdbool.h>
typedef unsigned char u_char;

u_char* get_lan_interface();
u_char* get_wan_interface();
u_char* get_client_mac();
u_char* get_router_mac();
bool get_mac_cloning_enabled();
u_char* get_run_on_success_cmd();
int get_required_success_count();

void print_header();
void process_cmdline(int argc, char* argv[]);

#endif