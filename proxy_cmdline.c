/**
 * Command line processor
 *
 * Reads command line options and set variables.
 * Give help when needed.
 *
 * Author: Hamster Tian <haotia@gmail.com>
 * Date: 2015/07/03
 */
 
#include "proxy_const.h"
#include "proxy_misc.h"
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

typedef unsigned char u_char;

/* MAC address of PC client in LAN. We only route packets from this MAC */
u_char client_mac[6]; // TODO: set this in pcap filter. Or proxy all?

/* MAC address of router WAN interface. We will replace MAC address to this */
u_char router_mac[6]; // TODO: auto discover by device name
// Don't tell me that there are longer-than-six-bytes MACs

/* Interface names to listen on */
u_char* lan_interface;
u_char* wan_interface;

/* Run this command when enough EAP Success'es is received */
u_char* cmd_on_success;
int required_success_count;

/* MAC cloning enabled or not. Only get enabled when
 * -c is given
 * -n is NOT given
 */
int mac_cloning_enabled = 0;

u_char* get_lan_interface() { return lan_interface; }
u_char* get_wan_interface() { return wan_interface; }
u_char* get_client_mac() { return client_mac; }
u_char* get_router_mac() { return router_mac; }
bool get_mac_cloning_enabled() { return mac_cloning_enabled; }
u_char* get_run_on_success_cmd() { return cmd_on_success; }
int get_required_success_count() { return required_success_count; }

void print_header() {
	printf("802.1x Proxy v" STRINGIFY(VERSION) "\n");
	printf("Inspired by & based on an issue on MentoHUST issue tracker.\n");
	printf("By Hamster Tian, an EE student of HUST. 2015\n");
#ifdef SPECIAL_THANKS
	printf(SPECIAL_THANKS);
#endif
	printf("\n");
}

static void print_help() {
	printf("\nThis is a 802.1x EAP packet proxy between LAN and WAN. " 
		"Normally used to fu some proprietary supplicant and get MentoHUST working\n"
		"Also acts as a MAC address cloner.\n");
	printf("\nUsage:\n");
	printf("	-h --help Show this help.\n");
	printf("	-r --router-mac xx:xx:xx:xx:xx:xx [OPTIONAL] MAC address of WAN interface. "
		"If set, auto-discovering will be disabled.\n");
	printf("	-c --client-mac xx:xx:xx:xx:xx:xx [OPTIONAL] MAC address of client computer. "
		"Only packets from this MAC will be accepted. "
		"If not set, all 802.1x (protocol 0x888E) packets will be routed. "
		"This is untested and COULD BE DANGEROUS! You'd better specific it.\n");
	printf("	-l --lan-interface ethX [REQUIRED] LAN interface to listen on.\n");
	printf("	-w --wan-interface ethY [REQUIRED] WAN interface to send packet to.\n");
	printf("	-n --no-mac-cloning [OPTIONAL] DO NOT clone MAC even if -c is given. "
		"By default MAC cloning is enabled when -c is given. "
		"With this option, -c will act as a filter.\n");
	printf("	-s --run-on-success COMMAND [OPTIONAL] Perform COMMAND on EAP Success.\n");
	printf("	-t --count-of-success X [OPTIONAL] Wait for X EAP success packets "
		"before performing shell command in -s. Default is 1.\n");
}

/* Converts xx:xx:xx:xx:xx:xx MAC address to 6 bytes */
static int process_mac_address(u_char mac_storage[], u_char* mac_string) {
	int scanned_elements = 0;
	
	scanned_elements = sscanf(mac_string, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
		&mac_storage[0], &mac_storage[1], &mac_storage[2], &mac_storage[3],
		&mac_storage[4], &mac_storage[5]);
	if (scanned_elements != 6) {
		fprintf(stderr, "MAC address %s has wrong format. "
			"xx:xx:xx:xx:xx:xx is allowed.\n", mac_string);
		return RESULT_FAIL;
	}
	return RESULT_OK;
}

static int process_string(u_char** intf_storage, u_char* intf_string) {
	// Silly bug here: u_char**
	size_t len = strlen(intf_string);
	if (*intf_storage != NULL)
		free(*intf_storage);
	*intf_storage = (char*) malloc(len > MAX_STRING_PARAM_LENGTH ?
		MAX_STRING_PARAM_LENGTH : len);
	// We have to use u_char** due to this malloc
	// We need to change the original pointer
	if (*intf_storage == NULL)
		return RESULT_FAIL;
	
	strncpy(*intf_storage, intf_string, MAX_STRING_PARAM_LENGTH);
	return RESULT_OK;
}

static int process_int(int* int_storage, u_char* int_str) {
	int scan_count = 0;
	scan_count = sscanf(int_str, "%d", int_storage);
	return scan_count ? RESULT_OK : RESULT_FAIL;
}

static void clean_vars() {
	memset(client_mac, 0 ,6);
	memset(router_mac, 0, 6);
	wan_interface = NULL;
	lan_interface = NULL;
	cmd_on_success = NULL;
	required_success_count = DEFAULT_REQUIRED_SUCCESS_COUNT;
}

static void dump_params() {
	u_char mac_buf[18]; // xx:xx:xx:xx:xx:xx for echoing

	hex_to_str(mac_buf, router_mac);
	printf("Router MAC: %s\n", mac_buf);
	hex_to_str(mac_buf, client_mac);
	printf("Client MAC: %s\n", mac_buf);
	printf("LAN Interface: %s\n", lan_interface);
	printf("WAN Interface: %s\n", wan_interface);
	printf("MAC Address Cloning: %s\n", mac_cloning_enabled ? "TRUE" : "FALSE");
}

/* Called by main function */
void process_cmdline(int argc, char* argv[]) {
	int i;
	bool mac_clone_force_off = false;
	bool wan_intf_set = false;
	bool lan_intf_set = false;
	bool router_mac_set = false;
	
	clean_vars();
	for (i = 1; i < argc; i++) { // Skip first executable name
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			print_help();
			exit(EXIT_NO_ERROR);
		} else if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--client-mac")) {
			if (i + 1 < argc && process_mac_address(client_mac, argv[i + 1]) == RESULT_OK) {
				mac_cloning_enabled = true;
				i++; // Skip next parameter in the loop. Already handled that.
			} else {
				fprintf(stderr, "Client MAC (-c) is wrong or missing!\n");
				exit(EINVAL);
			}
		} else if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--router-mac")) {
			if (i + 1 < argc && process_mac_address(router_mac, argv[i + 1]) == RESULT_OK) {
				router_mac_set = true;
				i++;
			} else {
				fprintf(stderr, "Router MAC (-r) is wrong or missing!\n");
				exit(EINVAL);
			}
		} else if (!strcmp(argv[i], "-w") || !strcmp(argv[i], "--wan-interface")) {
			if (i + 1 < argc && process_string(&wan_interface, argv[i + 1]) == RESULT_OK) {
				wan_intf_set = true;
				i++;
			} else {
				fprintf(stderr, "WAN interface (-w) is wrong or missing!\n");
				exit(EINVAL);
			}
		} else if (!strcmp(argv[i], "-l") || !strcmp(argv[i], "--lan-interface")) {
			if (i + 1 < argc && process_string(&lan_interface, argv[i + 1]) == RESULT_OK) {
				lan_intf_set = true;
				i++;
			} else {
				fprintf(stderr, "LAN interface (-l) is wrong or missing!\n");
				exit(EINVAL);
			}
		} else if (!strcmp(argv[i], "-n") || !strcmp(argv[i], "--no-mac-cloning")) {
			mac_clone_force_off = true; // Postpone until loop is finished.
		} else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--run-on-success")) {
			if (i + 1 < argc && process_string(&cmd_on_success, argv[i + 1]) == RESULT_OK) {
				i++;
			} else {
				fprintf(stderr, "Run-on-success command is wrong\n");
				exit(EINVAL);
			}
		} else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--count-of-success")) {
			if (i + 1 < argc && process_int(&required_success_count, argv[i + 1]) == RESULT_OK) {
				i++;
			} else {
				fprintf(stderr, "Count of success is wrong. Please enter an decimal integer\n");
				exit(EINVAL);
			}
		}
	}
	
	if (mac_clone_force_off)
		mac_cloning_enabled = FALSE; // Set it here in case we get "-n -c xx:xx.."
		
	if (!(wan_intf_set && lan_intf_set)) { // One of them is not set
		fprintf(stderr, "WAN interface (-w) and LAN interface (-l) must be defined!\n");
		exit(EINVAL);
	}
	
	if (!router_mac_set && mac_cloning_enabled
		&& get_mac_address(router_mac, wan_interface)) {
		// No WAN MAC, user ask to clone MAC, MAC auto-discover failed
		fprintf(stderr, "Router MAC address auto-discover failed "
			"while cloning MAC address is enabled, exiting. "
			"Please specific MAC address for WAN\n");
		exit(EIO);
	}
	
	// Echoing the parameters back
	dump_params();
}