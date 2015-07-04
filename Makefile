# Build options
DEBUG := false
DEBUG_MOD_PACKET := false

# Complier options
BINARY_NAME := 8021xproxy
SRC_FILES := 8021xproxy.c proxy_cmdline.c proxy_misc.c eap_packet.c
CFLAGS := -ldl -lpcap -lpthread -Wall -Wno-pointer-sign
CROSS_COMPILE_CC := /media/hamster/Android/openwrt_my/OpenWrt-Toolchain-ar71xx-for-mips_34kc-gcc-4.8-linaro_uClibc-0.9.33.2/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/bin/mips-openwrt-linux-gcc
ADDITIONAL_INCLUDE_DIR := /media/hamster/Android/openwrt/8021xproxy
ADDITIONAL_LIBS_DIR := /media/hamster/Android/openwrt/build_dir/target-mips_34kc_uClibc-0.9.33.2/libpcap-1.5.3

ifneq ($(CROSS_COMPILE_CC),)
    REAL_CC := $(CROSS_COMPILE_CC)
else
    REAL_CC := $(CC)
endif

ifneq ($(ADDITIONAL_INCLUDE_DIR),)
    CFLAGS += -I$(ADDITIONAL_INCLUDE_DIR)
endif

ifneq ($(ADDITIONAL_LIBS_DIR),)
    CFLAGS += -L$(ADDITIONAL_LIBS_DIR)
endif

ifeq ($(DEBUG), true)
    CFLAGS += -DDEBUG
endif

ifeq ($(DEBUG_MOD_PACKET), true)
    CFLAGS += -DDEBUG_MOD_PACKET
endif

8021xproxy: $(SRC_FILES)
	$(REAL_CC) $(SRC_FILES) -o $(BINARY_NAME) $(CFLAGS)

.PHONY: clean
clean:
	rm -f 8021xproxy *.o
