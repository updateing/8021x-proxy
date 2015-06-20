# Build options
DEBUG := true
DEBUG_MOD_PACKET := true
DISABLE_ALTERING_MAC := false

# Complier options
BINARY_NAME := 8021xproxy
SRC_FILES := 8021xproxy.c
CFLAGS := -ldl -lpcap -lpthread -Wall
CROSS_COMPILE_CC := /media/hamster/Android/openwrt/OpenWrt-Toolchain-ar71xx-for-mips_r2-gcc-4.6-linaro_uClibc-0.9.33.2/toolchain-mips_r2_gcc-4.6-linaro_uClibc-0.9.33.2/bin/mips-openwrt-linux-gcc
ADDITIONAL_INCLUDE_DIR := /media/hamster/Android/openwrt/8021xproxy
ADDITIONAL_LIBS_DIR := /media/hamster/Android/openwrt/8021xproxy

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

ifneq ($(DISABLE_ALTERING_MAC), true)
    CFLAGS += -DENABLE_MAC_ALTERING
endif

8021xproxy: $(SRC_FILES)
	$(REAL_CC) $(SRC_FILES) -o $(BINARY_NAME) $(CFLAGS)

.PHONY: clean
clean:
	rm 8021xproxy
