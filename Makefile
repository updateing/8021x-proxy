# Build options
DEBUG := true
DEBUG_MOD_PACKET := true
DISABLE_ALTERING_MAC := false

# Complier options
BINARY_NAME := 8021xproxy
SRC_FILES := 8021xproxy.c
CFLAGS := -ldl -lpcap -lpthread -Wall
CROSS_COMPILE_CC :=
ADDITIONAL_INCLUDE_DIR :=
ADDITIONAL_LIBS_DIR :=

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
    CFLAGS += -DENABLE_ALTERING_MAC
endif

8021xproxy: $(SRC_FILES)
	$(REAL_CC) $(SRC_FILES) -o $(BINARY_NAME) $(CFLAGS)

.PHONY: clean
clean:
	rm 8021xproxy
