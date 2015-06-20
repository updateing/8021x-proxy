BINARY_NAME := 8021xproxy
SRC_FILES := 8021xproxy.c
CFLAGS := -ldl -lpcap -lpthread -Wall
CROSS_COMPILE_CC :=

ifneq ($(CROSS_COMPILE_CC),)
    REAL_CC := $(CROSS_COMPILE_CC)
else
    REAL_CC := $(CC)
endif

8021xproxy:
	$(REAL_CC) $(SRC_FILES) -o $(BINARY_NAME) $(CFLAGS)

.PHONY: clean
clean:
	rm 8021xproxy
