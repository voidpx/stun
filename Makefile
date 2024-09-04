CC = gcc
CFLAGS = -Wall -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast

DF=
LF=
ifeq ($(DEBUG),1)
  DF := -DDEBUG=1
  CFLAGS += -g
else
  CFLAGS += -O3
endif
ifeq ($(ENABLE_LOG),1)
  LF := -DENABLE_LOG=1
endif

all: tun

tun: tun.c
	$(CC) $(DF) $(LF) $(CFLAGS) -o tun tun.c -lcrypto
	
clean:
	rm -f tun

.phony: clean all
