CC = gcc
CFLAGS = -Wall

DF=
ifeq ($(DEBUG),1)
  DF := -DDEBUG=1
  CFLAGS += -g
else
  CFLAGS += -O3
endif

all: tun

tun: tun.c
	$(CC) $(DF) $(CFLAGS) -o tun tun.c -lcrypto
	
clean:
	rm -f tun

.phony: clean all
